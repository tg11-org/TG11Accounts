# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""Account hub: profile media/bio/phone, email change, linked apps, wallet,
AI key vault, and the application-facing APIs."""
from __future__ import annotations

import io
import json
import secrets
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import accounts, oidc, payments, sms, vault
from .config import settings
from .models import ApplicationIdentityLink, Consent, OAuthClient, PaymentHold, Token, User, get_db, utcnow
from .tokens import hash_token

router = APIRouter()


# helpers imported lazily from web to avoid a circular import
def _web():
    from . import web

    return web


def current_user(request: Request, db: Session = Depends(get_db)):
    return _web().current_user(request, _web().current_user_optional(request, db, _web().get_session(request, db)))


async def csrf(request: Request, db: Session = Depends(get_db)):
    return await _web().csrf_protect(request, _web().get_session(request, db))


def render(request, name, ctx=None, status=200):
    return _web().render(request, name, ctx, status)


def redirect(url):
    return _web()._redirect(url)


# --- profile --------------------------------------------------------------------------

@router.post("/account/profile", dependencies=[Depends(csrf)])
def profile_save(display_name: str = Form(""), username: str = Form(...), bio: str = Form(""), website: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
    un = accounts.norm_username(username)
    if not accounts.USERNAME_RE.match(un):
        return redirect("/account?err=Invalid+username")
    other = accounts.by_username(db, un)
    if other is not None and other.id != user.id:
        return redirect("/account?err=Username+taken")
    website = website.strip()[:200]
    if website and not website.startswith(("http://", "https://")):
        website = "https://" + website
    user.username, user.display_name, user.bio, user.website = un, display_name.strip()[:80] or un, bio.strip()[:1000], website
    return redirect("/account?msg=Profile+saved")


def _store_image(user: User, upload: UploadFile, kind: str) -> str:
    from PIL import Image, ImageOps

    raw = upload.file.read(settings.TG11_MAX_UPLOAD_BYTES + 1)
    if len(raw) > settings.TG11_MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Image too large (max 8 MB)")
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
    except Exception:
        raise HTTPException(400, "That file is not an image")
    img = ImageOps.exif_transpose(img).convert("RGB")
    if kind == "avatar":
        img = ImageOps.fit(img, (512, 512))
    else:
        img.thumbnail((1600, 1600))
        w, h = img.size
        target_h = min(h, int(w / 3.2))
        img = img.crop((0, (h - target_h) // 2, w, (h - target_h) // 2 + target_h))
    folder = settings.media_dir / user.id
    folder.mkdir(parents=True, exist_ok=True)
    name = f"{kind}-{secrets.token_hex(4)}.jpg"
    img.save(folder / name, "JPEG", quality=88, optimize=True)
    for old in folder.glob(f"{kind}-*.jpg"):
        if old.name != name:
            old.unlink(missing_ok=True)
    return f"{user.id}/{name}"


@router.post("/account/avatar", dependencies=[Depends(csrf)])
def avatar_upload(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.avatar_path = _store_image(user, file, "avatar")
    return redirect("/account?msg=Profile+image+updated")


@router.post("/account/header", dependencies=[Depends(csrf)])
def header_upload(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.header_path = _store_image(user, file, "header")
    return redirect("/account?msg=Header+image+updated")


@router.post("/account/images/{kind}/remove", dependencies=[Depends(csrf)])
def image_remove(kind: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if kind == "avatar":
        user.avatar_path = ""
    elif kind == "header":
        user.header_path = ""
    return redirect("/account?msg=Image+removed")


# --- email change ---------------------------------------------------------------------

@router.post("/account/email", dependencies=[Depends(csrf)])
def email_change_request(new_email: str = Form(...), password: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
    from .passwords import verify_password

    new = accounts.norm_email(new_email)
    if not accounts.EMAIL_RE.match(new):
        return redirect("/account?err=Enter+a+valid+email")
    if user.password_hash and not verify_password(password, user.password_hash):
        return redirect("/account?err=Password+incorrect")
    if accounts.by_email(db, new):
        return redirect("/account?err=That+email+is+already+used+by+another+account")
    user.pending_email = new
    tok = accounts.issue_action(db, user, "change_email", 60 * 24, payload=new)
    accounts.send_mail(new, f"{settings.TG11_SITE_NAME}: confirm your new email", f"Hi {user.username},\n\nConfirm changing your TG11 account email to {new} by opening:\n\n{settings.issuer}/email/confirm/{tok}\n\nValid for 24 hours. If this wasn't you, ignore this message.\n")
    accounts.send_mail(user.email, f"{settings.TG11_SITE_NAME}: email change requested", f"A request was made to change this account's email to {new}. If that wasn't you, sign in and change your password.\n")
    return redirect("/account?msg=Check+the+new+address+for+a+confirmation+link")


@router.get("/email/confirm/{token}")
def email_change_confirm(token: str, db: Session = Depends(get_db)):
    from .models import ActionToken

    row = db.scalar(select(ActionToken).where(ActionToken.token_hash == hash_token(token), ActionToken.action == "change_email"))
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        return redirect("/account?err=Confirmation+link+invalid+or+expired")
    user = db.get(User, row.user_id)
    if user is None or accounts.by_email(db, row.payload):
        return redirect("/account?err=That+email+is+no+longer+available")
    row.used_at = utcnow()
    user.email, user.pending_email, user.email_verified_at = row.payload, "", utcnow()
    return redirect("/account?msg=Email+updated+and+verified")


@router.post("/account/email/cancel", dependencies=[Depends(csrf)])
def email_change_cancel(db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.pending_email = ""
    return redirect("/account?msg=Email+change+cancelled")


@router.post("/account/email/resend-verification", dependencies=[Depends(csrf)])
def resend_verification(db: Session = Depends(get_db), user: User = Depends(current_user)):
    accounts.send_verification(db, user)
    return redirect("/account?msg=Verification+email+sent")


# --- phone ---------------------------------------------------------------------------

@router.post("/account/phone", dependencies=[Depends(csrf)])
def phone_set(phone: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        number = sms.normalize_phone(phone)
    except ValueError as exc:
        return redirect(f"/account?err={exc}")
    user.phone, user.phone_verified_at = number, None
    code = f"{secrets.randbelow(10**6):06d}"
    from .models import ActionToken
    from datetime import timedelta

    db.add(ActionToken(user_id=user.id, action="verify_phone", token_hash=hash_token(f"{number}:{code}"), payload=number, expires_at=utcnow() + timedelta(minutes=10)))
    if sms.send_sms(number, f"Your TG11 verification code is {code}"):
        return redirect("/account?msg=Code+sent+by+SMS")
    return redirect("/account?msg=Number+saved.+SMS+verification+is+not+configured+on+this+server+yet,+so+it+stays+unverified.")


@router.post("/account/phone/verify", dependencies=[Depends(csrf)])
def phone_verify(code: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    from .models import ActionToken

    row = db.scalar(select(ActionToken).where(ActionToken.token_hash == hash_token(f"{user.phone}:{code.strip()}"), ActionToken.action == "verify_phone", ActionToken.user_id == user.id))
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        return redirect("/account?err=Invalid+or+expired+code")
    row.used_at = utcnow()
    user.phone_verified_at = utcnow()
    return redirect("/account?msg=Phone+verified")


@router.post("/account/phone/remove", dependencies=[Depends(csrf)])
def phone_remove(db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.phone, user.phone_verified_at = "", None
    return redirect("/account?msg=Phone+removed")


# --- wallet ----------------------------------------------------------------------------

@router.get("/wallet")
def wallet(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    clients = {c.client_id: c for c in db.scalars(select(OAuthClient))}
    return render(request, "wallet.html", {"methods": payments.list_methods(db, user), "holds": payments.list_holds(db, user), "providers": payments.provider_list(), "clients": clients})


@router.post("/wallet/add/{provider}", dependencies=[Depends(csrf)])
def wallet_add(request: Request, provider: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        setup = payments.get_provider(provider).begin_setup(db, user)
    except payments.PaymentError as exc:
        return redirect(f"/wallet?err={exc}")
    return render(request, "wallet_setup.html", {"provider": payments.get_provider(provider).info, "setup": setup})


@router.get("/wallet/stripe/complete")
def wallet_stripe_complete(setup_intent: str = "", redirect_status: str = "", db: Session = Depends(get_db), user: User = Depends(current_user)):
    if redirect_status not in ("succeeded", ""):
        return redirect("/wallet?err=Card+setup+was+not+completed")
    try:
        m = payments.get_provider("stripe").complete_setup(db, user, {"setup_intent": setup_intent})
        if not any(x.is_default for x in payments.list_methods(db, user)):
            payments.set_default(db, user, m)
    except payments.PaymentError as exc:
        return redirect(f"/wallet?err={exc}")
    return redirect("/wallet?msg=Payment+method+added")


@router.post("/wallet/methods/{method_id}/default", dependencies=[Depends(csrf)])
def wallet_default(method_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    m = payments.get_method(db, user, method_id)
    if m is None:
        raise HTTPException(404)
    payments.set_default(db, user, m)
    return redirect("/wallet?msg=Default+updated")


@router.post("/wallet/methods/{method_id}/remove", dependencies=[Depends(csrf)])
def wallet_remove(method_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    m = payments.get_method(db, user, method_id)
    if m is None:
        raise HTTPException(404)
    try:
        payments.remove_method(db, user, m)
    except payments.PaymentError as exc:
        return redirect(f"/wallet?err={exc}")
    return redirect("/wallet?msg=Payment+method+removed")


# --- AI key vault ----------------------------------------------------------------------

@router.get("/vault")
def vault_page(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return render(request, "vault.html", {"rows": vault.list_credentials(db, user), "known": vault.KNOWN_PROVIDERS, "vault_ready": _vault_ready()})


def _vault_ready() -> bool:
    try:
        from .crypto import get_cipher

        get_cipher()
        return True
    except Exception:
        return False


@router.post("/vault", dependencies=[Depends(csrf)])
def vault_save(provider: str = Form(...), api_key: str = Form(""), base_url: str = Form(""), label: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        vault.upsert(db, user, provider, api_key=api_key, base_url=base_url, label=label)
    except Exception as exc:
        return redirect(f"/vault?err={exc}")
    return redirect("/vault?msg=Saved.+Apps+you+trust+can+now+use+this+key.")


@router.post("/vault/{provider}/delete", dependencies=[Depends(csrf)])
def vault_delete(provider: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = vault.get_credential(db, user, provider)
    if row is not None:
        vault.delete(db, user, row)
    return redirect("/vault?msg=Removed")


# --- APIs for applications --------------------------------------------------------------

def _bearer_user(request: Request, db: Session, scope: str):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise oidc.OAuthError("invalid_token", "bearer token required", 401)
    user, tok = oidc.resolve_access_token(db, auth[7:].strip())
    if scope not in tok.scope.split():
        raise oidc.OAuthError("insufficient_scope", f"token lacks {scope}", 403)
    client = oidc.get_client(db, tok.client_id)
    return user, tok, client


@router.get("/api/v1/me")
def api_me(request: Request, db: Session = Depends(get_db)):
    user, tok, _ = _bearer_user(request, db, "openid")
    scopes = tok.scope.split()
    data = oidc.user_claims(user, scopes)
    if "profile" in scopes:
        data.update({"picture": user.avatar_url or None, "tg11_header_image": user.header_url or None, "tg11_bio": user.bio, "website": user.website or None})
    if "phone" in scopes:
        data.update({"phone_number": user.phone or None, "phone_number_verified": user.phone_verified_at is not None})
    return JSONResponse({k: v for k, v in data.items() if v is not None})


@router.get("/api/v1/ai/credentials")
def api_ai_credentials(request: Request, db: Session = Depends(get_db)):
    user, _tok, client = _bearer_user(request, db, "tg11.ai")
    if client is None or not client.trusted:
        raise oidc.OAuthError("insufficient_scope", "only trusted first-party applications may read the vault", 403)
    return JSONResponse({"credentials": vault.export_for_app(db, user)})


def _client_from_basic(request: Request, db: Session) -> OAuthClient:
    import base64

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        raise oidc.OAuthError("invalid_client", "client basic auth required", 401)
    try:
        cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
    except Exception:
        raise oidc.OAuthError("invalid_client", "malformed basic auth", 401)
    return oidc.authenticate_client(db, cid, secret)


def _consented(db: Session, user: User, client: OAuthClient, scope: str) -> bool:
    if client.trusted:
        return True
    c = db.scalar(select(Consent).where(Consent.user_id == user.id, Consent.client_id == client.client_id, Consent.revoked_at.is_(None)))
    return c is not None and scope in c.scope.split()


@router.post("/api/v1/links")
async def api_register_link(request: Request, db: Session = Depends(get_db)):
    """Apps report 'TG11 user <sub> is linked to my local account <legacy_id>'."""
    client = _client_from_basic(request, db)
    body = await request.json()
    user = db.get(User, str(body.get("sub", "")))
    if user is None:
        raise oidc.OAuthError("invalid_request", "unknown sub")
    legacy = str(body.get("legacy_id", ""))[:64]
    if not legacy:
        raise oidc.OAuthError("invalid_request", "legacy_id required")
    row = db.scalar(select(ApplicationIdentityLink).where(ApplicationIdentityLink.application == client.application, ApplicationIdentityLink.legacy_id == legacy, ApplicationIdentityLink.federation_id == str(body.get("federation_id", ""))))
    if row is None:
        row = ApplicationIdentityLink(application=client.application, legacy_id=legacy, federation_id=str(body.get("federation_id", ""))[:64])
        db.add(row)
    row.user_id, row.local_uuid, row.migration_source, row.migration_status = user.id, str(body.get("local_uuid", ""))[:36], str(body.get("source", "oidc_login"))[:32], "linked"
    db.flush()
    return JSONResponse({"ok": True, "link_id": row.id})


@router.post("/api/v1/payments/holds")
async def api_hold_create(request: Request, db: Session = Depends(get_db)):
    client = _client_from_basic(request, db)
    body = await request.json()
    user = db.get(User, str(body.get("sub", "")))
    if user is None:
        raise oidc.OAuthError("invalid_request", "unknown sub")
    if not _consented(db, user, client, "tg11.payments"):
        raise oidc.OAuthError("access_denied", "user has not granted tg11.payments to this application", 403)
    method = None
    if body.get("method_id"):
        method = payments.get_method(db, user, str(body["method_id"]))
        if method is None:
            raise oidc.OAuthError("invalid_request", "unknown method")
    try:
        hold = payments.place_hold(db, user, client.client_id, int(body.get("amount", 0)), str(body.get("currency", "usd")), str(body.get("description", "")), str(body.get("reference", "")), method, int(body.get("ttl_days", 7)))
    except (payments.PaymentError, ValueError) as exc:
        raise oidc.OAuthError("invalid_request", str(exc))
    return JSONResponse(payments.hold_dict(hold), status_code=201 if hold.status == "authorized" else 402)


def _client_hold(request: Request, db: Session, hold_id: str) -> PaymentHold:
    client = _client_from_basic(request, db)
    hold = db.get(PaymentHold, hold_id)
    if hold is None or hold.client_id != client.client_id:
        raise oidc.OAuthError("invalid_request", "unknown hold", 404)
    return hold


@router.get("/api/v1/payments/holds/{hold_id}")
def api_hold_get(request: Request, hold_id: str, db: Session = Depends(get_db)):
    return JSONResponse(payments.hold_dict(_client_hold(request, db, hold_id)))


@router.post("/api/v1/payments/holds/{hold_id}/capture")
async def api_hold_capture(request: Request, hold_id: str, db: Session = Depends(get_db)):
    hold = _client_hold(request, db, hold_id)
    body = await request.json() if request.headers.get("content-length", "0") not in ("0", "") else {}
    try:
        payments.capture_hold(db, hold, int(body["amount"]) if body.get("amount") else None)
    except payments.PaymentError as exc:
        raise oidc.OAuthError("invalid_request", str(exc))
    return JSONResponse(payments.hold_dict(hold))


@router.post("/api/v1/payments/holds/{hold_id}/release")
def api_hold_release(request: Request, hold_id: str, db: Session = Depends(get_db)):
    hold = _client_hold(request, db, hold_id)
    try:
        payments.release_hold(db, hold)
    except payments.PaymentError as exc:
        raise oidc.OAuthError("invalid_request", str(exc))
    return JSONResponse(payments.hold_dict(hold))


@router.get("/api/v1/payments/methods")
def api_methods(request: Request, db: Session = Depends(get_db)):
    """User-token endpoint: list the user's methods (labels only) for app UIs."""
    user, _tok, _client = _bearer_user(request, db, "tg11.payments")
    return JSONResponse({"methods": [{"id": m.id, "provider": m.provider, "kind": m.kind, "label": m.label, "is_default": m.is_default, "status": m.status} for m in payments.list_methods(db, user)]})
