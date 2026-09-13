# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""HTTP layer: account pages + OIDC endpoints."""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from typing import Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, accounts, mfa, oidc
from .config import settings
from .models import ApplicationIdentityLink, Base, Consent, OAuthClient, Token, User, UserSession, engine, ensure_schema, get_db, utcnow

log = logging.getLogger("tg11")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
templates.env.globals.update(site_name=settings.TG11_SITE_NAME, issuer=settings.issuer, version=__version__, registration=settings.TG11_ALLOW_REGISTRATION)
_signer = URLSafeTimedSerializer(settings.TG11_SECRET_KEY, salt="tg11-session")
#: a half-authenticated login: the password was right, the second factor is not
#: in yet. It is signed, short-lived, and grants nothing on its own.
_mfa_signer = URLSafeTimedSerializer(settings.TG11_SECRET_KEY, salt="tg11-mfa-pending")
COOKIE, CSRF_COOKIE, MFA_COOKIE = "tg11_session", "tg11_csrf", "tg11_mfa"
REAUTH_COOKIE = "tg11_oidc_reauth"
MFA_PENDING_MAX_AGE = 300  # seconds to finish the second step
REAUTH_MAX_AGE = 300
_reauth_signer = URLSafeTimedSerializer(settings.TG11_SECRET_KEY, salt="tg11-oidc-reauth")


class LoginRequired(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _safe_next(url: Optional[str]) -> str:
    return url if url and url.startswith("/") and not url.startswith("//") else "/account"


# Bind a fresh login to the exact authorization request and new session.
def _authorize_fingerprint(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.path != "/oauth/authorize" or parsed.fragment:
        return ""
    query = urlencode(parse_qsl(parsed.query, keep_blank_values=True))
    return hashlib.sha256(query.encode()).hexdigest()


def _set_reauth_proof(resp: Response, next_url: str, sid: str) -> None:
    fingerprint = _authorize_fingerprint(_safe_next(next_url))
    if fingerprint:
        resp.set_cookie(
            REAUTH_COOKIE,
            _reauth_signer.dumps({"sid": sid, "request": fingerprint}),
            max_age=REAUTH_MAX_AGE,
            httponly=True,
            secure=settings.TG11_COOKIE_SECURE and not settings.is_dev,
            samesite="lax",
            path="/oauth/authorize",
        )


def _completed_reauth(request: Request, sess: Optional[UserSession]) -> bool:
    if sess is None or not request.cookies.get(REAUTH_COOKIE):
        return False
    try:
        proof = _reauth_signer.loads(request.cookies[REAUTH_COOKIE], max_age=REAUTH_MAX_AGE)
    except BadSignature:
        return False
    if not isinstance(proof, dict):
        return False
    fingerprint = _authorize_fingerprint(str(request.url.path) + "?" + str(request.url.query))
    return bool(
        fingerprint
        and secrets.compare_digest(str(proof.get("sid", "")), str(sess.id))
        and secrets.compare_digest(str(proof.get("request", "")), fingerprint)
    )


def read_sid(request: Request) -> Optional[str]:
    raw = request.cookies.get(COOKIE)
    if not raw:
        return None
    try:
        return _signer.loads(raw, max_age=settings.TG11_SESSION_MAX_AGE)
    except BadSignature:
        return None


def set_session(resp: Response, sid: str) -> None:
    resp.set_cookie(COOKIE, _signer.dumps(sid), max_age=settings.TG11_SESSION_MAX_AGE, httponly=True, secure=settings.TG11_COOKIE_SECURE and not settings.is_dev, samesite="lax", path="/")


def get_session(request: Request, db: Session = Depends(get_db)) -> Optional[UserSession]:
    s = accounts.valid_session(db, read_sid(request) or "")
    if s is not None:
        s.last_seen_at = utcnow()
        request.state.session = s
    return s


def current_user_optional(request: Request, db: Session = Depends(get_db), sess: Optional[UserSession] = Depends(get_session)) -> Optional[User]:
    if sess is None:
        return None
    u = db.get(User, sess.user_id)
    if u is None or not u.is_active:
        return None
    request.state.user = u
    return u


def current_user(request: Request, user: Optional[User] = Depends(current_user_optional)) -> User:
    if user is None:
        raise LoginRequired(str(request.url.path) + (("?" + str(request.url.query)) if request.url.query else ""))
    return user


def csrf_token_for(request: Request) -> str:
    sess = getattr(request.state, "session", None)
    if sess is not None:
        return sess.csrf_token
    tok = request.cookies.get(CSRF_COOKIE)
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.state.new_csrf = tok
    return tok


async def csrf_protect(request: Request, sess: Optional[UserSession] = Depends(get_session)) -> None:
    if request.method in ("GET", "HEAD"):
        return
    form = await request.form()
    supplied = form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = sess.csrf_token if sess is not None else request.cookies.get(CSRF_COOKIE)
    if not supplied or not expected or not secrets.compare_digest(str(supplied), str(expected)):
        raise HTTPException(403, "CSRF token missing or invalid")


def render(request: Request, name: str, ctx: Optional[dict] = None, status: int = 200):
    context = {"request": request, "csrf_token": csrf_token_for(request), "user": getattr(request.state, "user", None), "msg": request.query_params.get("msg"), "err": request.query_params.get("err")}
    context.update(ctx or {})
    resp = templates.TemplateResponse(request, name, context, status_code=status)
    tok = getattr(request.state, "new_csrf", None)
    if tok:
        resp.set_cookie(CSRF_COOKIE, tok, httponly=True, secure=settings.TG11_COOKIE_SECURE and not settings.is_dev, samesite="lax", path="/", max_age=86400)
    return resp


app = FastAPI(title=settings.TG11_SITE_NAME, version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
if not settings.is_dev:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
from fastapi.staticfiles import StaticFiles  # noqa: E402

app.mount("/media", StaticFiles(directory=str(settings.media_dir)), name="media")
from .profile import router as profile_router  # noqa: E402

app.include_router(profile_router)


@app.on_event("startup")
def _startup():
    import time as _t
    from .models import SessionLocal

    for attempt in range(10):  # tolerate concurrent workers initialising the sqlite file
        try:
            ensure_schema()  # create_all + add new columns (small-service migrations)
            db = SessionLocal()
            try:
                oidc.ensure_signing_key(db)
                db.commit()
            finally:
                db.close()
            return
        except Exception as exc:  # pragma: no cover - startup race
            if attempt == 9:
                raise
            log.warning("startup retry %s: %s", attempt + 1, exc)
            _t.sleep(0.5 * (attempt + 1))


@app.middleware("http")
async def _headers(request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, exc: LoginRequired):
    return _redirect(f"/login?next={quote(exc.next_url)}")


@app.exception_handler(oidc.OAuthError)
async def _oauth_error(request: Request, exc: oidc.OAuthError):
    return JSONResponse({"error": exc.error, "error_description": exc.description}, status_code=exc.status, headers={"WWW-Authenticate": "Bearer"} if exc.status == 401 else None)


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__, "issuer": settings.issuer}


# --- OIDC discovery / keys ----------------------------------------------------

@app.get("/.well-known/openid-configuration")
def well_known():
    return JSONResponse(oidc.discovery(), headers={"Cache-Control": "public, max-age=3600"})


@app.get("/oauth/jwks.json")
def jwks(db: Session = Depends(get_db)):
    return JSONResponse(oidc.jwks(db), headers={"Cache-Control": "public, max-age=3600"})


# --- authorization ------------------------------------------------------------

def _authz_redirect(redirect_uri: str, params: dict, state: Optional[str]) -> RedirectResponse:
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


@app.get("/oauth/authorize")
def authorize(request: Request, response_type: str = "", client_id: str = "", redirect_uri: str = "", scope: str = "openid", state: Optional[str] = None, nonce: str = "", code_challenge: str = "", code_challenge_method: str = "", prompt: str = "", max_age: Optional[int] = None, acr_values: str = "", db: Session = Depends(get_db), user: Optional[User] = Depends(current_user_optional)):
    client = oidc.get_client(db, client_id)
    if client is None:
        return render(request, "error.html", {"title": "Unknown client", "detail": "The application that sent you here is not registered with TG11 Accounts."}, 400)
    try:
        oidc.validate_redirect_uri(client, redirect_uri)
    except oidc.OAuthError as exc:
        return render(request, "error.html", {"title": "Invalid redirect", "detail": exc.description}, 400)
    if response_type != "code":
        return _authz_redirect(redirect_uri, {"error": "unsupported_response_type"}, state)
    try:
        scopes = oidc.parse_scope(client, scope)
    except oidc.OAuthError as exc:
        return _authz_redirect(redirect_uri, {"error": exc.error, "error_description": exc.description}, state)
    if code_challenge and code_challenge_method not in ("S256",):
        return _authz_redirect(redirect_uri, {"error": "invalid_request", "error_description": "only S256 code_challenge_method is supported"}, state)
    if not code_challenge and not client.client_secret_hash:
        return _authz_redirect(redirect_uri, {"error": "invalid_request", "error_description": "PKCE required for public clients"}, state)
    here = "/oauth/authorize?" + str(request.url.query)
    sess = getattr(request.state, "session", None) if user is not None else None
    reauthenticated = _completed_reauth(request, sess)
    stale = False
    if sess is not None and max_age is not None:
        try:
            stale = (utcnow() - sess.created_at).total_seconds() > max(0, int(max_age))
        except (TypeError, ValueError):
            stale = False
    # an application asking for 2FA it cannot get is told, rather than handed a
    # single-factor session it would have to reject itself
    wants_mfa = oidc.ACR_MFA in (acr_values or "").split()
    unmet_acr = bool(sess is not None and wants_mfa and not ({"otp", "recovery"} & set(sess.amr.split())))
    if user is None or ((prompt == "login" or stale) and not reauthenticated) or unmet_acr:
        if prompt == "none":
            return _authz_redirect(redirect_uri, {"error": "login_required" if not unmet_acr else "unmet_authentication_requirements"}, state)
        if reauthenticated and unmet_acr:
            resp = _authz_redirect(redirect_uri, {"error": "unmet_authentication_requirements"}, state)
            resp.delete_cookie(REAUTH_COOKIE, path="/oauth/authorize")
            return resp
        return _redirect(f"/login?next={quote(here)}&reauth=1")
    if not oidc.has_consent(db, user, client, scopes):
        if prompt == "none":
            return _authz_redirect(redirect_uri, {"error": "consent_required"}, state)
        return render(request, "consent.html", {"client": client, "scopes": scopes, "query": str(request.url.query)})
    code = oidc.issue_code(db, user, client, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, sess.id, amr=sess.amr, auth_time=sess.created_at)
    resp = _authz_redirect(redirect_uri, {"code": code}, state)
    if reauthenticated:
        resp.delete_cookie(REAUTH_COOKIE, path="/oauth/authorize")
    return resp


@app.post("/oauth/authorize", dependencies=[Depends(csrf_protect)])
def authorize_consent(request: Request, decision: str = Form(...), query: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    from urllib.parse import parse_qs

    q = {k: v[0] for k, v in parse_qs(query).items()}
    client = oidc.get_client(db, q.get("client_id", ""))
    if client is None:
        raise HTTPException(400, "unknown client")
    oidc.validate_redirect_uri(client, q.get("redirect_uri", ""))
    if decision != "allow":
        return _authz_redirect(q["redirect_uri"], {"error": "access_denied"}, q.get("state"))
    scopes = oidc.parse_scope(client, q.get("scope", "openid"))
    oidc.grant_consent(db, user, client, scopes)
    return _redirect("/oauth/authorize?" + query)


# --- token / userinfo / revoke -------------------------------------------------

def _client_credentials(request: Request, form) -> tuple:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            raw = base64.b64decode(auth[6:]).decode()
            cid, _, secret = raw.partition(":")
            return cid, secret
        except Exception:
            raise oidc.OAuthError("invalid_client", "malformed basic auth", 401)
    return form.get("client_id", ""), form.get("client_secret")


@app.post("/oauth/token")
async def token(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    cid, secret = _client_credentials(request, form)
    client = oidc.authenticate_client(db, cid, secret)
    grant = form.get("grant_type")
    if grant == "authorization_code":
        code_row = oidc.redeem_code(db, client, form.get("code", ""), form.get("redirect_uri", ""), form.get("code_verifier"))
        user = db.get(User, code_row.user_id)
        if user is None or not user.is_active:
            raise oidc.OAuthError("invalid_grant", "user inactive")
        scopes = code_row.scope.split()
        return JSONResponse(oidc.token_response(db, user, client, scopes, code_row.nonce, code_row.auth_time, code_row.session_id, with_refresh="offline_access" in scopes, amr=code_row.amr), headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    if grant == "refresh_token":
        return JSONResponse(oidc.refresh(db, client, form.get("refresh_token", "")), headers={"Cache-Control": "no-store"})
    raise oidc.OAuthError("unsupported_grant_type", f"grant_type {grant} not supported")


@app.get("/oauth/userinfo")
@app.post("/oauth/userinfo")
def userinfo(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise oidc.OAuthError("invalid_token", "bearer token required", 401)
    user, tok = oidc.resolve_access_token(db, auth[7:].strip())
    return JSONResponse(oidc.user_claims(user, tok.scope.split()))


@app.post("/oauth/revoke")
async def revoke(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    cid, secret = _client_credentials(request, form)
    client = oidc.authenticate_client(db, cid, secret)
    oidc.revoke_token(db, client, form.get("token", ""))
    return Response(status_code=200)


@app.get("/oauth/logout")
def rp_logout(request: Request, post_logout_redirect_uri: Optional[str] = None, client_id: Optional[str] = None, state: Optional[str] = None, db: Session = Depends(get_db)):
    """RP-initiated logout: ends the TG11 session (and its tokens) and returns
    to the client if the URI is registered."""
    sid = read_sid(request)
    if sid:
        oidc.revoke_session_tokens(db, sid)
        accounts.revoke_session(db, sid)
    target = "/login?msg=Signed+out+of+TG11"
    if post_logout_redirect_uri and client_id:
        client = oidc.get_client(db, client_id)
        if client is not None and post_logout_redirect_uri in client.post_logout_uri_list:
            target = post_logout_redirect_uri + (("?" + urlencode({"state": state})) if state else "")
    resp = _redirect(target)
    resp.delete_cookie(COOKIE, path="/")
    return resp


# --- account pages -----------------------------------------------------------------

@app.get("/")
def home(user: Optional[User] = Depends(current_user_optional)):
    return _redirect("/account" if user else "/login")


@app.get("/login")
def login_page(request: Request, next: str = "/account", reauth: bool = False, user: Optional[User] = Depends(current_user_optional)):
    if user is not None and not reauth:
        return _redirect(_safe_next(next))
    return render(request, "login.html", {"next": _safe_next(next)})


@app.post("/login", dependencies=[Depends(csrf_protect)])
def login_submit(request: Request, identifier: str = Form(...), password: str = Form(...), next: str = Form("/account"), db: Session = Depends(get_db)):
    # A fresh sign-in always replaces the current session, so `prompt=login`
    # and `max_age` really do re-authenticate rather than reuse what is there.
    user = accounts.authenticate(db, identifier, password)
    if user is None:
        return render(request, "login.html", {"next": _safe_next(next), "error": "Invalid email/username or password.", "identifier": identifier}, 401)
    if settings.TG11_REQUIRE_EMAIL_VERIFICATION and not user.email_verified:
        return render(request, "login.html", {"next": _safe_next(next), "error": "Please verify your email first (check your inbox).", "identifier": identifier}, 403)
    if mfa.has_mfa(db, user):
        resp = _redirect(f"/login/mfa?next={quote(_safe_next(next))}")
        resp.set_cookie(MFA_COOKIE, _mfa_signer.dumps(user.id), max_age=MFA_PENDING_MAX_AGE, httponly=True,
                        secure=settings.TG11_COOKIE_SECURE and not settings.is_dev, samesite="lax", path="/")
        resp.delete_cookie(COOKIE, path="/")
        return resp
    sess = accounts.create_session(db, user, request.headers.get("user-agent", ""), request.client.host if request.client else "", amr="pwd")
    resp = _redirect(_safe_next(next))
    set_session(resp, sess.id)
    _set_reauth_proof(resp, next, sess.id)
    resp.delete_cookie(CSRF_COOKIE, path="/")
    return resp


def _pending_user(request: Request, db: Session) -> Optional[User]:
    raw = request.cookies.get(MFA_COOKIE)
    if not raw:
        return None
    try:
        uid = _mfa_signer.loads(raw, max_age=MFA_PENDING_MAX_AGE)
    except BadSignature:
        return None
    u = db.get(User, uid)
    return u if (u is not None and u.is_active) else None


@app.get("/login/mfa")
def mfa_page(request: Request, next: str = "/account", db: Session = Depends(get_db)):
    user = _pending_user(request, db)
    if user is None:
        return _redirect("/login?err=That+sign-in+expired.+Please+start+again.")
    return render(request, "mfa.html", {"next": _safe_next(next), "username": user.username})


@app.post("/login/mfa", dependencies=[Depends(csrf_protect)])
def mfa_submit(request: Request, code: str = Form(""), next: str = Form("/account"), db: Session = Depends(get_db)):
    user = _pending_user(request, db)
    if user is None:
        return _redirect("/login?err=That+sign-in+expired.+Please+start+again.")
    try:
        method = mfa.verify(db, user, code)
    except mfa.MFAError as exc:
        return render(request, "mfa.html", {"next": _safe_next(next), "username": user.username, "error": str(exc)}, 401)
    user.last_login_at = utcnow()
    sess = accounts.create_session(db, user, request.headers.get("user-agent", ""), request.client.host if request.client else "", amr=f"pwd {method}")
    resp = _redirect(_safe_next(next))
    set_session(resp, sess.id)
    _set_reauth_proof(resp, next, sess.id)
    resp.delete_cookie(MFA_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")
    log.info("tg11: signed in with a second factor (user=%s method=%s)", user.id, method)
    return resp


@app.get("/register")
def register_page(request: Request, next: str = "/account", user: Optional[User] = Depends(current_user_optional)):
    if user is not None:
        return _redirect(_safe_next(next))
    if not settings.TG11_ALLOW_REGISTRATION:
        return render(request, "error.html", {"title": "Registration closed", "detail": "New TG11 accounts are not being created right now."}, 403)
    return render(request, "register.html", {"next": _safe_next(next)})


@app.post("/register", dependencies=[Depends(csrf_protect)])
def register_submit(request: Request, email: str = Form(...), username: str = Form(...), password: str = Form(...), password2: str = Form(...), display_name: str = Form(""), next: str = Form("/account"), db: Session = Depends(get_db)):
    if not settings.TG11_ALLOW_REGISTRATION:
        raise HTTPException(403)
    ctx = {"email": email, "username": username, "display_name": display_name, "next": _safe_next(next)}
    if password != password2:
        return render(request, "register.html", {**ctx, "error": "Passwords do not match."}, 400)
    try:
        user = accounts.create_user(db, email=email, username=username, password=password, display_name=display_name)
    except accounts.AccountError as exc:
        return render(request, "register.html", {**ctx, "error": str(exc)}, 400)
    accounts.send_verification(db, user)
    if settings.TG11_REQUIRE_EMAIL_VERIFICATION:
        return render(request, "login.html", {"next": _safe_next(next), "notice": "Account created. Verify your email, then sign in."})
    sess = accounts.create_session(db, user, request.headers.get("user-agent", ""), request.client.host if request.client else "")
    resp = _redirect(_safe_next(next))
    set_session(resp, sess.id)
    return resp


@app.get("/verify/{token}")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = accounts.consume_action(db, "verify_email", token)
    if user is None:
        return _redirect("/login?err=Verification+link+invalid+or+expired")
    user.email_verified_at = utcnow()
    if user.state == "pending_verification":
        user.state = "active"
    return _redirect("/login?msg=Email+verified.+You+can+sign+in.")


@app.get("/password/forgot")
def forgot(request: Request):
    return render(request, "forgot.html")


@app.post("/password/forgot", dependencies=[Depends(csrf_protect)])
def forgot_submit(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    user = accounts.by_email(db, email)
    if user is not None and user.is_active:
        accounts.send_reset(db, user)
    return render(request, "forgot.html", {"sent": True})


@app.get("/password/reset/{token}")
def reset(request: Request, token: str):
    return render(request, "reset.html", {"token": token})


@app.post("/password/reset/{token}", dependencies=[Depends(csrf_protect)])
def reset_submit(request: Request, token: str, password: str = Form(...), password2: str = Form(...), db: Session = Depends(get_db)):
    if password != password2:
        return render(request, "reset.html", {"token": token, "error": "Passwords do not match."}, 400)
    user = accounts.consume_action(db, "reset_password", token)
    if user is None:
        return render(request, "reset.html", {"token": token, "error": "This link is invalid or has expired."}, 400)
    try:
        accounts.validate_password(password)
    except accounts.AccountError as exc:
        return render(request, "reset.html", {"token": token, "error": str(exc)}, 400)
    from .passwords import hash_password

    user.password_hash = hash_password(password)
    for s in db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))):
        s.revoked_at = utcnow()
        oidc.revoke_session_tokens(db, s.id)
    return _redirect("/login?msg=Password+updated")


@app.get("/account")
def account(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    sessions = list(db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None)).order_by(UserSession.last_seen_at.desc())))
    consents = list(db.scalars(select(Consent).where(Consent.user_id == user.id, Consent.revoked_at.is_(None))))
    clients = {c.client_id: c for c in db.scalars(select(OAuthClient).where(OAuthClient.enabled.is_(True)))}
    links = {l.application: l for l in db.scalars(select(ApplicationIdentityLink).where(ApplicationIdentityLink.user_id == user.id))}
    apps = sorted(clients.values(), key=lambda c: c.name.lower())
    return render(request, "account.html", {"sessions": sessions, "consents": consents, "clients": clients, "apps": apps, "links": links, "sid": read_sid(request), "sms_configured": settings.sms_configured})


@app.post("/account/password", dependencies=[Depends(csrf_protect)])
def account_password(request: Request, current_password: str = Form(""), new_password: str = Form(...), new_password2: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    from .passwords import hash_password, verify_password

    if user.password_hash and not verify_password(current_password, user.password_hash):
        return _redirect("/account?err=Current+password+incorrect")
    if new_password != new_password2:
        return _redirect("/account?err=Passwords+do+not+match")
    try:
        accounts.validate_password(new_password)
    except accounts.AccountError as exc:
        return _redirect(f"/account?err={exc}")
    user.password_hash = hash_password(new_password)
    sid = read_sid(request)
    for s in db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))):
        if s.id != sid:
            s.revoked_at = utcnow()
            oidc.revoke_session_tokens(db, s.id)
    return _redirect("/account?msg=Password+changed")


@app.post("/account/sessions/{sid}/revoke", dependencies=[Depends(csrf_protect)])
def account_revoke_session(sid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = db.get(UserSession, sid)
    if s is not None and s.user_id == user.id:
        accounts.revoke_session(db, sid)
        oidc.revoke_session_tokens(db, sid)
    return _redirect("/account?msg=Session+revoked")


@app.post("/account/consents/{client_id}/revoke", dependencies=[Depends(csrf_protect)])
def account_revoke_consent(client_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    c = db.scalar(select(Consent).where(Consent.user_id == user.id, Consent.client_id == client_id))
    if c is not None:
        c.revoked_at = utcnow()
    for t in db.scalars(select(Token).where(Token.user_id == user.id, Token.client_id == client_id, Token.revoked_at.is_(None))):
        t.revoked_at = utcnow()
    return _redirect("/account?msg=Application+access+revoked")


@app.post("/logout", dependencies=[Depends(csrf_protect)])
def logout(request: Request, db: Session = Depends(get_db)):
    sid = read_sid(request)
    if sid:
        oidc.revoke_session_tokens(db, sid)
        accounts.revoke_session(db, sid)
    resp = _redirect("/login?msg=Signed+out")
    resp.delete_cookie(COOKIE, path="/")
    return resp


# --- two-factor authentication -------------------------------------------------

@app.get("/account/security")
def security_page(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    device = mfa.device_for(db, user)
    pending = mfa.device_for(db, user, confirmed_only=False) if device is None else None
    return render(request, "security.html", {
        "device": device,
        "pending": pending is not None,
        "codes_left": mfa.recovery_codes_left(db, user) if device is not None else 0,
        "session_amr": (getattr(request.state, "session", None).amr if getattr(request.state, "session", None) else "pwd"),
    })


@app.post("/account/security/enable", dependencies=[Depends(csrf_protect)])
def security_enable(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Step one: show the secret. Nothing is enforced until it is confirmed."""
    try:
        _device, secret, uri = mfa.provision(db, user)
    except mfa.MFAError as exc:
        return render(request, "security.html", {"device": mfa.device_for(db, user), "error": str(exc)}, 400)
    return render(request, "security.html", {
        "device": None, "pending": True, "secret": secret, "otpauth": uri, "qr_svg": mfa.qr_svg(uri),
    })


@app.post("/account/security/confirm", dependencies=[Depends(csrf_protect)])
def security_confirm(request: Request, code: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        codes = mfa.confirm(db, user, code)
    except mfa.MFAError as exc:
        device = mfa.device_for(db, user, confirmed_only=False)
        secret = None
        uri = qr = None
        if device is not None and device.confirmed_at is None:
            secret = mfa._secret_of(device)
            uri = mfa.otpauth_uri(user, secret)
            qr = mfa.qr_svg(uri)
        return render(request, "security.html", {"device": None, "pending": device is not None, "secret": secret,
                                                 "otpauth": uri, "qr_svg": qr, "error": str(exc)}, 400)
    # the session that just enabled it counts as two-factor from here on
    sess = getattr(request.state, "session", None)
    if sess is not None and "otp" not in sess.amr.split():
        sess.amr = "pwd otp"
    return render(request, "security.html", {"device": mfa.device_for(db, user), "codes": codes,
                                             "codes_left": len(codes), "notice": "Two-factor authentication is on."})


@app.post("/account/security/recovery", dependencies=[Depends(csrf_protect)])
def security_recovery(request: Request, password: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
    """New recovery codes replace the old ones, so the password is required."""
    if accounts.authenticate(db, user.email, password) is None:
        return render(request, "security.html", {"device": mfa.device_for(db, user), "codes_left": mfa.recovery_codes_left(db, user),
                                                 "error": "That password is not right."}, 403)
    codes = mfa.regenerate_recovery_codes(db, user)
    return render(request, "security.html", {"device": mfa.device_for(db, user), "codes": codes, "codes_left": len(codes),
                                             "notice": "New recovery codes. The previous ones no longer work."})


@app.post("/account/security/disable", dependencies=[Depends(csrf_protect)])
def security_disable(request: Request, password: str = Form(""), code: str = Form(""), db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Turning a factor off needs the password *and* a current code - a borrowed
    session must not be enough to strip someone's second factor."""
    if accounts.authenticate(db, user.email, password) is None:
        return render(request, "security.html", {"device": mfa.device_for(db, user), "codes_left": mfa.recovery_codes_left(db, user),
                                                 "error": "That password is not right."}, 403)
    if mfa.has_mfa(db, user):
        try:
            mfa.verify(db, user, code)
        except mfa.MFAError as exc:
            return render(request, "security.html", {"device": mfa.device_for(db, user), "codes_left": mfa.recovery_codes_left(db, user),
                                                     "error": str(exc)}, 403)
    mfa.disable(db, user)
    sess = getattr(request.state, "session", None)
    if sess is not None:
        sess.amr = "pwd"
    return render(request, "security.html", {"device": None, "notice": "Two-factor authentication is off."})
