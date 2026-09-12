# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""HTTP layer: account pages + OIDC endpoints."""
from __future__ import annotations

import base64
import logging
import os
import secrets
from typing import Optional
from urllib.parse import quote, urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, accounts, oidc
from .config import settings
from .models import Base, Consent, OAuthClient, Token, User, UserSession, engine, get_db, utcnow

log = logging.getLogger("tg11")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
templates.env.globals.update(site_name=settings.TG11_SITE_NAME, issuer=settings.issuer, version=__version__, registration=settings.TG11_ALLOW_REGISTRATION)
_signer = URLSafeTimedSerializer(settings.TG11_SECRET_KEY, salt="tg11-session")
COOKIE, CSRF_COOKIE = "tg11_session", "tg11_csrf"


class LoginRequired(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _safe_next(url: Optional[str]) -> str:
    return url if url and url.startswith("/") and not url.startswith("//") else "/account"


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


@app.on_event("startup")
def _startup():
    import time as _t
    from .models import SessionLocal

    for attempt in range(10):  # tolerate concurrent workers initialising the sqlite file
        try:
            Base.metadata.create_all(engine)  # small schema; alembic not needed yet
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
def authorize(request: Request, response_type: str = "", client_id: str = "", redirect_uri: str = "", scope: str = "openid", state: Optional[str] = None, nonce: str = "", code_challenge: str = "", code_challenge_method: str = "", prompt: str = "", db: Session = Depends(get_db), user: Optional[User] = Depends(current_user_optional)):
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
    if user is None or prompt == "login":
        if prompt == "none":
            return _authz_redirect(redirect_uri, {"error": "login_required"}, state)
        return _redirect(f"/login?next={quote(here)}")
    sess = request.state.session
    if not oidc.has_consent(db, user, client, scopes):
        if prompt == "none":
            return _authz_redirect(redirect_uri, {"error": "consent_required"}, state)
        return render(request, "consent.html", {"client": client, "scopes": scopes, "query": str(request.url.query)})
    code = oidc.issue_code(db, user, client, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, sess.id)
    return _authz_redirect(redirect_uri, {"code": code}, state)


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
        return JSONResponse(oidc.token_response(db, user, client, scopes, code_row.nonce, code_row.auth_time, code_row.session_id, with_refresh="offline_access" in scopes), headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
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
def login_page(request: Request, next: str = "/account", user: Optional[User] = Depends(current_user_optional)):
    if user is not None:
        return _redirect(_safe_next(next))
    return render(request, "login.html", {"next": _safe_next(next)})


@app.post("/login", dependencies=[Depends(csrf_protect)])
def login_submit(request: Request, identifier: str = Form(...), password: str = Form(...), next: str = Form("/account"), db: Session = Depends(get_db)):
    user = accounts.authenticate(db, identifier, password)
    if user is None:
        return render(request, "login.html", {"next": _safe_next(next), "error": "Invalid email/username or password.", "identifier": identifier}, 401)
    if settings.TG11_REQUIRE_EMAIL_VERIFICATION and not user.email_verified:
        return render(request, "login.html", {"next": _safe_next(next), "error": "Please verify your email first (check your inbox).", "identifier": identifier}, 403)
    sess = accounts.create_session(db, user, request.headers.get("user-agent", ""), request.client.host if request.client else "")
    resp = _redirect(_safe_next(next))
    set_session(resp, sess.id)
    resp.delete_cookie(CSRF_COOKIE, path="/")
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
    clients = {c.client_id: c for c in db.scalars(select(OAuthClient))}
    return render(request, "account.html", {"sessions": sessions, "consents": consents, "clients": clients, "sid": read_sid(request)})


@app.post("/account/profile", dependencies=[Depends(csrf_protect)])
def account_profile(display_name: str = Form(""), username: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    un = accounts.norm_username(username)
    if not accounts.USERNAME_RE.match(un):
        return _redirect("/account?err=Invalid+username")
    other = accounts.by_username(db, un)
    if other is not None and other.id != user.id:
        return _redirect("/account?err=Username+taken")
    user.username, user.display_name = un, display_name.strip()[:80] or un
    return _redirect("/account?msg=Profile+saved")


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
