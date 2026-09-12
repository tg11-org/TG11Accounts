# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""OpenID Connect provider core: signing keys, ID tokens, authorization codes,
access/refresh tokens, PKCE verification, client validation."""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import AuthorizationCode, Consent, OAuthClient, SigningKey, Token, User, utcnow
from .passwords import verify_password
from .tokens import generate_token, hash_token

SUPPORTED_SCOPES = ["openid", "profile", "email", "tg11.profile", "offline_access"]


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(description or error)
        self.error, self.description, self.status = error, description, status


# --- signing keys -------------------------------------------------------------

def ensure_signing_key(db: Session) -> SigningKey:
    key = db.scalar(select(SigningKey).where(SigningKey.active.is_(True)).order_by(SigningKey.created_at.desc()))
    if key is None:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        key = SigningKey(kid=secrets.token_hex(8), private_pem=pem, active=True)
        db.add(key)
        db.flush()
    return key


def _rsa_key(key: SigningKey) -> RSAKey:
    return RSAKey.import_key(key.private_pem, {"kid": key.kid, "use": "sig", "alg": "RS256"})


def jwks(db: Session) -> Dict:
    keys = []
    for k in db.scalars(select(SigningKey).order_by(SigningKey.created_at.desc())):
        pub = _rsa_key(k).as_dict(private=False)
        pub.update({"kid": k.kid, "use": "sig", "alg": "RS256"})
        keys.append(pub)
    if not keys:
        ensure_signing_key(db)
        return jwks(db)
    return {"keys": keys}


def discovery() -> Dict:
    iss = settings.issuer
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "userinfo_endpoint": f"{iss}/oauth/userinfo",
        "jwks_uri": f"{iss}/oauth/jwks.json",
        "end_session_endpoint": f"{iss}/oauth/logout",
        "revocation_endpoint": f"{iss}/oauth/revoke",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": SUPPORTED_SCOPES,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "preferred_username", "name", "tg11_username", "account_state", "created_at"],
        "code_challenge_methods_supported": ["S256"],
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
    }


# --- clients ------------------------------------------------------------------

def get_client(db: Session, client_id: str) -> Optional[OAuthClient]:
    c = db.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))
    return c if c is not None and c.enabled else None


def authenticate_client(db: Session, client_id: str, client_secret: Optional[str]) -> OAuthClient:
    client = get_client(db, client_id)
    if client is None:
        raise OAuthError("invalid_client", "unknown client", 401)
    if client.client_secret_hash:
        if not client_secret or not verify_password(client_secret, client.client_secret_hash):
            raise OAuthError("invalid_client", "client authentication failed", 401)
    return client


def validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> None:
    if redirect_uri not in client.redirect_uri_list:
        raise OAuthError("invalid_request", "redirect_uri is not registered for this client")


def parse_scope(client: OAuthClient, scope: str) -> List[str]:
    requested = [s for s in (scope or "").split() if s]
    if "openid" not in requested:
        raise OAuthError("invalid_scope", "scope must include openid")
    allowed = set(client.allowed_scopes.split())
    bad = [s for s in requested if s not in SUPPORTED_SCOPES or s not in allowed]
    if bad:
        raise OAuthError("invalid_scope", f"scope not allowed: {' '.join(bad)}")
    return requested


# --- consent ------------------------------------------------------------------

def has_consent(db: Session, user: User, client: OAuthClient, scopes: List[str]) -> bool:
    if client.trusted:
        return True
    c = db.scalar(select(Consent).where(Consent.user_id == user.id, Consent.client_id == client.client_id, Consent.revoked_at.is_(None)))
    return c is not None and set(scopes) <= set(c.scope.split())


def grant_consent(db: Session, user: User, client: OAuthClient, scopes: List[str]) -> None:
    c = db.scalar(select(Consent).where(Consent.user_id == user.id, Consent.client_id == client.client_id))
    if c is None:
        db.add(Consent(user_id=user.id, client_id=client.client_id, scope=" ".join(scopes)))
    else:
        c.scope = " ".join(sorted(set(c.scope.split()) | set(scopes)))
        c.revoked_at = None
    db.flush()


# --- authorization code -------------------------------------------------------

def issue_code(db: Session, user: User, client: OAuthClient, redirect_uri: str, scopes: List[str], nonce: str, code_challenge: str, method: str, session_id: str) -> str:
    code = generate_token(32)
    db.add(AuthorizationCode(code_hash=hash_token(code), client_id=client.client_id, user_id=user.id, session_id=session_id, redirect_uri=redirect_uri, scope=" ".join(scopes), nonce=nonce or "", code_challenge=code_challenge or "", code_challenge_method=method or "", expires_at=utcnow() + timedelta(seconds=settings.TG11_CODE_TTL)))
    db.flush()
    return code


def _pkce_ok(verifier: str, challenge: str, method: str) -> bool:
    if method == "S256":
        digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        return secrets.compare_digest(digest, challenge)
    if method == "plain":
        return secrets.compare_digest(verifier, challenge)
    return False


def redeem_code(db: Session, client: OAuthClient, code: str, redirect_uri: str, code_verifier: Optional[str]) -> AuthorizationCode:
    row = db.scalar(select(AuthorizationCode).where(AuthorizationCode.code_hash == hash_token(code or "")))
    if row is None or row.client_id != client.client_id:
        raise OAuthError("invalid_grant", "unknown authorization code")
    if row.used_at is not None:
        # replay: revoke everything minted from this code's session for safety
        for t in db.scalars(select(Token).where(Token.session_id == row.session_id, Token.client_id == client.client_id, Token.revoked_at.is_(None))):
            t.revoked_at = utcnow()
        raise OAuthError("invalid_grant", "authorization code already used")
    if row.expires_at < utcnow():
        raise OAuthError("invalid_grant", "authorization code expired")
    row.used_at = utcnow()  # single use: any failure below burns the code
    db.commit()  # persist even if we raise (the request handler rolls back on error)
    if row.redirect_uri != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri mismatch")
    if row.code_challenge:
        if not code_verifier or not (43 <= len(code_verifier) <= 128) or not _pkce_ok(code_verifier, row.code_challenge, row.code_challenge_method):
            raise OAuthError("invalid_grant", "PKCE verification failed")
    elif not client.client_secret_hash:
        raise OAuthError("invalid_grant", "public clients must use PKCE")
    return row


# --- tokens -------------------------------------------------------------------

def _mint(db: Session, kind: str, user_id: str, client_id: str, scope: str, session_id: str, ttl: int, parent_id: Optional[str] = None) -> str:
    raw = generate_token(32)
    db.add(Token(kind=kind, token_hash=hash_token(raw), client_id=client_id, user_id=user_id, scope=scope, session_id=session_id, parent_id=parent_id, expires_at=utcnow() + timedelta(seconds=ttl)))
    db.flush()
    return raw


def user_claims(user: User, scopes: List[str]) -> Dict:
    claims: Dict = {"sub": user.id}
    if "email" in scopes:
        claims["email"] = user.email
        claims["email_verified"] = user.email_verified
    if "profile" in scopes:
        claims["preferred_username"] = user.username
        claims["name"] = user.display_name or user.username
        claims["updated_at"] = int(user.updated_at.timestamp()) if user.updated_at else None
    if "tg11.profile" in scopes:
        claims["tg11_username"] = user.username
        claims["account_state"] = user.state
        claims["created_at"] = user.created_at.isoformat() + "Z"
    return {k: v for k, v in claims.items() if v is not None}


def id_token(db: Session, user: User, client: OAuthClient, scopes: List[str], nonce: str, auth_time) -> str:
    key = ensure_signing_key(db)
    now = int(time.time())
    claims = {"iss": settings.issuer, "aud": client.client_id, "iat": now, "exp": now + settings.TG11_ID_TOKEN_TTL, "auth_time": int(auth_time.timestamp())}
    if nonce:
        claims["nonce"] = nonce
    claims.update(user_claims(user, scopes))
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, claims, _rsa_key(key))


def token_response(db: Session, user: User, client: OAuthClient, scopes: List[str], nonce: str, auth_time, session_id: str, with_refresh: bool) -> Dict:
    scope = " ".join(scopes)
    refresh = _mint(db, "refresh", user.id, client.client_id, scope, session_id, settings.TG11_REFRESH_TOKEN_TTL) if with_refresh else None
    access = _mint(db, "access", user.id, client.client_id, scope, session_id, settings.TG11_ACCESS_TOKEN_TTL)
    out = {"access_token": access, "token_type": "Bearer", "expires_in": settings.TG11_ACCESS_TOKEN_TTL, "scope": scope, "id_token": id_token(db, user, client, scopes, nonce, auth_time)}
    if refresh:
        out["refresh_token"] = refresh
    return out


def refresh(db: Session, client: OAuthClient, refresh_token: str) -> Dict:
    row = db.scalar(select(Token).where(Token.token_hash == hash_token(refresh_token or ""), Token.kind == "refresh"))
    if row is None or row.client_id != client.client_id or row.revoked_at is not None or row.expires_at < utcnow():
        raise OAuthError("invalid_grant", "refresh token invalid")
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise OAuthError("invalid_grant", "user inactive")
    row.revoked_at = utcnow()  # rotation
    scopes = row.scope.split()
    return token_response(db, user, client, scopes, "", utcnow(), row.session_id, with_refresh=True)


def resolve_access_token(db: Session, bearer: str) -> Tuple[User, Token]:
    row = db.scalar(select(Token).where(Token.token_hash == hash_token(bearer or ""), Token.kind == "access"))
    if row is None or row.revoked_at is not None or row.expires_at < utcnow():
        raise OAuthError("invalid_token", "access token invalid", 401)
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise OAuthError("invalid_token", "user inactive", 401)
    return user, row


def revoke_token(db: Session, client: OAuthClient, token: str) -> None:
    row = db.scalar(select(Token).where(Token.token_hash == hash_token(token or "")))
    if row is not None and row.client_id == client.client_id:
        row.revoked_at = utcnow()
        for child in db.scalars(select(Token).where(Token.parent_id == row.id)):
            child.revoked_at = utcnow()


def revoke_session_tokens(db: Session, session_id: str) -> None:
    for t in db.scalars(select(Token).where(Token.session_id == session_id, Token.revoked_at.is_(None))):
        t.revoked_at = utcnow()
