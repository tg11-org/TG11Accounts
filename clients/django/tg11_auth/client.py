# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""OpenID Connect relying party: authorization code + PKCE (S256).

Ported from Flowboard's `app/identity/oidc.py`, which has been running against
accounts.tg11.org in production; kept framework-agnostic so it can be unit
tested without Django.  Every ID token is checked for signature (JWKS, with one
forced refresh to survive key rotation), issuer, audience, azp, expiry, issued-at
skew and nonce before any of its claims are believed.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from joserfc import jwt as _jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from . import conf

CLOCK_SKEW = 60  # seconds tolerated on exp / iat
JWKS_TTL = 3600


class OIDCError(Exception):
    """Anything that makes the login untrustworthy.  Never leak the raw value
    of a token or code in the message."""


@dataclass
class Claims:
    subject: str
    id_token: str = ""
    email: str = ""
    email_verified: bool = False
    preferred_username: str = ""
    name: str = ""
    account_state: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    access_token: str = ""
    refresh_token: str = ""
    scope: str = ""

    @property
    def is_active_account(self) -> bool:
        """`account_state` only arrives with the tg11.profile scope; absent, we
        trust the provider not to have issued a token for a dead account."""
        return self.account_state in ("", "active")


class OIDCClient:
    def __init__(self, issuer: str, client_id: str, client_secret: str = "", scopes: str = conf.DEFAULT_SCOPES,
                 redirect_uri: str = "", http: Optional[httpx.Client] = None):
        self.issuer = (issuer or "").rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret or ""
        self.scopes = scopes or conf.DEFAULT_SCOPES
        self.redirect_uri = redirect_uri
        self.http = http or httpx.Client(timeout=15.0)
        self._metadata: Optional[Dict[str, Any]] = None
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_fetched = 0.0

    @classmethod
    def from_settings(cls, http: Optional[httpx.Client] = None) -> "OIDCClient":
        return cls(
            issuer=conf.required("TG11_OIDC_ISSUER"),
            client_id=conf.required("TG11_OIDC_CLIENT_ID"),
            client_secret=conf.get("TG11_OIDC_CLIENT_SECRET", "") or "",
            scopes=conf.scopes(),
            redirect_uri=conf.required("TG11_OIDC_REDIRECT_URI"),
            http=http,
        )

    # ---- discovery -------------------------------------------------------
    @property
    def metadata(self) -> Dict[str, Any]:
        if self._metadata is None:
            try:
                resp = self.http.get(f"{self.issuer}/.well-known/openid-configuration")
            except httpx.HTTPError as exc:
                raise OIDCError(f"TG11 is unreachable ({exc.__class__.__name__})")
            if resp.status_code != 200:
                raise OIDCError(f"discovery failed ({resp.status_code})")
            md = resp.json()
            if str(md.get("issuer", "")).rstrip("/") != self.issuer:
                raise OIDCError("issuer mismatch in discovery document")
            self._metadata = md
        return self._metadata

    def jwks(self, force: bool = False) -> Dict[str, Any]:
        if self._jwks is None or force or time.time() - self._jwks_fetched > JWKS_TTL:
            try:
                resp = self.http.get(self.metadata["jwks_uri"])
            except httpx.HTTPError as exc:
                raise OIDCError(f"could not fetch JWKS ({exc.__class__.__name__})")
            if resp.status_code != 200:
                raise OIDCError("could not fetch JWKS")
            self._jwks = resp.json()
            self._jwks_fetched = time.time()
        return self._jwks

    # ---- authorization request ------------------------------------------
    @staticmethod
    def new_flow_state() -> Dict[str, str]:
        verifier = secrets.token_urlsafe(64)[:96]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        return {
            "state": secrets.token_urlsafe(24),
            "nonce": secrets.token_urlsafe(24),
            "code_verifier": verifier,
            "code_challenge": challenge,
        }

    def authorization_url(self, flow: Dict[str, str], *, prompt: Optional[str] = None, login_hint: str = "") -> str:
        q = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": flow["state"],
            "nonce": flow["nonce"],
            "code_challenge": flow["code_challenge"],
            "code_challenge_method": "S256",
        }
        if prompt:
            q["prompt"] = prompt
        if login_hint:
            q["login_hint"] = login_hint
        return f"{self.metadata['authorization_endpoint']}?{urlencode(q)}"

    # ---- token exchange + validation ------------------------------------
    def exchange(self, code: str, flow: Dict[str, str]) -> Claims:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": flow["code_verifier"],
        }
        auth = (self.client_id, self.client_secret) if self.client_secret else None
        try:
            resp = self.http.post(self.metadata["token_endpoint"], data=data, auth=auth)
        except httpx.HTTPError as exc:
            raise OIDCError(f"token exchange failed ({exc.__class__.__name__})")
        if resp.status_code != 200:
            raise OIDCError(f"token exchange failed ({resp.status_code})")
        tokens = resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise OIDCError("no id_token in token response")
        claims = self.validate_id_token(id_token, flow["nonce"])
        if tokens.get("access_token") and self.metadata.get("userinfo_endpoint"):
            claims = self._merge_userinfo(claims, tokens["access_token"])
        return Claims(
            subject=str(claims["sub"]),
            id_token=id_token,  # kept only for the logout id_token_hint; never sent to the browser
            email=str(claims.get("email") or ""),
            email_verified=bool(claims.get("email_verified", False)),
            preferred_username=str(claims.get("preferred_username") or ""),
            name=str(claims.get("name") or ""),
            account_state=str(claims.get("account_state") or ""),
            raw=dict(claims),
            access_token=str(tokens.get("access_token") or ""),
            refresh_token=str(tokens.get("refresh_token") or ""),
            scope=str(tokens.get("scope") or self.scopes),
        )

    def _merge_userinfo(self, claims: Dict[str, Any], access_token: str) -> Dict[str, Any]:
        """Freshest profile wins - but only for the *same* subject."""
        try:
            resp = self.http.get(self.metadata["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"})
        except httpx.HTTPError:
            return claims
        if resp.status_code != 200:
            return claims
        info = resp.json()
        if info.get("sub") != claims.get("sub"):
            raise OIDCError("userinfo subject does not match the id_token")
        for key in ("email", "email_verified", "preferred_username", "name", "account_state", "picture"):
            if key in info:
                claims[key] = info[key]
        return claims

    def validate_id_token(self, id_token: str, nonce: str) -> Dict[str, Any]:
        algs = [a for a in (self.metadata.get("id_token_signing_alg_values_supported") or ["RS256"]) if a != "none"] or ["RS256"]

        def _decode(force: bool) -> Dict[str, Any]:
            key_set = KeySet.import_key_set(self.jwks(force=force))
            return dict(_jwt.decode(id_token, key_set, algorithms=algs).claims)

        try:
            claims = _decode(False)
        except (JoseError, ValueError):
            try:
                claims = _decode(True)  # the provider may have rotated its key
            except (JoseError, ValueError) as exc:
                raise OIDCError(f"invalid id_token signature: {exc}")

        now = time.time()
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or now > exp + CLOCK_SKEW:
            raise OIDCError("id_token expired")
        iat = claims.get("iat")
        if isinstance(iat, (int, float)) and iat > now + CLOCK_SKEW:
            raise OIDCError("id_token issued in the future")
        if str(claims.get("iss", "")).rstrip("/") != self.issuer:
            raise OIDCError("id_token issuer mismatch")
        aud = claims.get("aud")
        if aud is None or (isinstance(aud, list) and self.client_id not in aud) or (isinstance(aud, str) and aud != self.client_id):
            raise OIDCError("id_token audience mismatch")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") not in (None, self.client_id):
            raise OIDCError("id_token azp mismatch")
        if nonce and claims.get("nonce") != nonce:
            raise OIDCError("id_token nonce mismatch")
        if not claims.get("sub"):
            raise OIDCError("id_token missing sub")
        return claims

    # ---- logout ----------------------------------------------------------
    def end_session_url(self, post_logout_redirect: str, id_token_hint: str = "") -> Optional[str]:
        endpoint = self.metadata.get("end_session_endpoint")
        if not endpoint:
            return None
        q = {"post_logout_redirect_uri": post_logout_redirect, "client_id": self.client_id}
        if id_token_hint:
            q["id_token_hint"] = id_token_hint
        return f"{endpoint}?{urlencode(q)}"


# ---- one client per configuration ---------------------------------------
# Discovery and JWKS are cached on the instance, so the client is kept between
# requests; the cache key means a settings override (tests, a re-pointed issuer)
# transparently builds a new one.
_CACHE: Dict[tuple, OIDCClient] = {}


def get_client() -> OIDCClient:
    key = (
        str(conf.get("TG11_OIDC_ISSUER", "")),
        str(conf.get("TG11_OIDC_CLIENT_ID", "")),
        str(conf.get("TG11_OIDC_CLIENT_SECRET", "")),
        conf.scopes(),
        str(conf.get("TG11_OIDC_REDIRECT_URI", "")),
    )
    client = _CACHE.get(key)
    if client is None:
        client = OIDCClient.from_settings()
        _CACHE[key] = client
    return client


def reset_client_cache() -> None:
    _CACHE.clear()
