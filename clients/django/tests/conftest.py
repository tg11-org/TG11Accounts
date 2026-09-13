# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""A fake TG11 provider.

It is a real RS256 signer behind an httpx MockTransport: discovery, JWKS, token
and userinfo all answer like accounts.tg11.org, and the token endpoint *checks
the PKCE verifier*, so the tests prove the client actually does PKCE rather than
just sending the parameter. No network, no accounts.tg11.org, no secrets.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qs

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

ISSUER = "https://accounts.example.test"
CLIENT_ID = "testapp"


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


class FakeIdP:
    """Records what the client sent and answers as the provider."""

    def __init__(self, issuer: str = ISSUER, client_id: str = CLIENT_ID):
        self.issuer = issuer
        self.client_id = client_id
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1"})
        self.extra_keys: list = []
        self.sign_with: Optional[RSAKey] = None  # override to fake a bad signature
        self.claims: Dict[str, Any] = {
            "sub": "018f4f1e-0000-7000-a000-00000000cafe",
            "email": "new@example.test",
            "email_verified": True,
            "preferred_username": "newbie",
            "name": "New Person",
            "account_state": "active",
        }
        self.userinfo: Optional[Dict[str, Any]] = None
        self.nonce_override: Optional[str] = None
        self.aud_override: Optional[Any] = None
        self.iss_override: Optional[str] = None
        self.exp_delta = 300
        self.iat_delta = 0
        self.include_refresh = True
        self.token_status = 200
        self.codes: Dict[str, Dict[str, str]] = {}
        self.jwks_hits = 0
        self.last_authorize: Dict[str, list] = {}
        self.token_requests: list = []

    # -- issuing -----------------------------------------------------------
    def jwks(self) -> Dict[str, Any]:
        return KeySet([self.key] + self.extra_keys).as_dict(private=False)

    def rotate_key(self) -> None:
        """New signing key, old one no longer published - as a real rotation."""
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k2"})
        self.extra_keys = []

    def id_token(self, nonce: str) -> str:
        now = int(time.time())
        claims = dict(self.claims)
        claims.update({
            "iss": self.iss_override or self.issuer,
            "aud": self.aud_override if self.aud_override is not None else self.client_id,
            "exp": now + self.exp_delta,
            "iat": now + self.iat_delta,
            "nonce": self.nonce_override if self.nonce_override is not None else nonce,
        })
        key = self.sign_with or self.key
        return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)

    # -- transport ---------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": self.issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "userinfo_endpoint": f"{self.issuer}/userinfo",
                "jwks_uri": f"{self.issuer}/jwks.json",
                "end_session_endpoint": f"{self.issuer}/logout",
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256"],
            })
        if path == "/jwks.json":
            self.jwks_hits += 1
            return httpx.Response(200, json=self.jwks())
        if path == "/token":
            body = parse_qs(request.content.decode())
            self.token_requests.append(body)
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            code = body.get("code", [""])[0]
            verifier = body.get("code_verifier", [""])[0]
            record = self.codes.get(code)
            if record is None:
                return httpx.Response(400, json={"error": "invalid_grant"})
            if not verifier or s256(verifier) != record["challenge"]:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "PKCE failed"})
            tokens = {
                "token_type": "Bearer",
                "access_token": "at-" + code,
                "id_token": self.id_token(record["nonce"]),
                "scope": "openid profile email tg11.profile",
                "expires_in": 300,
            }
            if self.include_refresh:
                tokens["refresh_token"] = "rt-super-secret-value"
            return httpx.Response(200, json=tokens)
        if path == "/userinfo":
            if self.userinfo is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.userinfo)
        return httpx.Response(404, json={"error": "not_found"})  # pragma: no cover

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler), base_url=self.issuer)

    # -- helpers -----------------------------------------------------------
    def issue_code(self, *, state: str, nonce: str, challenge: str, code: str = "code-1") -> str:
        self.codes[code] = {"state": state, "nonce": nonce, "challenge": challenge}
        return code


@pytest.fixture
def idp(monkeypatch):
    """A fake provider wired into tg11_auth's cached client."""
    from tg11_auth import client as client_mod

    fake = FakeIdP()
    client_mod.reset_client_cache()
    built = client_mod.OIDCClient(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret="s3cret",
        scopes="openid profile email tg11.profile",
        redirect_uri="http://testserver/auth/tg11/callback/",
        http=fake.client(),
    )
    monkeypatch.setattr(client_mod, "get_client", lambda: built)
    monkeypatch.setattr("tg11_auth.views.get_client", lambda: built)
    fake.oidc = built
    yield fake
    client_mod.reset_client_cache()


@pytest.fixture
def start_login(client, idp):
    """Drive the authorization request and hand back the callback query string."""

    def _start(url: str = "/auth/tg11/login/", **params):
        resp = client.get(url, params or None)
        assert resp.status_code == 302, resp.status_code
        location = resp["Location"]
        q = {k: v[0] for k, v in parse_qs(location.split("?", 1)[1]).items()}
        flow = client.session["tg11_auth_flow"]
        code = idp.issue_code(state=q["state"], nonce=q["nonce"], challenge=q["code_challenge"])
        return {"authorize": q, "flow": flow, "code": code, "location": location}

    return _start


def sess(client) -> Dict[str, Any]:
    return dict(client.session.items())


def session_blob(client) -> str:
    return json.dumps(sess(client), default=str)
