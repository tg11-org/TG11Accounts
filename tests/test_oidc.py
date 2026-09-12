# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end OIDC test: Flowboard's OIDC client library against this provider."""
import os
import re
import sys
import tempfile
from urllib.parse import parse_qs, urlparse

os.environ.update({"TG11_ENV": "test", "TG11_DATA_DIR": tempfile.mkdtemp(), "TG11_SECRET_KEY": "test-secret-0123456789", "TG11_ISSUER": "http://accounts.test", "TG11_COOKIE_SECURE": "false"})

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tg11.web import app  # noqa: E402
from tg11.cli import main as cli  # noqa: E402
from tg11.models import Base, engine  # noqa: E402

FLOWBOARD = "/home/claude/flowboard"


@pytest.fixture(autouse=True)
def fresh():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


@pytest.fixture
def client():
    with TestClient(app, base_url="http://accounts.test") as c:
        yield c


def _register(c, email="alice@example.com", username="alice", pw="correct-horse-battery"):
    csrf = c.get("/register").cookies.get("tg11_csrf")
    r = c.post("/register", data={"email": email, "username": username, "password": pw, "password2": pw, "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303, r.text


def _add_client(capsys, **kw):
    args = ["add-client", "--client-id", kw.get("client_id", "flowboard"), "--name", "Flowboard", "--application", "flowboard", "--redirect", kw.get("redirect", "https://flowboard.test/auth/tg11/callback"), "--scopes", "openid profile email offline_access"]
    if kw.get("trusted"):
        args.append("--trusted")
    if kw.get("public"):
        args.append("--public")
    cli(args)
    out = capsys.readouterr().out
    return re.search(r"client_secret=(\S+)", out).group(1)


def test_discovery_and_jwks(client):
    d = client.get("/.well-known/openid-configuration").json()
    assert d["issuer"] == "http://accounts.test" and d["authorization_endpoint"].endswith("/oauth/authorize")
    k = client.get("/oauth/jwks.json").json()
    assert k["keys"][0]["kty"] == "RSA" and "d" not in k["keys"][0]


def test_full_code_flow_with_flowboard_client(client, capsys, monkeypatch):
    secret = _add_client(capsys, trusted=True)
    _register(client)
    # use Flowboard's relying-party implementation against this provider
    sys.path.insert(0, FLOWBOARD)
    os.environ.setdefault("FLOWBOARD_ENV", "test")
    from app.identity.oidc import OIDCClient

    def _forward(req: httpx.Request) -> httpx.Response:
        r = client.request(req.method, str(req.url), content=req.content, headers=dict(req.headers), follow_redirects=False)
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)

    rp = OIDCClient("http://accounts.test", "flowboard", secret, "openid profile email offline_access", "https://flowboard.test/auth/tg11/callback", http=httpx.Client(transport=httpx.MockTransport(_forward)))
    flow = rp.new_flow_state()
    url = rp.authorization_url(flow)
    # user (already signed in on the IdP) hits authorize -> code redirect (trusted client => no consent screen)
    r = client.get(url, follow_redirects=False)
    assert r.status_code == 302, r.text
    loc = urlparse(r.headers["location"])
    q = parse_qs(loc.query)
    assert loc.netloc == "flowboard.test" and q["state"] == [flow["state"]] and "code" in q
    claims = rp.exchange(q["code"][0], flow)
    assert claims.email == "alice@example.com" and claims.preferred_username == "alice" and claims.email_verified is False
    assert len(claims.subject) == 36
    # code replay is rejected
    r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": "https://flowboard.test/auth/tg11/callback", "code_verifier": flow["code_verifier"]}, auth=("flowboard", secret))
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    # wrong nonce fails validation
    with pytest.raises(Exception):
        rp.validate_id_token("garbage", flow["nonce"])


def test_pkce_and_client_auth_enforced(client, capsys):
    secret = _add_client(capsys, trusted=True)
    _register(client)
    import base64, hashlib, secrets as s

    verifier = s.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = client.get("/oauth/authorize", params={"response_type": "code", "client_id": "flowboard", "redirect_uri": "https://flowboard.test/auth/tg11/callback", "scope": "openid email", "state": "xyz", "code_challenge": challenge, "code_challenge_method": "S256"}, follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    # wrong verifier
    r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": "https://flowboard.test/auth/tg11/callback", "code_verifier": "x" * 50}, auth=("flowboard", secret))
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    # code is now burned (single use) -> even the right verifier fails
    r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": "https://flowboard.test/auth/tg11/callback", "code_verifier": verifier}, auth=("flowboard", secret))
    assert r.status_code == 400
    # bad client secret
    r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code}, auth=("flowboard", "nope"))
    assert r.status_code == 401
    # unregistered redirect uri is refused before any redirect happens
    r = client.get("/oauth/authorize", params={"response_type": "code", "client_id": "flowboard", "redirect_uri": "https://evil.test/cb", "scope": "openid"}, follow_redirects=False)
    assert r.status_code == 400 and "not registered" in r.text


def test_consent_and_userinfo_and_refresh(client, capsys):
    secret = _add_client(capsys, trusted=False)
    _register(client)
    params = {"response_type": "code", "client_id": "flowboard", "redirect_uri": "https://flowboard.test/auth/tg11/callback", "scope": "openid profile email offline_access", "state": "s1", "nonce": "n1"}
    r = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert r.status_code == 200 and "Allow" in r.text  # consent screen
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
    query = re.search(r'name="query" value="([^"]+)"', r.text).group(1)
    r = client.post("/oauth/authorize", data={"decision": "deny", "query": query.replace("&amp;", "&"), "csrf_token": csrf}, follow_redirects=False)
    assert "error=access_denied" in r.headers["location"]
    r = client.post("/oauth/authorize", data={"decision": "allow", "query": query.replace("&amp;", "&"), "csrf_token": csrf}, follow_redirects=False)
    r = client.get(r.headers["location"], follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    t = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": params["redirect_uri"], "client_id": "flowboard", "client_secret": secret}).json()
    assert "refresh_token" in t and t["token_type"] == "Bearer"
    ui = client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {t['access_token']}"}).json()
    assert ui["email"] == "alice@example.com" and ui["preferred_username"] == "alice"
    t2 = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": "flowboard", "client_secret": secret}).json()
    assert t2["access_token"] != t["access_token"]
    # old refresh token rotated out
    assert client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": "flowboard", "client_secret": secret}).status_code == 400
    # consent remembered: second authorize skips the screen
    r = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert r.status_code == 302 and "code=" in r.headers["location"]
    # revoking from the account page kills tokens
    page = client.get("/account")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/account/consents/flowboard/revoke", data={"csrf_token": csrf})
    assert client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {t2['access_token']}"}).status_code == 401


def test_login_required_redirect_and_logout(client, capsys):
    _add_client(capsys, trusted=True)
    r = client.get("/oauth/authorize", params={"response_type": "code", "client_id": "flowboard", "redirect_uri": "https://flowboard.test/auth/tg11/callback", "scope": "openid", "code_challenge": "a" * 43, "code_challenge_method": "S256"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=/oauth/authorize")
    _register(client)
    assert client.get("/account").status_code == 200
    r = client.get("/oauth/logout", follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/account", follow_redirects=False).status_code == 303
