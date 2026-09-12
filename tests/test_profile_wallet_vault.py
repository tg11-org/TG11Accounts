# SPDX-License-Identifier: AGPL-3.0-or-later
import io
import json
import os
import re
import tempfile

os.environ.update({"TG11_ENV": "test", "TG11_DATA_DIR": tempfile.mkdtemp(), "TG11_SECRET_KEY": "test-secret-0123456789", "TG11_ISSUER": "http://accounts.test", "TG11_COOKIE_SECURE": "false", "TG11_VAULT_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from tg11 import payments  # noqa: E402
from tg11.cli import main as cli  # noqa: E402
from tg11.models import ActionToken, Base, PaymentMethod, SessionLocal, User, engine, ensure_schema  # noqa: E402
from tg11.web import app  # noqa: E402


@pytest.fixture(autouse=True)
def fresh():
    Base.metadata.drop_all(engine)
    ensure_schema()


@pytest.fixture
def client():
    with TestClient(app, base_url="http://accounts.test") as c:
        yield c


def _login(c, email="alice@example.com", username="alice"):
    csrf = c.get("/register").cookies.get("tg11_csrf")
    r = c.post("/register", data={"email": email, "username": username, "password": "correct-horse-battery", "password2": "correct-horse-battery", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303
    page = c.get("/account")
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def _png(w=64, h=32):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (w, h), (10, 200, 100)).save(buf, "PNG")
    return buf.getvalue()


def test_profile_bio_images_phone(client):
    csrf = _login(client)
    r = client.post("/account/profile", data={"username": "alice", "display_name": "Alice", "bio": "hello\nworld", "website": "example.com", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/account/avatar", data={"csrf_token": csrf}, files={"file": ("a.png", _png(), "image/png")}, follow_redirects=False)
    assert r.status_code == 303 and "updated" in r.headers["location"]
    r = client.post("/account/header", data={"csrf_token": csrf}, files={"file": ("h.png", _png(1200, 300), "image/png")}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/account/avatar", data={"csrf_token": csrf}, files={"file": ("x.txt", b"not an image", "text/plain")})
    assert r.status_code == 400
    page = client.get("/account").text
    m = re.search(r'src="(/media/[^"]+avatar-[^"]+\.jpg)"', page)
    assert m and client.get(m.group(1)).status_code == 200
    assert "hello" in page and "https://example.com" in page
    # phone: saved but unverified when SMS not configured; code path still works
    r = client.post("/account/phone", data={"phone": "(555) 123-4567", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303
    db = SessionLocal()
    u = db.scalar(select(User).where(User.username == "alice"))
    assert u.phone == "+15551234567" and u.phone_verified_at is None
    tok = db.scalar(select(ActionToken).where(ActionToken.action == "verify_phone"))
    assert tok is not None
    db.close()
    r = client.post("/account/phone/verify", data={"code": "000000", "csrf_token": csrf}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    r = client.post("/account/phone", data={"phone": "12", "csrf_token": csrf}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_email_change_flow(client, monkeypatch):
    sent = []
    from tg11 import accounts

    monkeypatch.setattr(accounts, "send_mail", lambda to, subject, body: sent.append((to, body)) or True)
    csrf = _login(client)
    r = client.post("/account/email", data={"new_email": "New@Example.com", "password": "correct-horse-battery", "csrf_token": csrf}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    link = re.search(r"(http://accounts.test/email/confirm/\S+)", [b for t, b in sent if t == "new@example.com"][0]).group(1)
    assert any(t == "alice@example.com" for t, _ in sent)  # old address notified
    r = client.get(link, follow_redirects=False)
    assert "Email+updated" in r.headers["location"]
    db = SessionLocal()
    u = db.scalar(select(User).where(User.username == "alice"))
    assert u.email == "new@example.com" and u.email_verified and u.pending_email == ""
    db.close()
    assert "invalid" in client.get(link, follow_redirects=False).headers["location"]  # single use
    # wrong password refused
    r = client.post("/account/email", data={"new_email": "x@example.com", "password": "nope", "csrf_token": csrf}, follow_redirects=False)
    assert "Password+incorrect" in r.headers["location"]


def test_vault_and_api(client, capsys):
    cli(["add-client", "--client-id", "flowboard", "--name", "Flowboard", "--application", "flowboard", "--redirect", "https://fb.test/cb", "--scopes", "openid profile tg11.ai tg11.payments", "--trusted", "--link-url", "https://fb.test/auth/tg11/login?link=1"])
    secret = re.search(r"client_secret=(\S+)", capsys.readouterr().out).group(1)
    csrf = _login(client)
    r = client.post("/vault", data={"provider": "openai", "api_key": "sk-proj-vaultkey1234", "label": "main", "csrf_token": csrf}, follow_redirects=False)
    assert "Saved" in r.headers["location"]
    page = client.get("/vault").text
    assert "sk-proj-••••••••1234" in page and "vaultkey" not in page
    assert "Link my account" in client.get("/account").text
    # get a user token with tg11.ai via the code flow
    r = client.get("/oauth/authorize", params={"response_type": "code", "client_id": "flowboard", "redirect_uri": "https://fb.test/cb", "scope": "openid profile tg11.ai tg11.payments"}, follow_redirects=False)
    code = re.search(r"code=([^&]+)", r.headers["location"]).group(1)
    tok = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": "https://fb.test/cb"}, auth=("flowboard", secret)).json()
    creds = client.get("/api/v1/ai/credentials", headers={"Authorization": f"Bearer {tok['access_token']}"}).json()["credentials"]
    assert creds[0]["provider"] == "openai" and creds[0]["secrets"]["api_key"] == "sk-proj-vaultkey1234"
    me = client.get("/api/v1/me", headers={"Authorization": f"Bearer {tok['access_token']}"}).json()
    assert me["preferred_username"] == "alice"
    # app pushes keys back into the vault (reverse sync)
    r = client.put("/api/v1/ai/credentials", json={"credentials": [{"provider": "anthropic", "secrets": {"api_key": "sk-ant-pushed"}, "config": {"base_url": "https://x"}}, {"provider": "bad provider!", "secrets": {"api_key": "x"}}, {"provider": "openai", "secrets": {}}]}, headers={"Authorization": f"Bearer {tok['access_token']}"})
    assert r.status_code == 200 and r.json()["written"] == ["anthropic"] and set(r.json()["skipped"]) == {"bad provider!", "openai"}
    creds = {c["provider"]: c for c in client.get("/api/v1/ai/credentials", headers={"Authorization": f"Bearer {tok['access_token']}"}).json()["credentials"]}
    assert creds["anthropic"]["secrets"]["api_key"] == "sk-ant-pushed" and creds["anthropic"]["config"]["base_url"] == "https://x" and creds["anthropic"]["source"] == "flowboard"
    assert creds["openai"]["secrets"]["api_key"] == "sk-proj-vaultkey1234"  # untouched by a partial push
    assert "from flowboard" in client.get("/vault").text
    r = client.put("/api/v1/ai/credentials", json={"credentials": [{"provider": "anthropic", "secrets": {"api_key": "sk-ant-2"}}], "replace": True}, headers={"Authorization": f"Bearer {tok['access_token']}"})
    assert r.json()["removed"] == ["openai"]
    # link registration by the app
    r = client.post("/api/v1/links", json={"sub": me["sub"], "legacy_id": "fb-user-1"}, auth=("flowboard", secret))
    assert r.status_code == 200
    assert "linked" in client.get("/account").text
    # payments API: no method yet => 402-ish error
    r = client.post("/api/v1/payments/holds", json={"sub": me["sub"], "amount": 500, "currency": "usd", "reference": "order-1"}, auth=("flowboard", secret))
    assert r.status_code == 400 and "no active payment method" in r.json()["error_description"]


def test_hold_lifecycle_with_fake_provider(client, capsys, monkeypatch):
    cli(["add-client", "--client-id", "freeparty", "--name", "FreeParty", "--application", "freeparty", "--redirect", "https://fp.test/cb", "--scopes", "openid tg11.payments"])
    secret = re.search(r"client_secret=(\S+)", capsys.readouterr().out).group(1)
    csrf = _login(client)
    calls = []

    class Fake(payments.PaymentProvider):
        info = payments.ProviderInfo("stripe", "Fake", "card", "available")

        def authorize(self, method, amount, currency, description, reference):
            calls.append(("auth", amount)); return "pi_123"

        def capture(self, hold, amount):
            calls.append(("capture", amount))

        def release(self, hold):
            calls.append(("release", hold.external_id))

    monkeypatch.setitem(payments.PROVIDERS, "stripe", Fake())
    db = SessionLocal()
    u = db.scalar(select(User).where(User.username == "alice"))
    db.add(PaymentMethod(user_id=u.id, provider="stripe", kind="card", label="Visa •••• 4242", external_customer_id="cus_1", external_method_id="pm_1", status="active", is_default=True))
    db.commit(); sub = u.id; db.close()
    # not consented yet -> 403
    r = client.post("/api/v1/payments/holds", json={"sub": sub, "amount": 1500, "currency": "usd", "reference": "ticket-9"}, auth=("freeparty", secret))
    assert r.status_code == 403
    # grant consent via authorize screen
    r = client.get("/oauth/authorize", params={"response_type": "code", "client_id": "freeparty", "redirect_uri": "https://fp.test/cb", "scope": "openid tg11.payments"}, follow_redirects=False)
    q = re.search(r'name="query" value="([^"]+)"', r.text).group(1).replace("&amp;", "&")
    client.post("/oauth/authorize", data={"decision": "allow", "query": q, "csrf_token": csrf}, follow_redirects=False)
    r = client.post("/api/v1/payments/holds", json={"sub": sub, "amount": 1500, "currency": "usd", "reference": "ticket-9", "description": "Event deposit"}, auth=("freeparty", secret))
    assert r.status_code == 201 and r.json()["status"] == "authorized"
    hid = r.json()["id"]
    assert "Event deposit" in client.get("/wallet").text
    r = client.post(f"/api/v1/payments/holds/{hid}/capture", json={"amount": 1000}, auth=("freeparty", secret))
    assert r.json()["status"] == "captured" and r.json()["captured_amount"] == 1000
    assert client.post(f"/api/v1/payments/holds/{hid}/release", auth=("freeparty", secret)).status_code == 400
    # other client cannot see it
    cli(["add-client", "--client-id", "other", "--name", "O", "--application", "o", "--redirect", "https://o.test/cb"])
    s2 = re.search(r"client_secret=(\S+)", capsys.readouterr().out).group(1)
    assert client.get(f"/api/v1/payments/holds/{hid}", auth=("other", s2)).status_code == 404
    assert calls == [("auth", 1500), ("capture", 1000)]
