# SPDX-License-Identifier: AGPL-3.0-or-later
"""Two-factor authentication: enrollment, the login step, recovery codes, and
the `amr`/`acr` claims applications rely on."""
import os
import re
import tempfile
import time
from urllib.parse import parse_qs, urlparse

os.environ.update({
    "TG11_ENV": "test",
    "TG11_DATA_DIR": os.environ.get("TG11_DATA_DIR") or tempfile.mkdtemp(),
    "TG11_SECRET_KEY": "test-secret-0123456789",
    "TG11_ISSUER": "http://accounts.test",
    "TG11_COOKIE_SECURE": "false",
    "TG11_VAULT_KEY": os.environ.get("TG11_VAULT_KEY") or "dGcxMS10ZXN0LXZhdWx0LWtleS0zMi1ieXRlcyEhISE=",
})

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from joserfc import jwt as _jwt  # noqa: E402
from joserfc.jwk import KeySet  # noqa: E402

from tg11 import mfa  # noqa: E402
from tg11.cli import main as cli  # noqa: E402
from tg11.models import Base, RecoveryCode, SessionLocal, TOTPDevice, User, engine  # noqa: E402
from tg11.web import app  # noqa: E402

PW = "correct-horse-battery"


@pytest.fixture(autouse=True)
def fresh():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    mfa._attempts.clear()


@pytest.fixture
def client():
    with TestClient(app, base_url="http://accounts.test") as c:
        yield c


def _csrf(c, path="/login"):
    return c.get(path).cookies.get("tg11_csrf") or c.cookies.get("tg11_csrf")


def _register(c, email="alice@example.com", username="alice"):
    csrf = _csrf(c, "/register")
    r = c.post("/register", data={"email": email, "username": username, "password": PW, "password2": PW, "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303, r.text


def _session_csrf(c):
    """The CSRF token of the signed-in session, taken from a rendered form."""
    html = c.get("/account/security").text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _login_code(secret, monkeypatch, steps: int = 1) -> str:
    """A code for a *later* step.

    Enrollment consumes the current step (that is the replay guard doing its
    job), so a test that signs in a moment later has to move to the next window
    exactly as a real user would by waiting.
    """
    future = int(time.time()) + mfa.PERIOD * steps
    monkeypatch.setattr(mfa.time, "time", lambda: future)
    return pyotp.TOTP(secret).at(future)


def _codes_from(html: str) -> list:
    """The codes live in the <pre> block; a looser regex also matches CSS."""
    block = re.search(r"<pre[^>]*>(.*?)</pre>", html, re.S)
    return re.findall(r"\b([a-z2-7]{5}-[a-z2-7]{5})\b", block.group(1)) if block else []


def _enable_totp(c):
    """Enrol through the real pages and return (secret, recovery codes)."""
    r = c.post("/account/security/enable", data={"csrf_token": _session_csrf(c)})
    assert r.status_code == 200, r.text
    secret = re.search(r"<code>([A-Z2-7]+)</code>", r.text).group(1)
    code = pyotp.TOTP(secret).now()
    r = c.post("/account/security/confirm", data={"code": code, "csrf_token": _session_csrf(c)})
    assert r.status_code == 200, r.text
    codes = _codes_from(r.text)
    assert len(codes) == mfa.RECOVERY_CODES
    return secret, codes


# ---- enrollment --------------------------------------------------------------

def test_enrollment_requires_a_live_code(client):
    _register(client)
    client.post("/account/security/enable", data={"csrf_token": _session_csrf(client)})
    r = client.post("/account/security/confirm", data={"code": "000000", "csrf_token": _session_csrf(client)})
    assert r.status_code == 400
    with SessionLocal() as db:
        device = db.query(TOTPDevice).one()
        assert device.confirmed_at is None          # nothing is enforced yet
        assert db.query(RecoveryCode).count() == 0


def test_enrollment_stores_the_secret_encrypted(client):
    _register(client)
    secret, _ = _enable_totp(client)
    with SessionLocal() as db:
        device = db.query(TOTPDevice).one()
        assert device.confirmed_at is not None
        assert secret.encode() not in bytes(device.secret_blob)   # not sitting in the clear
        assert mfa._secret_of(device) == secret                   # but we can still read it


def test_recovery_codes_are_hashed_not_stored(client):
    _register(client)
    _secret, codes = _enable_totp(client)
    with SessionLocal() as db:
        stored = [r.code_hash for r in db.query(RecoveryCode).all()]
        assert len(stored) == len(codes)
        assert not (set(codes) & set(stored))


def test_cannot_enrol_twice_without_disabling(client):
    _register(client)
    _enable_totp(client)
    r = client.post("/account/security/enable", data={"csrf_token": _session_csrf(client)})
    assert r.status_code == 400 and "already enabled" in r.text


# ---- the login step ----------------------------------------------------------

def _password_login(c, next_url="/account"):
    csrf = _csrf(c, "/login")
    return c.post("/login", data={"identifier": "alice@example.com", "password": PW, "next": next_url, "csrf_token": csrf}, follow_redirects=False)


def test_password_alone_no_longer_signs_you_in(client):
    _register(client)
    _enable_totp(client)
    client.cookies.clear()

    r = _password_login(client)
    assert r.status_code == 303 and r.headers["location"].startswith("/login/mfa")
    assert client.cookies.get("tg11_session") is None      # half-authenticated only
    assert client.get("/account", follow_redirects=False).status_code == 303


def test_correct_code_completes_the_sign_in(client, monkeypatch):
    _register(client)
    secret, _ = _enable_totp(client)
    client.cookies.clear()
    _password_login(client)

    page = client.get("/login/mfa")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    r = client.post("/login/mfa", data={"code": _login_code(secret, monkeypatch), "next": "/account", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/account").status_code == 200


def test_wrong_code_is_refused_and_rate_limited(client):
    _register(client)
    _enable_totp(client)
    client.cookies.clear()
    _password_login(client)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login/mfa").text).group(1)

    for _ in range(mfa.MAX_ATTEMPTS):
        r = client.post("/login/mfa", data={"code": "123456", "csrf_token": csrf}, follow_redirects=False)
        assert r.status_code == 401
    r = client.post("/login/mfa", data={"code": "123456", "csrf_token": csrf}, follow_redirects=False)
    assert "Too many" in r.text
    assert client.get("/account", follow_redirects=False).status_code == 303


def test_a_recovery_code_works_once(client):
    _register(client)
    _secret, codes = _enable_totp(client)
    client.cookies.clear()
    _password_login(client)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login/mfa").text).group(1)

    r = client.post("/login/mfa", data={"code": codes[0], "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/account").status_code == 200

    client.cookies.clear()
    _password_login(client)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login/mfa").text).group(1)
    again = client.post("/login/mfa", data={"code": codes[0], "csrf_token": csrf}, follow_redirects=False)
    assert again.status_code == 401                        # single use


def test_a_code_cannot_be_replayed(client, monkeypatch):
    _register(client)
    secret, _ = _enable_totp(client)
    code = _login_code(secret, monkeypatch)
    with SessionLocal() as db:
        device = db.query(TOTPDevice).one()
        assert mfa._verify_totp(device, code) is True
        assert mfa._verify_totp(device, code) is False     # same step, refused
        db.commit()


def test_the_enrollment_code_cannot_be_reused_to_sign_in(client):
    """The code that turned 2FA on is spent; someone who shoulder-surfed it
    cannot walk in with it a second later."""
    _register(client)
    secret, _ = _enable_totp(client)
    with SessionLocal() as db:
        device = db.query(TOTPDevice).one()
        assert mfa._verify_totp(device, pyotp.TOTP(secret).now()) is False


def test_pending_login_expires(client, monkeypatch):
    _register(client)
    _enable_totp(client)
    client.cookies.clear()
    _password_login(client)
    monkeypatch.setattr("tg11.web.MFA_PENDING_MAX_AGE", 0)
    time.sleep(1)
    r = client.get("/login/mfa", follow_redirects=False)
    assert r.status_code == 303 and "/login" in r.headers["location"]


# ---- turning it off ----------------------------------------------------------

def test_disabling_needs_password_and_a_code(client, monkeypatch):
    _register(client)
    secret, _ = _enable_totp(client)
    r = client.post("/account/security/disable", data={"password": "wrong", "code": "000000", "csrf_token": _session_csrf(client)})
    assert r.status_code == 403
    r = client.post("/account/security/disable", data={"password": PW, "code": "000000", "csrf_token": _session_csrf(client)})
    assert r.status_code == 403
    with SessionLocal() as db:
        assert db.query(TOTPDevice).count() == 1

    r = client.post("/account/security/disable", data={"password": PW, "code": _login_code(secret, monkeypatch), "csrf_token": _session_csrf(client)})
    assert r.status_code == 200 and "off" in r.text
    with SessionLocal() as db:
        assert db.query(TOTPDevice).count() == 0 and db.query(RecoveryCode).count() == 0


def test_new_recovery_codes_replace_the_old_ones(client):
    _register(client)
    _secret, codes = _enable_totp(client)
    r = client.post("/account/security/recovery", data={"password": PW, "csrf_token": _session_csrf(client)})
    assert r.status_code == 200
    fresh_codes = _codes_from(r.text)
    assert len(fresh_codes) == mfa.RECOVERY_CODES and not (set(codes) & set(fresh_codes))
    with SessionLocal() as db:
        user = db.query(User).one()
        assert mfa.consume_recovery_code(db, user, codes[0]) is False
        assert mfa.consume_recovery_code(db, user, fresh_codes[0]) is True


# ---- what applications are told ---------------------------------------------

def _add_client(capsys, scopes="openid profile email"):
    cli(["add-client", "--client-id", "app1", "--name", "App", "--application", "app1",
         "--redirect", "https://app.test/cb", "--scopes", scopes, "--trusted"])
    return re.search(r"client_secret=(\S+)", capsys.readouterr().out).group(1)


def _id_token_claims(client, secret, extra=""):
    from tg11.oidc import ACR_MFA  # noqa: F401

    flow_state = "st4te"
    url = (f"/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"
           f"&scope=openid+profile+email&state={flow_state}&nonce=n0nce{extra}")
    r = client.get(url, follow_redirects=False)
    assert r.status_code == 302, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    tok = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                            "redirect_uri": "https://app.test/cb"}, auth=("app1", secret))
    assert tok.status_code == 200, tok.text
    jwks = client.get("/oauth/jwks.json").json()
    return dict(_jwt.decode(tok.json()["id_token"], KeySet.import_key_set(jwks), algorithms=["RS256"]).claims), tok.json()


def test_id_token_reports_a_single_factor(client, capsys):
    secret = _add_client(capsys)
    _register(client)
    claims, _ = _id_token_claims(client, secret)
    assert claims["amr"] == ["pwd"]
    assert claims["acr"] == "urn:tg11:1fa"
    assert isinstance(claims["auth_time"], int)


def test_id_token_reports_the_second_factor(client, capsys, monkeypatch):
    secret = _add_client(capsys)
    _register(client)
    totp_secret, _ = _enable_totp(client)
    client.cookies.clear()
    _password_login(client)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login/mfa").text).group(1)
    client.post("/login/mfa", data={"code": _login_code(totp_secret, monkeypatch), "csrf_token": csrf}, follow_redirects=False)

    claims, _ = _id_token_claims(client, secret)
    assert "otp" in claims["amr"] and "pwd" in claims["amr"]
    assert claims["acr"] == "urn:tg11:2fa"


def test_discovery_advertises_acr_and_amr(client):
    d = client.get("/.well-known/openid-configuration").json()
    assert "urn:tg11:2fa" in d["acr_values_supported"]
    assert "amr" in d["claims_supported"] and "acr" in d["claims_supported"]


def test_acr_values_forces_reauthentication_when_unmet(client, capsys):
    secret = _add_client(capsys)
    _register(client)                                    # password-only session
    r = client.get("/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"
                   "&scope=openid&state=s&nonce=n&acr_values=urn%3Atg11%3A2fa", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_max_age_forces_reauthentication(client, capsys):
    _add_client(capsys)
    _register(client)
    r = client.get("/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"
                   "&scope=openid&state=s&nonce=n&max_age=0", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_prompt_none_with_unmet_acr_reports_it_to_the_application(client, capsys):
    _add_client(capsys)
    _register(client)
    r = client.get("/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"
                   "&scope=openid&state=s&nonce=n&acr_values=urn%3Atg11%3A2fa&prompt=none", follow_redirects=False)
    assert r.status_code == 302
    assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["unmet_authentication_requirements"]


def test_refreshed_id_token_keeps_the_real_factors(client, capsys, monkeypatch):
    secret = _add_client(capsys, scopes="openid profile email offline_access")
    _register(client)
    totp_secret, _ = _enable_totp(client)
    client.cookies.clear()
    _password_login(client)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login/mfa").text).group(1)
    client.post("/login/mfa", data={"code": _login_code(totp_secret, monkeypatch), "csrf_token": csrf}, follow_redirects=False)

    url = ("/oauth/authorize?response_type=code&client_id=app1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"
           "&scope=openid+profile+email+offline_access&state=s&nonce=n")
    r = client.get(url, follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    tok = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app.test/cb"}, auth=("app1", secret)).json()
    refreshed = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, auth=("app1", secret)).json()
    jwks = client.get("/oauth/jwks.json").json()
    claims = dict(_jwt.decode(refreshed["id_token"], KeySet.import_key_set(jwks), algorithms=["RS256"]).claims)
    assert "otp" in claims["amr"] and claims["acr"] == "urn:tg11:2fa"


# ---- connected applications --------------------------------------------------

def test_connections_page_lists_apps_and_state(client, capsys):
    secret = _add_client(capsys)
    _register(client)
    page = client.get("/connections")
    assert page.status_code == 200
    assert "App" in page.text and "never used" in page.text

    _id_token_claims(client, secret)                 # now it has been used
    page = client.get("/connections")
    assert "signed in" in page.text or "active token" in page.text
    assert "Revoke access" in page.text


def test_connections_requires_a_session(client):
    r = client.get("/connections", follow_redirects=False)
    assert r.status_code == 303 and "/login" in r.headers["location"]


def test_revoking_access_kills_tokens_and_consent(client, capsys):
    secret = _add_client(capsys)
    _register(client)
    _id_token_claims(client, secret)
    with SessionLocal() as db:
        from tg11.models import Consent, Token
        assert db.query(Token).filter(Token.revoked_at.is_(None)).count() >= 1

    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/connections").text).group(1)
    r = client.post("/connections/revoke", data={"client_id": "app1", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303
    with SessionLocal() as db:
        from tg11.models import Consent, Token
        assert db.query(Token).filter(Token.revoked_at.is_(None)).count() == 0
        assert db.query(Consent).filter(Consent.revoked_at.is_(None)).count() == 0


def test_revoking_an_unknown_application_is_refused(client, capsys):
    _add_client(capsys)
    _register(client)
    csrf = _session_csrf(client)     # no revoke form is rendered when nothing is connected
    r = client.post("/connections/revoke", data={"client_id": "nope", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"]
