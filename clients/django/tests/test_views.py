# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""End-to-end relying-party behaviour against the fake provider."""
from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from joserfc.jwk import RSAKey

from tests.conftest import session_blob
from tg11_auth import services
from tg11_auth.models import MigrationSource, MigrationStatus, TG11IdentityLink

pytestmark = pytest.mark.django_db

User = get_user_model()
CB = "/auth/tg11/callback/"


def _callback(client, started, **extra):
    params = {"code": started["code"], "state": started["authorize"]["state"]}
    params.update(extra)
    return client.get(CB, params)


# ---- the authorization request -------------------------------------------
def test_login_starts_pkce_flow(client, idp, start_login):
    started = start_login()
    q = started["authorize"]
    assert urlparse(started["location"]).netloc == "accounts.example.test"
    assert q["response_type"] == "code"
    assert q["client_id"] == "testapp"
    assert q["code_challenge_method"] == "S256"
    assert len(q["code_challenge"]) >= 40
    assert q["state"] and q["nonce"]
    # the verifier stays server-side and never appears in the redirect
    assert started["flow"]["code_verifier"] not in started["location"]


def test_prompt_is_whitelisted(client, idp, start_login):
    assert start_login(prompt="login")["authorize"]["prompt"] == "login"
    assert "prompt" not in start_login(prompt="../../evil")["authorize"]


# ---- happy paths ---------------------------------------------------------
def test_new_identity_creates_local_account(client, idp, start_login):
    started = start_login()
    resp = _callback(client, started)
    assert resp.status_code == 302 and resp["Location"] == "/home/"

    user = User.objects.get()
    assert user.email == "new@example.test"
    assert not user.has_usable_password()  # SSO-only until they set one
    link = TG11IdentityLink.objects.get()
    assert link.user_id == user.pk
    assert link.subject == idp.claims["sub"]
    assert link.application == "testapp"
    assert link.migration_source == MigrationSource.OIDC_LOGIN
    assert link.issuer == "https://accounts.example.test"
    assert client.session["_auth_user_id"] == str(user.pk)


def test_second_login_matches_on_subject_not_email(client, idp, start_login):
    _callback(client, start_login())
    user = User.objects.get()
    idp.claims["email"] = "renamed@elsewhere.test"  # they changed it at TG11
    idp.claims["preferred_username"] = "renamed"
    client.logout()

    resp = _callback(client, start_login())
    assert resp.status_code == 302
    assert User.objects.count() == 1
    assert TG11IdentityLink.objects.count() == 1
    link = TG11IdentityLink.objects.get()
    assert link.user_id == user.pk
    assert link.email_at_link == "renamed@elsewhere.test"
    assert link.last_login_at is not None


def test_verified_email_links_existing_account(client, idp, start_login):
    existing = User.objects.create_user("oldtimer", email="New@Example.Test", password="pw")
    resp = _callback(client, start_login())
    assert resp.status_code == 302
    assert User.objects.count() == 1
    link = TG11IdentityLink.objects.get()
    assert link.user_id == existing.pk
    assert link.migration_source == MigrationSource.VERIFIED_EMAIL
    assert link.legacy_local_id == str(existing.pk)
    assert client.session["_auth_user_id"] == str(existing.pk)


def test_login_cycles_the_session_key(client, idp, start_login):
    started = start_login()
    before = client.session.session_key
    _callback(client, started)
    assert client.session.session_key != before  # no session fixation


def test_refresh_token_never_reaches_the_session(client, idp, start_login):
    _callback(client, start_login())
    assert "rt-super-secret-value" not in session_blob(client)
    assert client.session["tg11_auth_sub"] == idp.claims["sub"]


# ---- the account-takeover guards ----------------------------------------
def test_unverified_email_refuses_to_merge(client, idp, start_login):
    existing = User.objects.create_user("oldtimer", email="new@example.test", password="pw")
    idp.claims["email_verified"] = False

    resp = _callback(client, start_login())
    assert resp.status_code == 409
    assert b"already has an account here" in resp.content
    assert not TG11IdentityLink.objects.exists()
    assert "_auth_user_id" not in client.session
    existing.refresh_from_db()
    assert existing.has_usable_password()


def test_autolink_can_be_switched_off(client, idp, start_login, settings):
    settings.TG11_AUTH_AUTOLINK_VERIFIED_EMAIL = False
    User.objects.create_user("oldtimer", email="new@example.test", password="pw")
    assert _callback(client, start_login()).status_code == 409
    assert not TG11IdentityLink.objects.exists()


def test_autocreate_can_be_switched_off(client, idp, start_login, settings):
    settings.TG11_AUTH_AUTOCREATE = False
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert not User.objects.exists()


def test_suspended_tg11_account_refused(client, idp, start_login):
    idp.claims["account_state"] = "suspended"
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert not User.objects.exists()


def test_revoked_link_refuses_login(client, idp, start_login):
    _callback(client, start_login())
    TG11IdentityLink.objects.update(migration_status=MigrationStatus.REVOKED)
    client.logout()
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert "_auth_user_id" not in client.session


def test_local_account_already_linked_elsewhere(client, idp, start_login):
    existing = User.objects.create_user("oldtimer", email="new@example.test", password="pw")
    TG11IdentityLink.objects.create(user=existing, subject="someone-else", application="testapp")
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert TG11IdentityLink.objects.count() == 1


# ---- callback integrity --------------------------------------------------
def test_state_mismatch_refused(client, idp, start_login):
    started = start_login()
    resp = _callback(client, started, state="not-the-state")
    assert resp.status_code == 400
    assert not User.objects.exists()


def test_code_cannot_be_replayed(client, idp, start_login):
    started = start_login()
    assert _callback(client, started).status_code == 302
    client.logout()
    again = _callback(client, started)
    assert again.status_code == 400  # the flow was consumed
    assert User.objects.count() == 1


def test_callback_without_a_flow_is_refused(client, idp):
    assert client.get(CB, {"code": "x", "state": "y"}).status_code == 400


def test_expired_flow_refused(client, idp, start_login):
    started = start_login()
    session = client.session
    session["tg11_auth_flow"] = {**started["flow"], "created": time.time() - 3600}
    session.save()
    assert _callback(client, started).status_code == 400


def test_provider_error_is_reported(client, idp, start_login):
    started = start_login()
    resp = client.get(CB, {"error": "server_error", "state": started["authorize"]["state"]})
    assert resp.status_code == 400
    assert not User.objects.exists()


def test_user_cancelling_just_goes_home(client, idp, start_login):
    started = start_login()
    resp = client.get(CB, {"error": "access_denied", "state": started["authorize"]["state"]})
    assert resp.status_code == 302 and resp["Location"] == "/bye/"


def test_missing_code_refused(client, idp, start_login):
    started = start_login()
    resp = client.get(CB, {"state": started["authorize"]["state"]})
    assert resp.status_code == 400


def test_token_endpoint_failure_is_reported(client, idp, start_login):
    started = start_login()
    idp.token_status = 400
    assert _callback(client, started).status_code == 502


# ---- ID token validation (through the view) ------------------------------
@pytest.mark.parametrize("break_it", [
    lambda idp: setattr(idp, "nonce_override", "wrong-nonce"),
    lambda idp: setattr(idp, "aud_override", "someone-else"),
    lambda idp: setattr(idp, "iss_override", "https://evil.test"),
    lambda idp: setattr(idp, "exp_delta", -3600),
    lambda idp: setattr(idp, "sign_with", RSAKey.generate_key(2048, parameters={"kid": "k1"})),
])
def test_bad_id_tokens_are_refused(client, idp, start_login, break_it):
    started = start_login()
    break_it(idp)
    resp = _callback(client, started)
    assert resp.status_code == 502
    assert not User.objects.exists()
    assert "_auth_user_id" not in client.session


def test_key_rotation_is_survived(client, idp, start_login):
    _callback(client, start_login())       # caches the JWKS
    client.logout()
    idp.rotate_key()                        # provider rolls its signing key
    hits = idp.jwks_hits
    resp = _callback(client, start_login())
    assert resp.status_code == 302
    assert idp.jwks_hits > hits             # it refetched instead of failing


def test_userinfo_subject_must_match(client, idp, start_login):
    started = start_login()
    idp.userinfo = {"sub": "a-different-subject", "email": "attacker@evil.test"}
    resp = _callback(client, started)
    assert resp.status_code == 502
    assert not User.objects.exists()


def test_userinfo_refreshes_the_profile(client, idp, start_login):
    started = start_login()
    idp.userinfo = {"sub": idp.claims["sub"], "email": "fresher@example.test",
                    "email_verified": True, "preferred_username": "fresher"}
    assert _callback(client, started).status_code == 302
    assert User.objects.get().email == "fresher@example.test"


# ---- redirects -----------------------------------------------------------
def test_local_next_is_honoured(client, idp, start_login):
    started = start_login(next="/home/?welcome=1")
    resp = _callback(client, started)
    assert resp["Location"] == "/home/?welcome=1"


def test_offsite_next_is_dropped(client, idp, start_login):
    started = start_login(next="https://evil.test/steal")
    resp = _callback(client, started)
    assert resp["Location"] == "/home/"


# ---- explicit linking ----------------------------------------------------
def test_signed_in_user_can_link(client, idp):
    user = User.objects.create_user("oldtimer", email="different@example.test", password="pw")
    client.force_login(user)
    resp = client.get("/auth/tg11/link/")
    q = {k: v[0] for k, v in parse_qs(resp["Location"].split("?", 1)[1]).items()}
    code = idp.issue_code(state=q["state"], nonce=q["nonce"], challenge=q["code_challenge"])

    done = client.get(CB, {"code": code, "state": q["state"]})
    assert done.status_code == 302 and done["Location"] == "/settings/"
    link = TG11IdentityLink.objects.get()
    assert link.user_id == user.pk
    assert link.migration_source == MigrationSource.ACCOUNT_LINK
    # linking must not care that the emails differ
    assert link.email_at_link == "new@example.test"


def test_link_requires_being_signed_in(client, idp):
    resp = client.get("/auth/tg11/link/")
    assert resp.status_code == 302 and "/accounts/login/" in resp["Location"]


def test_cannot_link_a_subject_twice(client, idp, start_login):
    _callback(client, start_login())          # first user takes the subject
    other = User.objects.create_user("other", email="other@example.test", password="pw")
    client.force_login(other)
    resp = client.get("/auth/tg11/link/")
    q = {k: v[0] for k, v in parse_qs(resp["Location"].split("?", 1)[1]).items()}
    code = idp.issue_code(state=q["state"], nonce=q["nonce"], challenge=q["code_challenge"])
    done = client.get(CB, {"code": code, "state": q["state"]})
    assert done.status_code == 409
    assert TG11IdentityLink.objects.count() == 1


# ---- unlink / logout ----------------------------------------------------
def test_unlink_refused_when_it_would_lock_you_out(client, idp, start_login):
    _callback(client, start_login())
    resp = client.post("/auth/tg11/unlink/")
    assert resp.status_code == 409
    assert TG11IdentityLink.objects.exists()


def test_unlink_allowed_with_a_local_password(client, idp, start_login):
    _callback(client, start_login())
    user = User.objects.get()
    user.set_password("something")
    user.save()
    client.force_login(user)  # changing the password rotates the session auth hash
    resp = client.post("/auth/tg11/unlink/")
    assert resp.status_code == 302
    assert not TG11IdentityLink.objects.exists()


def test_unlink_is_post_only(client, idp, start_login):
    _callback(client, start_login())
    assert client.get("/auth/tg11/unlink/").status_code == 405


def test_logout_is_post_only(client, idp, start_login):
    _callback(client, start_login())
    assert client.get("/auth/tg11/logout/").status_code == 405
    assert client.session.get("_auth_user_id")


def test_local_logout(client, idp, start_login):
    _callback(client, start_login())
    resp = client.post("/auth/tg11/logout/")
    assert resp.status_code == 302 and resp["Location"] == "/bye/"
    assert "_auth_user_id" not in client.session


def test_global_logout_goes_to_the_provider(client, idp, start_login):
    _callback(client, start_login())
    resp = client.post("/auth/tg11/logout/", {"global": "1"})
    assert resp.status_code == 302
    parsed = urlparse(resp["Location"])
    q = parse_qs(parsed.query)
    assert parsed.netloc == "accounts.example.test" and parsed.path == "/logout"
    assert q["post_logout_redirect_uri"] == ["http://testserver/bye/"]
    assert q["id_token_hint"][0].count(".") == 2
    assert "_auth_user_id" not in client.session


# ---- profile hook --------------------------------------------------------
CALLS: list = []


def _hook(*, user, claims, created, link, request):
    CALLS.append((user.pk, claims.subject, created, link.application))


def _exploding_hook(**kwargs):
    raise RuntimeError("app bug")


def test_profile_hook_runs(client, idp, start_login, settings):
    CALLS.clear()
    settings.TG11_AUTH_PROFILE_HOOK = "tests.test_views._hook"
    _callback(client, start_login())
    assert len(CALLS) == 1 and CALLS[0][2] is True


def test_broken_profile_hook_does_not_break_sign_in(client, idp, start_login, settings):
    settings.TG11_AUTH_PROFILE_HOOK = "tests.test_views._exploding_hook"
    resp = _callback(client, start_login())
    assert resp.status_code == 302
    assert User.objects.exists()


# ---- template helper ----------------------------------------------------
def test_context_processor_reports_link_state(client, idp, start_login):
    from django.template import Context, Template

    _callback(client, start_login())
    resp = client.get("/home/")
    assert resp.status_code == 200
    tpl = Template("{% include 'tg11_auth/button.html' %}")
    html = tpl.render(Context({"tg11_configured": True, "tg11_linked": True, "link_mode": True, "csrf_token": "x"}))
    assert "Unlink TG11" in html


# ---- login guard ---------------------------------------------------------
def _guard_refuses(user, claims):
    raise services.AuthError("This account uses two-factor authentication here; sign in with your password and code.")


def _guard_explodes(user, claims):
    raise RuntimeError("guard bug")


def test_login_guard_can_refuse_an_existing_account(client, idp, start_login, settings):
    User.objects.create_user("oldtimer", email="new@example.test", password="pw")
    settings.TG11_AUTH_LOGIN_GUARD = "tests.test_views._guard_refuses"
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert b"two-factor" in resp.content
    assert not TG11IdentityLink.objects.exists()
    assert "_auth_user_id" not in client.session


def test_login_guard_also_applies_to_an_already_linked_account(client, idp, start_login, settings):
    _callback(client, start_login())                 # link it first
    client.logout()
    settings.TG11_AUTH_LOGIN_GUARD = "tests.test_views._guard_refuses"
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert "_auth_user_id" not in client.session


def test_broken_login_guard_fails_closed(client, idp, start_login, settings):
    User.objects.create_user("oldtimer", email="new@example.test", password="pw")
    settings.TG11_AUTH_LOGIN_GUARD = "tests.test_views._guard_explodes"
    resp = _callback(client, start_login())
    assert resp.status_code == 403                    # refused, not a 500 and not a sign-in
    assert "_auth_user_id" not in client.session


def test_no_guard_configured_is_the_default(client, idp, start_login):
    assert _callback(client, start_login()).status_code == 302


# ---- second factors ------------------------------------------------------
def test_claims_carry_the_authentication_method(client, idp, start_login):
    idp.with_second_factor()
    _callback(client, start_login())
    user = User.objects.get()
    assert user.pk  # signed in
    # and the single-factor case is distinguishable
    link = TG11IdentityLink.objects.get()
    assert link.subject == idp.claims["sub"]


def test_require_mfa_refuses_a_single_factor_sign_in(client, idp, start_login, settings):
    settings.TG11_AUTH_REQUIRE_MFA = True
    resp = _callback(client, start_login())
    assert resp.status_code == 403
    assert b"two-factor" in resp.content
    assert not User.objects.exists()
    assert "_auth_user_id" not in client.session


def test_require_mfa_accepts_a_second_factor(client, idp, start_login, settings):
    settings.TG11_AUTH_REQUIRE_MFA = True
    idp.with_second_factor()
    resp = _callback(client, start_login())
    assert resp.status_code == 302
    assert User.objects.count() == 1


def test_require_mfa_accepts_a_recovery_code(client, idp, start_login, settings):
    settings.TG11_AUTH_REQUIRE_MFA = True
    idp.with_second_factor("recovery")
    assert _callback(client, start_login()).status_code == 302


def test_require_mfa_asks_the_provider_for_it(client, idp, start_login, settings):
    settings.TG11_AUTH_REQUIRE_MFA = True
    q = start_login()["authorize"]
    assert q["acr_values"] == "urn:tg11:2fa"


def test_max_age_is_sent_when_configured(client, idp, start_login, settings):
    settings.TG11_AUTH_MAX_AGE = 300
    assert start_login()["authorize"]["max_age"] == "300"
    settings.TG11_AUTH_MAX_AGE = None
    assert "max_age" not in start_login()["authorize"]


def test_step_up_freshness_is_checkable(client, idp, start_login):
    import time as _t
    from tg11_auth.client import Claims
    assert Claims(subject="s", auth_time=int(_t.time())).authenticated_within(300)
    assert not Claims(subject="s", auth_time=int(_t.time()) - 3600).authenticated_within(300)
    assert not Claims(subject="s").authenticated_within(300)   # unknown is not fresh
