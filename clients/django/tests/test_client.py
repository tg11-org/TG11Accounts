# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Unit tests for the OIDC client and the linking rules, without the views."""
from __future__ import annotations

import base64
import hashlib
import time

import pytest
from django.contrib.auth import get_user_model

from tests.conftest import CLIENT_ID, ISSUER, FakeIdP
from tg11_auth import conf, services
from tg11_auth.client import CLOCK_SKEW, Claims, OIDCClient, OIDCError, get_client, reset_client_cache
from tg11_auth.models import MigrationSource, TG11IdentityLink


def _client(fake: FakeIdP) -> OIDCClient:
    return OIDCClient(issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret",
                      redirect_uri="http://testserver/auth/tg11/callback/", http=fake.client())


def _flow(fake: FakeIdP):
    flow = OIDCClient.new_flow_state()
    fake.issue_code(state=flow["state"], nonce=flow["nonce"], challenge=flow["code_challenge"])
    return flow


# ---- PKCE ---------------------------------------------------------------
def test_verifier_and_challenge_are_a_real_s256_pair():
    flow = OIDCClient.new_flow_state()
    expected = base64.urlsafe_b64encode(hashlib.sha256(flow["code_verifier"].encode()).digest()).decode().rstrip("=")
    assert flow["code_challenge"] == expected
    assert "=" not in flow["code_challenge"]
    assert len({OIDCClient.new_flow_state()["state"] for _ in range(50)}) == 50  # not predictable


def test_token_exchange_sends_the_verifier():
    fake = FakeIdP()
    cl = _client(fake)
    flow = _flow(fake)
    claims = cl.exchange("code-1", flow)
    assert claims.subject == fake.claims["sub"]
    assert fake.token_requests[0]["code_verifier"] == [flow["code_verifier"]]
    assert fake.token_requests[0]["grant_type"] == ["authorization_code"]


def test_wrong_verifier_is_rejected_by_the_provider():
    fake = FakeIdP()
    cl = _client(fake)
    flow = _flow(fake)
    with pytest.raises(OIDCError):  # a stolen code is useless without the verifier
        cl.exchange("code-1", {**flow, "code_verifier": "not-the-verifier"})
    assert cl.exchange("code-1", flow).subject  # the genuine verifier still works


# ---- discovery ----------------------------------------------------------
def test_discovery_issuer_must_match():
    fake = FakeIdP()
    fake.issuer = "https://accounts.example.test"
    cl = OIDCClient(issuer="https://accounts.other.test", client_id=CLIENT_ID, http=fake.client())
    with pytest.raises(OIDCError):
        cl.metadata


def test_jwks_is_cached_then_refetched_on_rotation():
    fake = FakeIdP()
    cl = _client(fake)
    cl.exchange("code-1", _flow(fake))
    assert fake.jwks_hits == 1
    cl.exchange("code-1", _flow(fake))
    assert fake.jwks_hits == 1           # cached, not refetched per login
    fake.rotate_key()
    cl.exchange("code-1", _flow(fake))   # succeeds only because it refetched
    assert fake.jwks_hits == 2


def test_clock_skew_is_tolerated():
    fake = FakeIdP()
    fake.exp_delta = -int(CLOCK_SKEW / 2)     # just expired, inside the tolerance
    assert _client(fake).exchange("code-1", _flow(fake)).subject
    fake.exp_delta = -(CLOCK_SKEW + 120)
    with pytest.raises(OIDCError):
        _client(fake).exchange("code-1", _flow(fake))


def test_future_issued_at_is_refused():
    fake = FakeIdP()
    fake.iat_delta = CLOCK_SKEW + 600
    with pytest.raises(OIDCError):
        _client(fake).exchange("code-1", _flow(fake))


def test_missing_sub_is_refused():
    fake = FakeIdP()
    fake.claims.pop("sub")
    with pytest.raises(OIDCError):
        _client(fake).exchange("code-1", _flow(fake))


def test_azp_is_checked_for_multi_audience_tokens():
    fake = FakeIdP()
    fake.aud_override = [CLIENT_ID, "another-client"]
    fake.claims["azp"] = "another-client"
    with pytest.raises(OIDCError):
        _client(fake).exchange("code-1", _flow(fake))
    fake.claims["azp"] = CLIENT_ID
    assert _client(fake).exchange("code-1", _flow(fake)).subject


def test_end_session_url():
    fake = FakeIdP()
    url = _client(fake).end_session_url("https://app.test/bye/", "idtok")
    assert url.startswith("https://accounts.example.test/logout?")
    assert "id_token_hint=idtok" in url and "post_logout_redirect_uri" in url


def test_client_cache_keys_on_settings(settings):
    reset_client_cache()
    first = get_client()
    assert get_client() is first
    settings.TG11_OIDC_CLIENT_ID = "another"
    assert get_client() is not first
    reset_client_cache()


# ---- claims ------------------------------------------------------------
@pytest.mark.parametrize("state,active", [("", True), ("active", True), ("suspended", False), ("limited", False)])
def test_account_state(state, active):
    assert Claims(subject="s", account_state=state).is_active_account is active


# ---- the linking rules, directly --------------------------------------
User = get_user_model()
pytestmark_db = pytest.mark.django_db


@pytest.mark.django_db
def test_resolve_creates_then_reuses():
    claims = Claims(subject="sub-1", email="a@b.test", email_verified=True, preferred_username="ab")
    user, created, link = services.resolve_user(claims)
    assert created and link.migration_source == MigrationSource.OIDC_LOGIN
    again_user, again_created, _ = services.resolve_user(claims)
    assert again_user.pk == user.pk and not again_created
    assert TG11IdentityLink.objects.count() == 1


@pytest.mark.django_db
def test_resolve_refuses_unverified_email_match():
    User.objects.create_user("x", email="a@b.test", password="pw")
    with pytest.raises(services.LinkRequired):
        services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=False))
    assert not TG11IdentityLink.objects.exists()


@pytest.mark.django_db
def test_resolve_matches_email_case_insensitively():
    existing = User.objects.create_user("x", email="Mixed@Case.Test", password="pw")
    user, created, link = services.resolve_user(Claims(subject="sub-1", email="mixed@case.test", email_verified=True))
    assert user.pk == existing.pk and not created
    assert link.migration_source == MigrationSource.VERIFIED_EMAIL


@pytest.mark.django_db
def test_resolve_refuses_inactive_local_user():
    existing = User.objects.create_user("x", email="a@b.test", password="pw")
    services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=True))
    existing.is_active = False
    existing.save()
    with pytest.raises(services.AccountDisabled):
        services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=True))


@pytest.mark.django_db
def test_resolve_refuses_suspended_tg11_account():
    with pytest.raises(services.AccountDisabled):
        services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=True, account_state="suspended"))
    assert not User.objects.exists()


@pytest.mark.django_db
def test_require_active_state_can_be_relaxed(settings):
    settings.TG11_AUTH_REQUIRE_ACTIVE_STATE = False
    user, created, _ = services.resolve_user(
        Claims(subject="sub-1", email="a@b.test", email_verified=True, account_state="limited"))
    assert created and user.pk


@pytest.mark.django_db
def test_created_users_cannot_log_in_with_a_password():
    user, _, _ = services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=True))
    assert not user.has_usable_password()


@pytest.mark.django_db
def test_username_collisions_are_resolved():
    User.objects.create_user("ab", email="other@b.test", password="pw")
    user, _, _ = services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=True, preferred_username="ab"))
    assert user.get_username() != "ab"


@pytest.mark.django_db
def test_explicit_link_then_unlink():
    user = User.objects.create_user("x", email="local@b.test", password="pw")
    claims = Claims(subject="sub-9", email="tg11@b.test", email_verified=True)
    link = services.link_to_current_user(user, claims)
    assert link.migration_source == MigrationSource.ACCOUNT_LINK and link.verified
    assert services.resolve_user(claims)[0].pk == user.pk      # now the sub wins
    assert services.unlink(user) is True
    assert not TG11IdentityLink.objects.exists()


@pytest.mark.django_db
def test_explicit_link_refuses_a_second_identity():
    user = User.objects.create_user("x", email="local@b.test", password="pw")
    services.link_to_current_user(user, Claims(subject="sub-9", email="a@b.test", email_verified=True))
    with pytest.raises(services.AuthError):
        services.link_to_current_user(user, Claims(subject="sub-10", email="a@b.test", email_verified=True))


@pytest.mark.django_db
def test_application_id_is_stamped(settings):
    settings.TG11_APPLICATION = "freeparty"
    settings.TG11_AUTH_FEDERATION_ID = "fed-7"
    _, _, link = services.resolve_user(Claims(subject="sub-1", email="a@b.test", email_verified=True))
    assert link.application == "freeparty" and link.federation_id == "fed-7"
    assert conf.application() == "freeparty"


# ---- packaging ----------------------------------------------------------
def test_migrations_are_a_package_and_discovered():
    """The app's migration must ship and be found; a missing
    migrations/__init__.py makes Django silently report 'no migrations' and the
    link table never gets created."""
    import importlib
    from django.db.migrations.loader import MigrationLoader

    importlib.import_module("tg11_auth.migrations")
    loader = MigrationLoader(None, ignore_no_migrations=True)
    assert ("tg11_auth", "0001_initial") in loader.disk_migrations


@pytest.mark.django_db
def test_no_model_changes_are_unmigrated():
    from django.core.management import call_command
    call_command("makemigrations", "tg11_auth", "--check", "--dry-run", verbosity=0)
