# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""The linking rules against a custom user model (UUID pk, email as
USERNAME_FIELD, a separate required username).

Run with:  python -m pytest --ds=tests.settings_customuser tests/test_customuser.py
"""
from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from tg11_auth import services
from tg11_auth.client import Claims
from tg11_auth.models import MigrationSource, TG11IdentityLink

pytestmark = pytest.mark.django_db
User = get_user_model()


def test_the_model_under_test_is_the_custom_one():
    assert User._meta.label == "customuser.User"
    assert User.USERNAME_FIELD == "email" and "username" in User.REQUIRED_FIELDS


def test_new_identity_gets_a_valid_username_and_uuid_pk():
    import uuid
    user, created, link = services.resolve_user(
        Claims(subject="sub-1", email="new@example.test", email_verified=True,
               preferred_username="New.Person!", name="New Person"))
    assert created
    assert isinstance(user.pk, uuid.UUID)
    assert user.username == "newperson"          # sanitised to the model's validator
    assert user.email == "new@example.test"
    assert user.display_name == "New Person"
    assert not user.has_usable_password()
    assert link.migration_source == MigrationSource.OIDC_LOGIN
    assert link.local_uuid == str(user.pk)       # provenance for a UUID-keyed app
    user.full_clean(exclude=["password"])        # the model itself is happy


def test_verified_email_promotes_state_and_stamps_verification():
    user, _, _ = services.resolve_user(
        Claims(subject="sub-1", email="a@b.test", email_verified=True, preferred_username="ab"))
    assert user.state == "active"                # not parked in pending_verification
    assert user.email_verified_at is not None


def test_unverified_email_leaves_the_models_own_default():
    user, _, _ = services.resolve_user(
        Claims(subject="sub-2", email="c@d.test", email_verified=False, preferred_username="cd"))
    assert user.state == "pending_verification"
    assert user.email_verified_at is None


def test_username_collision_gets_a_suffix_within_max_length():
    User.objects.create_user(email="taken@example.test", username="ab")
    user, _, _ = services.resolve_user(
        Claims(subject="sub-3", email="other@example.test", email_verified=True, preferred_username="ab"))
    assert user.username != "ab" and len(user.username) <= 30
    assert user.username.startswith("ab")


def test_long_username_is_trimmed_to_the_field():
    user, _, _ = services.resolve_user(
        Claims(subject="sub-4", email="long@example.test", email_verified=True,
               preferred_username="x" * 80))
    assert len(user.username) <= 30


def test_existing_account_links_on_verified_email_without_touching_it():
    existing = User.objects.create_user(email="member@example.test", username="member")
    existing.set_password("pw"); existing.save()
    user, created, link = services.resolve_user(
        Claims(subject="sub-5", email="MEMBER@example.test", email_verified=True))
    assert not created and user.pk == existing.pk
    assert link.migration_source == MigrationSource.VERIFIED_EMAIL
    existing.refresh_from_db()
    assert existing.has_usable_password() and existing.username == "member"


def test_unverified_email_never_merges():
    User.objects.create_user(email="member@example.test", username="member")
    with pytest.raises(services.LinkRequired):
        services.resolve_user(Claims(subject="sub-6", email="member@example.test", email_verified=False))
    assert not TG11IdentityLink.objects.exists()
