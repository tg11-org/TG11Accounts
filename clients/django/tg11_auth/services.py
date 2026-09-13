# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Claims → local user.  This is the security-critical half of the client.

The rules, in order, and why:

1. **A link for this `sub` exists** → that local user. The `sub` is the only
   identifier we trust; email and username change.
2. **No link, but a local account has the same email AND the provider asserts
   `email_verified`** → link them (`verified_email`). The provider proving
   control of the address is what makes this safe.
3. **No link, a local account has the same email, but the email is NOT
   verified** → refuse. `LinkRequired` is raised and the user is asked to sign
   in locally and link from their settings. Never merge on an unverified
   address: anyone could register that address at the IdP and walk into the
   account.
4. **Nothing matches** → create a local account (`oidc_login`), or refuse if the
   application has auto-creation switched off.

Suspended or limited TG11 accounts are refused before any of this when the
`account_state` claim is present.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional, Tuple

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from . import conf
from .client import Claims
from .models import MigrationSource, MigrationStatus, TG11IdentityLink

log = logging.getLogger("tg11_auth")


class AuthError(Exception):
    """Refused - the message is safe to show the user."""


class LinkRequired(AuthError):
    """A local account with this email exists but ownership is not proven.

    The view turns this into "sign in and link from your settings" rather than
    creating a duplicate or taking over the account.
    """

    def __init__(self, email: str):
        self.email = email
        super().__init__(
            f"An account with {email} already exists here. Sign in to it the usual way, "
            "then link TG11 from your account settings - we will not merge accounts automatically."
        )


class AccountDisabled(AuthError):
    pass


def _user_by_email(email: str):
    User = get_user_model()
    if not email:
        return None
    field = getattr(User, "EMAIL_FIELD", "email")
    if not hasattr(User, field) and not any(f.name == field for f in User._meta.fields):
        return None
    return User._default_manager.filter(**{f"{field}__iexact": email}).order_by("pk").first()


def _unique_username(base: str) -> str:
    """Only used when the local model has a username field (many do not)."""
    User = get_user_model()
    field = getattr(User, "USERNAME_FIELD", "username")
    base = (base or "user").strip().lower()[:24] or "user"
    candidate, n = base, 1
    while User._default_manager.filter(**{field: candidate}).exists():
        n += 1
        candidate = f"{base}{n}"[:30]
    return candidate


def create_local_user(claims: Claims):
    """Create an account for a TG11 identity that has none here yet.

    SSO-only: the local password is left unusable, so the only way in is TG11
    until the user sets one.
    """
    User = get_user_model()
    username_field = getattr(User, "USERNAME_FIELD", "username")
    email_field = getattr(User, "EMAIL_FIELD", "email")
    fields: Dict[str, Any] = {}
    if email_field:
        fields[email_field] = claims.email
    if username_field and username_field != email_field:
        fields[username_field] = _unique_username(claims.preferred_username or (claims.email.split("@")[0] if claims.email else ""))
    for optional, value in (("display_name", claims.name), ("first_name", (claims.name or "").split(" ")[0])):
        if any(f.name == optional for f in User._meta.fields) and value:
            fields.setdefault(optional, value[:80])
    user = User(**fields)
    user.set_unusable_password()
    if any(f.name == "email_verified_at" for f in User._meta.fields) and claims.email_verified:
        user.email_verified_at = timezone.now()
    if any(f.name == "state" for f in User._meta.fields):
        user.state = "active"
    user.full_clean(exclude=[f.name for f in User._meta.fields if f.name not in fields])
    user.save()
    return user


@transaction.atomic
def resolve_user(claims: Claims, *, request=None) -> Tuple[Any, bool, TG11IdentityLink]:
    """(user, created, link) for a completed OIDC login.  Raises AuthError."""
    if conf.require_active_state() and not claims.is_active_account:
        raise AccountDisabled(f"That TG11 account is {claims.account_state}; sign in at the TG11 account page to resolve it.")

    app = conf.application()
    link = TG11IdentityLink.objects.select_related("user").filter(subject=claims.subject, application=app).first()
    if link is not None:
        if link.migration_status == MigrationStatus.REVOKED:
            raise AuthError("That TG11 link was revoked here. Link it again from your account settings.")
        user = link.user
        if not getattr(user, "is_active", True):
            raise AccountDisabled("That account is disabled here.")
        _refresh_snapshot(link, claims)
        link.touch()
        _run_hook(user=user, claims=claims, created=False, link=link, request=request)
        return user, False, link

    existing = _user_by_email(claims.email)
    if existing is not None:
        if not (claims.email_verified and conf.autolink_verified_email()):
            raise LinkRequired(claims.email)
        if TG11IdentityLink.objects.filter(user=existing).exists():
            raise AuthError("That account is already linked to a different TG11 identity.")
        link = _make_link(existing, claims, MigrationSource.VERIFIED_EMAIL)
        log.info("tg11_auth: linked existing local account by verified email (app=%s sub=%s)", app, claims.subject)
        _run_hook(user=existing, claims=claims, created=False, link=link, request=request)
        return existing, False, link

    if not conf.autocreate():
        raise AuthError("No account here matches that TG11 identity, and self-registration is disabled.")

    user = create_local_user(claims)
    link = _make_link(user, claims, MigrationSource.OIDC_LOGIN)
    log.info("tg11_auth: created local account for new TG11 identity (app=%s sub=%s)", app, claims.subject)
    _run_hook(user=user, claims=claims, created=True, link=link, request=request)
    return user, True, link


@transaction.atomic
def link_to_current_user(user, claims: Claims, *, request=None) -> TG11IdentityLink:
    """Explicit linking: the user is already signed in locally and proved who
    they are here, so no email matching is needed."""
    if conf.require_active_state() and not claims.is_active_account:
        raise AccountDisabled(f"That TG11 account is {claims.account_state}.")
    app = conf.application()
    clash = TG11IdentityLink.objects.filter(subject=claims.subject, application=app).exclude(user=user).first()
    if clash is not None:
        raise AuthError("That TG11 identity is already linked to another account here.")
    existing = TG11IdentityLink.objects.filter(user=user).first()
    if existing is not None and existing.subject != claims.subject:
        raise AuthError("This account is already linked to a different TG11 identity. Unlink it first.")
    link = existing or TG11IdentityLink(user=user, application=app)
    link.subject = claims.subject
    link.migration_source = MigrationSource.ACCOUNT_LINK
    link.migration_status = MigrationStatus.LINKED
    link.verified = True
    _refresh_snapshot(link, claims, save=False)
    link.legacy_local_id = link.legacy_local_id or str(user.pk)
    link.linked_at = link.linked_at or timezone.now()
    link.save()
    _run_hook(user=user, claims=claims, created=False, link=link, request=request)
    return link


def unlink(user) -> bool:
    """Remove the link.  Callers must check the user can still sign in
    afterwards (a usable password or another method) before calling this."""
    deleted, _ = TG11IdentityLink.objects.filter(user=user).delete()
    return bool(deleted)


def _make_link(user, claims: Claims, source: str) -> TG11IdentityLink:
    link = TG11IdentityLink(
        user=user,
        subject=claims.subject,
        issuer=str(conf.get("TG11_OIDC_ISSUER", "") or ""),
        application=conf.application(),
        legacy_local_id=str(user.pk),
        local_uuid=str(user.pk) if isinstance(user.pk, uuid.UUID) else "",
        federation_id=conf.federation_id(),
        migration_source=source,
        migration_status=MigrationStatus.LINKED,
        verified=True,
        last_login_at=timezone.now(),
    )
    _refresh_snapshot(link, claims, save=False)
    link.save()
    return link


def _refresh_snapshot(link: TG11IdentityLink, claims: Claims, *, save: bool = True) -> None:
    link.email_at_link = claims.email[:254]
    link.username_at_link = (claims.preferred_username or "")[:150]
    if save:
        link.save(update_fields=["email_at_link", "username_at_link"])


def _run_hook(**kwargs) -> None:
    hook = conf.profile_hook()
    if hook is None:
        return
    try:
        hook(**kwargs)
    except Exception:  # an application's profile hook must not break sign-in
        log.exception("tg11_auth: profile hook failed")
