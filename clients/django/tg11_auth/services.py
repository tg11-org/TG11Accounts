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
import re
import uuid
from typing import Any, Dict, Optional, Tuple

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
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


USERNAME_SAFE = re.compile(r"[^a-z0-9_]+")


def _max_length(field_name: str, default: int = 30) -> int:
    User = get_user_model()
    try:
        return getattr(User._meta.get_field(field_name), "max_length", None) or default
    except Exception:
        return default


def _unique_username(base: str, field: str = "username") -> str:
    """A handle the local model will actually accept.

    Applications validate usernames (FreeParty's regex, the length limits), and
    some of them build other things out of it - FreeParty mints an ActivityPub
    actor from it on first save - so it is sanitised to [a-z0-9_], trimmed to
    the field's real max_length, and made unique with a numeric suffix.
    """
    User = get_user_model()
    limit = _max_length(field)
    base = USERNAME_SAFE.sub("", (base or "").strip().lower()) or "tg11user"
    base = base[: max(1, limit - 3)]
    candidate, n = base, 1
    while User._default_manager.filter(**{field: candidate}).exists():
        n += 1
        suffix = str(n)
        candidate = f"{base[: limit - len(suffix)]}{suffix}"
    return candidate


def create_local_user(claims: Claims):
    """Create an account for a TG11 identity that has none here yet.

    SSO-only: the local password is left unusable, so the only way in is TG11
    until the user sets one.

    Local models differ more than you would hope - `USERNAME_FIELD` may be
    `email` (FreeParty, Shop) or `username` (stock Django), and `REQUIRED_FIELDS`
    may demand a handle on top of that - so every required field is filled
    before validating, and a model we cannot satisfy raises AuthError rather
    than a 500.
    """
    User = get_user_model()
    username_field = getattr(User, "USERNAME_FIELD", "username")
    email_field = getattr(User, "EMAIL_FIELD", "email")
    names = {f.name for f in User._meta.fields}
    fields: Dict[str, Any] = {}

    if email_field and email_field in names:
        fields[email_field] = claims.email
    handle_seed = claims.preferred_username or (claims.email.split("@")[0] if claims.email else "")
    if username_field and username_field != email_field and username_field in names:
        fields[username_field] = _unique_username(handle_seed, username_field)

    # REQUIRED_FIELDS is what the model says it cannot live without.
    for required in list(getattr(User, "REQUIRED_FIELDS", []) or []):
        if required in fields or required not in names:
            continue
        if required in ("username", "handle", "nickname", "slug"):
            fields[required] = _unique_username(handle_seed, required)
        elif required in ("email", "email_address"):
            fields[required] = claims.email
        elif required in ("first_name", "name", "display_name", "full_name"):
            fields[required] = (claims.name or handle_seed)[: _max_length(required, 80)]
        else:
            raise AuthError(
                f"This application's account model requires '{required}', which TG11 cannot supply. "
                "Sign up here first, then link TG11 from your account settings."
            )

    for optional, value in (("display_name", claims.name), ("first_name", (claims.name or "").split(" ")[0])):
        if optional in names and value:
            fields.setdefault(optional, value[: _max_length(optional, 80)])

    user = User(**fields)
    user.set_unusable_password()
    if "email_verified_at" in names and claims.email_verified:
        user.email_verified_at = timezone.now()
        fields["email_verified_at"] = user.email_verified_at
    if "state" in names and claims.email_verified:
        # The IdP already proved the address; don't park them in a
        # pending-verification state they can never clear here.
        user.state = "active"
        fields["state"] = "active"
    try:
        user.full_clean(exclude=[n for n in names if n not in fields])
    except ValidationError as exc:
        log.warning("tg11_auth: local account model rejected a TG11 identity: %s", exc.message_dict)
        raise AuthError(
            "This application could not create an account from that TG11 profile. "
            "Sign up here first, then link TG11 from your account settings."
        )
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
        _run_guard(user, claims)
        _refresh_snapshot(link, claims)
        link.touch()
        _run_hook(user=user, claims=claims, created=False, link=link, request=request)
        return user, False, link

    existing = _user_by_email(claims.email)
    if existing is not None:
        _run_guard(existing, claims)
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


def _run_guard(user, claims: Claims) -> None:
    """An application's own veto on a TG11 sign-in.

    ``TG11_AUTH_LOGIN_GUARD`` names a callable ``(user, claims) -> None`` that
    raises ``AuthError`` to refuse. The case it exists for: an account with a
    *local* second factor. Until MFA lands at the provider, letting a single
    TG11 password stand in for password + TOTP would quietly downgrade that
    account's security, so the application refuses instead::

        def refuse_if_local_2fa(user, claims):
            if TOTPDevice.objects.filter(user=user, verified=True).exists():
                raise AuthError("This account uses two-factor authentication here …")

    Unlike the profile hook, an exception here is **not** swallowed - vetoing is
    the whole point - but a non-AuthError bug is turned into a refusal rather
    than a 500, so a broken guard fails closed.
    """
    guard = conf.login_guard()
    if guard is None:
        return
    try:
        guard(user, claims)
    except AuthError:
        raise
    except Exception:
        log.exception("tg11_auth: login guard failed; refusing the sign-in")
        raise AuthError("This application could not verify that TG11 sign-in. Please sign in the usual way.")


def _run_hook(**kwargs) -> None:
    hook = conf.profile_hook()
    if hook is None:
        return
    try:
        hook(**kwargs)
    except Exception:  # an application's profile hook must not break sign-in
        log.exception("tg11_auth: profile hook failed")
