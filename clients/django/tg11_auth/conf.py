# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Settings for the TG11 relying party.

Everything is read from Django settings, which should in turn read the
environment - the issuer is never hard-coded (see docs/TG11_APP_INTEGRATION.md):

    TG11_OIDC_ISSUER        https://accounts.tg11.org
    TG11_OIDC_CLIENT_ID     freeparty
    TG11_OIDC_CLIENT_SECRET …                       (omit for a public client)
    TG11_OIDC_REDIRECT_URI  https://freeparty.dev/auth/tg11/callback/
    TG11_OIDC_SCOPES        openid profile email    (default)
    TG11_APPLICATION        freeparty               (stable app id in link rows)

Optional behaviour:

    TG11_AUTH_AUTOCREATE                True   create a local user for a new sub
    TG11_AUTH_AUTOLINK_VERIFIED_EMAIL   True   link to an existing local account
                                               when the IdP asserts email_verified
    TG11_AUTH_REQUIRE_ACTIVE_STATE      True   refuse suspended/limited TG11 accounts
    TG11_AUTH_PROFILE_HOOK              ""     "myapp.auth.on_tg11_login"
    TG11_AUTH_LOGIN_GUARD               ""     "myapp.auth.refuse_if_local_2fa"
    TG11_AUTH_LOGIN_REDIRECT            LOGIN_REDIRECT_URL
    TG11_AUTH_POST_LOGOUT_REDIRECT      "/"
    TG11_AUTH_FEDERATION_ID             ""     stamped on link rows (FurryParty…)
"""
from __future__ import annotations

from typing import Any, Optional

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

DEFAULT_SCOPES = "openid profile email"


def get(name: str, default: Any = None) -> Any:
    return getattr(settings, name, default)


def required(name: str) -> str:
    value = get(name, "")
    if not value:
        raise ImproperlyConfigured(f"{name} must be set to use TG11 authentication")
    return str(value)


def is_configured() -> bool:
    """Templates use this to decide whether to show the button at all."""
    return bool(get("TG11_OIDC_ISSUER") and get("TG11_OIDC_CLIENT_ID"))


def application() -> str:
    return str(get("TG11_APPLICATION") or get("TG11_OIDC_CLIENT_ID") or "app")


def scopes() -> str:
    return str(get("TG11_OIDC_SCOPES") or DEFAULT_SCOPES)


def autocreate() -> bool:
    return bool(get("TG11_AUTH_AUTOCREATE", True))


def autolink_verified_email() -> bool:
    return bool(get("TG11_AUTH_AUTOLINK_VERIFIED_EMAIL", True))


def require_active_state() -> bool:
    return bool(get("TG11_AUTH_REQUIRE_ACTIVE_STATE", True))


def federation_id() -> str:
    return str(get("TG11_AUTH_FEDERATION_ID") or "")


def login_redirect() -> str:
    return str(get("TG11_AUTH_LOGIN_REDIRECT") or get("LOGIN_REDIRECT_URL") or "/")


def post_logout_redirect() -> str:
    return str(get("TG11_AUTH_POST_LOGOUT_REDIRECT") or "/")


def login_guard() -> Optional[Any]:
    """Callable the application supplies to veto a TG11 sign-in:

        def refuse_if_local_2fa(user, claims): ...   # raise AuthError to refuse
    """
    path = get("TG11_AUTH_LOGIN_GUARD") or ""
    return import_string(path) if path else None


def profile_hook() -> Optional[Any]:
    """Callable the application supplies to map claims onto its own profile:

        def on_tg11_login(*, user, claims, created, link, request): ...
    """
    path = get("TG11_AUTH_PROFILE_HOOK") or ""
    return import_string(path) if path else None
