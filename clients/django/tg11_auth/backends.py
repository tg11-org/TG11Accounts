# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""A backend that exists only so Django can remember *how* a session was
authenticated.

It deliberately never authenticates anybody: `authenticate()` always returns
None, so no password or credential path can ever go through TG11.  The views
establish the identity themselves (signature-checked ID token, then the linking
rules in services.py) and then call `login()` naming this backend.

Add it to AUTHENTICATION_BACKENDS alongside whatever the application already
uses::

    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "tg11_auth.backends.TG11Backend",
    ]

If it is absent, the views fall back to the application's existing backend, so
an app can adopt TG11 without touching that setting.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

BACKEND_PATH = "tg11_auth.backends.TG11Backend"


class TG11Backend(BaseBackend):
    def authenticate(self, request, **kwargs):  # noqa: D401 - never authenticates
        return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            user = User._default_manager.get(pk=user_id)
        except (User.DoesNotExist, ValueError, TypeError):
            return None
        return user if getattr(user, "is_active", True) else None
