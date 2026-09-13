# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Mount once, anywhere::

    path("auth/tg11/", include("tg11_auth.urls")),

The callback path must match TG11_OIDC_REDIRECT_URI and the redirect URI
registered for the client at accounts.tg11.org, exactly.
"""
from __future__ import annotations

from django.urls import path

from . import views

app_name = "tg11_auth"

urlpatterns = [
    path("login/", views.login, name="login"),
    path("callback/", views.callback, name="callback"),
    path("link/", views.link, name="link"),
    path("unlink/", views.unlink, name="unlink"),
    path("logout/", views.logout, name="logout"),
]
