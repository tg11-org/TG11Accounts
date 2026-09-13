# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
from __future__ import annotations

from django.apps import AppConfig


class TG11AuthConfig(AppConfig):
    name = "tg11_auth"
    label = "tg11_auth"
    verbose_name = "TG11 identity"
    default_auto_field = "django.db.models.BigAutoField"
