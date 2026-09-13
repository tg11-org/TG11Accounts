# SPDX-License-Identifier: AGPL-3.0-or-later
from django.apps import AppConfig


class CustomUserConfig(AppConfig):
    name = "tests.customuser"
    label = "customuser"
    default_auto_field = "django.db.models.BigAutoField"
