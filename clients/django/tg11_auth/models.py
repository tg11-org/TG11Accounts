# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""The one table every TG11 application gains.

A link says: *this local account is that TG11 identity*.  It is deliberately
one-to-one in both directions - a local account maps to at most one `sub`, and
a `sub` to at most one local account per application - so a login can never
silently land on someone else's data.  Legacy ids are kept next to it so an
application that used integer primary keys can still prove which row a migrated
user came from.
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class MigrationSource(models.TextChoices):
    OIDC_LOGIN = "oidc_login", "First TG11 login (new local account)"
    VERIFIED_EMAIL = "verified_email", "Matched an existing account by verified email"
    ACCOUNT_LINK = "account_link", "User linked it explicitly while signed in"
    LINK_TOKEN = "link_token", "Migration/link token"
    ADMIN = "admin", "Linked by an administrator"


class MigrationStatus(models.TextChoices):
    LINKED = "linked", "Linked"
    PENDING = "pending", "Pending confirmation"
    REVOKED = "revoked", "Revoked"


class TG11IdentityLink(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tg11_link")

    #: the TG11 user UUID - the `sub` claim, stable across every service
    subject = models.CharField(max_length=64, unique=True, db_index=True)
    issuer = models.CharField(max_length=255, blank=True, default="")
    #: stable application identifier: freeparty, furryparty, shop, echoquill, foxpay…
    application = models.CharField(max_length=64, db_index=True)

    #: provenance for migrations and audits
    legacy_local_id = models.CharField(max_length=64, blank=True, default="")
    local_uuid = models.CharField(max_length=36, blank=True, default="")
    federation_id = models.CharField(max_length=64, blank=True, default="")
    email_at_link = models.CharField(max_length=254, blank=True, default="")
    username_at_link = models.CharField(max_length=150, blank=True, default="")

    migration_source = models.CharField(max_length=32, choices=MigrationSource.choices, default=MigrationSource.OIDC_LOGIN)
    migration_status = models.CharField(max_length=16, choices=MigrationStatus.choices, default=MigrationStatus.LINKED)
    verified = models.BooleanField(default=True, help_text="Ownership of both sides was established")

    linked_at = models.DateTimeField(default=timezone.now)
    last_login_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "TG11 identity link"
        verbose_name_plural = "TG11 identity links"
        indexes = [models.Index(fields=["application", "subject"], name="tg11_auth_app_subject_idx")]

    def __str__(self) -> str:  # pragma: no cover - admin convenience
        return f"{self.application}:{self.user_id} → {self.subject}"

    @property
    def is_active(self) -> bool:
        return self.migration_status == MigrationStatus.LINKED

    def touch(self) -> None:
        self.last_login_at = timezone.now()
        self.save(update_fields=["last_login_at"])
