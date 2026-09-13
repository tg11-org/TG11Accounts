# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Read-mostly admin.  Links can be revoked, not hand-edited: a mistyped
`subject` would hand one person's account to another.
"""
from __future__ import annotations

from django.contrib import admin

from .models import MigrationStatus, TG11IdentityLink


@admin.register(TG11IdentityLink)
class TG11IdentityLinkAdmin(admin.ModelAdmin):
    list_display = ("user", "application", "subject", "migration_source", "migration_status", "linked_at", "last_login_at")
    list_filter = ("application", "migration_source", "migration_status", "verified")
    search_fields = ("subject", "email_at_link", "username_at_link", "legacy_local_id")
    readonly_fields = tuple(f.name for f in TG11IdentityLink._meta.fields if f.name != "migration_status")
    ordering = ("-linked_at",)
    actions = ("revoke_links",)

    def has_add_permission(self, request):  # links are created by the login flow
        return False

    @admin.action(description="Revoke selected links (the user must link again)")
    def revoke_links(self, request, queryset):
        updated = queryset.update(migration_status=MigrationStatus.REVOKED)
        self.message_user(request, f"{updated} link(s) revoked.")
