# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="TG11IdentityLink",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("subject", models.CharField(db_index=True, max_length=64, unique=True)),
                ("issuer", models.CharField(blank=True, default="", max_length=255)),
                ("application", models.CharField(db_index=True, max_length=64)),
                ("legacy_local_id", models.CharField(blank=True, default="", max_length=64)),
                ("local_uuid", models.CharField(blank=True, default="", max_length=36)),
                ("federation_id", models.CharField(blank=True, default="", max_length=64)),
                ("email_at_link", models.CharField(blank=True, default="", max_length=254)),
                ("username_at_link", models.CharField(blank=True, default="", max_length=150)),
                ("migration_source", models.CharField(choices=[("oidc_login", "First TG11 login (new local account)"), ("verified_email", "Matched an existing account by verified email"), ("account_link", "User linked it explicitly while signed in"), ("link_token", "Migration/link token"), ("admin", "Linked by an administrator")], default="oidc_login", max_length=32)),
                ("migration_status", models.CharField(choices=[("linked", "Linked"), ("pending", "Pending confirmation"), ("revoked", "Revoked")], default="linked", max_length=16)),
                ("verified", models.BooleanField(default=True, help_text="Ownership of both sides was established")),
                ("linked_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("last_login_at", models.DateTimeField(blank=True, null=True)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="tg11_link", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "TG11 identity link",
                "verbose_name_plural": "TG11 identity links",
            },
        ),
        migrations.AddIndex(
            model_name="tg11identitylink",
            index=models.Index(fields=["application", "subject"], name="tg11_auth_app_subject_idx"),
        ),
    ]
