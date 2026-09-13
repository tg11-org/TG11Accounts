# SPDX-License-Identifier: AGPL-3.0-or-later
"""A user model shaped like FreeParty's and Shop's: UUID primary key, email as
the USERNAME_FIELD, a *separate* required username with a validator, and an
account state machine. This is the shape that broke the first version of
create_local_user, so it is worth a suite of its own."""
from __future__ import annotations

import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.db import models

USERNAME_VALIDATOR = RegexValidator(r"^[a-zA-Z0-9_]+$", "Letters, numbers and underscores only.")


class UserManager(BaseUserManager):
    def create_user(self, email, username="", password=None, **extra):
        user = self.model(email=self.normalize_email(email), username=username or email.split("@")[0], **extra)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    class AccountState(models.TextChoices):
        ACTIVE = "active", "Active"
        PENDING_VERIFICATION = "pending_verification", "Pending Verification"
        LIMITED = "limited", "Limited"
        SUSPENDED = "suspended", "Suspended"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=30, unique=True, validators=[USERNAME_VALIDATOR])
    display_name = models.CharField(max_length=80, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    state = models.CharField(max_length=32, choices=AccountState.choices, default=AccountState.PENDING_VERIFICATION)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
