# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Password hashing compatible with Django's `pbkdf2_sha256` hasher.

Format: ``pbkdf2_sha256$<iterations>$<salt>$<base64 hash>``

Using the Django format means a Flowboard password hash can be imported into
the future TG11 accounts service (Django based, like FreeParty/Shop) verbatim
when accounts are linked/migrated - no forced password reset.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 870_000  # Django 5.1 default
SALT_LEN = 22


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_urlsafe(SALT_LEN)[:SALT_LEN].replace("$", "x")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"{ALGORITHM}${iterations}${salt}${base64.b64encode(digest).decode().strip()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded or not password:
        return False
    try:
        algorithm, iterations, salt, b64hash = encoded.split("$", 3)
    except ValueError:
        return False
    if algorithm != ALGORITHM:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
    return hmac.compare_digest(base64.b64encode(digest).decode().strip(), b64hash)


def needs_rehash(encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, iterations, _salt, _h = encoded.split("$", 3)
    except ValueError:
        return True
    return algorithm != ALGORITHM or int(iterations) < ITERATIONS
