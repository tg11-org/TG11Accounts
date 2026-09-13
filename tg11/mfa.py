# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""Second factors: TOTP (RFC 6238) and single-use recovery codes.

Design notes, because the details are what make or break this:

* The shared secret is stored **encrypted** with the same AES-256-GCM vault the
  AI keys use, with the AAD bound to the user and purpose, so a blob lifted from
  another row cannot be decrypted here.
* A device only counts once it is **confirmed** with a live code, so a failed
  enrollment can never lock anyone out.
* Codes are checked against a one-step window either side (±30 s) for clock
  drift, and the accepted step is recorded: replaying the same code inside its
  own window is refused.
* Recovery codes are stored as SHA-256 hashes, shown exactly once, and each is
  single use.
* Attempts are rate limited per user; recovery-code attempts count too.

Everything here is deliberately independent of the web layer so it can be
tested without HTTP.
"""
from __future__ import annotations

import base64
import logging
import secrets
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

import pyotp
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .crypto import get_cipher
from .models import RecoveryCode, TOTPDevice, User, utcnow
from .tokens import hash_token

log = logging.getLogger("tg11.mfa")

DIGITS = 6
PERIOD = 30
WINDOW = 1                 # ±1 step of clock drift
RECOVERY_CODES = 10
MAX_ATTEMPTS = 5           # per user, per window
ATTEMPT_WINDOW = 300       # seconds

_attempts: dict[str, list[float]] = {}


class MFAError(Exception):
    """Safe to show the user."""


def _aad(user_id: str) -> str:
    return f"tg11-totp:{user_id}"


# --- rate limiting ------------------------------------------------------------

def _record_attempt(user_id: str) -> None:
    now = time.time()
    hits = [t for t in _attempts.get(user_id, []) if now - t < ATTEMPT_WINDOW]
    hits.append(now)
    _attempts[user_id] = hits


def attempts_left(user_id: str) -> int:
    now = time.time()
    hits = [t for t in _attempts.get(user_id, []) if now - t < ATTEMPT_WINDOW]
    _attempts[user_id] = hits
    return max(0, MAX_ATTEMPTS - len(hits))


def clear_attempts(user_id: str) -> None:
    _attempts.pop(user_id, None)


def _check_rate(user: User) -> None:
    if attempts_left(user.id) <= 0:
        raise MFAError("Too many incorrect codes. Wait a few minutes and try again.")


# --- devices ------------------------------------------------------------------

def device_for(db: Session, user: User, *, confirmed_only: bool = True) -> Optional[TOTPDevice]:
    q = select(TOTPDevice).where(TOTPDevice.user_id == user.id)
    if confirmed_only:
        q = q.where(TOTPDevice.confirmed_at.is_not(None))
    return db.scalar(q)


def has_mfa(db: Session, user: User) -> bool:
    return device_for(db, user) is not None


def _secret_of(device: TOTPDevice) -> str:
    return get_cipher().decrypt_json(device.secret_blob, _aad(device.user_id))["secret"]


def provision(db: Session, user: User, label: str = "Authenticator") -> Tuple[TOTPDevice, str, str]:
    """Create (or replace) an *unconfirmed* device. Returns (device, secret, otpauth URI).

    An existing confirmed device is left alone - re-enrolling must go through
    `disable()` first, so nobody can quietly swap the second factor on an
    account they have merely borrowed a session for.
    """
    if has_mfa(db, user):
        raise MFAError("Two-factor authentication is already enabled on this account.")
    existing = device_for(db, user, confirmed_only=False)
    if existing is not None:
        db.delete(existing)
        db.flush()
    secret = pyotp.random_base32()
    blob, ver = get_cipher().encrypt_json({"secret": secret}, _aad(user.id))
    device = TOTPDevice(user_id=user.id, label=(label or "Authenticator")[:64], secret_blob=blob, key_version=ver)
    db.add(device)
    db.flush()
    return device, secret, otpauth_uri(user, secret)


def otpauth_uri(user: User, secret: str) -> str:
    issuer = quote(settings.TG11_SITE_NAME)
    account = quote(f"{user.username}@tg11")
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"


def qr_svg(uri: str) -> str:
    """Inline SVG for the enrollment page - no image files, no CDN, no PIL."""
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    from io import BytesIO

    buf = BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def _verify_totp(device: TOTPDevice, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return False
    totp = pyotp.TOTP(_secret_of(device), digits=DIGITS, interval=PERIOD)
    now = int(time.time())
    for offset in range(-WINDOW, WINDOW + 1):
        step = now // PERIOD + offset
        if secrets.compare_digest(totp.at(step * PERIOD), code):
            if device.last_used_step and step <= device.last_used_step:
                return False  # already used: no replay inside the window
            device.last_used_step = step
            return True
    return False


def confirm(db: Session, user: User, code: str) -> List[str]:
    """Finish enrollment. Returns the recovery codes, which are shown once."""
    device = device_for(db, user, confirmed_only=False)
    if device is None:
        raise MFAError("Start the setup again - there is nothing to confirm.")
    if device.confirmed_at is not None:
        raise MFAError("Two-factor authentication is already enabled.")
    _check_rate(user)
    if not _verify_totp(device, code):
        _record_attempt(user.id)
        raise MFAError("That code did not match. Check your device's clock and try the current code.")
    clear_attempts(user.id)
    device.confirmed_at = utcnow()
    codes = regenerate_recovery_codes(db, user)
    log.info("tg11.mfa: TOTP enabled (user=%s)", user.id)
    return codes


def verify(db: Session, user: User, code: str) -> str:
    """Check a login code. Returns "otp" or "recovery"; raises MFAError.

    Recovery codes are accepted here too, so a person who has lost their phone
    still has one honest way in.
    """
    _check_rate(user)
    device = device_for(db, user)
    if device is not None and _verify_totp(device, code):
        clear_attempts(user.id)
        device.last_used_at = utcnow()
        return "otp"
    if consume_recovery_code(db, user, code):
        clear_attempts(user.id)
        log.info("tg11.mfa: recovery code used (user=%s)", user.id)
        return "recovery"
    _record_attempt(user.id)
    raise MFAError("That code was not accepted.")


def disable(db: Session, user: User) -> bool:
    """Remove every second factor. The caller must have re-authenticated."""
    removed = False
    for device in db.scalars(select(TOTPDevice).where(TOTPDevice.user_id == user.id)):
        db.delete(device)
        removed = True
    for row in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id)):
        db.delete(row)
    clear_attempts(user.id)
    if removed:
        log.info("tg11.mfa: TOTP disabled (user=%s)", user.id)
    return removed


# --- recovery codes -----------------------------------------------------------

def _format_code(raw: bytes) -> str:
    body = base64.b32encode(raw).decode().rstrip("=").lower()[:10]
    return f"{body[:5]}-{body[5:]}"


def regenerate_recovery_codes(db: Session, user: User, count: int = RECOVERY_CODES) -> List[str]:
    for row in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id)):
        db.delete(row)
    codes = [_format_code(secrets.token_bytes(8)) for _ in range(count)]
    for code in codes:
        db.add(RecoveryCode(user_id=user.id, code_hash=hash_token(code)))
    db.flush()
    return codes


def recovery_codes_left(db: Session, user: User) -> int:
    return len(list(db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)))))


def consume_recovery_code(db: Session, user: User, code: str) -> bool:
    candidate = (code or "").strip().lower().replace(" ", "")
    if not candidate:
        return False
    if len(candidate) == 10 and "-" not in candidate:
        candidate = f"{candidate[:5]}-{candidate[5:]}"
    row = db.scalar(select(RecoveryCode).where(
        RecoveryCode.user_id == user.id,
        RecoveryCode.code_hash == hash_token(candidate),
        RecoveryCode.used_at.is_(None),
    ))
    if row is None:
        return False
    row.used_at = utcnow()
    return True
