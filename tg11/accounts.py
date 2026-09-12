# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""User accounts: registration, login, sessions, verification, password reset."""
from __future__ import annotations

import logging
import re
import secrets
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import ActionToken, User, UserSession, utcnow
from .passwords import hash_password, needs_rehash, verify_password
from .tokens import generate_token, hash_token

USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
log = logging.getLogger("tg11.accounts")


class AccountError(Exception):
    pass


def norm_email(e: str) -> str:
    return (e or "").strip().lower()


def norm_username(u: str) -> str:
    return (u or "").strip().lower()


def by_email(db: Session, email: str) -> Optional[User]:
    return db.scalar(select(User).where(User.email == norm_email(email)))


def by_username(db: Session, username: str) -> Optional[User]:
    return db.scalar(select(User).where(User.username == norm_username(username)))


def validate_password(pw: str) -> None:
    if len(pw or "") < 10:
        raise AccountError("Password must be at least 10 characters.")


def create_user(db: Session, *, email: str, username: str, password: Optional[str], display_name: str = "", verified: bool = False, staff: bool = False) -> User:
    email, username = norm_email(email), norm_username(username)
    if not EMAIL_RE.match(email):
        raise AccountError("Enter a valid email address.")
    if not USERNAME_RE.match(username):
        raise AccountError("Username: 3-30 lowercase letters, digits, underscore or dot.")
    if by_email(db, email):
        raise AccountError("An account with that email already exists.")
    if by_username(db, username):
        raise AccountError("That username is taken.")
    if password is not None:
        validate_password(password)
    u = User(email=email, username=username, display_name=(display_name or username)[:80], password_hash=hash_password(password) if password else None, is_staff=staff,
             email_verified_at=utcnow() if verified else None, state="active" if (verified or not settings.TG11_REQUIRE_EMAIL_VERIFICATION) else "pending_verification")
    db.add(u)
    db.flush()
    return u


def authenticate(db: Session, identifier: str, password: str) -> Optional[User]:
    ident = (identifier or "").strip().lower()
    u = by_email(db, ident) if "@" in ident else by_username(db, ident)
    if u is None or not u.is_active or not u.password_hash:
        verify_password(password, hash_password("timing-equaliser"))
        return None
    if not verify_password(password, u.password_hash):
        return None
    if needs_rehash(u.password_hash):
        u.password_hash = hash_password(password)
    u.last_login_at = utcnow()
    return u


def create_session(db: Session, user: User, ua: str = "", ip: str = "") -> UserSession:
    s = UserSession(user_id=user.id, csrf_token=secrets.token_urlsafe(32), expires_at=utcnow() + timedelta(seconds=settings.TG11_SESSION_MAX_AGE), user_agent=ua[:255], ip_address=ip[:64])
    db.add(s)
    db.flush()
    return s


def valid_session(db: Session, sid: str) -> Optional[UserSession]:
    if not sid:
        return None
    s = db.get(UserSession, sid)
    if s is None or s.revoked_at is not None or s.expires_at < utcnow():
        return None
    return s


def revoke_session(db: Session, sid: str) -> None:
    s = db.get(UserSession, sid)
    if s is not None:
        s.revoked_at = utcnow()


# --- action tokens ------------------------------------------------------------

def issue_action(db: Session, user: User, action: str, ttl_min: int, payload: str = "") -> str:
    tok = generate_token(32)
    db.add(ActionToken(user_id=user.id, action=action, token_hash=hash_token(tok), payload=payload, expires_at=utcnow() + timedelta(minutes=ttl_min)))
    db.flush()
    return tok


def consume_action(db: Session, action: str, token: str) -> Optional[User]:
    row = db.scalar(select(ActionToken).where(ActionToken.token_hash == hash_token(token or ""), ActionToken.action == action))
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        return None
    row.used_at = utcnow()
    return db.get(User, row.user_id)


def send_mail(to: str, subject: str, body: str) -> bool:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.EMAIL_FROM, to, subject
    msg.set_content(body)
    if not settings.SMTP_HOST:
        log.warning("SMTP not configured; mail to %s: %s\n%s", to, subject, body)
        return False
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as s:
            if settings.SMTP_USE_TLS:
                s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.send_message(msg)
        return True
    except Exception as exc:  # pragma: no cover
        log.error("mail failed: %s", exc)
        return False


def send_verification(db: Session, user: User) -> None:
    tok = issue_action(db, user, "verify_email", 60 * 24)
    send_mail(user.email, f"{settings.TG11_SITE_NAME}: verify your email", f"Hi {user.username},\n\nConfirm your TG11 account email by opening:\n\n{settings.issuer}/verify/{tok}\n\nThe link is valid for 24 hours.\n")


def send_reset(db: Session, user: User) -> None:
    tok = issue_action(db, user, "reset_password", 60)
    send_mail(user.email, f"{settings.TG11_SITE_NAME}: reset your password", f"Hi {user.username},\n\nReset your TG11 password within 60 minutes:\n\n{settings.issuer}/password/reset/{tok}\n\nIf you did not request this, ignore this email.\n")
