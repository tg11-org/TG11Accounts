# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""Identity data model.  Deliberately mirrors FreeParty's `accounts.User`
(the canonical TG11 account shape) so rows can later be migrated between the
Django applications and this service without transformation.

Identity only: no application data lives here.  Applications keep their own
profile tables keyed on `users.id` (the OIDC `sub`).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)  # OIDC `sub`, stable forever
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Django pbkdf2_sha256 format
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_staff: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # active|pending_verification|limited|suspended
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    # reserved for future MFA: totp_secret (encrypted), passkeys live in their own tables later

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    user_agent: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), default="", nullable=False)


class ActionToken(Base):
    """Email verification / password reset tokens (hashed)."""

    __tablename__ = "action_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # verify_email|reset_password
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    client_secret_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # None => public client (PKCE only)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    application: Mapped[str] = mapped_column(String(64), nullable=False)  # stable app identifier: flowboard, freeparty, shop...
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False)  # newline separated, exact match
    post_logout_redirect_uris: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed_scopes: Mapped[str] = mapped_column(String(255), default="openid profile email", nullable=False)
    trusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # first-party: skip consent screen
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    @property
    def redirect_uri_list(self):
        return [u.strip() for u in self.redirect_uris.splitlines() if u.strip()]

    @property
    def post_logout_uri_list(self):
        return [u.strip() for u in self.post_logout_redirect_uris.splitlines() if u.strip()]


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id: Mapped[str] = mapped_column(String(36), default="", nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    nonce: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(String(8), default="", nullable=False)
    auth_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Token(Base):
    """Access + refresh tokens (opaque, stored hashed)."""

    __tablename__ = "tokens"
    __table_args__ = (Index("ix_tokens_user_client", "user_id", "client_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)  # access|refresh
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(36), default="", nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # refresh token that minted this access token
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Consent(Base):
    __tablename__ = "consents"
    __table_args__ = (UniqueConstraint("user_id", "client_id", name="uq_consent_user_client"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class ApplicationIdentityLink(Base):
    """Legacy account mapping: which local account in which application this
    TG11 identity corresponds to (for migrations/auditing)."""

    __tablename__ = "application_identity_links"
    __table_args__ = (UniqueConstraint("application", "legacy_id", "federation_id", name="uq_app_legacy"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    application: Mapped[str] = mapped_column(String(64), nullable=False)
    legacy_id: Mapped[str] = mapped_column(String(64), nullable=False)  # original local user id (int or uuid, as text)
    local_uuid: Mapped[str] = mapped_column(String(36), default="", nullable=False)
    federation_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    migration_source: Mapped[str] = mapped_column(String(32), default="link", nullable=False)  # verified_email|link_token|admin
    migration_status: Mapped[str] = mapped_column(String(16), default="linked", nullable=False)
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class SigningKey(Base):
    __tablename__ = "signing_keys"
    kid: Mapped[str] = mapped_column(String(32), primary_key=True)
    private_pem: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# --- engine ---------------------------------------------------------------

def _engine(url: str):
    kw = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
    eng = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragmas(conn, _):
            c = conn.cursor(); c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA journal_mode=WAL"); c.close()
    return eng


engine = _engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
