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
    # profile (public-ish; exposed through the `profile` / `phone` scopes)
    bio: Mapped[str] = mapped_column(Text, default="", nullable=False)
    website: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    avatar_path: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    header_path: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    phone: Mapped[str] = mapped_column(String(32), default="", nullable=False)  # E.164
    phone_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    pending_email: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    # reserved for future MFA: totp_secret (encrypted), passkeys live in their own tables later

    @property
    def avatar_url(self) -> str:
        from .config import settings as _s

        return f"{_s.issuer}/media/{self.avatar_path}" if self.avatar_path else ""

    @property
    def header_url(self) -> str:
        from .config import settings as _s

        return f"{_s.issuer}/media/{self.header_path}" if self.header_path else ""

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
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # verify_email|reset_password|change_email|verify_phone
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    payload: Mapped[str] = mapped_column(Text, default="", nullable=False)  # e.g. the new email address
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
    home_url: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    link_url: Mapped[str] = mapped_column(String(300), default="", nullable=False)  # where the app starts "link my TG11 account"
    icon: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    description: Mapped[str] = mapped_column(String(300), default="", nullable=False)

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


class AIVaultCredential(Base):
    """Central BYO AI key vault: one encrypted secret blob per (user, provider).
    Trusted apps with the `tg11.ai` scope can fetch a user's keys."""

    __tablename__ = "ai_vault_credentials"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_vault_user_provider"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    label: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    secret_blob: Mapped[bytes] = mapped_column(nullable=False)
    key_version: Mapped[int] = mapped_column(default=1, nullable=False)
    secret_hint: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class PaymentMethod(Base):
    """A user's stored way to pay, held by an external provider (we store only references)."""

    __tablename__ = "payment_methods"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # stripe|paypal|venmo|cashapp|airwallex|adyen|btc|eth|tg11coin|foxpay
    kind: Mapped[str] = mapped_column(String(16), default="card", nullable=False)  # card|wallet|bank|crypto
    label: Mapped[str] = mapped_column(String(80), default="", nullable=False)  # "Visa •••• 4242"
    external_customer_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    external_method_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)  # pending|active|removed|error
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    meta_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class PaymentHold(Base):
    """An authorization placed by an application (e.g. FreeParty) against a
    user's payment method. Amounts are integer minor units (cents/sats)."""

    __tablename__ = "payment_holds"
    __table_args__ = (Index("ix_holds_user", "user_id"), Index("ix_holds_client", "client_id"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)  # requesting application
    method_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    amount: Mapped[int] = mapped_column(nullable=False)
    currency: Mapped[str] = mapped_column(String(8), default="usd", nullable=False)
    captured_amount: Mapped[int] = mapped_column(default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="requested", nullable=False)  # requested|authorized|captured|released|failed|expired
    reference: Mapped[str] = mapped_column(String(120), default="", nullable=False)  # app-side reference (order id...)
    description: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    external_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    error: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


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


def ensure_schema() -> None:
    """create_all + add columns that exist on the models but not in the db
    (sqlite ALTER TABLE ADD COLUMN) - small-service migration strategy."""
    from sqlalchemy import inspect, text

    Base.metadata.create_all(engine)
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                ctype = col.type.compile(engine.dialect)
                default = col.default.arg if col.default is not None and not callable(col.default.arg) else None
                ddl = f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ctype}'
                if default is not None:
                    ddl += f" DEFAULT {repr(default) if isinstance(default, str) else (1 if default is True else 0 if default is False else default)}"
                elif not col.nullable:
                    ddl += " DEFAULT ''" if "CHAR" in ctype or "TEXT" in ctype else " DEFAULT 0"
                conn.execute(text(ddl))


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
