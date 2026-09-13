# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    TG11_ENV: str = "production"
    TG11_SECRET_KEY: str = "dev-insecure"
    TG11_ISSUER: str = "https://accounts.tg11.org"  # must equal the public URL, no trailing slash
    TG11_SITE_NAME: str = "TG11 Account"
    TG11_DATA_DIR: str = ""
    TG11_DATABASE_URL: str = ""
    TG11_ALLOWED_HOSTS: str = "accounts.tg11.org,localhost,127.0.0.1"
    TG11_ALLOW_REGISTRATION: bool = True
    TG11_REQUIRE_EMAIL_VERIFICATION: bool = False  # set true once SMTP works
    TG11_SESSION_MAX_AGE: int = 60 * 60 * 24 * 30
    TG11_ACCESS_TOKEN_TTL: int = 3600
    TG11_ID_TOKEN_TTL: int = 3600
    TG11_REFRESH_TOKEN_TTL: int = 60 * 60 * 24 * 30
    TG11_CODE_TTL: int = 600
    TG11_COOKIE_SECURE: bool = True
    TG11_VAULT_KEY: str = ""  # AES-256-GCM key for the AI key vault (base64/hex 32 bytes)
    TG11_MEDIA_DIR: str = ""  # uploaded avatars/headers (default <data>/media)
    TG11_MAX_UPLOAD_BYTES: int = 8 * 1024 * 1024
    # SMS verification (Twilio Messages API)
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_NUMBER: str = ""
    # Payments: Stripe (cards, Link). Others are registered as planned providers until keys exist.
    STRIPE_SECRET_KEY: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    PAYPAL_CLIENT_ID: str = ""
    PAYPAL_CLIENT_SECRET: str = ""
    PAYPAL_ENV: str = "sandbox"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    EMAIL_FROM: str = "TG11 Accounts <noreply@tg11.org>"

    @property
    def data_dir(self) -> Path:
        p = Path(self.TG11_DATA_DIR) if self.TG11_DATA_DIR else BASE_DIR / "data"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def database_url(self) -> str:
        return self.TG11_DATABASE_URL or f"sqlite:///{self.data_dir / 'accounts.sqlite3'}"

    @property
    def media_dir(self) -> Path:
        p = Path(self.TG11_MEDIA_DIR) if self.TG11_MEDIA_DIR else self.data_dir / "media"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def sms_configured(self) -> bool:
        return bool(self.TWILIO_ACCOUNT_SID and self.TWILIO_AUTH_TOKEN and self.TWILIO_FROM_NUMBER)

    @property
    def stripe_configured(self) -> bool:
        return bool(self.STRIPE_SECRET_KEY and self.STRIPE_PUBLISHABLE_KEY)

    @property
    def paypal_configured(self) -> bool:
        return bool(self.PAYPAL_CLIENT_ID and self.PAYPAL_CLIENT_SECRET)

    @property
    def paypal_api(self) -> str:
        return "https://api-m.paypal.com" if self.PAYPAL_ENV.lower() == "live" else "https://api-m.sandbox.paypal.com"

    @property
    def issuer(self) -> str:
        return self.TG11_ISSUER.rstrip("/")

    @property
    def allowed_hosts(self) -> List[str]:
        return [h.strip() for h in self.TG11_ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def is_dev(self) -> bool:
        return self.TG11_ENV in ("development", "test")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
