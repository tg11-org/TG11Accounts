# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""Central BYO AI key vault (encrypted with AES-256-GCM, AAD bound to the user
and provider).  Trusted applications fetch a user's keys with an access token
carrying the `tg11.ai` scope; keys are never rendered back to the browser."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import CredentialCipher, get_cipher, mask_secret
from .models import AIVaultCredential, User

# Provider ids mirror Flowboard's registry so imports are 1:1.
KNOWN_PROVIDERS = [
    ("openai", "OpenAI"), ("anthropic", "Anthropic"), ("gemini", "Google Gemini"), ("xai", "xAI (Grok)"), ("groq", "Groq"),
    ("github_models", "GitHub Models"), ("together", "Together AI"), ("mistral", "Mistral AI"), ("openrouter", "OpenRouter"),
    ("deepseek", "DeepSeek"), ("moonshot", "Moonshot / Kimi"), ("cerebras", "Cerebras"), ("perplexity", "Perplexity"),
    ("cohere", "Cohere"), ("stability", "Stability AI"), ("novita", "Novita"), ("minimax", "MiniMax"), ("replicate", "Replicate"),
    ("azure_openai", "Azure OpenAI"), ("huggingface", "Hugging Face"), ("fireworks", "Fireworks AI"), ("deepinfra", "DeepInfra"),
    ("ollama", "Ollama (local)"), ("lmstudio", "LM Studio (local)"), ("vllm", "vLLM / self-hosted"), ("custom_openai", "Custom OpenAI-compatible"),
]


def _aad(user_id: str, provider: str) -> str:
    return f"tg11-vault:{user_id}:{provider}"


def list_credentials(db: Session, user: User) -> List[AIVaultCredential]:
    return list(db.scalars(select(AIVaultCredential).where(AIVaultCredential.user_id == user.id).order_by(AIVaultCredential.provider)))


def get_credential(db: Session, user: User, provider: str) -> Optional[AIVaultCredential]:
    return db.scalar(select(AIVaultCredential).where(AIVaultCredential.user_id == user.id, AIVaultCredential.provider == provider))


def upsert(db: Session, user: User, provider: str, *, api_key: str, base_url: str = "", label: str = "", extra: Optional[Dict[str, str]] = None, config: Optional[Dict[str, Any]] = None, source: str = "tg11") -> AIVaultCredential:
    provider = (provider or "").strip().lower()[:40]
    if not provider or not provider.replace("_", "").isalnum():
        raise ValueError("invalid provider id")
    cipher = get_cipher()
    row = get_credential(db, user, provider)
    secrets: Dict[str, str] = {}
    if row is not None:
        try:
            secrets = cipher.decrypt_json(row.secret_blob, _aad(user.id, provider))
        except Exception:
            secrets = {}
    if api_key.strip():
        secrets["api_key"] = api_key.strip()
    for k, v in (extra or {}).items():
        if v:
            secrets[k] = v
    if not secrets.get("api_key") and provider != "custom_openai":
        raise ValueError("API key is required")
    blob, ver = cipher.encrypt_json(secrets, _aad(user.id, provider))
    if row is None:
        row = AIVaultCredential(user_id=user.id, provider=provider)
        db.add(row)
    row.secret_blob, row.key_version = blob, ver
    row.secret_hint = mask_secret(secrets.get("api_key", ""))
    cfg = json.loads(row.config_json or "{}") if row.config_json else {}
    if base_url.strip():
        cfg["base_url"] = base_url.strip()
    for k, v in (config or {}).items():
        if k and v not in (None, ""):
            cfg[str(k)[:40]] = str(v)[:500]
    row.config_json = json.dumps(cfg)
    row.label = label.strip()[:80]
    row.source = (source or "tg11")[:40]
    db.flush()
    return row


def import_from_app(db: Session, user: User, application: str, items: List[Dict[str, Any]], *, replace: bool = False) -> Dict[str, Any]:
    """Upsert keys pushed by a trusted app (secrets are a dict, e.g. {"api_key": ...}).
    replace=True also removes vault entries for providers the app did not send."""
    written, skipped = [], []
    seen = set()
    for it in items or []:
        provider = str(it.get("provider") or "").strip().lower()
        secrets = it.get("secrets") if isinstance(it.get("secrets"), dict) else {}
        api_key = str(secrets.get("api_key") or "")
        extra = {k: str(v) for k, v in secrets.items() if k != "api_key" and v}
        if not api_key and not extra:  # nothing secret to store - never blank an existing key
            skipped.append(provider or "?")
            continue
        try:
            upsert(db, user, provider, api_key=api_key, label=str(it.get("label") or f"from {application}"), extra=extra, config=it.get("config") if isinstance(it.get("config"), dict) else None, source=application)
            written.append(provider)
            seen.add(provider)
        except ValueError:
            skipped.append(provider or "?")
    removed = []
    if replace:
        for row in list_credentials(db, user):
            if row.provider not in seen:
                removed.append(row.provider)
                delete(db, user, row)
    return {"written": written, "skipped": skipped, "removed": removed}


def delete(db: Session, user: User, row: AIVaultCredential) -> None:
    assert row.user_id == user.id
    db.delete(row)
    db.flush()


def export_for_app(db: Session, user: User) -> List[Dict[str, Any]]:
    """Decrypted view for a trusted app holding a `tg11.ai` token."""
    cipher = get_cipher()
    out = []
    for row in list_credentials(db, user):
        try:
            secrets = cipher.decrypt_json(row.secret_blob, _aad(user.id, row.provider))
        except Exception:
            continue
        out.append({"provider": row.provider, "label": row.label, "secrets": secrets, "config": json.loads(row.config_json or "{}"), "source": row.source, "updated_at": row.updated_at.isoformat() + "Z"})
    return out
