# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Authenticated encryption for stored secrets (API keys, OAuth tokens).

Algorithm: AES-256-GCM (via `cryptography`), 96-bit random nonce, with a
small versioned envelope so keys can be rotated:

    envelope = b"FB1" + key_version(1 byte) + nonce(12) + ciphertext+tag

The master key comes from `TG11_VAULT_KEY` (base64 or hex
encoded 32 bytes).  Additional keys for rotation can be supplied as
`TG11_VAULT_KEY_V<n>`; the highest version is used for new
writes and older versions only for decryption.

The associated data (AAD) binds a ciphertext to its owner + purpose so a blob
copied between rows cannot be decrypted in another context.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FB1"


class CredentialCryptoError(Exception):
    pass


def _decode_key(raw: str) -> bytes:
    raw = raw.strip()
    if not raw:
        raise CredentialCryptoError("TG11_VAULT_KEY is not set")
    for decoder in (base64.urlsafe_b64decode, base64.b64decode, binascii.unhexlify):
        try:
            key = decoder(raw + ("=" * (-len(raw) % 4)) if decoder is not binascii.unhexlify else raw)
            if len(key) == 32:
                return key
        except Exception:
            continue
    raise CredentialCryptoError("credential encryption key must decode to 32 bytes (base64 or hex)")


def generate_key() -> str:
    """Return a fresh, urlsafe-base64 encoded 256-bit key suitable for .env."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


class CredentialCipher:
    def __init__(self, keys: Dict[int, bytes]):
        if not keys:
            raise CredentialCryptoError("no encryption keys configured")
        self._keys = keys
        self.current_version = max(keys)

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "CredentialCipher":
        env = env if env is not None else os.environ
        keys: Dict[int, bytes] = {}
        base = env.get("TG11_VAULT_KEY", "")
        if base:
            keys[1] = _decode_key(base)
        for name, value in env.items():
            if name.startswith("TG11_VAULT_KEY_V") and value:
                try:
                    version = int(name.rsplit("_V", 1)[1])
                except ValueError:
                    continue
                keys[version] = _decode_key(value)
        if not keys:
            from .config import settings

            if settings.is_dev and not getattr(settings, "TG11_VAULT_KEY", ""):
                # Deterministic dev key so local runs work without setup; never used in prod.
                keys[1] = b"\x01" * 32
            else:
                raise CredentialCryptoError(
                    "TG11_VAULT_KEY is required (generate one with "
                    "`python -m tg11.crypto`)"
                )
        return cls(keys)

    # ------------------------------------------------------------------
    def encrypt(self, plaintext: bytes, aad: str) -> Tuple[bytes, int]:
        version = self.current_version
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._keys[version]).encrypt(nonce, plaintext, aad.encode())
        return MAGIC + bytes([version]) + nonce + ct, version

    def decrypt(self, blob: bytes, aad: str) -> bytes:
        if not blob or blob[:3] != MAGIC or len(blob) < 3 + 1 + 12 + 16:
            raise CredentialCryptoError("malformed credential envelope")
        version = blob[3]
        key = self._keys.get(version)
        if key is None:
            raise CredentialCryptoError(f"no encryption key for version {version}")
        nonce, ct = blob[4:16], blob[16:]
        try:
            return AESGCM(key).decrypt(nonce, ct, aad.encode())
        except InvalidTag as exc:
            raise CredentialCryptoError("credential could not be decrypted (wrong key or tampered data)") from exc

    def encrypt_json(self, data: Dict[str, Any], aad: str) -> Tuple[bytes, int]:
        return self.encrypt(json.dumps(data, separators=(",", ":")).encode(), aad)

    def decrypt_json(self, blob: bytes, aad: str) -> Dict[str, Any]:
        return json.loads(self.decrypt(blob, aad).decode())

    def needs_rotation(self, blob: bytes) -> bool:
        return bool(blob) and blob[:3] == MAGIC and blob[3] != self.current_version


_cipher: Optional[CredentialCipher] = None


def get_cipher() -> CredentialCipher:
    global _cipher
    if _cipher is None:
        _cipher = CredentialCipher.from_env()
    return _cipher


def reset_cipher() -> None:  # for tests
    global _cipher
    _cipher = None


def mask_secret(secret: str, keep: int = 4) -> str:
    """Return a display hint like `sk-••••••••4X2q` without leaking the key."""
    if not secret:
        return ""
    s = secret.strip()
    prefix = ""
    for p in ("sk-ant-", "sk-or-", "sk-proj-", "gsk_", "xai-", "sk-", "csk-", "AIza", "r8_", "pplx-", "github_pat_", "ghp_"):
        if s.startswith(p):
            prefix = p
            break
    tail = s[-keep:] if len(s) > keep + len(prefix) else ""
    return f"{prefix}••••••••{tail}"


if __name__ == "__main__":  # pragma: no cover
    print(generate_key())
