# TG11 Accounts

The OpenID Connect identity provider for the TG11 / VulpFin ecosystem
("Sign in with TG11"). Reference implementation of the architecture described
in Flowboard's `docs/TG11_SSO.md`.

* Authorization code flow with PKCE (S256), `client_secret_basic`/`_post` or public clients
* Discovery, JWKS (RS256, key stored in the db), ID token, userinfo, refresh-token rotation, revocation, RP-initiated logout
* Users mirror FreeParty's account model (UUID `sub`, unique lower-cased email + username, Django-compatible `pbkdf2_sha256` password hashes, account state)
* Consent screen for third-party clients; first-party (`--trusted`) clients skip it
* Account page: profile, password, connected applications, sessions
* `application_identity_links` table for legacy account mapping
* Identity only — applications keep their own profile/content data keyed on `sub`

```
python -m tg11.cli add-client --client-id flowboard --name Flowboard --application flowboard \
    --redirect https://flowboard.fyi/auth/tg11/callback --post-logout https://flowboard.fyi/login \
    --scopes "openid profile email" --trusted
python -m tg11.cli create-user --email you@tg11.org --username you --staff
uvicorn tg11.web:app --host 127.1.0.5 --port 8000
pytest
```

Roadmap (schema-ready, not implemented): email verification enforcement
(`TG11_REQUIRE_EMAIL_VERIFICATION`), TOTP, WebAuthn/passkeys, recovery codes,
trusted devices, admin UI, social login providers, account-link tokens for
migrating FreeParty/Shop/Echoquil accounts.
