# TG11 Identity — the ecosystem SSO contract

**Status:** provider live at <https://accounts.tg11.org> (TG11 Accounts 0.2.2);
Flowboard is the first relying party in production. This document is the
contract every other TG11 application integrates against. The per-application
recipe lives in [TG11_APP_INTEGRATION.md](TG11_APP_INTEGRATION.md).

---

## 1. What this is, in one paragraph

One TG11 identity — a UUID — can sign a person in to every TG11 service, while
each application keeps owning its own data. Applications never share a session
cookie and never touch the identity database. They speak standard **OAuth 2.0 /
OpenID Connect, authorization code flow with PKCE (S256)**, over HTTPS, to a
single provider. The provider answers with an ID token whose `sub` claim is the
person's TG11 UUID; the application stores that UUID next to its own user row
and keys its own profile data on its own row. That is the whole idea.

### Explicit non-goals

| Not this | Why |
| --- | --- |
| Shared cookies across `tg11.org`, `freeparty.dev`, `furryparty.xyz`, `foxpay.fyi` | Unrelated registrable domains; a shared cookie would be both impossible and a cross-site risk. Each app keeps its own session cookie on its own host. |
| Every app authenticating against one shared user database | Couples deployments, spreads credentials, and one bad query in one app reaches everyone's password hashes. Apps hold no credentials at all. |
| Email address as the identity key | People change email. Email is a *hint* for the one-time linking decision, never the key. |
| A homegrown token format | Standards mean off-the-shelf libraries, review, and other people's bugs already found. |

---

## 2. Roles and addresses

| Role | What | Where |
| --- | --- | --- |
| Identity provider (OP) | TG11 Accounts — FastAPI + SQLAlchemy, RS256 signing key in the database | `https://accounts.tg11.org` (configurable; never hard-code it) |
| Relying party (RP) | Each application: Flowboard, FreeParty, FurryParty, Shop, Echoquill, FoxPay, CircuitSmith, GridGoblin | its own domain |

The issuer is **always** read from configuration — `TG11_OIDC_ISSUER` in the
environment — so a staging deployment can point at a staging provider and a
future move of the provider is a config change, not a code change. Discovery
documents are fetched from the configured issuer and the `issuer` value inside
them must match, or the client refuses to continue.

### Endpoints (from discovery, never hard-coded in apps)

```
GET  /.well-known/openid-configuration
GET  /oauth/jwks.json
GET  /oauth/authorize          response_type=code, PKCE S256 required
POST /oauth/token              client_secret_basic | client_secret_post | none
GET  /oauth/userinfo           Bearer access token
POST /oauth/revoke
GET  /oauth/logout             RP-initiated logout (end_session_endpoint)
```

Signing algorithm: **RS256** only. `code_challenge_methods_supported: ["S256"]`
only — plain PKCE is not accepted.

---

## 3. The identity model

The TG11 user id is a **UUID string** (`users.id`, `String(36)`), generated at
account creation and never reused, never recycled, never changed. It is what
the `sub` claim carries.

```
TG11 Accounts (accounts.tg11.org)
  users.id = 018f4f1e-…-cafe        ← the identity. Stable forever.
  users.email, users.username       ← mutable. Never an identity key.
  users.state                       ← active | pending_verification | limited | suspended

FreeParty (freeparty.dev)                     Shop (shop.tg11.org)
  auth_user.id = <local pk>                     auth_user.id = <local pk>
  tg11_auth_tg11identitylink                    tg11_auth_tg11identitylink
    subject = 018f4f1e-…-cafe   ────────┐         subject = 018f4f1e-…-cafe
  freeparty_profile.user_id = <local pk> │       shop_order.user_id = <local pk>
                                         └── same person, two unrelated datasets
```

Each application owns its own tables and its own primary keys. The link row is
the only thing that knows about TG11, and it is what makes "same person" true
across services.

### Claims

| Claim | Scope | Notes |
| --- | --- | --- |
| `sub` | `openid` | **The TG11 UUID.** The only identifier to key on. |
| `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce` | `openid` | validated on every login |
| `amr` | `openid` | what was actually proved: `["pwd"]`, `["pwd","otp"]`, `["pwd","recovery"]` |
| `acr` | `openid` | `urn:tg11:1fa` or `urn:tg11:2fa` |
| `email`, `email_verified` | `email` | `email_verified` is what makes a one-time link safe |
| `preferred_username`, `name`, `picture`, `website`, `updated_at` | `profile` | display only |
| `phone_number`, `phone_number_verified` | `phone` | |
| `tg11_username`, `tg11_bio`, `tg11_header_image`, `account_state`, `created_at` | `tg11.profile` | `account_state` lets an app refuse a suspended identity |

Scopes supported by the provider: `openid profile email phone tg11.profile
tg11.ai tg11.payments offline_access`. Each client is granted a subset
(`oauth_clients.allowed_scopes`); asking for more is `invalid_scope`. Ask for
the least you need — `openid profile email` covers a normal sign-in, plus
`tg11.profile` if you want `account_state`.

### Token lifetimes

| Token | TTL |
| --- | --- |
| authorization code | 600 s, single use, bound to client + redirect URI + PKCE challenge |
| access token | 3600 s |
| ID token | 3600 s |
| refresh token | 30 days, **rotated on every use**; reuse of a rotated token revokes the chain |

Refresh tokens are only issued with `offline_access`. Most applications should
not ask for them: a web app that just needs sign-in has no use for one, and not
having one is the easiest way to never leak one.

---

## 4. The login flow

```
browser            application (RP)                   accounts.tg11.org (OP)
   │  GET /auth/tg11/login/
   ├──────────────────────▶ create state, nonce, PKCE verifier
   │                        store all three in the server-side session
   │  302 to /oauth/authorize?response_type=code&client_id=…&redirect_uri=…
   │        &scope=…&state=…&nonce=…&code_challenge=…&code_challenge_method=S256
   ├───────────────────────────────────────────────────────────▶ sign in / consent
   │  302 back to redirect_uri?code=…&state=…
   ├──────────────────────▶ compare state (constant time), then
   │                        POST /oauth/token  code + code_verifier  ────────▶
   │                        ◀──── id_token, access_token [, refresh_token]
   │                        validate id_token: signature (JWKS), iss, aud, azp,
   │                        exp, iat skew, nonce, sub
   │                        GET /oauth/userinfo (optional) — sub must match
   │                        claims → local user (section 5)
   │                        login(); session key cycled
   │  302 to next / LOGIN_REDIRECT_URL
   ◀──────────────────────
```

What is enforced, and where it matters:

* **PKCE S256, always.** The verifier never leaves the server, so an
  intercepted code is useless.
* `state` — single use, expires in 10 minutes, compared with
  `secrets.compare_digest`.
* `nonce` — must appear in the ID token, bound to the same flow.
* **Every ID token is fully validated**: signature against the published JWKS
  (with one forced refresh so a key rotation is survived rather than an
  outage), `iss` exactly the configured issuer, `aud` contains our client id,
  `azp` checked when `aud` is multi-valued, `exp` and `iat` within a 60 s skew,
  `nonce` match, `sub` present.
* `userinfo` is merged only when its `sub` equals the ID token's `sub`.
* `redirect_uri` is matched **exactly** by the provider against the registered
  list; no wildcards, no prefix matching.
* `next`/`return` targets are validated as same-host before any redirect.
* The session key is cycled on login (no session fixation).
* **Refresh tokens are never sent to the browser, never stored in a cookie or
  session, and never logged. Nothing token-shaped is logged, ever.**

---

## 5. Claims → a local account (the linking rules)

This is where account takeover would live if it lived anywhere, so the rules are
fixed and identical in every application. Given a validated set of claims:

1. **A link row for this `sub` exists** → that local account. Done. Email and
   username may have changed at TG11; they are irrelevant here.
2. **No link row, a local account has the same email (case-insensitive), and the
   provider asserts `email_verified: true`** → link them, stamped
   `migration_source = verified_email`. The provider proving control of the
   address is what makes this safe.
3. **Same email but `email_verified` is false** → **refuse**. The user is told
   to sign in locally the usual way and link TG11 from their account settings.
   Accounts are *never* merged on an unverified address: otherwise anyone who
   registers that address at the IdP walks into the local account.
4. **Nothing matches** → create a local account with an **unusable password**
   (`migration_source = oidc_login`), unless the application sets
   `TG11_AUTH_AUTOCREATE = False`, in which case refuse.

Before all of that: if `account_state` is present and is not `active`, the login
is refused (`suspended`, `limited`, `pending_verification`).

Also enforced:

* A local account may hold **at most one** TG11 link, and a `sub` may map to at
  most one local account per application (`OneToOne` + unique `subject`).
* Linking while signed in (rule 3's remedy) needs no email match at all — the
  user has already proven both sides.
* A `revoked` link refuses login until the user links again.
* Unlink is refused when TG11 is the only way into the account (no usable
  password), so nobody can lock themselves out.
* A local account that is `is_active = False` cannot be signed into via TG11.

**No account is ever merged, renamed, deleted or silently repointed.** Existing
accounts everywhere are preserved; the only write a first TG11 login makes to an
existing account is the new link row.

### The link row

Every application gains exactly one table (`tg11_auth_tg11identitylink`):

| Column | Purpose |
| --- | --- |
| `user` (OneToOne) | the local account |
| `subject` (unique) | the TG11 UUID |
| `issuer` | which provider issued it |
| `application` | stable app id: `freeparty`, `furryparty`, `shop`, `echoquill`, `foxpay` |
| `legacy_local_id`, `local_uuid` | provenance: which local row this was before the link |
| `federation_id` | optional cross-app grouping (FurryParty/FreeParty share a federation) |
| `email_at_link`, `username_at_link` | what the claims said at link time — for audits, not for matching |
| `migration_source` | `oidc_login` / `verified_email` / `account_link` / `link_token` / `admin` |
| `migration_status` | `linked` / `pending` / `revoked` |
| `verified` | ownership of both sides was established |
| `linked_at`, `last_login_at` | |

The provider keeps the mirror image in `application_identity_links`
(`user_id`, `application`, `legacy_id`, `local_uuid`, `federation_id`,
`migration_source`, `migration_status`), so a link can be reconstructed from
either side after an incident.

---

## 5a. Second factors

A TG11 account can carry a TOTP authenticator. What that changes:

| | |
| --- | --- |
| Enrolling | `/account/security` → scan → confirm with a live code → ten recovery codes, shown once |
| Signing in | password, then a six-digit code (or one recovery code) before any session exists |
| Turning it off | password **and** a current code, so a borrowed session cannot strip it |
| New recovery codes | password required; the previous set stops working |
| What applications see | `amr: ["pwd","otp"]` and `acr: "urn:tg11:2fa"` in the ID token |
| Asking for it | `acr_values=urn:tg11:2fa`, or `TG11_AUTH_REQUIRE_MFA = True` in the Django client |

Half-finished logins hold nothing: the password step issues a signed,
five-minute, single-purpose cookie that grants no access on its own, and the
session is created only after the second factor. Failed codes are rate limited
per account (5 per 5 minutes), and the accepted TOTP step is recorded so the
same code cannot be used twice — including the one that enrolled the device.

An application that requires MFA should also keep its own local second factor
working, or make sure its users have enrolled at TG11 first; otherwise turning
`TG11_AUTH_REQUIRE_MFA` on locks out everyone who has not.

## 6. Sessions and logout

Each application keeps **its own** session cookie on its own host, with its own
lifetime, `Secure`, `HttpOnly` and `SameSite=Lax`. There is no cross-domain
cookie and no cross-domain session store.

* **Local logout** ends the application session only. The person stays signed
  in at TG11, so the next "Continue with TG11" is one click.
* **Global logout** (`POST /auth/tg11/logout/` with `global=1`) ends the local
  session and then redirects to the provider's `end_session_endpoint` with
  `id_token_hint` and a registered `post_logout_redirect_uri`.
* Logout is POST-only everywhere, so no cross-site GET can sign anyone out.
* Revoking a TG11 session or a client's tokens at accounts.tg11.org does not
  immediately kill already-established application sessions — applications hold
  their own. Short session lifetimes are the mitigation for sensitive apps;
  step-up re-authentication (`prompt=login`) is the tool for sensitive actions.

---

## 7. Registering an application

One CLI call on the provider host, per application, per environment:

```bash
cd /srv/tg11-accounts
.venv/bin/python -m tg11.cli add-client \
    --client-id   freeparty \
    --name        "FreeParty" \
    --application freeparty \
    --redirect    https://freeparty.dev/auth/tg11/callback/ \
    --post-logout https://freeparty.dev/ \
    --scopes      "openid profile email tg11.profile" \
    --trusted
```

* `--trusted` marks a first-party application, which skips the consent screen.
  Anything that is not ours does not get it.
* Redirect URIs are matched exactly — register every environment you use
  (production, and a `http://127.0.0.1:8000/...` one for local development),
  always with the same trailing slash the app actually serves.
* The command prints the client secret **once**. It goes into that
  application's `.env` (mode `0640`, owned by the service user) and nowhere
  else. **No secret is ever committed to Git.** Each application gets its own
  secret; they are never shared between applications or environments.
* Rotating a secret: add the new one, deploy, then disable the old — the
  provider accepts `client_secret_basic` and `client_secret_post`, so nothing
  else has to change.
* A public client (a native or fully-client-side app) registers with no secret
  and relies on PKCE alone. Every server-rendered application we run is a
  confidential client.

---

## 8. Migrating an application that already has accounts

The order is fixed and each step is reversible:

1. **Back up.** Database dump plus the application's media, with a SHA-256
   checksum, copied off the server before anything else. Verify the checksum;
   for SQLite use the online backup API rather than copying a WAL-mode file.
   *No destructive step runs until a verified backup exists.*
2. **Install the client, add the table.** `pip install tg11-auth`,
   `INSTALLED_APPS`, `migrate tg11_auth`. This adds one new table and changes
   nothing else — the application keeps working exactly as before.
3. **Offer TG11 as an additional way in.** The existing login form stays.
   "Continue with TG11" appears next to it, and "Link my TG11 account" appears
   in account settings.
4. **Let people link at their own pace.** Rules 1–4 above do the work. Nobody
   is forced, nothing is merged behind their back.
5. **Only if and when it is wanted:** make TG11 the primary path for new
   registrations (`TG11_AUTH_AUTOCREATE`), and later retire the local password
   form. The link rows and `legacy_local_id` mean the mapping is auditable
   afterwards.

Rollback at any point is: remove `tg11_auth` from `INSTALLED_APPS` and the URL
include, restart. The table can stay (it is inert); local logins were never
disabled. If a migration must be undone destructively, restore the verified
backup.

---

## 9. Security posture

* Standards only: OAuth 2.0 + OIDC, authorization code + PKCE S256, RS256
  signatures, discovery, JWKS rotation. No invented token formats, no shared
  secrets between applications, no application-to-identity-database access.
* TLS everywhere; `Secure` cookies; HSTS on the provider.
* Passwords live only at the provider (`pbkdf2_sha256`, Django-compatible).
  Applications that adopt TG11 for a new account store an unusable password.
* **MFA is implemented** (0.3): TOTP in an authenticator app plus ten
  single-use recovery codes. The shared secret is encrypted with the same
  AES-256-GCM vault as the AI keys, AAD-bound to the user; a device only counts
  once confirmed with a live code; codes are accepted within one 30-second step
  either side and cannot be replayed; attempts are rate limited. WebAuthn and
  passkeys will reuse the same `amr` plumbing when they land.
* **Applications can require a second factor** without implementing one.
  `acr_values=urn:tg11:2fa` on the authorization request makes the provider
  re-authenticate until the session has one, and the resulting ID token reports
  `amr`/`acr` so the application can verify rather than hope. In the Django
  client that is one setting, `TG11_AUTH_REQUIRE_MFA = True`.
* **Step-up authentication** for sensitive actions: `prompt=login` forces a
  fresh sign-in, `max_age=<seconds>` forces one when the session is older than
  that, and `auth_time` in the ID token lets the application check freshness
  itself (`claims.authenticated_within(300)`). This is the mechanism FoxPay will
  use for payment-changing actions — the application never handles a factor
  itself.
* **Audit logging:** log the event, never the material. `sub`, client id,
  application, outcome, `migration_source`, IP and user agent are fine. Tokens,
  codes, verifiers, secrets and password material are never logged, at any log
  level, including on error paths.
* **Payment data stays out of the identity database.** TG11 stores payment
  *provider references* (`payment_methods.external_customer_id`,
  `external_method_id`, a display label such as "Visa •••• 4242") and never raw
  card numbers, CVVs, bank credentials or anything else that would put the
  identity database in PCI scope. Payment credentials live with the payment
  provider; FoxPay holds tokens, not cards.
* **The wallet's providers.** Stripe (cards and Link) and PayPal (a PayPal
  account the person approves once, vaulted by PayPal) are implemented; the
  rest are registered with their integration notes so the data model, the API
  and the UI are already final. An application places a *hold* through
  `/api/v1/payments/...` with the `tg11.payments` scope and captures or releases
  it later; TG11 stores the provider's token ids and a display label, nothing
  else. PayPal additionally requires PayPal to switch Vault on for the merchant
  account before an account can be saved — until they do, the wallet says so
  instead of failing obscurely.
* AI credentials are the user's own, encrypted at rest in the provider's vault
  (`ai_vault_credentials.secret_blob`, versioned key). No operator keys are
  ever placed in an application, and every AI call uses the user's own
  credentials.
* Early-stage is not a reason for an insecure shortcut. If a piece of this is
  not ready, the application ships without that feature rather than with a fake
  or weakened version of it.

---

## 10. Adding a *new* TG11 application

1. Pick a stable lowercase application id (`gridgoblin`) — it goes in link rows
   forever, so choose it once.
2. Register the client (section 7) with the smallest scope set that works.
3. Install `tg11-auth` (Django) or port the ~200-line client for another stack;
   the reference implementations are `clients/django/tg11_auth/client.py` here
   and `app/identity/oidc.py` in Flowboard (FastAPI).
4. Key the application's own profile/content on its **own** user row; keep the
   TG11 UUID only in the link row. If the app wants the UUID handy, read it
   from the link.
5. Greenfield applications can be TG11-only from day one: no local password
   form, no password reset, no email verification to build — the provider owns
   all of it.

---

## 11. Where the code is

| Piece | Path |
| --- | --- |
| Provider | `tg11/oidc.py`, `tg11/web.py`, `tg11/models.py` (this repo) |
| Reusable Django relying party | `clients/django/tg11_auth/` (this repo) |
| Provider-side link table | `application_identity_links` in `tg11/models.py` |
| FastAPI reference relying party | Flowboard `app/identity/oidc.py` |
| Per-application recipe | [TG11_APP_INTEGRATION.md](TG11_APP_INTEGRATION.md) |
