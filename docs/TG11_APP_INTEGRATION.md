# Adding "Sign in with TG11" to an application

The recipe. Read [TG11_IDENTITY.md](TG11_IDENTITY.md) first for *why* it is
shaped this way; this document is *how*, step by step, plus the per-application
plans for everything we run.

Two rules that apply to every step below:

* **Nothing destructive runs before a verified backup exists** (section 2).
* **Nothing is merged, renamed or repointed.** Existing accounts keep working
  exactly as they did; TG11 is an *additional* way in until you choose
  otherwise.

---

## 1. The 30-minute Django recipe

### 1.1 Register the client (on the provider host)

```bash
cd /srv/tg11-accounts
.venv/bin/python -m tg11.cli add-client \
    --client-id   myapp \
    --name        "My App" \
    --application myapp \
    --redirect    https://myapp.example/auth/tg11/callback/ \
    --redirect    http://127.0.0.1:8000/auth/tg11/callback/ \
    --post-logout https://myapp.example/ \
    --scopes      "openid profile email tg11.profile" \
    --trusted
```

It prints the secret **once**. Redirect URIs are matched exactly — trailing
slash included.

### 1.2 Install the client library

```bash
/path/to/venv/bin/pip install "tg11-auth @ git+ssh://…/TG11Accounts#subdirectory=clients/django"
# or, on the same host:  pip install -e /srv/tg11-accounts/clients/django
```

### 1.3 Settings

```python
INSTALLED_APPS += ["tg11_auth"]

AUTHENTICATION_BACKENDS = [
    *AUTHENTICATION_BACKENDS,            # keep what is already there
    "tg11_auth.backends.TG11Backend",
]

TG11_OIDC_ISSUER        = os.environ["TG11_OIDC_ISSUER"]          # never hard-coded
TG11_OIDC_CLIENT_ID     = os.environ["TG11_OIDC_CLIENT_ID"]
TG11_OIDC_CLIENT_SECRET = os.environ["TG11_OIDC_CLIENT_SECRET"]
TG11_OIDC_REDIRECT_URI  = os.environ["TG11_OIDC_REDIRECT_URI"]
TG11_OIDC_SCOPES        = "openid profile email tg11.profile"
TG11_APPLICATION        = "myapp"
TG11_AUTH_BASE_TEMPLATE = "base.html"
```

`.env` (mode `0640`, owned by the service user, **never committed**; keep each
comment on its own line — an inline `#` becomes part of the value in some
loaders):

```
TG11_OIDC_ISSUER=https://accounts.tg11.org
TG11_OIDC_CLIENT_ID=myapp
TG11_OIDC_CLIENT_SECRET=…
TG11_OIDC_REDIRECT_URI=https://myapp.example/auth/tg11/callback/
```

### 1.4 URLs and the table

```python
urlpatterns += [path("auth/tg11/", include("tg11_auth.urls"))]
```

```bash
python manage.py migrate tg11_auth        # one new table, nothing altered
```

### 1.5 Templates

```django
{# login page, next to the existing form — not instead of it #}
{% include "tg11_auth/button.html" %}

{# account settings #}
{% include "tg11_auth/button.html" with link_mode=True next="/settings/" %}
```

Add `tg11_auth.context_processors.tg11` to `TEMPLATES` so those know whether
TG11 is configured and already linked.

### 1.6 Application profile data

```python
TG11_AUTH_PROFILE_HOOK = "myapp.auth.on_tg11_login"
```

```python
def on_tg11_login(*, user, claims, created, link, request):
    profile, _ = Profile.objects.get_or_create(user=user)
    if created:                      # only seed on first sight; never overwrite
        profile.display_name = claims.name or profile.display_name
        profile.save(update_fields=["display_name"])
```

Keyed on the **local** user; the TG11 UUID stays in the link row. A raised
exception is logged, never fatal to a sign-in.

### 1.7 Verify

```bash
python manage.py check --deploy
python -m pytest            # or manage.py test
```

Then, against the deployed site: sign in with TG11 as a throwaway TG11 account,
confirm a link row appears, sign out, sign in again (must reuse the same local
account), link and unlink from settings, and check the logs contain no token,
code or secret. Delete the throwaway account and its local row afterwards.

---

## 2. Backups — before any auth change

Nothing below starts until this has been done **and verified**.

**Postgres** (FreeParty, FurryParty, Shop, Echoquill):

```bash
ts=$(date +%Y%m%d-%H%M%S); app=freeparty
docker compose exec -T db pg_dump -Fc -U "$app" "$app" > /root/backups/$app-$ts.dump
# or: sudo -u postgres pg_dump -Fc freeparty > /root/backups/freeparty-$ts.dump
sha256sum /root/backups/$app-$ts.dump | tee /root/backups/$app-$ts.dump.sha256
pg_restore --list /root/backups/$app-$ts.dump | tail -5     # proves it is readable
```

**SQLite** (FoxPay, Flowboard) — a `cp` of a WAL-mode database is **not** a
backup; use the online backup API:

```bash
python -m app.cli backup --keep 20         # Flowboard's helper does exactly this
sqlite3 app.db ".backup '/root/backups/app-$ts.db'"   # equivalent elsewhere
sha256sum /root/backups/app-$ts.db | tee /root/backups/app-$ts.db.sha256
sqlite3 /root/backups/app-$ts.db "pragma integrity_check; select count(*) from users;"
```

Then **copy the dump and its checksum off the server** and re-verify the
checksum locally. Record the row counts you saw; they are what you compare
against afterwards.

---

## 3. Per-application plans

Ordered by value-over-risk. Each is independently deployable and independently
reversible.

### 3.1 FreeParty — `freeparty.dev`, `freeparty.tg11.org`

| | |
| --- | --- |
| Code / serving | `/var/www/Freeparty`, docker compose → `127.5.0.0:18000`, Django 5.1 |
| Data | Postgres 16.3, `accounts.User` with **UUID** PK, `pbkdf2_sha256` hashes |
| Live users | 7 |
| Risk | **Medium** — most users of any app, and the codebase is shared with FurryParty |

Already has account states, TOTP devices, recovery codes and action tokens, so
its model is the one TG11 Accounts was built to mirror. The integration is
mostly configuration.

Steps: backup → `pip install tg11-auth` into the image (add to
`requirements.txt`, rebuild) → settings + `.env` via compose env → `migrate
tg11_auth` → button on the login page and in settings → profile hook creating
the FreeParty profile → deploy → verify with a throwaway account → delete it.

`local_uuid` in the link row is the FreeParty UUID, so the two identifiers stay
traceable to each other without either becoming the other.

Rollback: remove the two settings lines and the URL include, rebuild, restart.
The table can stay. Local logins were never disabled.

### 3.2 FurryParty — `furryparty.xyz`

| | |
| --- | --- |
| Code / serving | `/var/www/Freeparty.dev` (byte-identical accounts app), docker → `127.9.0.0:18000` |
| Data | separate Postgres 16.3, same schema |
| Live users | 1 |
| Risk | **Low** — the FreeParty work, done twice |

Same steps, its own client id (`furryparty`), its own secret, its own
`TG11_APPLICATION`. Set `TG11_AUTH_FEDERATION_ID` here (this is Federation 1) so
link rows carry the federation membership. Because the code is shared, land
FreeParty first and keep the diff configuration-only.

### 3.3 Shop — `shop.tg11.org`

| | |
| --- | --- |
| Code / serving | `/var/www/storefront`, docker → `127.6.0.10:8000`, Django 6.0.4 |
| Data | Postgres 17, `accounts.CustomUser`, **int** PK, django-allauth 65.16, email-only login with mandatory verification |
| Live users | 1 |
| Risk | **Medium** — `bettercorporatelogowear.org` is a second deployment of this codebase |

Two options, and the choice is real:

* **allauth's own OIDC provider** (`allauth.socialaccount.providers.openid_connect`
  pointed at the issuer) — least new code, and allauth already handles the
  social-account plumbing, email verification interplay and connections UI.
  It does *not* give you the `TG11IdentityLink` row or our linking rules, so add
  `tg11_auth` alongside it purely for the link table, or accept allauth's
  `SocialAccount` as the link and set `SOCIALACCOUNT_EMAIL_AUTHENTICATION =
  False` so an unverified email can never auto-connect.
* **`tg11_auth` directly**, bypassing allauth for this one provider — identical
  behaviour to every other app, one linking implementation to audit.

Recommendation: `tg11_auth` directly, for consistency and because the linking
rules are the part worth having identical everywhere. Keep allauth for
everything it already does.

Its int PK stays internal. Add a UUID column only if Shop wants one of its own;
the link row already carries the TG11 UUID. Remember the second deployment when
changing settings — give it its own client id and redirect URI, or exclude it.

### 3.4 Echoquill — `echoquill.tg11.org`

| | |
| --- | --- |
| Code / serving | `/var/www/Echoquill`, daphne (ASGI, websockets) → `127.1.0.4:8000`, Django 5.2 |
| Publishing | **live**: vhost in `tg11.org.conf` (`:80` line 210, `:443` line 283), Cloudflare DNS, Cloudflare Origin CA cert `*.tg11.org` valid to 2040, public HTTPS returns 200 |
| Data | Postgres, **stock `auth.User`**, int PK, 1 user (`echquil_usr`) |
| Live users | 1 |
| Risk | **Low** — one user, and the stock user model is exactly what `tg11_auth` is written against |

Note the spelling: the host is `echoquill.tg11.org` with two l's (the service,
the paths and the logs all use `Echoquill`). `echoquil.tg11.org` does not exist —
if that single-l name should also work, it needs its own Cloudflare CNAME and a
`ServerAlias`; the wildcard certificate already covers it.

Two tidy-ups to do while in there, neither required for TG11: the `:80` block
still carries dead `WSGIDaemonProcess` / `WSGIScriptAlias` directives from
before the move to daphne, sitting next to the `ProxyPass` that actually
serves; and `/var/www/Echoquill` is not a git repository, so there is no
deploy/rollback path except file copies. Fix the second one before touching
authentication — a rollback plan that is "remember what you changed" is not one.

Steps: backup → `pip install tg11-auth` in `/var/www/Echoquill/venv` →
settings + `.env` → `migrate tg11_auth` → button → `collectstatic` →
`systemctl restart echoquill` → verify over HTTPS. Because it is ASGI behind a
websocket-aware proxy, check that a page using websockets still works after the
restart.

### 3.5 FoxPay — `foxpay.fyi`

**Left alone for now, by your decision.** It is being built elsewhere (seven
commits and a live service as of last night) and already has its own
`docs/TG11_AUTH.md`, so two of us editing it would collide.

When it is time, the design constraints are already fixed by
[TG11_IDENTITY.md](TG11_IDENTITY.md) §9:

* MFA happens at the provider; FoxPay never handles a second factor itself.
* **Step-up authentication** before any payment-changing action: send the user
  through `/auth/tg11/login/?prompt=login` and require a fresh `auth_time`
  (e.g. within 5 minutes) on the resulting ID token.
* Audit-log every auth event and every payment action: `sub`, client, action,
  outcome, IP, user agent — and **never** a token, code, verifier or secret.
* **No payment credentials in the identity database.** Provider references only
  (`external_customer_id`, `external_method_id`, "Visa •••• 4242"). Raw card
  data never touches TG11 or FoxPay's own tables.
* Its SQLite database gets the online-backup procedure in section 2, not `cp`.

### 3.6 Flowboard — `flowboard.fyi` (already integrated, for reference)

Flowboard is FastAPI, not Django, and has been running as a TG11 relying party
in production since 2.1. Its client is `app/identity/oidc.py` — the same
validation logic the Django client was ported from — with
`app/identity/linking.py` doing the claims→user step and a `tg11_identity_links`
table holding `subject`, `issuer`, `application`, provenance and status. Use it
as the reference for a non-Django stack; use it as the reference for what
"finished" looks like.

### 3.7 CircuitSmith — `circuitsmith.vulpfin.com`

Not yet surveyed for this program. When it is picked up: register
`circuitsmith`, install the client, and follow section 1 unchanged if it is
Django. Nothing about it needs to be special — that is the point of the client
library.

### 3.8 GridGoblin — `gridgoblin.net`

Same. If it is greenfield enough to go TG11-only, do that: no local password
form, no password reset, no email verification to build or maintain, one link
row per user, `TG11_AUTH_AUTOCREATE = True`.

---

## 4. Rollout order

1. ~~The contract + the reusable client~~ — done: this document,
   [TG11_IDENTITY.md](TG11_IDENTITY.md), and `clients/django/` (69 tests).
2. **Echoquill** — one user, stock `auth.User`, now known to be live. The
   cheapest first real integration, after giving it a git repo.
3. **FreeParty** — the canonical model; validates the library against UUID PKs
   and 7 real users.
4. **FurryParty** — the same change as configuration, plus the federation id.
5. **Shop** — allauth coexistence.
6. **FoxPay** — only once you say it is free to touch.

One application per session, each ending deployed, verified and documented.

---

## 5. Checklist per application

```
[ ] client registered, secret in .env only (0640, service user, not in Git)
[ ] verified backup taken and copied off the server, checksum re-checked locally
[ ] row counts recorded before the change
[ ] tg11-auth installed, INSTALLED_APPS, AUTHENTICATION_BACKENDS, urls
[ ] migrate tg11_auth (one new table; no existing table altered)
[ ] issuer/client id/secret/redirect URI from the environment, nothing hard-coded
[ ] button on the login page *next to* the existing form; link/unlink in settings
[ ] profile hook creates app-local profile rows keyed on the local user
[ ] tests pass; check --deploy clean
[ ] deployed; throwaway TG11 account: sign in, sign in again, link, unlink
[ ] throwaway account and its local row deleted
[ ] logs reviewed: no token, code, verifier or secret at any level
[ ] row counts match expectations; existing accounts still sign in as before
[ ] rollback tested or written down precisely
```
