# tg11-auth

The TG11 ecosystem OpenID Connect relying party for Django. One TG11 identity
(a UUID — the `sub` claim) across every TG11 service; each application keeps
owning its own data.

Full background: `docs/TG11_IDENTITY.md`. Step-by-step per-application recipe:
`docs/TG11_APP_INTEGRATION.md`. This README is the short version.

## Install

```bash
pip install -e /srv/tg11-accounts/clients/django    # or a wheel / git URL
```

```python
INSTALLED_APPS += ["tg11_auth"]
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "tg11_auth.backends.TG11Backend",              # recommended, not required
]

TG11_OIDC_ISSUER        = env("TG11_OIDC_ISSUER")        # https://accounts.tg11.org
TG11_OIDC_CLIENT_ID     = env("TG11_OIDC_CLIENT_ID")     # freeparty
TG11_OIDC_CLIENT_SECRET = env("TG11_OIDC_CLIENT_SECRET")
TG11_OIDC_REDIRECT_URI  = env("TG11_OIDC_REDIRECT_URI")  # https://freeparty.dev/auth/tg11/callback/
TG11_APPLICATION        = "freeparty"
```

```python
urlpatterns += [path("auth/tg11/", include("tg11_auth.urls"))]
```

```bash
python manage.py migrate tg11_auth
```

The issuer is **never** hard-coded — it comes from the environment, so a staging
deployment can point at a staging provider.

## Use

```django
{% include "tg11_auth/button.html" %}                      {# login page #}
{% include "tg11_auth/button.html" with link_mode=True %}  {# account settings #}
```

Add `tg11_auth.context_processors.tg11` to `TEMPLATES` so those includes know
whether TG11 is configured and already linked, or pass `tg11_configured` /
`tg11_linked` yourself.

Routes mounted: `login/`, `callback/`, `link/`, `unlink/`, `logout/`.
`unlink/` and `logout/` are POST-only (CSRF-protected); `logout/` takes
`global=1` to also end the session at TG11.

## How a login resolves to a local account

1. A link row for this `sub` exists → that account. The `sub` is the only
   identifier trusted; email and username change.
2. No link, a local account has the same email **and** the provider asserts
   `email_verified` → linked (`verified_email`).
3. Same email but **not** verified → refused, with "sign in and link from your
   settings". Accounts are never merged on an unverified address.
4. Nothing matches → a new local account with an unusable password
   (`oidc_login`), unless `TG11_AUTH_AUTOCREATE = False`.

Suspended or limited TG11 accounts are refused before any of that.

## Application-specific profile data

```python
TG11_AUTH_PROFILE_HOOK = "myapp.auth.on_tg11_login"

def on_tg11_login(*, user, claims, created, link, request):
    Profile.objects.get_or_create(user=user)     # keyed on the local user,
                                                 # which is keyed on the TG11 UUID
```

Exceptions raised in the hook are logged, never fatal to a sign-in.

## Settings reference

| Setting | Default | Meaning |
| --- | --- | --- |
| `TG11_OIDC_ISSUER` | — | required |
| `TG11_OIDC_CLIENT_ID` | — | required |
| `TG11_OIDC_CLIENT_SECRET` | `""` | omit for a public client |
| `TG11_OIDC_REDIRECT_URI` | — | required, must match the registered URI exactly |
| `TG11_OIDC_SCOPES` | `openid profile email` | add `tg11.profile` for `account_state` |
| `TG11_APPLICATION` | client id | stable app id stamped on link rows |
| `TG11_AUTH_AUTOCREATE` | `True` | create a local account for a new `sub` |
| `TG11_AUTH_AUTOLINK_VERIFIED_EMAIL` | `True` | rule 2 above |
| `TG11_AUTH_REQUIRE_ACTIVE_STATE` | `True` | refuse suspended/limited accounts |
| `TG11_AUTH_PROFILE_HOOK` | `""` | dotted path |
| `TG11_AUTH_LOGIN_REDIRECT` | `LOGIN_REDIRECT_URL` | after sign-in |
| `TG11_AUTH_POST_LOGOUT_REDIRECT` | `/` | after sign-out |
| `TG11_AUTH_ACCOUNT_URL` | guessed | where "link"/"unlink" return to |
| `TG11_AUTH_BASE_TEMPLATE` | `tg11_auth/_standalone.html` | your own base template |
| `TG11_AUTH_FEDERATION_ID` | `""` | stamped on link rows (FurryParty etc.) |
| `TG11_AUTH_ALLOW_LOCKOUT` | `False` | permit unlinking with no local password |

## Security properties worth keeping

* Authorization code + PKCE (S256). `state`, `nonce` and the verifier live in
  the server-side session, are single-use and expire after 10 minutes.
* Every ID token is checked for signature (JWKS, one forced refresh to survive
  key rotation), `iss`, `aud`, `azp`, `exp`, `iat` skew, `nonce` and `sub`.
* `userinfo` is only merged when its `sub` matches the ID token's.
* **Refresh tokens never reach the browser and are never stored in the session.**
  Nothing token-shaped is logged.
* `login()` cycles the session key; `next` goes through
  `url_has_allowed_host_and_scheme`.
* No shared cookies between domains, and no application ever talks to the
  identity database — everything is standard OIDC over HTTPS.

## Tests

```bash
cd clients/django && python -m pytest
```

The suite runs against a fake provider (locally generated RS256 key, stubbed
discovery/token/userinfo), so it needs no network and no accounts.tg11.org.
