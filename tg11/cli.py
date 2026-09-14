# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""Admin CLI.

  python -m tg11.cli create-user --email .. --username .. [--password ..] [--staff]
  python -m tg11.cli add-client --client-id flowboard --name "Flowboard" --application flowboard \
        --redirect https://flowboard.fyi/auth/tg11/callback [--redirect ...] [--post-logout https://flowboard.fyi/login] \
        [--scopes "openid profile email"] [--trusted] [--public]
  python -m tg11.cli list-clients | rotate-secret --client-id .. | link --user .. --application .. --legacy-id ..
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys

from sqlalchemy import select

from .models import ApplicationIdentityLink, Base, OAuthClient, SessionLocal, engine
from .passwords import hash_password
from . import accounts


def _db():
    from .models import ensure_schema

    ensure_schema()
    return SessionLocal()


def cmd_create_user(a):
    db = _db()
    pw = a.password or getpass.getpass("Password: ")
    u = accounts.create_user(db, email=a.email, username=a.username, password=pw, display_name=a.display_name or "", verified=True, staff=a.staff)
    db.commit()
    print(f"created {u.username} <{u.email}> sub={u.id}")


def cmd_add_client(a):
    db = _db()
    c = db.scalar(select(OAuthClient).where(OAuthClient.client_id == a.client_id))
    secret = None if (a.public or (a.keep_secret and c is not None)) else secrets.token_urlsafe(40)
    if c is None:
        c = OAuthClient(client_id=a.client_id)
        db.add(c)
    c.name, c.application = a.name, a.application
    c.redirect_uris = "\n".join(a.redirect)
    c.post_logout_redirect_uris = "\n".join(a.post_logout or [])
    c.allowed_scopes = a.scopes
    c.trusted = bool(a.trusted)
    if a.home_url is not None: c.home_url = a.home_url
    if a.link_url is not None: c.link_url = a.link_url
    if a.icon is not None: c.icon = a.icon
    if a.description is not None: c.description = a.description
    if secret or c.client_secret_hash is None or not a.keep_secret:
        c.client_secret_hash = hash_password(secret) if secret else None
    db.commit()
    print(f"client_id={c.client_id}")
    print(f"client_secret={secret or ('(unchanged)' if a.keep_secret else '(public client, PKCE only)')}")


def cmd_list_clients(_a):
    db = _db()
    for c in db.scalars(select(OAuthClient)):
        print(f"{c.client_id:20} {c.name:24} app={c.application:12} trusted={c.trusted} enabled={c.enabled} scopes='{c.allowed_scopes}' redirects={c.redirect_uri_list}")


def cmd_rotate_secret(a):
    db = _db()
    c = db.scalar(select(OAuthClient).where(OAuthClient.client_id == a.client_id))
    if c is None:
        sys.exit("unknown client")
    secret = secrets.token_urlsafe(40)
    c.client_secret_hash = hash_password(secret)
    db.commit()
    print(f"client_secret={secret}")


def _user_or_die(db, who: str):
    from sqlalchemy import select

    from .models import User

    row = db.scalar(select(User).where((User.email == who) | (User.username == who) | (User.id == who)))
    if row is None:
        raise SystemExit(f"no such user: {who}")
    return row


def _parse_allowances(values):
    """--allowance flowboard.ai.requests=50/day  ->  {key: {limit, period}}"""
    out = {}
    for raw in values or []:
        key, _, spec = raw.partition("=")
        limit, _, period = spec.partition("/")
        if not key or not limit.isdigit():
            raise SystemExit(f"bad --allowance {raw!r}; expected key=LIMIT/period")
        out[key.strip()] = {"limit": int(limit), "period": (period or "day").strip()}
    return out


def cmd_entitlement_grant(a):
    from datetime import timedelta

    from . import entitlements as ent
    from .models import SessionLocal, utcnow

    db = SessionLocal()
    user = _user_or_die(db, a.user)
    expires = utcnow() + timedelta(days=a.days) if a.days else None
    row = ent.grant(db, user, a.kind, scope=a.scope, tier=a.tier or "", expires_at=expires,
                    source=a.source, note=a.note or "", allowances=_parse_allowances(a.allowance) or None)
    db.commit()
    print(f"granted {row.kind} ({row.scope}) to {user.username}"
          + (f" until {row.expires_at:%Y-%m-%d}" if row.expires_at else " with no expiry"))
    db.close()


def cmd_entitlement_revoke(a):
    from . import entitlements as ent
    from .models import SessionLocal

    db = SessionLocal()
    user = _user_or_die(db, a.user)
    n = ent.revoke(db, user, a.kind, a.scope)
    db.commit()
    print(f"revoked {n} entitlement(s) from {user.username}")
    db.close()


def cmd_entitlement_list(a):
    from . import entitlements as ent
    from .models import SessionLocal

    db = SessionLocal()
    user = _user_or_die(db, a.user)
    rows = ent.active(db, user, any_scope=True)
    for r in rows:
        print(f"{r.kind:16} {r.scope:22} {r.tier or '-':12} "
              f"{'until ' + r.expires_at.strftime('%Y-%m-%d') if r.expires_at else 'no expiry':22} {r.source}")
    print(f"credits: {ent.balance(db, user)}")
    for key in sorted(ent.DEFAULT_ALLOWANCES):
        s = ent.allowance_status(db, user, key, any_scope=True)
        print(f"allowance {key}: {s['used']}/{s['limit']} per {s['period']} (resets {s['resets_at']})")
    if not rows:
        print("(no entitlements)")
    db.close()


def cmd_credits_add(a):
    from . import entitlements as ent
    from .models import SessionLocal

    db = SessionLocal()
    user = _user_or_die(db, a.user)
    balance = ent.add_credits(db, user, a.amount, reason=a.reason or "manual grant", ref=a.ref or "")
    db.commit()
    print(f"{user.username} now has {balance} credits")
    db.close()


def cmd_link(a):
    db = _db()
    u = accounts.by_email(db, a.user) or accounts.by_username(db, a.user)
    if u is None:
        sys.exit("unknown user")
    db.add(ApplicationIdentityLink(user_id=u.id, application=a.application, legacy_id=a.legacy_id, local_uuid=a.local_uuid or "", federation_id=a.federation or "", migration_source="admin"))
    db.commit()
    print("linked")


def main(argv=None):
    p = argparse.ArgumentParser(prog="tg11")
    s = p.add_subparsers(dest="cmd", required=True)
    x = s.add_parser("create-user"); x.add_argument("--email", required=True); x.add_argument("--username", required=True); x.add_argument("--password"); x.add_argument("--display-name", dest="display_name"); x.add_argument("--staff", action="store_true"); x.set_defaults(fn=cmd_create_user)
    x = s.add_parser("add-client"); x.add_argument("--client-id", dest="client_id", required=True); x.add_argument("--name", required=True); x.add_argument("--application", required=True); x.add_argument("--redirect", action="append", required=True); x.add_argument("--post-logout", dest="post_logout", action="append"); x.add_argument("--scopes", default="openid profile email"); x.add_argument("--trusted", action="store_true"); x.add_argument("--public", action="store_true"); x.add_argument("--keep-secret", dest="keep_secret", action="store_true", help="update metadata without rotating the secret"); x.add_argument("--home-url", dest="home_url"); x.add_argument("--link-url", dest="link_url", help="URL where the app starts 'link my TG11 account'"); x.add_argument("--icon"); x.add_argument("--description"); x.set_defaults(fn=cmd_add_client)
    s.add_parser("list-clients").set_defaults(fn=cmd_list_clients)
    x = s.add_parser("rotate-secret"); x.add_argument("--client-id", dest="client_id", required=True); x.set_defaults(fn=cmd_rotate_secret)
    x = s.add_parser("entitlement-grant"); x.add_argument("--user", required=True); x.add_argument("--kind", required=True); x.add_argument("--scope", default="all", help="all or app:<client_id>"); x.add_argument("--tier", default=""); x.add_argument("--days", type=int, default=0, help="0 = no expiry"); x.add_argument("--source", default="manual"); x.add_argument("--note", default=""); x.add_argument("--allowance", action="append", help="key=LIMIT/period, e.g. flowboard.ai.requests=50/day"); x.set_defaults(fn=cmd_entitlement_grant)
    x = s.add_parser("entitlement-revoke"); x.add_argument("--user", required=True); x.add_argument("--kind", required=True); x.add_argument("--scope", default="all"); x.set_defaults(fn=cmd_entitlement_revoke)
    x = s.add_parser("entitlement-list"); x.add_argument("--user", required=True); x.set_defaults(fn=cmd_entitlement_list)
    x = s.add_parser("credits-add"); x.add_argument("--user", required=True); x.add_argument("--amount", type=int, required=True); x.add_argument("--reason", default=""); x.add_argument("--ref", default=""); x.set_defaults(fn=cmd_credits_add)
    x = s.add_parser("link"); x.add_argument("--user", required=True); x.add_argument("--application", required=True); x.add_argument("--legacy-id", dest="legacy_id", required=True); x.add_argument("--local-uuid", dest="local_uuid"); x.add_argument("--federation"); x.set_defaults(fn=cmd_link)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    main()
