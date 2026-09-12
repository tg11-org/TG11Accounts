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
    x = s.add_parser("link"); x.add_argument("--user", required=True); x.add_argument("--application", required=True); x.add_argument("--legacy-id", dest="legacy_id", required=True); x.add_argument("--local-uuid", dest="local_uuid"); x.add_argument("--federation"); x.set_defaults(fn=cmd_link)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    main()
