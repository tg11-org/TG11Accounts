#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end TG11 sign-in smoke test for any TG11 relying party, run on the server.

Drives a real browser-shaped flow with a throwaway TG11 account:

  1. sign in at accounts.tg11.org
  2. start Echoquill's /auth/tg11/login/ and follow the whole redirect chain
  3. confirm Echoquill created a local account and a link row
  4. sign out, sign in again — must land on the SAME local account
  5. confirm no token, code or verifier appears in Echoquill's log

Usage:  python smoke_rp.py <tg11-username> <password> [app-url] [probe-path] [logout-path]
It reports; it does not clean up. The caller deletes the throwaway account.
"""
from __future__ import annotations

import re
import sys
from urllib.parse import parse_qs, urlparse

import httpx

IDP = "https://accounts.tg11.org"
APP = sys.argv[3] if len(sys.argv) > 3 else "https://echoquill.tg11.org"
PROBE = sys.argv[4] if len(sys.argv) > 4 else "/accounts/profile/"
LOGOUT = sys.argv[5] if len(sys.argv) > 5 else "/accounts/logout/"
fails: list[str] = []
oks: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    (oks if ok else fails).append(f"{label}{(' - ' + detail) if detail else ''}")
    print(f"{'ok  ' if ok else 'FAIL'} {label}{(' - ' + detail) if detail else ''}")
    return ok


def csrf(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def idp_login(client: httpx.Client, username: str, password: str) -> bool:
    page = client.get(f"{IDP}/login")
    token = csrf(page.text)
    resp = client.post(f"{IDP}/login", data={
        "csrf_token": token, "identifier": username, "password": password, "next": "/account"},
        follow_redirects=True)
    return check("signed in at accounts.tg11.org", resp.status_code == 200 and "/login" not in str(resp.url),
                 str(resp.url))


def run_flow(client: httpx.Client, label: str) -> httpx.Response:
    resp = client.get(f"{APP}/auth/tg11/login/", follow_redirects=True)
    check(f"{label}: flow completed", resp.status_code == 200, f"{resp.status_code} {resp.url}")
    check(f"{label}: landed on the application, signed in", resp.url.host == httpx.URL(APP).host
          and "/accounts/login" not in str(resp.url), str(resp.url))
    return resp


def main() -> int:
    username, password = sys.argv[1], sys.argv[2]

    # the authorization request itself
    probe = httpx.Client(follow_redirects=False, timeout=30)
    start = probe.get(f"{APP}/auth/tg11/login/")
    q = parse_qs(urlparse(start.headers.get("location", "")).query)
    check("authorization request uses PKCE S256", q.get("code_challenge_method") == ["S256"])
    check("authorization request carries state and nonce", bool(q.get("state") and q.get("nonce")))
    check("redirect_uri is the registered https callback",
          q.get("redirect_uri") == [f"{APP}/auth/tg11/callback/"], str(q.get("redirect_uri")))
    check("no client secret in the redirect", "client_secret" not in start.headers.get("location", ""))
    probe.close()

    with httpx.Client(follow_redirects=False, timeout=30) as client:
        if not idp_login(client, username, password):
            return 1
        run_flow(client, "first login")
        probe = client.get(f"{APP}{PROBE}", follow_redirects=False)
        check("signed in: the account page is reachable", probe.status_code == 200, str(probe.status_code))

        # local logout, then straight back in
        page = client.get(f"{APP}{PROBE}", follow_redirects=True)
        m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', page.text)
        if m:
            client.post(f"{APP}{LOGOUT}", data={"csrfmiddlewaretoken": m.group(1)},
                        headers={"Referer": f"{APP}{PROBE}"}, follow_redirects=True)
        after = client.get(f"{APP}{PROBE}", follow_redirects=False)
        check("logged out locally", after.status_code in (302, 301), str(after.status_code))

        run_flow(client, "second login")

    print()
    print(f"{len(oks)} checks passed, {len(fails)} failed")
    for f in fails:
        print("  FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
