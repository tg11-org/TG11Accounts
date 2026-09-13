# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""The six views an application needs: start, callback, link, unlink, logout.

Security notes, because this is the part that is easy to get subtly wrong:

* `state`, `nonce` and the PKCE verifier live in the **server-side session**
  only, are single-use (popped on callback) and expire after ``FLOW_TTL``.
* `state` is compared with `secrets.compare_digest`.
* `next` is validated with `url_has_allowed_host_and_scheme`, so an open
  redirect cannot be smuggled through the login link.
* `django.contrib.auth.login()` cycles the session key, so a pre-login session
  cannot be fixated.
* **Refresh tokens are never written to the session and never leave the
  server.** Only the ID token is kept, and only to use as `id_token_hint` on
  RP-initiated logout. Nothing token-shaped is logged.
* Logout and unlink are POST-only, so they are CSRF-protected and cannot be
  triggered by a third-party page.
"""
from __future__ import annotations

import logging
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import NoReverseMatch, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from . import conf, services
from .backends import BACKEND_PATH
from .client import OIDCClient, OIDCError, get_client

log = logging.getLogger("tg11_auth")

FLOW_SESSION_KEY = "tg11_auth_flow"
ID_TOKEN_SESSION_KEY = "tg11_auth_id_token"
SUBJECT_SESSION_KEY = "tg11_auth_sub"
FLOW_TTL = 600  # seconds a half-finished login stays valid
ALLOWED_PROMPTS = {"login", "consent", "select_account", "none"}


# ---- helpers ------------------------------------------------------------
def _base_template() -> str:
    return str(conf.get("TG11_AUTH_BASE_TEMPLATE") or "tg11_auth/_standalone.html")


def _render_error(request, message: str, *, status: int = 400, retry: bool = True) -> HttpResponse:
    log.warning("tg11_auth: %s", message)
    return render(
        request,
        "tg11_auth/error.html",
        {
            "base_template": _base_template(),
            "message": message,
            "retry": retry,
            "home_url": conf.post_logout_redirect(),
        },
        status=status,
    )


def _safe_next(request, param: str = "next") -> str:
    candidate = request.POST.get(param) or request.GET.get(param) or ""
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return ""


def _absolute(request, url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    return request.build_absolute_uri(url or "/")


def _login_user(request, user) -> None:
    """`login()` needs a backend path that is actually installed, or `get_user`
    drops the session on the next request."""
    installed = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
    if BACKEND_PATH in installed:
        backend = BACKEND_PATH
    elif "django.contrib.auth.backends.ModelBackend" in installed:
        backend = "django.contrib.auth.backends.ModelBackend"
    elif installed:
        backend = installed[0]
    else:  # pragma: no cover - Django always defaults to ModelBackend
        backend = "django.contrib.auth.backends.ModelBackend"
    auth_login(request, user, backend=backend)


def _remember(request, claims) -> None:
    request.session[ID_TOKEN_SESSION_KEY] = claims.id_token
    request.session[SUBJECT_SESSION_KEY] = claims.subject
    # claims.refresh_token is deliberately dropped here: nothing needs it, and a
    # session-stored refresh token is a long-lived credential in a cookie jar.


def _forget(request) -> Optional[str]:
    request.session.pop(FLOW_SESSION_KEY, None)
    request.session.pop(SUBJECT_SESSION_KEY, None)
    return request.session.pop(ID_TOKEN_SESSION_KEY, None)


def _start(request, mode: str) -> HttpResponse:
    if not conf.is_configured():
        return _render_error(request, "TG11 sign-in is not configured on this site.", status=503, retry=False)
    try:
        client = get_client()
        flow: Dict[str, Any] = OIDCClient.new_flow_state()
        flow["mode"] = mode
        flow["created"] = time.time()
        flow["next"] = _safe_next(request)
        prompt = request.GET.get("prompt", "")
        url = client.authorization_url(
            flow,
            prompt=prompt if prompt in ALLOWED_PROMPTS else None,
            login_hint=request.GET.get("login_hint", "")[:254],
            acr_values=conf.ACR_MFA if conf.require_mfa() else "",
            max_age=conf.max_age(),
        )
    except OIDCError as exc:
        return _render_error(request, f"Could not reach TG11 right now ({exc}).", status=502)
    request.session[FLOW_SESSION_KEY] = flow
    return HttpResponseRedirect(url)


def _after_login_url(request, flow: Dict[str, Any]) -> str:
    return flow.get("next") or conf.login_redirect()


def _settings_url() -> str:
    """Where to send someone who has just linked or must link.  Applications
    override it with TG11_AUTH_ACCOUNT_URL; otherwise we guess sensibly."""
    configured = conf.get("TG11_AUTH_ACCOUNT_URL")
    if configured:
        return str(configured)
    for name in ("account_settings", "settings", "profile", "account"):
        try:
            return reverse(name)
        except NoReverseMatch:
            continue
    return conf.login_redirect()


# ---- views --------------------------------------------------------------
@never_cache
def login(request) -> HttpResponse:
    """Start a TG11 login.  ``?next=`` is honoured if it is local."""
    if request.user.is_authenticated and not request.GET.get("force"):
        return redirect(_safe_next(request) or conf.login_redirect())
    return _start(request, "login")


@never_cache
@login_required
def link(request) -> HttpResponse:
    """Attach a TG11 identity to the account the user is *already* signed in to.
    This is the safe path for accounts that predate TG11."""
    return _start(request, "link")


@never_cache
def callback(request) -> HttpResponse:
    flow = request.session.pop(FLOW_SESSION_KEY, None)  # single use, whatever happens next

    if request.GET.get("error"):
        code = request.GET["error"][:64]
        if code == "access_denied":
            return redirect(conf.post_logout_redirect())
        return _render_error(request, f"TG11 refused the sign-in ({code}).")

    if not isinstance(flow, dict) or not flow.get("state"):
        return _render_error(request, "That sign-in link has already been used or the session expired. Please try again.")
    if time.time() - float(flow.get("created") or 0) > FLOW_TTL:
        return _render_error(request, "That sign-in took too long and expired. Please try again.")
    if not secrets.compare_digest(str(request.GET.get("state", "")), str(flow["state"])):
        return _render_error(request, "Sign-in could not be verified (state mismatch). Please try again.")
    code = request.GET.get("code", "")
    if not code:
        return _render_error(request, "TG11 did not return an authorization code.")

    try:
        claims = get_client().exchange(code, flow)
    except OIDCError as exc:
        return _render_error(request, f"TG11 sign-in failed: {exc}", status=502)

    if flow.get("mode") == "link":
        if not request.user.is_authenticated:
            return _render_error(request, "You were signed out before the link completed. Sign in and try again.")
        try:
            services.link_to_current_user(request.user, claims, request=request)
        except services.AuthError as exc:
            return _render_error(request, str(exc), status=409)
        _remember(request, claims)
        return redirect(flow.get("next") or _settings_url())

    try:
        user, created, _link = services.resolve_user(claims, request=request)
    except services.LinkRequired as exc:
        return render(
            request,
            "tg11_auth/link_required.html",
            {"base_template": _base_template(), "email": exc.email, "message": str(exc),
             "login_url": _local_login_url(request), "home_url": conf.post_logout_redirect()},
            status=409,
        )
    except services.AuthError as exc:
        return _render_error(request, str(exc), status=403)

    _login_user(request, user)  # cycles the session key
    _remember(request, claims)
    log.info("tg11_auth: signed in (app=%s created=%s)", conf.application(), created)
    return redirect(_after_login_url(request, flow))


def _local_login_url(request) -> str:
    for name in ("login", "account_login", "accounts:login"):
        try:
            return reverse(name)
        except NoReverseMatch:
            continue
    return str(getattr(settings, "LOGIN_URL", "/") or "/")


@never_cache
@require_POST
def logout(request) -> HttpResponse:
    """Local logout, plus RP-initiated logout at TG11 when ``global=1``.

    Kept POST-only so a cross-site GET cannot sign people out.
    """
    id_token = _forget(request)
    wants_global = request.POST.get("global") in ("1", "true", "on", "yes")
    auth_logout(request)
    target = _safe_next(request) or conf.post_logout_redirect()
    if wants_global and conf.is_configured():
        try:
            url = get_client().end_session_url(_absolute(request, target), id_token or "")
        except OIDCError:
            url = None
        if url:
            return HttpResponseRedirect(url)
    return redirect(target)


@never_cache
@require_POST
@login_required
def unlink(request) -> HttpResponse:
    """Detach TG11 from this account - refused if it would lock the user out."""
    user = request.user
    if not user.has_usable_password() and not conf.get("TG11_AUTH_ALLOW_LOCKOUT", False):
        return _render_error(
            request,
            "Set a password here first - TG11 is currently the only way into this account.",
            status=409,
            retry=False,
        )
    services.unlink(user)
    _forget(request)
    return redirect(_safe_next(request) or _settings_url())


def status(request) -> Dict[str, Any]:
    """Small context helper for templates/other views (not routed)."""
    linked = False
    if request.user.is_authenticated:
        linked = services.TG11IdentityLink.objects.filter(user=request.user).exists()
    return {
        "tg11_configured": conf.is_configured(),
        "tg11_linked": linked,
        "tg11_issuer_host": urlparse(str(conf.get("TG11_OIDC_ISSUER", "") or "")).netloc,
    }
