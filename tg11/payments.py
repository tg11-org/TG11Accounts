# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""Provider-agnostic wallet + payment holds.

Users pick the provider they like; TG11 stores only references (customer ids,
payment-method ids, hold ids) - never card numbers or keys.  Applications
(FreeParty, Shop...) place *holds* through the API (`/api/v1/payments/...`)
using their client credentials, provided the user granted that app the
`tg11.payments` scope.

Provider adapters implement:
    begin_setup(user)                        -> dict describing how the UI collects the method
    complete_setup(user, payload)            -> PaymentMethod (active)
    authorize(method, amount, currency, ...) -> external hold id
    capture(hold, amount) / release(hold)
Only Stripe is fully implemented; the others are registered with their
integration notes so the UI, data model and API are already final.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import PaymentHold, PaymentMethod, User, utcnow

log = logging.getLogger("tg11.payments")


class PaymentError(Exception):
    pass


# Money crosses a provider boundary in whatever units that provider counts in.
# TG11 counts ISO minor units everywhere; these are the exceptions to the usual
# two decimal places, and the shorter list is what PayPal refuses decimals for.
ISO_ZERO_DECIMAL = {"BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF"}
ISO_THREE_DECIMAL = {"BHD", "JOD", "KWD", "OMR", "TND"}
PAYPAL_NO_DECIMALS = {"HUF", "JPY", "TWD"}


def iso_places(currency: str) -> int:
    currency = str(currency).upper()
    return 0 if currency in ISO_ZERO_DECIMAL else 3 if currency in ISO_THREE_DECIMAL else 2


def paypal_value(amount: int, currency: str) -> str:
    """Minor units -> the decimal string PayPal quotes money in."""
    places = 0 if str(currency).upper() in PAYPAL_NO_DECIMALS else iso_places(currency)
    return f"{Decimal(int(amount)) / (10 ** iso_places(currency)):.{places}f}"


@dataclass
class ProviderInfo:
    id: str
    name: str
    kind: str  # card|wallet|bank|crypto|internal
    status: str  # available|not_configured|planned
    notes: str = ""
    supports_holds: bool = True


class PaymentProvider:
    info: ProviderInfo

    def begin_setup(self, db: Session, user: User) -> Dict[str, Any]:
        raise PaymentError(f"{self.info.name} is not available yet")

    def complete_setup(self, db: Session, user: User, payload: Dict[str, Any]) -> PaymentMethod:
        raise PaymentError(f"{self.info.name} is not available yet")

    def authorize(self, method: PaymentMethod, amount: int, currency: str, description: str, reference: str) -> str:
        raise PaymentError(f"{self.info.name} cannot place holds yet")

    def capture(self, hold: PaymentHold, amount: int) -> None:
        raise PaymentError("capture not supported")

    def release(self, hold: PaymentHold) -> None:
        raise PaymentError("release not supported")

    def remove(self, method: PaymentMethod) -> None:
        return None


# --- Stripe (cards + Link) ------------------------------------------------------

class StripeProvider(PaymentProvider):
    api = "https://api.stripe.com/v1"

    def __init__(self):
        self.info = ProviderInfo("stripe", "Card / Link (Stripe)", "card", "available" if settings.stripe_configured else "not_configured", "Cards, Apple/Google Pay and Link via Stripe. Holds use manual-capture PaymentIntents (7-day authorisation window for cards).")

    def _req(self, method: str, path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            r = httpx.request(method, f"{self.api}{path}", data=data, auth=(settings.STRIPE_SECRET_KEY, ""), timeout=30)
        except httpx.HTTPError as exc:
            raise PaymentError(f"Stripe unreachable: {exc.__class__.__name__}")
        body = r.json() if r.content else {}
        if r.status_code >= 400:
            raise PaymentError((body.get("error") or {}).get("message") or f"Stripe error {r.status_code}")
        return body

    def _customer(self, db: Session, user: User) -> str:
        existing = db.scalar(select(PaymentMethod).where(PaymentMethod.user_id == user.id, PaymentMethod.provider == "stripe", PaymentMethod.external_customer_id != ""))
        if existing:
            return existing.external_customer_id
        c = self._req("POST", "/customers", {"email": user.email, "name": user.display_name or user.username, "metadata[tg11_user_id]": user.id})
        return c["id"]

    def begin_setup(self, db: Session, user: User) -> Dict[str, Any]:
        if not settings.stripe_configured:
            raise PaymentError("Stripe is not configured on this server")
        customer = self._customer(db, user)
        si = self._req("POST", "/setup_intents", {"customer": customer, "payment_method_types[]": "card", "usage": "off_session", "metadata[tg11_user_id]": user.id})
        return {"mode": "stripe_elements", "client_secret": si["client_secret"], "publishable_key": settings.STRIPE_PUBLISHABLE_KEY, "customer": customer}

    def complete_setup(self, db: Session, user: User, payload: Dict[str, Any]) -> PaymentMethod:
        si = self._req("GET", f"/setup_intents/{payload.get('setup_intent', '')}")
        if si.get("status") != "succeeded" or si.get("metadata", {}).get("tg11_user_id") != user.id:
            raise PaymentError("Card setup did not complete")
        pm = self._req("GET", f"/payment_methods/{si['payment_method']}")
        card = pm.get("card") or {}
        label = f"{(card.get('brand') or 'card').title()} •••• {card.get('last4', '????')}"
        method = PaymentMethod(user_id=user.id, provider="stripe", kind="card", label=label, external_customer_id=si["customer"], external_method_id=pm["id"], status="active", meta_json=json.dumps({"exp": f"{card.get('exp_month')}/{card.get('exp_year')}", "wallet": (card.get("wallet") or {}).get("type")}))
        db.add(method)
        db.flush()
        return method

    def authorize(self, method: PaymentMethod, amount: int, currency: str, description: str, reference: str) -> str:
        pi = self._req("POST", "/payment_intents", {"amount": amount, "currency": currency, "customer": method.external_customer_id, "payment_method": method.external_method_id, "capture_method": "manual", "confirm": "true", "off_session": "true", "description": description[:200], "metadata[tg11_reference]": reference[:120], "metadata[tg11_user_id]": method.user_id})
        if pi.get("status") != "requires_capture":
            raise PaymentError(f"authorisation not completed (status {pi.get('status')})")
        return pi["id"]

    def capture(self, hold: PaymentHold, amount: int) -> None:
        self._req("POST", f"/payment_intents/{hold.external_id}/capture", {"amount_to_capture": amount})

    def release(self, hold: PaymentHold) -> None:
        self._req("POST", f"/payment_intents/{hold.external_id}/cancel", {})

    def remove(self, method: PaymentMethod) -> None:
        if method.external_method_id:
            try:
                self._req("POST", f"/payment_methods/{method.external_method_id}/detach", {})
            except PaymentError:
                pass


# --- PayPal (a saved PayPal account) --------------------------------------------

class PayPalProvider(PaymentProvider):
    """A PayPal account saved once and charged later.

    PayPal's own names for the three pieces: a *setup token* is the approval the
    person gives at PayPal, a *payment token* is what TG11 keeps afterwards, and
    an *authorization* is the hold an application places against it. TG11 stores
    the token ids and the payer's email address - never credentials, never a
    funding instrument.
    """

    def __init__(self):
        self.info = ProviderInfo(
            "paypal", "PayPal", "wallet",
            "available" if settings.paypal_configured else "not_configured",
            "Approve TG11 at PayPal once (PayPal Vault), then apps place holds against the saved account. PayPal honours an authorisation for 3 days and keeps it voidable for 29. Saving an account needs PayPal to switch Vault on for the merchant account first.",
        )
        self._access: tuple[str, float] = ("", 0.0)

    @property
    def api(self) -> str:
        return settings.paypal_api

    def _token(self) -> str:
        import time

        token, expires = self._access
        if token and expires > time.time() + 60:
            return token
        try:
            r = httpx.post(f"{self.api}/v1/oauth2/token", data={"grant_type": "client_credentials"},
                           auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET), timeout=30)
        except httpx.HTTPError as exc:
            raise PaymentError(f"PayPal unreachable: {exc.__class__.__name__}")
        if r.status_code >= 400:
            raise PaymentError("PayPal rejected this server's credentials")
        body = r.json()
        self._access = (body.get("access_token", ""), time.time() + float(body.get("expires_in", 0) or 0))
        return self._access[0]

    def _req(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json",
                   "PayPal-Request-Id": uuid4().hex}
        try:
            r = httpx.request(method, f"{self.api}{path}", json=body, headers=headers, timeout=30)
        except httpx.HTTPError as exc:
            raise PaymentError(f"PayPal unreachable: {exc.__class__.__name__}")
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            detail = (data.get("details") or [{}])[0]
            raise PaymentError(str(detail.get("description") or data.get("message") or f"PayPal error {r.status_code}")[:200])
        return data if isinstance(data, dict) else {}

    def begin_setup(self, db: Session, user: User) -> Dict[str, Any]:
        if not settings.paypal_configured:
            raise PaymentError("PayPal is not configured on this server")
        try:
            data = self._setup_token()
        except PaymentError as exc:
            if "not allowed to vault" in str(exc).lower() or "not_enabled_to_vault" in str(exc).lower():
                raise PaymentError("PayPal has not switched Vault on for this merchant account yet, so a PayPal account cannot be saved here. Ask PayPal support to enable saved payment methods, then try again.")
            raise
        approve = next((l.get("href", "") for l in data.get("links", []) if l.get("rel") in ("approve", "payer-action")), "")
        if not approve:
            raise PaymentError("PayPal did not offer an approval link")
        return {"mode": "redirect", "url": approve, "setup_token": data.get("id", "")}

    def _setup_token(self) -> Dict[str, Any]:
        return self._req("POST", "/v3/vault/setup-tokens", {
            "payment_source": {"paypal": {
                "usage_type": "MERCHANT",
                "customer_type": "CONSUMER",
                "permit_multiple_payment_tokens": False,
                "experience_context": {
                    "brand_name": settings.TG11_SITE_NAME,
                    "vault_instruction": "ON_CREATE_PAYMENT_TOKENS",
                    "shipping_preference": "NO_SHIPPING",
                    "return_url": f"{settings.issuer}/wallet/paypal/complete",
                    "cancel_url": f"{settings.issuer}/wallet?err=PayPal+setup+was+cancelled",
                },
            }},
        })

    def complete_setup(self, db: Session, user: User, payload: Dict[str, Any]) -> PaymentMethod:
        setup_token = str(payload.get("approval_token_id") or payload.get("setup_token") or "").strip()
        if not setup_token:
            raise PaymentError("PayPal setup was not completed")
        data = self._req("POST", "/v3/vault/payment-tokens", {"payment_source": {"token": {"id": setup_token, "type": "SETUP_TOKEN"}}})
        if not data.get("id"):
            raise PaymentError("PayPal did not return a saved account")
        source = (data.get("payment_source") or {}).get("paypal") or {}
        email = str(source.get("email_address", ""))
        method = PaymentMethod(
            user_id=user.id, provider="paypal", kind="wallet",
            label=f"PayPal ({email})" if email else "PayPal account",
            external_customer_id=str((data.get("customer") or {}).get("id", "")),
            external_method_id=str(data["id"]), status="active",
            meta_json=json.dumps({"email": email, "payer_id": source.get("account_id", ""), "env": settings.PAYPAL_ENV}),
        )
        db.add(method)
        db.flush()
        return method

    def authorize(self, method: PaymentMethod, amount: int, currency: str, description: str, reference: str) -> str:
        order = self._req("POST", "/v2/checkout/orders", {
            "intent": "AUTHORIZE",
            "purchase_units": [{
                "custom_id": (reference or method.user_id)[:127],
                "description": (description or "TG11 authorisation")[:127],
                "amount": {"currency_code": currency.upper(), "value": paypal_value(amount, currency)},
            }],
            "payment_source": {"paypal": {"vault_id": method.external_method_id}},
        })
        if order.get("status") not in ("COMPLETED", "APPROVED"):
            raise PaymentError(f"PayPal would not charge the saved account (order {order.get('status', 'unknown')})")
        if not self._authorization_id(order):
            order = self._req("POST", f"/v2/checkout/orders/{order.get('id', '')}/authorize", {})
        hold_id = self._authorization_id(order)
        if not hold_id:
            raise PaymentError("PayPal did not place an authorisation")
        return hold_id

    @staticmethod
    def _authorization_id(order: Dict[str, Any]) -> str:
        for unit in order.get("purchase_units") or []:
            for auth in (unit.get("payments") or {}).get("authorizations") or []:
                if auth.get("id") and auth.get("status") in ("CREATED", "PENDING", None):
                    return str(auth["id"])
        return ""

    def capture(self, hold: PaymentHold, amount: int) -> None:
        self._req("POST", f"/v2/payments/authorizations/{hold.external_id}/capture", {
            "amount": {"currency_code": hold.currency.upper(), "value": paypal_value(amount, hold.currency)},
            "final_capture": True,
        })

    def release(self, hold: PaymentHold) -> None:
        self._req("POST", f"/v2/payments/authorizations/{hold.external_id}/void", None)

    def remove(self, method: PaymentMethod) -> None:
        if method.external_method_id:
            try:
                self._req("DELETE", f"/v3/vault/payment-tokens/{method.external_method_id}")
            except PaymentError:
                pass


class PlannedProvider(PaymentProvider):
    def __init__(self, info: ProviderInfo):
        self.info = info


PROVIDERS: Dict[str, PaymentProvider] = {
    "stripe": StripeProvider(),
    "paypal": PayPalProvider(),
    "venmo": PlannedProvider(ProviderInfo("venmo", "Venmo", "wallet", "planned", "Venmo is only available through PayPal (Braintree / PayPal Checkout with Venmo funding source, US only); holds follow the PayPal adapter, which is implemented.")),
    "cashapp": PlannedProvider(ProviderInfo("cashapp", "Cash App Pay", "wallet", "planned", "Cash App Pay is offered through Stripe (payment_method_types cashapp) or Block's own API; Stripe route can reuse the Stripe adapter once enabled on your Stripe account. Cash App Pay does not support authorisation holds - charges are immediate.", supports_holds=False)),
    "airwallex": PlannedProvider(ProviderInfo("airwallex", "Airwallex", "card", "planned", "Airwallex Payment Acceptance API: PaymentConsents (saved cards) + PaymentIntents with capture_method=manual. Needs API key + client id.")),
    "adyen": PlannedProvider(ProviderInfo("adyen", "Adyen", "card", "planned", "Adyen Checkout: tokenised shopperReference + /payments with manual capture (adjust/capture/cancel). Needs merchant account + API key.")),
    "btc": PlannedProvider(ProviderInfo("btc", "Bitcoin", "crypto", "planned", "On-chain BTC cannot be 'held' like a card. Planned model: per-user deposit address derived from a TG11 xpub, a chain watcher credits an internal balance, and holds reserve balance (escrow) that apps capture/release. Needs a node/indexer (e.g. mempool.space API) and a hot-wallet policy for payouts.", supports_holds=True)),
    "eth": PlannedProvider(ProviderInfo("eth", "Ethereum / ERC-20", "crypto", "planned", "Same escrow-balance model as BTC using an RPC provider (Alchemy/Infura) and per-user deposit addresses; ERC-20 (USDC) recommended for stable holds.")),
    "tg11coin": PlannedProvider(ProviderInfo("tg11coin", "TG11 Coin", "internal", "planned", "Your own coin: once the chain/ledger is reachable over an API, register it here as an internal-balance provider (same escrow model as BTC/ETH). Value/peg is a product question, the adapter is mechanical.")),
    "foxpay": PlannedProvider(ProviderInfo("foxpay", "FoxPay", "wallet", "planned", "Reserved for your FoxPay project: implement PaymentProvider (setup → link account, authorize/capture/release) and register it here.")),
}


def provider_list() -> List[ProviderInfo]:
    return [p.info for p in PROVIDERS.values()]


def get_provider(pid: str) -> PaymentProvider:
    try:
        return PROVIDERS[pid]
    except KeyError:
        raise PaymentError("unknown payment provider")


# --- service ---------------------------------------------------------------------

def list_methods(db: Session, user: User) -> List[PaymentMethod]:
    return list(db.scalars(select(PaymentMethod).where(PaymentMethod.user_id == user.id, PaymentMethod.status != "removed").order_by(PaymentMethod.created_at)))


def get_method(db: Session, user: User, method_id: str) -> Optional[PaymentMethod]:
    m = db.get(PaymentMethod, method_id)
    return m if m is not None and m.user_id == user.id and m.status != "removed" else None


def default_method(db: Session, user: User, provider: Optional[str] = None) -> Optional[PaymentMethod]:
    methods = [m for m in list_methods(db, user) if m.status == "active" and (provider is None or m.provider == provider)]
    for m in methods:
        if m.is_default:
            return m
    return methods[0] if methods else None


def set_default(db: Session, user: User, method: PaymentMethod) -> None:
    for m in list_methods(db, user):
        m.is_default = m.id == method.id
    db.flush()


def remove_method(db: Session, user: User, method: PaymentMethod) -> None:
    open_holds = db.scalar(select(PaymentHold).where(PaymentHold.method_id == method.id, PaymentHold.status == "authorized"))
    if open_holds is not None:
        raise PaymentError("This method has an active hold; it can be removed once the hold is captured or released.")
    get_provider(method.provider).remove(method)
    method.status = "removed"
    db.flush()


def list_holds(db: Session, user: User) -> List[PaymentHold]:
    return list(db.scalars(select(PaymentHold).where(PaymentHold.user_id == user.id).order_by(PaymentHold.created_at.desc()).limit(100)))


def place_hold(db: Session, user: User, client_id: str, amount: int, currency: str, description: str, reference: str, method: Optional[PaymentMethod] = None, ttl_days: int = 7) -> PaymentHold:
    if amount <= 0:
        raise PaymentError("amount must be positive (minor units)")
    method = method or default_method(db, user)
    if method is None:
        raise PaymentError("user has no active payment method")
    provider = get_provider(method.provider)
    if not provider.info.supports_holds:
        raise PaymentError(f"{provider.info.name} does not support holds")
    hold = PaymentHold(user_id=user.id, client_id=client_id, method_id=method.id, provider=method.provider, amount=amount, currency=currency.lower(), description=description[:200], reference=reference[:120], expires_at=utcnow() + timedelta(days=ttl_days))
    db.add(hold)
    db.flush()
    try:
        hold.external_id = provider.authorize(method, amount, currency.lower(), description, reference)
        hold.status = "authorized"
    except PaymentError as exc:
        hold.status, hold.error = "failed", str(exc)[:300]
    db.flush()
    return hold


def capture_hold(db: Session, hold: PaymentHold, amount: Optional[int] = None) -> PaymentHold:
    if hold.status != "authorized":
        raise PaymentError(f"hold is {hold.status}")
    amt = amount or hold.amount
    if amt > hold.amount:
        raise PaymentError("cannot capture more than authorised")
    get_provider(hold.provider).capture(hold, amt)
    hold.captured_amount, hold.status = amt, "captured"
    db.flush()
    return hold


def release_hold(db: Session, hold: PaymentHold) -> PaymentHold:
    if hold.status != "authorized":
        raise PaymentError(f"hold is {hold.status}")
    get_provider(hold.provider).release(hold)
    hold.status = "released"
    db.flush()
    return hold


def hold_dict(h: PaymentHold) -> Dict[str, Any]:
    return {"id": h.id, "user_id": h.user_id, "client_id": h.client_id, "provider": h.provider, "amount": h.amount, "currency": h.currency, "captured_amount": h.captured_amount, "status": h.status, "reference": h.reference, "description": h.description, "error": h.error, "expires_at": h.expires_at.isoformat() + "Z" if h.expires_at else None, "created_at": h.created_at.isoformat() + "Z"}
