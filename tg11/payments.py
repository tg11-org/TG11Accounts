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
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import PaymentHold, PaymentMethod, User, utcnow

log = logging.getLogger("tg11.payments")


class PaymentError(Exception):
    pass


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


class PlannedProvider(PaymentProvider):
    def __init__(self, info: ProviderInfo):
        self.info = info


PROVIDERS: Dict[str, PaymentProvider] = {
    "stripe": StripeProvider(),
    "paypal": PlannedProvider(ProviderInfo("paypal", "PayPal", "wallet", "not_configured" if not settings.PAYPAL_CLIENT_ID else "planned", "PayPal Vault (save a PayPal account) + Orders API with intent=AUTHORIZE for holds (3-day honour period, 29-day authorisation). Needs PAYPAL_CLIENT_ID/SECRET and the adapter.")),
    "venmo": PlannedProvider(ProviderInfo("venmo", "Venmo", "wallet", "planned", "Venmo is only available through PayPal (Braintree / PayPal Checkout with Venmo funding source, US only); holds follow the PayPal adapter.")),
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
