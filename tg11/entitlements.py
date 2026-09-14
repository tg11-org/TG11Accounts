# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""What a person is entitled to, across every TG11 application.

Three ideas, deliberately separate:

* An **entitlement** is a durable grant - "supporter", "ads_free" - scoped
  either to everything (`all`) or to one application (`app:flowboard`). It can
  expire, it can be revoked, and it records where it came from so a future
  subscription system can hang off the same table.
* An **allowance** is a quota that refills on a clock: 20 assistant requests a
  day, say. Free limits are declared in code (`DEFAULT_ALLOWANCES`) so everyone
  gets them without a row existing; an entitlement can raise them.
* **Credits** are a purchased balance spent when the allowance runs out. The
  balance is the sum of a ledger rather than a column, so it cannot silently
  drift away from its own history.

Nothing here knows about money. A grant's `source` is a free-form string, so
whatever eventually pays for these - Fox Pay, a coupon, an operator's goodwill
- writes the same rows.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import CreditLedger, Entitlement, AllowanceUsage, User, utcnow

SCOPE_ALL = "all"

# Free limits everybody gets, with no row in the database. An entitlement that
# names the same key raises the limit; it never lowers it.
DEFAULT_ALLOWANCES: Dict[str, Dict[str, Any]] = {
    # key: {"limit": int, "period": "day"|"week"|"month"}
    "flowboard.ai.requests": {"limit": 0, "period": "day"},
}

PERIODS = ("day", "week", "month")


class EntitlementError(Exception):
    pass


# --- scopes ---------------------------------------------------------------

def app_scope(application: str) -> str:
    return f"app:{application}" if application and application != SCOPE_ALL else SCOPE_ALL


def scopes_for(application: Optional[str]) -> List[str]:
    """The scopes that answer for this application: its own, plus everything."""
    return [SCOPE_ALL] if not application else [SCOPE_ALL, app_scope(application)]


# --- periods --------------------------------------------------------------

def period_start(period: str, now: Optional[datetime] = None) -> date:
    now = now or utcnow()
    today = now.date()
    if period == "day":
        return today
    if period == "week":  # ISO weeks, Monday
        return today - timedelta(days=today.weekday())
    if period == "month":
        return today.replace(day=1)
    raise EntitlementError(f"unknown period {period!r}")


def period_end(period: str, start: date) -> date:
    if period == "day":
        return start + timedelta(days=1)
    if period == "week":
        return start + timedelta(days=7)
    if period == "month":
        return (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    raise EntitlementError(f"unknown period {period!r}")


# --- entitlements ---------------------------------------------------------

def grant(db: Session, user: User, kind: str, *, scope: str = SCOPE_ALL, tier: str = "",
          expires_at: Optional[datetime] = None, source: str = "manual", note: str = "",
          allowances: Optional[Dict[str, Dict[str, Any]]] = None) -> Entitlement:
    """Give somebody something. Granting a kind+scope they already hold extends
    the existing row rather than stacking duplicates nobody can reason about."""
    kind = (kind or "").strip().lower()
    if not kind:
        raise EntitlementError("a kind is required")
    for key, spec in (allowances or {}).items():
        if spec.get("period", "day") not in PERIODS:
            raise EntitlementError(f"allowance {key}: period must be one of {', '.join(PERIODS)}")
        if int(spec.get("limit", 0)) < 0:
            raise EntitlementError(f"allowance {key}: limit cannot be negative")

    existing = db.scalar(select(Entitlement).where(
        Entitlement.user_id == user.id, Entitlement.kind == kind,
        Entitlement.scope == scope, Entitlement.status == "active"))
    row = existing or Entitlement(user_id=user.id, kind=kind, scope=scope)
    row.tier = tier or row.tier
    row.source = source
    row.note = note or row.note
    row.status = "active"
    row.expires_at = expires_at
    if allowances is not None:
        row.meta_json = json.dumps({"allowances": allowances})
    db.add(row)
    db.flush()
    return row


def revoke(db: Session, user: User, kind: str, scope: str = SCOPE_ALL) -> int:
    rows = list(db.scalars(select(Entitlement).where(
        Entitlement.user_id == user.id, Entitlement.kind == kind.lower(),
        Entitlement.scope == scope, Entitlement.status == "active")))
    for row in rows:
        row.status = "revoked"
        row.revoked_at = utcnow()
    db.flush()
    return len(rows)


def active(db: Session, user: User, application: Optional[str] = None, *, any_scope: bool = False) -> List[Entitlement]:
    """What is in force right now.

    An application asks about itself and gets its own grants plus the global
    ones. `any_scope` is the person's own view (and the operator's): everything
    they hold, whichever application it belongs to.
    """
    now = utcnow()
    query = select(Entitlement).where(
        Entitlement.user_id == user.id, Entitlement.status == "active")
    if not any_scope:
        query = query.where(Entitlement.scope.in_(scopes_for(application)))
    rows = db.scalars(query.order_by(Entitlement.granted_at))
    return [r for r in rows if r.expires_at is None or r.expires_at > now]


def has(db: Session, user: User, kind: str, application: Optional[str] = None) -> bool:
    return any(r.kind == kind.lower() for r in active(db, user, application))


def as_claims(db: Session, user: User, application: Optional[str] = None) -> List[str]:
    """['supporter:all', 'ads_free:app:flowboard'] - what goes in an ID token."""
    return [f"{r.kind}:{r.scope}" for r in active(db, user, application)]


# --- allowances -----------------------------------------------------------

def _allowance_spec(db: Session, user: User, key: str, application: Optional[str] = None,
                    any_scope: bool = False) -> Dict[str, Any]:
    """The most generous limit this person has for a key: the free default,
    raised by any entitlement that names it."""
    spec = dict(DEFAULT_ALLOWANCES.get(key, {"limit": 0, "period": "day"}))
    for row in active(db, user, application, any_scope=any_scope):
        try:
            granted = (json.loads(row.meta_json or "{}") or {}).get("allowances", {}).get(key)
        except ValueError:
            granted = None
        if not granted:
            continue
        if int(granted.get("limit", 0)) > int(spec.get("limit", 0)):
            spec = {"limit": int(granted["limit"]), "period": granted.get("period", spec.get("period", "day"))}
    return spec


def allowance_status(db: Session, user: User, key: str, application: Optional[str] = None,
                     *, any_scope: bool = False) -> Dict[str, Any]:
    spec = _allowance_spec(db, user, key, application, any_scope)
    period = spec.get("period", "day")
    start = period_start(period)
    used = db.scalar(select(AllowanceUsage.used).where(
        AllowanceUsage.user_id == user.id, AllowanceUsage.key == key,
        AllowanceUsage.period == period, AllowanceUsage.period_start == start)) or 0
    limit = int(spec.get("limit", 0))
    return {"key": key, "limit": limit, "used": int(used), "remaining": max(0, limit - int(used)),
            "period": period, "resets_at": period_end(period, start).isoformat()}


def consume(db: Session, user: User, key: str, amount: int = 1, *, application: Optional[str] = None,
            allow_credits: bool = True, reason: str = "") -> Dict[str, Any]:
    """Spend `amount` units of an allowance, falling back to credits.

    All or nothing: a request that cannot be paid for in full changes nothing,
    so a caller never has to unpick a partial debit.
    """
    if amount <= 0:
        raise EntitlementError("amount must be positive")
    spec = _allowance_spec(db, user, key, application)
    period = spec.get("period", "day")
    limit = int(spec.get("limit", 0))
    start = period_start(period)

    row = db.scalar(select(AllowanceUsage).where(
        AllowanceUsage.user_id == user.id, AllowanceUsage.key == key,
        AllowanceUsage.period == period, AllowanceUsage.period_start == start))
    if row is None:
        row = AllowanceUsage(user_id=user.id, key=key, period=period, period_start=start, used=0)
        db.add(row)
        db.flush()

    from_allowance = max(0, min(amount, limit - row.used))
    shortfall = amount - from_allowance
    from_credits = 0
    if shortfall:
        if not allow_credits:
            return _denied(db, user, key, row, limit, period, start, "allowance exhausted")
        if balance(db, user) < shortfall:
            return _denied(db, user, key, row, limit, period, start, "allowance exhausted and not enough credits")
        from_credits = shortfall

    row.used += from_allowance
    if from_credits:
        spend_credits(db, user, from_credits, reason=reason or f"allowance:{key}")
    db.flush()
    return {"allowed": True, "key": key, "charged": amount, "from_allowance": from_allowance,
            "from_credits": from_credits, "limit": limit, "used": row.used,
            "remaining": max(0, limit - row.used), "period": period,
            "resets_at": period_end(period, start).isoformat(), "credit_balance": balance(db, user)}


def _denied(db: Session, user: User, key: str, row: AllowanceUsage, limit: int, period: str,
            start: date, why: str) -> Dict[str, Any]:
    return {"allowed": False, "key": key, "charged": 0, "from_allowance": 0, "from_credits": 0,
            "limit": limit, "used": row.used, "remaining": max(0, limit - row.used), "period": period,
            "resets_at": period_end(period, start).isoformat(), "credit_balance": balance(db, user),
            "reason": why}


# --- credits --------------------------------------------------------------

def balance(db: Session, user: User) -> int:
    return int(db.scalar(select(func.coalesce(func.sum(CreditLedger.delta), 0))
                         .where(CreditLedger.user_id == user.id)) or 0)


def add_credits(db: Session, user: User, amount: int, *, reason: str = "", ref: str = "") -> int:
    if amount <= 0:
        raise EntitlementError("amount must be positive")
    db.add(CreditLedger(user_id=user.id, delta=amount, reason=reason or "grant", ref=ref))
    db.flush()
    return balance(db, user)


def spend_credits(db: Session, user: User, amount: int, *, reason: str = "", ref: str = "") -> int:
    if amount <= 0:
        raise EntitlementError("amount must be positive")
    if balance(db, user) < amount:
        raise EntitlementError("not enough credits")
    db.add(CreditLedger(user_id=user.id, delta=-amount, reason=reason or "spend", ref=ref))
    db.flush()
    return balance(db, user)


def ledger(db: Session, user: User, limit: int = 50) -> List[CreditLedger]:
    return list(db.scalars(select(CreditLedger).where(CreditLedger.user_id == user.id)
                           .order_by(CreditLedger.created_at.desc()).limit(limit)))


# --- what an application asks for -----------------------------------------

def summary(db: Session, user: User, application: Optional[str] = None,
            keys: Optional[List[str]] = None, *, any_scope: bool = False) -> Dict[str, Any]:
    rows = active(db, user, application, any_scope=any_scope)
    keys = keys if keys is not None else sorted(DEFAULT_ALLOWANCES)
    return {
        "sub": user.id,
        "entitlements": [
            {"kind": r.kind, "scope": r.scope, "tier": r.tier or None,
             "expires_at": r.expires_at.isoformat() + "Z" if r.expires_at else None,
             "source": r.source}
            for r in rows
        ],
        "credits": balance(db, user),
        "allowances": {k: allowance_status(db, user, k, application, any_scope=any_scope) for k in keys},
    }
