# SPDX-License-Identifier: AGPL-3.0-or-later
"""Entitlements, allowances and credits."""
import os
import tempfile
from datetime import timedelta

os.environ.update({"TG11_ENV": "test", "TG11_DATA_DIR": tempfile.mkdtemp(), "TG11_SECRET_KEY": "test-secret-0123456789",
                   "TG11_ISSUER": "http://accounts.test", "TG11_COOKIE_SECURE": "false",
                   "TG11_VAULT_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="})

import pytest  # noqa: E402

from tg11 import entitlements as ent  # noqa: E402
from tg11.models import Base, SessionLocal, User, engine, ensure_schema, utcnow  # noqa: E402


@pytest.fixture(autouse=True)
def fresh():
    Base.metadata.drop_all(engine)
    ensure_schema()


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


def _user(db, username="alice"):
    u = User(email=f"{username}@example.com", username=username, password_hash="x")
    db.add(u)
    db.flush()
    return u


def test_a_grant_is_visible_to_the_right_application_only(db):
    u = _user(db)
    ent.grant(db, u, "supporter", scope=ent.app_scope("flowboard"), tier="monthly")
    assert ent.has(db, u, "supporter", "flowboard")
    assert not ent.has(db, u, "supporter", "shop")
    assert not ent.has(db, u, "supporter")          # the global view does not see an app grant
    ent.grant(db, u, "ads_free")                     # scope=all
    assert ent.has(db, u, "ads_free", "shop") and ent.has(db, u, "ads_free")
    assert sorted(ent.as_claims(db, u, "flowboard")) == ["ads_free:all", "supporter:app:flowboard"]


def test_granting_twice_extends_rather_than_stacking(db):
    u = _user(db)
    first = ent.grant(db, u, "supporter", expires_at=utcnow() + timedelta(days=30))
    second = ent.grant(db, u, "supporter", expires_at=utcnow() + timedelta(days=60))
    assert first.id == second.id
    assert len(ent.active(db, u)) == 1


def test_expiry_and_revocation_both_end_it(db):
    u = _user(db)
    ent.grant(db, u, "supporter", expires_at=utcnow() - timedelta(minutes=1))
    assert not ent.has(db, u, "supporter")
    ent.grant(db, u, "ads_free")
    assert ent.revoke(db, u, "ads_free") == 1
    assert not ent.has(db, u, "ads_free")
    assert ent.revoke(db, u, "ads_free") == 0


def test_the_free_allowance_needs_no_row_and_an_entitlement_raises_it(db):
    u = _user(db)
    key = "test.thing"
    ent.DEFAULT_ALLOWANCES[key] = {"limit": 2, "period": "day"}
    try:
        assert ent.allowance_status(db, u, key)["limit"] == 2
        assert ent.consume(db, u, key, allow_credits=False)["allowed"]
        assert ent.consume(db, u, key, allow_credits=False)["remaining"] == 0
        assert not ent.consume(db, u, key, allow_credits=False)["allowed"]

        ent.grant(db, u, "supporter", allowances={key: {"limit": 10, "period": "day"}})
        status = ent.allowance_status(db, u, key)
        assert status["limit"] == 10 and status["used"] == 2 and status["remaining"] == 8
        assert ent.consume(db, u, key, 8, allow_credits=False)["allowed"]
        assert not ent.consume(db, u, key, allow_credits=False)["allowed"]
    finally:
        ent.DEFAULT_ALLOWANCES.pop(key, None)


def test_credits_cover_the_shortfall_but_only_in_full(db):
    u = _user(db)
    key = "test.credits"
    ent.DEFAULT_ALLOWANCES[key] = {"limit": 1, "period": "day"}
    try:
        ent.add_credits(db, u, 3, reason="test")
        # 1 from the allowance, 2 from credits
        result = ent.consume(db, u, key, 3, reason="a big request")
        assert result["allowed"] and result["from_allowance"] == 1 and result["from_credits"] == 2
        assert ent.balance(db, u) == 1

        # 4 more: nothing left in the allowance and only 1 credit, so nothing happens
        denied = ent.consume(db, u, key, 4)
        assert not denied["allowed"] and "not enough credits" in denied["reason"]
        assert ent.balance(db, u) == 1, "a refused request must not spend anything"
    finally:
        ent.DEFAULT_ALLOWANCES.pop(key, None)


def test_the_balance_is_the_ledger(db):
    u = _user(db)
    ent.add_credits(db, u, 100, reason="grant")
    ent.spend_credits(db, u, 30, reason="spend")
    assert ent.balance(db, u) == 70
    assert [e.delta for e in ent.ledger(db, u)] == [-30, 100]
    with pytest.raises(ent.EntitlementError):
        ent.spend_credits(db, u, 1000)
    with pytest.raises(ent.EntitlementError):
        ent.add_credits(db, u, 0)


def test_periods_land_where_they_should(db):
    from datetime import datetime

    wednesday = datetime(2026, 9, 16, 13, 0)
    assert ent.period_start("day", wednesday).isoformat() == "2026-09-16"
    assert ent.period_start("week", wednesday).isoformat() == "2026-09-14"   # Monday
    assert ent.period_start("month", wednesday).isoformat() == "2026-09-01"
    assert ent.period_end("month", ent.period_start("month", wednesday)).isoformat() == "2026-10-01"
    with pytest.raises(ent.EntitlementError):
        ent.period_start("fortnight")


def test_summary_is_what_an_application_asks_for(db):
    u = _user(db)
    ent.grant(db, u, "supporter", scope=ent.app_scope("flowboard"),
              allowances={"flowboard.ai.requests": {"limit": 50, "period": "day"}})
    ent.add_credits(db, u, 250, reason="one-time")
    data = ent.summary(db, u, "flowboard", ["flowboard.ai.requests"])
    assert data["sub"] == u.id
    assert data["credits"] == 250
    assert data["entitlements"][0]["kind"] == "supporter"
    assert data["allowances"]["flowboard.ai.requests"]["limit"] == 50


def test_a_bad_grant_is_refused(db):
    u = _user(db)
    with pytest.raises(ent.EntitlementError):
        ent.grant(db, u, "")
    with pytest.raises(ent.EntitlementError):
        ent.grant(db, u, "supporter", allowances={"k": {"limit": 5, "period": "fortnight"}})
    with pytest.raises(ent.EntitlementError):
        ent.grant(db, u, "supporter", allowances={"k": {"limit": -1, "period": "day"}})
    with pytest.raises(ent.EntitlementError):
        ent.consume(db, u, "anything", 0)


def test_a_person_sees_every_grant_they_hold_whatever_application_it_is_for(db):
    """The application view is scoped; the person's own view is not. An operator
    listing an account must see the app-scoped grant they just made."""
    u = _user(db)
    ent.grant(db, u, "supporter", scope=ent.app_scope("flowboard"),
              allowances={"flowboard.ai.requests": {"limit": 9, "period": "day"}})
    assert ent.active(db, u) == []                       # nothing is global
    assert len(ent.active(db, u, any_scope=True)) == 1    # but they do hold it
    assert ent.allowance_status(db, u, "flowboard.ai.requests")["limit"] == 0
    assert ent.allowance_status(db, u, "flowboard.ai.requests", any_scope=True)["limit"] == 9
    assert ent.summary(db, u, any_scope=True)["entitlements"][0]["scope"] == "app:flowboard"
