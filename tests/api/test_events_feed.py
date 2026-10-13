"""``GET /api/me/events``: the account dashboard's monitoring events feed."""

from __future__ import annotations

import itertools
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from tests.conftest import ADDR, requires_postgres

pytestmark = requires_postgres

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture()
def client(db_session):
    @contextmanager
    def fake_session_local():
        yield db_session

    with patch("routers.deps.SessionLocal", fake_session_local):
        from fastapi.testclient import TestClient

        import api

        yield TestClient(api.app)


def _sign_in(db_session, client, email="user@example.com"):
    from services.auth.sessions import SESSION_COOKIE, create_session, upsert_neon_user

    user = upsert_neon_user(
        db_session, neon_auth_id=email, email=email, email_verified=True, display_name=None, avatar_url=None
    )
    token = create_session(db_session, user)
    db_session.commit()
    client.cookies.set(SESSION_COOKIE, token)
    return user


def _protocol(db_session, name):
    from db.models import Protocol

    proto = Protocol(name=name)
    db_session.add(proto)
    db_session.flush()
    return proto


def _subscribe(db_session, user, proto):
    from db.models import ProtocolSubscription

    db_session.add(ProtocolSubscription(protocol_id=proto.id, user_id=user.id))
    db_session.flush()


def _monitored(db_session, proto, n, chain="ethereum", name=None):
    from db.models import Contract, MonitoredContract

    contract_id = None
    if name:
        contract = Contract(address=ADDR(n), chain=chain, protocol_id=proto.id, contract_name=name)
        db_session.add(contract)
        db_session.flush()
        contract_id = contract.id
    mc = MonitoredContract(address=ADDR(n), chain=chain, protocol_id=proto.id, contract_id=contract_id)
    db_session.add(mc)
    db_session.flush()
    return mc


def _insert_events(db_session, rows):
    from sqlalchemy import insert

    from db.models import MonitoredEvent

    db_session.execute(insert(MonitoredEvent), rows)
    db_session.commit()


def _event(mc, i, event_type="upgraded", *, at=None, block=None, tx_hash=None, salience=None):
    return {
        "id": uuid.uuid4(),
        "monitored_contract_id": mc.id,
        "event_type": event_type,
        "block_number": block if block is not None else 1000 + i,
        "tx_hash": tx_hash if tx_hash is not None else "0x" + f"{i:064x}",
        "log_index": i,
        "data": {"salience": salience} if salience else {},
        "detected_at": at or T0 + timedelta(minutes=i),
    }


def _all_pages(client, limit=50, **params):
    events, cursor = [], None
    while True:
        query = {**params, "limit": limit}
        if cursor:
            query["cursor"] = cursor
        body = client.get("/api/me/events", params=query).json()
        events += body["events"]
        cursor = body["next_cursor"]
        if not cursor:
            return events


def test_requires_sign_in(client):
    assert client.get("/api/me/events").status_code == 401
    assert client.get("/api/me/events/filters").status_code == 401


def test_feed_lists_subscribed_events_newest_first_with_details(client, db_session):
    user = _sign_in(db_session, client)
    mine = _protocol(db_session, "__feed_mine__")
    other = _protocol(db_session, "__feed_other__")
    _subscribe(db_session, user, mine)
    vault = _monitored(db_session, mine, 1, name="Vault")
    bridge = _monitored(db_session, mine, 2, chain="arbitrum")
    elsewhere = _monitored(db_session, other, 3)
    tx = "0x" + "ab" * 32
    _insert_events(
        db_session,
        [
            _event(vault, 1, "ownership_transferred", tx_hash=tx, salience="alert"),
            _event(bridge, 2, "paused"),
            _event(vault, 3, "state_changed_poll", tx_hash=""),
            _event(elsewhere, 4, "upgraded"),
        ],
    )

    body = client.get("/api/me/events").json()
    assert body["next_cursor"] is None
    events = body["events"]
    assert [e["event_type"] for e in events] == ["state_changed_poll", "paused", "ownership_transferred"]
    poll, paused, owner = events
    assert owner == {
        "id": owner["id"],
        "event_type": "ownership_transferred",
        "block_number": 1001,
        "tx_hash": tx,
        "log_index": 1,
        "detected_at": owner["detected_at"],
        "data": {"salience": "alert"},
        "contract": {"address": ADDR(1), "chain": "ethereum", "name": "Vault"},
        "protocol": {"id": mine.id, "name": "__feed_mine__"},
    }
    assert datetime.fromisoformat(owner["detected_at"]) == T0 + timedelta(minutes=1)
    assert paused["contract"] == {"address": ADDR(2), "chain": "arbitrum", "name": None}
    assert paused["data"] == {}
    # Poll-path rows have no transaction to link to.
    assert poll["tx_hash"] is None


def test_other_users_subscriptions_never_leak(client, db_session):
    alice = _sign_in(db_session, client, "alice@example.com")
    proto = _protocol(db_session, "__feed_alice__")
    _subscribe(db_session, alice, proto)
    _insert_events(db_session, [_event(_monitored(db_session, proto, 1), 1)])
    assert len(client.get("/api/me/events").json()["events"]) == 1

    _sign_in(db_session, client, "mallory@example.com")
    # Naming the protocol outright doesn't widen the feed past the user's subscriptions.
    assert client.get("/api/me/events", params={"protocol_id": proto.id}).json()["events"] == []
    assert client.get("/api/me/events/filters").json() == {"protocols": [], "event_types": []}


def test_subscribed_protocol_without_events_returns_empty_feed(client, db_session):
    user = _sign_in(db_session, client)
    proto = _protocol(db_session, "__feed_quiet__")
    _subscribe(db_session, user, proto)
    _monitored(db_session, proto, 1)
    db_session.commit()

    assert client.get("/api/me/events").json() == {"events": [], "next_cursor": None}
    assert client.get("/api/me/events/filters").json() == {
        "protocols": [{"id": proto.id, "name": "__feed_quiet__"}],
        "event_types": [],
    }


def test_filters_return_only_matching_events_in_every_combination(client, db_session):
    user = _sign_in(db_session, client)
    protos = [_protocol(db_session, f"__feed_{n}__") for n in ("a", "b", "c")]
    for p in protos:
        _subscribe(db_session, user, p)
    contracts = [_monitored(db_session, p, i) for i, p in enumerate(protos, start=1)]
    types = ["upgraded", "ownership_transferred", "paused", "role_granted"]
    rows = [_event(contracts[i % 3], i, types[i % 4], at=T0 + timedelta(hours=i)) for i in range(60)]
    _insert_events(db_session, rows)
    proto_of = {c.id: p.id for c, p in zip(contracts, protos)}

    protocol_opts = [None, [protos[0].id], [protos[1].id, protos[2].id]]
    type_opts = [None, ["upgraded"], ["paused", "role_granted"]]
    range_opts = [
        (None, None),
        (T0 + timedelta(hours=10), None),
        (None, T0 + timedelta(hours=30)),
        (T0 + timedelta(hours=12), T0 + timedelta(hours=40)),
    ]
    combos = list(itertools.product(protocol_opts, type_opts, range_opts))
    assert len(combos) >= 20

    for protocol_ids, event_types, (since, until) in combos:
        params = {}
        if protocol_ids:
            params["protocol_id"] = protocol_ids
        if event_types:
            params["event_type"] = event_types
        if since:
            params["since"] = since.isoformat()
        if until:
            params["until"] = until.isoformat()
        expected = sorted(
            (
                r
                for r in rows
                if (not protocol_ids or proto_of[r["monitored_contract_id"]] in protocol_ids)
                and (not event_types or r["event_type"] in event_types)
                and (not since or r["detected_at"] >= since)
                and (not until or r["detected_at"] < until)
            ),
            key=lambda r: r["detected_at"],
            reverse=True,
        )
        got = _all_pages(client, limit=7, **params)
        assert [e["id"] for e in got] == [str(r["id"]) for r in expected], params

    # No filters is the full list again.
    assert len(_all_pages(client)) == 60

    options = client.get("/api/me/events/filters").json()
    assert [p["name"] for p in options["protocols"]] == ["__feed_a__", "__feed_b__", "__feed_c__"]
    assert {t["event_type"]: t["count"] for t in options["event_types"]} == {t: 15 for t in types}


def test_paging_5000_events_has_no_duplicates_or_gaps(client, db_session):
    user = _sign_in(db_session, client)
    proto = _protocol(db_session, "__feed_busy__")
    _subscribe(db_session, user, proto)
    mc = _monitored(db_session, proto, 1)
    # One scan pass stamps many rows with the same now(), and blocks repeat too, so the id tiebreak is exercised.
    rows = [_event(mc, i, at=T0 + timedelta(seconds=i // 25), block=i // 5) for i in range(5000)]
    _insert_events(db_session, rows)
    expected = [
        str(r["id"]) for r in sorted(rows, key=lambda r: (r["detected_at"], r["block_number"], r["id"]), reverse=True)
    ]

    seen, cursor, slowest = [], None, 0.0
    while True:
        params = {"limit": 100, **({"cursor": cursor} if cursor else {})}
        started = time.monotonic()
        body = client.get("/api/me/events", params=params).json()
        slowest = max(slowest, time.monotonic() - started)
        seen += [e["id"] for e in body["events"]]
        cursor = body["next_cursor"]
        if len(seen) == 100:
            # A row detected mid-scroll lands above the cursor, not inside the remaining pages.
            _insert_events(db_session, [_event(mc, 9999, at=T0 + timedelta(days=1))])
        if not cursor:
            break

    assert seen == expected
    assert slowest < 1.0


def test_rejects_a_malformed_cursor(client, db_session):
    _sign_in(db_session, client)
    assert client.get("/api/me/events", params={"cursor": "not-a-cursor"}).status_code == 422
