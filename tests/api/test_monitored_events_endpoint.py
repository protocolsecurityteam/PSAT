"""Tests for `GET /api/monitored-events` filter modes.

The address+chain filter is the new path that lets the frontend render a
per-Safe / per-Timelock activity panel without first having to resolve
the MonitoredContract uuid. Existing contract_id and event_type filter
modes are also exercised here so a future refactor that drops one of
them fails loudly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


@pytest.fixture()
def seeded_events(db_session):
    """Two MonitoredContracts on the same address but different chains
    plus a handful of MonitoredEvents across them. Cleaned up at teardown.
    """
    from db.models import MonitoredContract, MonitoredEvent

    addr = "0x" + "ab" * 20
    other_addr = "0x" + "cd" * 20

    mc_eth = MonitoredContract(
        id=uuid.uuid4(),
        address=addr,
        chain="ethereum",
        contract_type="safe",
        monitoring_config={"watch_safe_signers": True},
        last_known_state={},
        last_scanned_block=0,
        is_active=True,
    )
    mc_base = MonitoredContract(
        id=uuid.uuid4(),
        address=addr,  # same address, different chain
        chain="base",
        contract_type="safe",
        monitoring_config={"watch_safe_signers": True},
        last_known_state={},
        last_scanned_block=0,
        is_active=True,
    )
    mc_other = MonitoredContract(
        id=uuid.uuid4(),
        address=other_addr,
        chain="ethereum",
        contract_type="safe",
        monitoring_config={"watch_safe_signers": True},
        last_known_state={},
        last_scanned_block=0,
        is_active=True,
    )
    db_session.add_all([mc_eth, mc_base, mc_other])
    db_session.commit()

    def _ev(mc_id, event_type, block):
        return MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc_id,
            event_type=event_type,
            block_number=block,
            tx_hash="0x" + format(block, "x").zfill(64),
            data={},
            detected_at=datetime.now(timezone.utc),
        )

    events = [
        _ev(mc_eth.id, "safe_tx_executed", 100),
        _ev(mc_eth.id, "signer_added", 101),
        _ev(mc_base.id, "safe_tx_executed", 200),
        _ev(mc_other.id, "safe_tx_executed", 300),
    ]
    db_session.add_all(events)
    db_session.commit()

    try:
        yield {
            "addr": addr,
            "other_addr": other_addr,
            "mc_eth_id": mc_eth.id,
            "mc_base_id": mc_base.id,
            "mc_other_id": mc_other.id,
            "events": events,
        }
    finally:
        for e in events:
            db_session.delete(e)
        for mc in [mc_eth, mc_base, mc_other]:
            db_session.delete(mc)
        db_session.commit()


def test_filter_by_address_returns_all_chains(api_client, seeded_events):
    """Without ``chain``, the address filter returns events from every
    MonitoredContract that shares the address — both ethereum and base.
    """
    resp = api_client.get("/api/monitored-events", params={"address": seeded_events["addr"]})
    assert resp.status_code == 200
    body = resp.json()
    block_numbers = sorted(e["block_number"] for e in body)
    assert block_numbers == [100, 101, 200]


def test_filter_by_address_and_chain(api_client, seeded_events):
    """``chain`` narrows to one MonitoredContract row's events."""
    resp = api_client.get(
        "/api/monitored-events",
        params={"address": seeded_events["addr"], "chain": "ethereum"},
    )
    assert resp.status_code == 200
    body = resp.json()
    block_numbers = sorted(e["block_number"] for e in body)
    assert block_numbers == [100, 101]


def test_filter_by_address_and_event_type(api_client, seeded_events):
    """address + event_type filters compose."""
    resp = api_client.get(
        "/api/monitored-events",
        params={"address": seeded_events["addr"], "event_type": "safe_tx_executed"},
    )
    assert resp.status_code == 200
    body = resp.json()
    block_numbers = sorted(e["block_number"] for e in body)
    assert block_numbers == [100, 200]


def test_unknown_address_returns_empty(api_client):
    """Address that has no MonitoredContract row → empty list, not 404."""
    resp = api_client.get(
        "/api/monitored-events",
        params={"address": "0x" + "00" * 20},
    )
    assert resp.status_code == 200
    assert resp.json() == []


def test_address_lookup_lowercases(api_client, seeded_events):
    """Mixed-case address input still resolves — keep the URL bar friendly."""
    addr = seeded_events["addr"]
    resp = api_client.get("/api/monitored-events", params={"address": addr.upper()})
    assert resp.status_code == 200
    block_numbers = sorted(e["block_number"] for e in resp.json())
    assert block_numbers == [100, 101, 200]


def test_filter_by_chain_only(api_client, seeded_events):
    """``chain`` alone narrows to all MonitoredContracts on that chain.

    Without this, a request like ``?chain=base`` was silently ignored
    and returned global recent events (codex flagged on review).
    """
    resp = api_client.get("/api/monitored-events", params={"chain": "ethereum"})
    assert resp.status_code == 200
    block_numbers = sorted(e["block_number"] for e in resp.json())
    # ethereum events: mc_eth (100, 101) + mc_other (300)
    assert block_numbers == [100, 101, 300]


def test_filter_by_chain_only_unknown(api_client):
    """Unknown chain → empty list (no events on a chain we don't track)."""
    resp = api_client.get("/api/monitored-events", params={"chain": "moonbeam"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_filter_by_chain_and_event_type(api_client, seeded_events):
    """chain + event_type compose."""
    resp = api_client.get(
        "/api/monitored-events",
        params={"chain": "ethereum", "event_type": "safe_tx_executed"},
    )
    assert resp.status_code == 200
    block_numbers = sorted(e["block_number"] for e in resp.json())
    # ethereum + safe_tx_executed: mc_eth (100), mc_other (300)
    assert block_numbers == [100, 300]


def test_same_detected_at_orders_stably_by_block_then_id(api_client, db_session):
    """When multiple events share `detected_at` (e.g. inserted in a single
    scan pass), the response must still come back in deterministic order:
    detected_at desc → block_number desc → id desc. Codex flagged that
    relying on detected_at alone left ties undefined.
    """
    from db.models import MonitoredContract, MonitoredEvent

    addr = "0x" + "ee" * 20
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=addr,
        chain="ethereum",
        contract_type="timelock",
        monitoring_config={"watch_timelock": True},
        last_known_state={},
        last_scanned_block=0,
        is_active=True,
    )
    db_session.add(mc)
    db_session.commit()

    same_ts = datetime.now(timezone.utc)
    # Three events with identical detected_at, distinct block_numbers.
    # Insert in non-monotonic block order to prove the SQL sort, not
    # insertion order, is what determines the response order.
    events = []
    for block in (3000, 1000, 2000):
        events.append(
            MonitoredEvent(
                id=uuid.uuid4(),
                monitored_contract_id=mc.id,
                event_type="timelock_scheduled",
                block_number=block,
                tx_hash="0x" + format(block, "x").zfill(64),
                data={},
                detected_at=same_ts,
            )
        )
    db_session.add_all(events)
    db_session.commit()

    try:
        resp = api_client.get("/api/monitored-events", params={"address": addr})
        assert resp.status_code == 200
        body = resp.json()
        # Newest block first.
        assert [e["block_number"] for e in body] == [3000, 2000, 1000]
    finally:
        for e in events:
            db_session.delete(e)
        db_session.delete(mc)
        db_session.commit()


def test_upsert_monitoring_seeds_enrollment_block_at_head(api_client, db_session, monkeypatch):
    """A manually-added (surface_alert) contract starts watching from the current
    head, not block 0, and records enrollment_block as the pre-watch floor — so
    the scanner won't notify its entire pre-add history on the first pass."""
    from sqlalchemy import select

    from db.models import MonitoredContract, Protocol

    head = 21_000_000
    monkeypatch.setattr("routers.monitored.rpc_request", lambda *a, **k: hex(head))

    proto = Protocol(name="__test_upsert_monitoring__")
    db_session.add(proto)
    db_session.commit()

    addr = "0x" + "3e" * 20
    try:
        resp = api_client.post(
            f"/api/protocols/{proto.id}/monitoring",
            json={"address": addr, "chain": "ethereum", "contract_type": "regular"},
        )
        assert resp.status_code == 200
        # The serialized payload surfaces enrollment_block so the frontend can
        # place the monitoring-start boundary on the Activity timeline.
        assert resp.json()["enrollment_block"] == head

        mc = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == addr)).scalar_one()
        assert mc.enrollment_block == head  # floor set → pre-add history is suppressed
        assert mc.last_scanned_block == head  # start from now, not block 0
    finally:
        db_session.query(MonitoredContract).filter(MonitoredContract.address == addr).delete()
        db_session.query(Protocol).filter(Protocol.id == proto.id).delete()
        db_session.commit()


def test_protocol_monitoring_list_serializes_enrollment_block(api_client, db_session):
    """``GET /api/protocols/{id}/monitoring`` — the endpoint the Activity tab
    reads — carries ``enrollment_block`` (including null for rows enrolled
    before the column landed) so the frontend can place the boundary."""
    from db.models import MonitoredContract, Protocol

    proto = Protocol(name="__test_monitoring_list_enrollment__")
    db_session.add(proto)
    db_session.commit()

    with_block = MonitoredContract(
        id=uuid.uuid4(),
        address="0x" + "a1" * 20,
        chain="ethereum",
        contract_type="proxy",
        monitoring_config={"watch_upgrades": True},
        last_known_state={},
        last_scanned_block=25_000_000,
        enrollment_block=24_900_000,
        protocol_id=proto.id,
        is_active=True,
    )
    # Legacy row: enrolled before the column existed → enrollment_block is null.
    legacy = MonitoredContract(
        id=uuid.uuid4(),
        address="0x" + "b2" * 20,
        chain="ethereum",
        contract_type="safe",
        monitoring_config={"watch_safe_signers": True},
        last_known_state={},
        last_scanned_block=0,
        enrollment_block=None,
        protocol_id=proto.id,
        is_active=True,
    )
    db_session.add_all([with_block, legacy])
    db_session.commit()

    try:
        resp = api_client.get(f"/api/protocols/{proto.id}/monitoring")
        assert resp.status_code == 200
        by_addr = {row["address"]: row for row in resp.json()}
        assert "enrollment_block" in by_addr[with_block.address]
        assert by_addr[with_block.address]["enrollment_block"] == 24_900_000
        # Nullable — the field is present and null, never absent.
        assert by_addr[legacy.address]["enrollment_block"] is None
    finally:
        for mc in (with_block, legacy):
            db_session.delete(mc)
        db_session.delete(proto)
        db_session.commit()


def test_protocol_feed_scopes_to_the_requested_chain(api_client, db_session, seeded_events):
    """`/api/protocols/{id}/events?chain=` returns only that chain's monitored
    rows' events. The fixture's shared address is the load-bearing case: the
    same address is a distinct deployment per chain, so only the monitored
    row's own chain — never the address — can scope the feed. Every row also
    carries its chain so an unscoped fetch is self-describing.
    """
    from db.models import MonitoredContract, Protocol

    proto = Protocol(name="__feed_chain_scope__")
    db_session.add(proto)
    db_session.flush()
    for key in ("mc_eth_id", "mc_base_id", "mc_other_id"):
        db_session.get(MonitoredContract, seeded_events[key]).protocol_id = proto.id
    db_session.commit()

    try:
        unscoped = api_client.get(f"/api/protocols/{proto.id}/events")
        assert unscoped.status_code == 200
        assert len(unscoped.json()) == 4
        assert all(row["data"]["chain"] in ("ethereum", "base") for row in unscoped.json())

        base = api_client.get(f"/api/protocols/{proto.id}/events", params={"chain": "base"})
        assert base.status_code == 200
        rows = base.json()
        # Only the base twin's event — not the ethereum twin's at the SAME address.
        assert [r["block_number"] for r in rows] == [200]
        assert rows[0]["data"]["contract_address"] == seeded_events["addr"]
        assert rows[0]["data"]["chain"] == "base"
        # The row states its emitter's type — the frontend badge must never
        # have to guess it from a local lookup that can miss.
        assert rows[0]["data"]["contract_type"] == "safe"

        eth = api_client.get(f"/api/protocols/{proto.id}/events", params={"chain": "ethereum"})
        assert sorted(r["block_number"] for r in eth.json()) == [100, 101, 300]

        # The legacy fold: "mainnet" scopes identically to "ethereum".
        mainnet = api_client.get(f"/api/protocols/{proto.id}/events", params={"chain": "mainnet"})
        assert sorted(r["block_number"] for r in mainnet.json()) == [100, 101, 300]
    finally:
        for key in ("mc_eth_id", "mc_base_id", "mc_other_id"):
            db_session.get(MonitoredContract, seeded_events[key]).protocol_id = None
        db_session.commit()
        db_session.delete(proto)
        db_session.commit()
