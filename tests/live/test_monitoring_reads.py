"""Monitoring read endpoints — shape checks only (row counts depend on preview history)."""

from __future__ import annotations

from tests.live.conftest import LiveClient


def test_list_monitored_contracts_shape(live_client: LiveClient):
    rows = live_client.list_monitored_contracts()
    assert isinstance(rows, list)
    if not rows:
        return
    for row in rows[:5]:
        for key in ("id", "address", "chain", "contract_type", "is_active"):
            assert key in row, f"monitored contract row missing {key!r}: {row}"


def test_list_monitored_events_shape(live_client: LiveClient):
    rows = live_client.list_monitored_events(limit=20)
    assert isinstance(rows, list)
    for row in rows:
        for key in ("id", "monitored_contract_id", "event_type", "detected_at"):
            assert key in row, f"monitored event row missing {key!r}: {row}"
