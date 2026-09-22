"""A caller-authored ``monitoring_config`` may not read as an analysis result.

``services/monitoring/enrollment._build_monitoring_config`` gives
``monitored_contracts.monitoring_config`` a tracking-plan discriminant that is
always a positive token, stated in its own docstring:

* ``tracked_topics`` present (possibly ``[]``) — the plan was read; an empty
  list is the witnessed "read and named nothing" finding and may be relied on;
* ``observation_plan_not_determined``             — the plan was not read; the
  token says why.

The builder never emits neither key; a row carrying neither predates this
discriminant (or, before the route fix below, was caller-authored).

``POST /api/protocols/{id}/monitoring`` and ``PATCH /api/monitored-contracts/{id}``
never called that builder — they stored the caller's dict verbatim — so
caller-enrolled rows carried neither key and were indistinguishable from
analyzer output. On the PR-161 preview all 3 ``enrollment_source='surface_alert'``
rows had that shape, for contracts no tracking-plan artifact was ever
consulted for.

The siblings that give it teeth are the two keys the live monitor ACTS on, and
nothing checked where either came from:

* ``tracked_topics`` — ``unified_watcher._scan_topics_union`` unions it over
  every active row into the live scan filter;
* ``polling_plan``   — ``unified_watcher.poll_for_state_changes`` turns each
  entry into an ``eth_call``/``eth_getStorageAt`` and ``_apply_poll_result``
  mints a ``state_changed_poll`` ``MonitoredEvent`` from the result, keyed on
  the entry's own ``field`` name. That event carries no provenance of its own,
  so the config stamp cannot mark it: a caller-chosen slot would surface as a
  monitor finding indistinguishable from an analyzer-derived one.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select, text

from db.models import MonitoredContract, Protocol
from routers.monitored import CALLER_SUPPLIED_TRACKING_PLAN

ADDR = "0x" + "7d" * 20
TOPIC0 = "0x" + "e1" * 32
SLOT = "0x" + "0" * 63 + "7"
_PLAN_ENTRY = {"kind": "storage_slot", "slot": SLOT, "field": "owner", "type_kind": "address"}


@pytest.fixture
def protocol_id(db_session):
    protocol = Protocol(name="caller_provenance_co")
    db_session.add(protocol)
    db_session.commit()
    try:
        yield protocol.id
    finally:
        db_session.rollback()
        db_session.execute(text("DELETE FROM monitored_contracts WHERE protocol_id = :p"), {"p": protocol.id})
        db_session.execute(text("DELETE FROM protocols WHERE id = :p"), {"p": protocol.id})
        db_session.commit()


@pytest.fixture
def admin_headers(monkeypatch):
    from routers import deps

    monkeypatch.setattr(deps, "ADMIN_KEY", "test-admin-key")
    return {"X-PSAT-Admin-Key": "test-admin-key"}


@pytest.fixture(autouse=True)
def _no_wire(monkeypatch):
    """``_current_head_block`` seeds the cursor over RPC; the offline suite is
    hermetic, so stub the one call these routes make."""
    from routers import monitored

    monkeypatch.setattr(monitored, "rpc_request", lambda *a, **k: hex(21_000_000))


def _post(api_client, protocol_id: int, admin_headers: dict[str, str], config: dict[str, Any] | None):
    return api_client.post(
        f"/api/protocols/{protocol_id}/monitoring",
        json={
            "address": ADDR,
            "chain": "ethereum",
            "contract_type": "proxy",
            "monitoring_config": config,
            "needs_polling": False,
            "is_active": True,
        },
        headers=admin_headers,
    )


def test_caller_enrolled_row_is_stamped_not_silently_proven_absent(api_client, db_session, protocol_id, admin_headers):
    """The positive case: a plain flags-only config — the exact shape the live
    fixtures and the Surface alert UI send — comes back carrying the provenance
    token, so no reader can take its missing ``tracked_topics`` for a finding."""
    resp = _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True, "watch_ownership": True})
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["enrollment_source"] == "surface_alert"
    assert body["monitoring_config"]["observation_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN
    # The caller's own flags are untouched.
    assert body["monitoring_config"]["watch_upgrades"] is True
    assert body["monitoring_config"]["watch_ownership"] is True

    row = db_session.execute(
        select(MonitoredContract).where(MonitoredContract.id == uuid.UUID(body["id"]))
    ).scalar_one()
    db_session.refresh(row)
    assert row.monitoring_config["observation_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN


def test_null_monitoring_config_is_stamped_too(api_client, protocol_id, admin_headers):
    """``monitoring_config`` is optional; the omitted case stored ``None``, which
    reads as proven-absent just as loudly as ``{}``."""
    resp = _post(api_client, protocol_id, admin_headers, None)
    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"] == {"observation_plan_not_determined": CALLER_SUPPLIED_TRACKING_PLAN}


def test_caller_monitoring_config_uses_the_same_strict_schema(api_client, protocol_id, admin_headers):
    resp = _post(api_client, protocol_id, admin_headers, {"watch_pause": "yes"})

    assert resp.status_code == 422
    assert "watch_pause" in resp.text


def test_a_forged_reason_token_cannot_survive_the_route(api_client, protocol_id, admin_headers):
    """A caller naming an analyzer reason gets the route's own token instead —
    the route owns this key. Overwrite rather than reject so that reading a
    stamped row and writing it back still works."""
    resp = _post(
        api_client,
        protocol_id,
        admin_headers,
        {"watch_pause": True, "observation_plan_not_determined": "plan_not_readable"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"]["observation_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN


def test_caller_supplied_tracked_topics_are_rejected(api_client, protocol_id, admin_headers):
    """``tracked_topics`` is an analysis output that feeds the live scan filter.
    422, not a silent drop — a discarded list would tell the caller those topics
    are being scanned."""
    resp = _post(api_client, protocol_id, admin_headers, {"tracked_topics": [{"topic0": TOPIC0}]})
    assert resp.status_code == 422, resp.text
    assert "tracked_topics" in resp.text


def test_caller_supplied_polling_plan_is_rejected(api_client, protocol_id, admin_headers):
    """``polling_plan`` is the second analyzer-owned key, and the more
    consequential one: the poller does not merely filter on it, it ACTS on it."""
    resp = _post(api_client, protocol_id, admin_headers, {"polling_plan": [_PLAN_ENTRY]})
    assert resp.status_code == 422, resp.text
    assert "polling_plan" in resp.text


def test_rejected_polling_plan_never_reaches_the_wire_or_the_event_stream(
    api_client, db_session, protocol_id, admin_headers
):
    """The two consequences the rejection exists for, named at the functions that
    would carry them out.

    ``_rpc_call_for_entry`` shows the entry is one the poller WOULD issue (an
    ``eth_getStorageAt`` on a slot the caller chose) — a plan the poller ignored
    would need no rejection. ``_apply_poll_result`` then mints a
    ``state_changed_poll`` ``MonitoredEvent`` keyed on the entry's own ``field``,
    and that event carries no provenance, so the caller stamp on the config
    cannot mark it. Both start from a stored plan; the assertion is that after a
    422 no row holds one."""
    from services.monitoring.unified_watcher import _rpc_call_for_entry

    assert _rpc_call_for_entry(ADDR, _PLAN_ENTRY) == ("eth_getStorageAt", [ADDR, SLOT, "latest"])

    assert _post(api_client, protocol_id, admin_headers, {"polling_plan": [_PLAN_ENTRY]}).status_code == 422
    assert _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True}).status_code == 200

    rows = db_session.execute(select(MonitoredContract).where(MonitoredContract.protocol_id == protocol_id)).scalars()
    for row in rows:
        db_session.refresh(row)
        assert "polling_plan" not in (row.monitoring_config or {})


def test_the_watch_flags_stay_caller_settable(api_client, protocol_id, admin_headers):
    """The negative control on the rejection's reach. ``_build_monitoring_config``
    also derives the ``watch_*`` booleans, but those only gate whether an
    already-detected event notifies (``unified_watcher._should_watch``) — no wire
    call, no minted finding — so they are a caller preference and must survive.
    Without this, widening the reject-list to every builder-written key would
    still look correct."""
    resp = _post(
        api_client,
        protocol_id,
        admin_headers,
        {"watch_upgrades": False, "watch_ownership": True, "watch_pause": True, "watch_roles": True},
    )
    assert resp.status_code == 200, resp.text
    config = resp.json()["monitoring_config"]
    assert config["watch_upgrades"] is False
    assert config["watch_ownership"] is True
    assert config["watch_pause"] is True
    assert config["watch_roles"] is True


def test_patch_applies_the_same_two_rules(api_client, protocol_id, admin_headers):
    """PATCH replaces the config wholesale, so it is the same door."""
    created = _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True})
    assert created.status_code == 200, created.text
    contract_id = created.json()["id"]

    forged = api_client.patch(
        f"/api/monitored-contracts/{contract_id}",
        json={"monitoring_config": {"watch_pause": True, "observation_plan_not_determined": "contract_not_analyzed"}},
        headers=admin_headers,
    )
    assert forged.status_code == 200, forged.text
    assert forged.json()["monitoring_config"]["observation_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN
    assert forged.json()["monitoring_config"]["watch_pause"] is True

    for key, payload in (
        ("tracked_topics", [{"topic0": TOPIC0}]),
        ("polling_plan", [_PLAN_ENTRY]),
        ("scan_gaps", [{"from_block": 1, "to_block": 2, "reason": "unfloored_runaway"}]),
    ):
        resp = api_client.patch(
            f"/api/monitored-contracts/{contract_id}",
            json={"monitoring_config": {key: payload}},
            headers=admin_headers,
        )
        assert resp.status_code == 422, resp.text
        assert key in resp.text


def test_caller_supplied_scan_gaps_are_rejected(api_client, protocol_id, admin_headers):
    """``scan_gaps`` is the scanner's own record of what it never covered.

    It is written only by the cursor-clamp repair and is carried across every
    subsequent config rebuild (``observation_plan_state.preserve_scan_plane_facts``),
    so a forged entry would be indistinguishable from a clamp-authored one and
    would outlive every enrollment — asserting a coverage hole nobody observed.
    Rejected rather than dropped, like the analyzer-owned keys: a silently
    discarded value would leave the caller believing it was recorded.
    """
    gap = [{"from_block": 9_400_001, "to_block": 25_662_000, "reason": "unfloored_runaway"}]
    resp = _post(api_client, protocol_id, admin_headers, {"scan_gaps": gap})
    assert resp.status_code == 422, resp.text
    assert "scan_gaps" in resp.text


def test_rejected_topics_never_reach_the_live_scan_filter(api_client, db_session, protocol_id, admin_headers):
    """The consequence the rejection exists for, asserted end to end against the
    query the scanner actually runs (``_scan_topics_union``)."""
    from services.monitoring.unified_watcher import _scan_topics_union

    assert _post(api_client, protocol_id, admin_headers, {"tracked_topics": [{"topic0": TOPIC0}]}).status_code == 422
    assert _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True}).status_code == 200

    assert TOPIC0 not in _scan_topics_union(db_session)
