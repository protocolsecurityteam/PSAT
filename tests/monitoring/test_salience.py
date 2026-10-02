"""The salience spine: the rule table, the mechanical gate keeping ``routine`` honest,
E5's ``signal_class``, the three mint sites, the notifier opt-in, and the enrichment seam.

The census is per-RULE: every row is exercised with its basis asserted. The gate:
**no ``routine`` is minted from an absent input**; both routine arms need a positive finding
(stamped ``signal_class`` with basis, or decoded ``not_top_level_call``), and removing either
must fall back to ``not_determined`` (visible), never ``routine``.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import select

from db.models import (
    Contract,
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
)
from services.monitoring import salience as sal
from services.monitoring.enrichment import ENRICHERS, NEEDS_TX, enrich_events
from services.monitoring.notifier import _salience_allows, notify_protocol_events
from services.monitoring.polling_plan import (
    SIGNAL_BASIS_CALLER_GATE,
    SIGNAL_BASIS_NO_GATE_PROVENANCE,
    SIGNAL_BASIS_TYPE_KIND_REFERENCE,
    SIGNAL_CLASS_CONFIG,
    SIGNAL_CLASS_METRIC,
    build_polling_plan,
)
from services.monitoring.unified_watcher import (
    _apply_poll_result,
    scan_for_events,
)
from services.resolution.repos.event_logs_rpc import FetchedEventLog


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


SAFE = ADDR(0x5AFE)


@pytest.fixture()
def make_mc(db_session):
    protocol = Protocol(name="salience", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()
    counter = iter(range(0x5AFE, 0x6000))

    def make(
        *,
        address: str | None = None,
        contract_type: str = "regular",
        enrollment_block: int | None = 1,
        monitoring_config: dict | None = None,
        last_known_state: dict | None = None,
    ) -> MonitoredContract:
        # ``contracts`` is keyed on (address, chain), so each call gets its own address.
        address = address or ADDR(next(counter))
        contract = Contract(protocol_id=protocol.id, address=address, chain="ethereum")
        db_session.add(contract)
        db_session.flush()
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=address,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_id=contract.id,
            contract_type=contract_type,
            monitoring_config=monitoring_config or {},
            last_known_state=last_known_state or {},
            last_scanned_block=100,
            enrollment_block=enrollment_block,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()
        return mc

    return make


def rate(db_session, mc, event_type: str, data: dict | None = None) -> tuple[str, list[str]]:
    return sal.assign_salience(db_session, event_type, data, mc)


# ---------------------------------------------------------------------------
# Salience rule table — one named test per rule, basis asserted
# ---------------------------------------------------------------------------


def test_rule_reinitialization(db_session, make_mc):
    """A second Initialized on an enrolled proxy is a takeover signal."""
    mc = make_mc()
    assert rate(db_session, mc, "initialized", {}) == (sal.SALIENCE_NOT_DETERMINED, [sal.BASIS_NO_RULE])

    db_session.add(
        MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type="initialized",
            block_number=5,
            tx_hash="0x" + "11" * 32,
            log_index=0,
            data={},
        )
    )
    db_session.commit()
    assert rate(db_session, mc, "initialized", {}) == (sal.SALIENCE_ALERT, [sal.BASIS_REINITIALIZATION])


@pytest.mark.parametrize("event_type", ["state_changed_poll", "value_changed:state_variable:owner"])
def test_rule_config_field_diff(db_session, make_mc, event_type):
    data = {"signal_class": SIGNAL_CLASS_CONFIG, "signal_class_basis": SIGNAL_BASIS_TYPE_KIND_REFERENCE}
    assert rate(db_session, make_mc(), event_type, data) == (
        sal.SALIENCE_NOTABLE,
        [sal.BASIS_CONFIG_FIELD_DIFF],
    )


def test_correlated_cause_replaces_no_rule(db_session, make_mc):
    data = {"correlated_events": [{"event_id": "a", "event_type": "paused", "salience": sal.SALIENCE_ALERT}]}
    assert rate(db_session, make_mc(), "some_unrated_type", data) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_CORRELATED_CAUSE],
    )


def test_a_metric_class_without_its_basis_cannot_mint_routine(db_session, make_mc):
    for basis in (None, "", 3):
        data = {"signal_class": SIGNAL_CLASS_METRIC, "signal_class_basis": basis}
        level, codes = rate(db_session, make_mc(), "state_changed_poll", data)
        assert level == sal.SALIENCE_NOT_DETERMINED
        assert codes == [sal.BASIS_NO_RULE]


def test_no_rule_mints_routine_without_a_positive_basis(db_session, make_mc):
    """The only two routine inputs are a stamped metric class with basis and a decoded ``not_top_level_call``."""
    mc = make_mc()
    shapes: list[tuple[str, dict | None]] = [
        ("state_changed_poll", None),
        ("state_changed_poll", {}),
        ("state_changed_poll", {"signal_class": SIGNAL_CLASS_METRIC}),
        ("state_changed_poll", {"signal_class": "made_up"}),
        ("value_changed:state_variable:x", {}),
        ("value_changed:state_variable:x", {"signal_class_basis": SIGNAL_BASIS_NO_GATE_PROVENANCE}),
        ("safe_tx_executed", {}),
        ("safe_tx_executed", {"safe_exec": {}}),
        ("safe_tx_executed", {"safe_exec": {"status": "over_budget"}}),
        ("safe_tx_executed", {"safe_exec": {"status": "decoded"}}),
        ("safe_module_executed", {}),
        ("initialized", {}),
        ("unknown_type", {}),
    ]
    for event_type, data in shapes:
        level, codes = rate(db_session, mc, event_type, data)
        assert level != sal.SALIENCE_ROUTINE, (event_type, data, codes)


# ---------------------------------------------------------------------------
# Signal classification on freshly built polling plans
# ---------------------------------------------------------------------------


def _tracking_plan(*controllers: dict) -> dict:
    return {"schema_version": "0.1", "tracked_controllers": list(controllers)}


def _controller(controller_id: str, *, type_kind: str, type_str: str = "", provenance: str | None = None) -> dict:
    tc: dict = {
        "controller_id": controller_id,
        "label": controller_id,
        "read_spec": {
            "strategy": "getter_call",
            "target": controller_id.split(":")[-1],
            "state_variable_name": controller_id.split(":")[-1],
            "type_kind": type_kind,
            "type": type_str,
        },
    }
    if provenance:
        tc["authority_provenance"] = provenance
    return tc


def _by_field(plan: list[dict]) -> dict[str, dict]:
    return {entry["field"]: entry for entry in plan}


def test_a_proven_caller_gate_primitive_classifies_config():
    plan = _by_field(
        build_polling_plan(
            contract_type="regular",
            tracking_plan=_tracking_plan(
                _controller("state_variable:isPaused", type_kind="primitive", type_str="bool", provenance="caller_gate")
            ),
        )
    )
    assert plan["isPaused"]["signal_class"] == SIGNAL_CLASS_CONFIG
    assert plan["isPaused"]["signal_class_basis"] == SIGNAL_BASIS_CALLER_GATE


def _poll_entry(signal_class: str | None = None, basis: str | None = None) -> dict:
    entry = {
        "field": "rate",
        "kind": "getter_call",
        "target": "rate",
        "selector": RATE_SELECTOR,
        "type_kind": "primitive",
        "type": "uint256",
        "source": "analyzer:state_variable:rate",
    }
    if signal_class:
        entry["signal_class"] = signal_class
    if basis:
        entry["signal_class_basis"] = basis
    return entry


def _poll(db_session, mc, entry, raw_value: int) -> dict:
    new_events: list[MonitoredEvent] = []
    _apply_poll_result(db_session, mc, entry, "0x" + hex(raw_value)[2:].zfill(64), new_events)
    db_session.commit()
    assert len(new_events) == 1
    return new_events[0].data or {}


RATE_TOPIC0 = "0x" + keccak(text="RateUpdated(uint256)").hex()
RATE_SELECTOR = "0x" + keccak(text="rate()").hex()[:8]


def _fetched(topic0: str, *, address: str, data: str = "0x", block: int = 200, idx: int = 0) -> FetchedEventLog:
    raw = {
        "address": address,
        "topics": [topic0],
        "data": data,
        "blockNumber": hex(block),
        "transactionHash": "0x" + f"{idx:064x}",
        "logIndex": hex(idx),
        "blockHash": "0x" + "b" * 64,
        "transactionIndex": "0x0",
    }
    return FetchedEventLog(
        tx_hash=bytes.fromhex(f"{idx:064x}"),
        log_index=idx,
        block_number=block,
        block_hash=b"\xbb" * 32,
        transaction_index=0,
        topics=[topic0],
        data_words=[],
        address=address,
        raw=raw,
    )


def _hint_spec() -> dict:
    return {
        "topic0": RATE_TOPIC0,
        "signature": "RateUpdated(uint256)",
        "event_type": "state_changed:state_variable:rate",
        "controller_id": "state_variable:rate",
        "witness_tier": "hint",
        "inputs": [{"name": "rate", "type": "uint256", "indexed": False}],
        "effect_tags": {"writes": ["rate", "lastUpdate"]},
        "writer_openness": "not_determined",
    }


def test_verification_read_mint_stamps_the_entrys_signal_class(db_session, make_mc):
    """Only here is the answering plan entry in scope."""
    entry = _poll_entry(SIGNAL_CLASS_METRIC, SIGNAL_BASIS_NO_GATE_PROVENANCE)
    mc = make_mc(
        monitoring_config={"tracked_topics": [_hint_spec()], "polling_plan": [entry]},
        last_known_state={"rate": 7},
    )
    log = _fetched(RATE_TOPIC0, address=mc.address, data="0x" + hex(11)[2:].zfill(64))

    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")],
        ),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: [log]
        scan_for_events(db_session, "http://rpc.invalid")

    row = (
        db_session.execute(
            select(MonitoredEvent).where(MonitoredEvent.event_type == "value_changed:state_variable:rate")
        )
        .scalars()
        .one()
    )
    assert row.data["signal_class"] == SIGNAL_CLASS_METRIC
    assert row.data["signal_class_basis"] == SIGNAL_BASIS_NO_GATE_PROVENANCE
    assert row.data["salience"] == sal.SALIENCE_ROUTINE
    assert row.data["salience_basis"] == [sal.BASIS_METRIC_FIELD_DIFF]
    # The routine level did not gate the insert.
    assert row.data["witness"] == "read_verified"


@pytest.fixture(autouse=True)
def _no_wire():
    """The driver's transaction fetch issues RPC calls, and these tests
    hand it an unreachable endpoint. Stub the batch call so the offline suite
    stays hermetic; the fetch itself is exercised against fixture transactions
    in ``tests/monitoring/test_enrichment_decode.py``."""
    with patch(
        "services.monitoring.enrichment.rpc_batch_request_classified",
        side_effect=lambda _url, calls, *_a, **_kw: [(None, "transport")] * len(calls),
    ):
        yield


def _seed_event(db_session, mc, event_type: str, data: dict) -> MonitoredEvent:
    event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type=event_type,
        block_number=10,
        tx_hash="0x" + "cd" * 32,
        log_index=0,
        data=data,
    )
    db_session.add(event)
    db_session.commit()
    return event


def test_a_type_the_registry_does_not_cover_is_left_untouched(db_session, make_mc):
    """``authority_updated`` alone in its transaction has no decoder or correlation partner."""
    assert set(ENRICHERS) == {"safe_tx_executed", "safe_tx_failed", "timelock_scheduled", "timelock_executed"}
    assert NEEDS_TX == frozenset({"safe_tx_executed", "safe_tx_failed"})

    mc = make_mc()
    before = {
        "new_authority": ADDR(3),
        "salience": sal.SALIENCE_ALERT,
        "salience_basis": [sal.BASIS_CANONICAL_CONFIG_FAMILY],
    }
    event = _seed_event(db_session, mc, "authority_updated", dict(before))

    enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    assert db_session.get(MonitoredEvent, event.id).data == before


# ---------------------------------------------------------------------------
# The notifier opt-in
# ---------------------------------------------------------------------------


@pytest.fixture()
def notify_env(db_session, make_mc):
    mc = make_mc(monitoring_config={"watch_ownership": True})
    sub = ProtocolSubscription(
        id=uuid.uuid4(),
        protocol_id=mc.protocol_id,
        discord_webhook_url="https://discord.com/api/webhooks/1/test",
    )
    db_session.add(sub)
    db_session.commit()

    def emit(event_type: str, data: dict | None) -> MonitoredEvent:
        event = _seed_event(db_session, mc, event_type, data or {})
        db_session.refresh(event)
        return event

    return sub, emit


@pytest.mark.parametrize(
    "minimum,level,allowed",
    [
        (None, "routine", True),
        (None, None, True),
        ("routine", "routine", True),
        ("notable", "routine", False),
        ("notable", "notable", True),
        ("notable", "not_determined", True),
        ("notable", None, True),
        ("notable", "alert", True),
        ("alert", "notable", False),
        ("alert", "not_determined", False),
        ("alert", "alert", True),
        ("nonsense", "routine", True),
    ],
)
def test_salience_allows(db_session, notify_env, minimum, level, allowed):
    """An unrated event must not be dropped by a bar it was never measured against; it doesn't pass ``alert``."""
    sub, emit = notify_env
    sub.event_filter = {"min_salience": minimum} if minimum else None
    db_session.commit()
    event = emit("ownership_transferred", {"salience": level} if level else {})
    assert _salience_allows(sub, event) is allowed


def test_a_rejected_webhook_is_not_counted_as_a_sent_notification(db_session, notify_env, caplog):
    import logging as _logging
    from types import SimpleNamespace

    _sub, emit = notify_env
    event = emit("ownership_transferred", {"salience": sal.SALIENCE_ROUTINE, "new_owner": ADDR(9)})
    with patch("services.monitoring.notifier.requests.post") as post:
        post.return_value = SimpleNamespace(ok=False, status_code=401, text="unauthorized")
        with caplog.at_level(_logging.INFO, logger="services.monitoring.notifier"):
            notify_protocol_events(db_session, [event])

    assert post.call_count == 1
    summary = next(r for r in caplog.records if hasattr(r, "sent") and hasattr(r, "failed"))
    assert summary.sent == 0
    assert summary.failed == 1


def test_min_salience_composes_with_the_event_type_filter(db_session, notify_env):
    sub, emit = notify_env
    routine = emit("ownership_transferred", {"salience": sal.SALIENCE_ROUTINE, "new_owner": ADDR(9)})

    sub.event_filter = {"event_types": ["ownership_transferred"]}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [routine])
    assert send.call_count == 1

    sub.event_filter = {"event_types": ["ownership_transferred"], "min_salience": "notable"}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [routine])
    assert send.call_count == 0

    sub.event_filter = {"event_types": ["paused"], "min_salience": "routine"}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [routine])
    assert send.call_count == 0


# ---------------------------------------------------------------------------
# The API boundary
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Additive enrichment, enforced at the driver
# ---------------------------------------------------------------------------
