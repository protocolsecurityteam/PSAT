"""Observability locks for the monitoring daemons (scan / poll / TVL cycles).

These daemons run outside ``BaseWorker``, so the job-scoped ``record_degraded``
accumulator is a no-op. The house-standard substitute is a per-cycle
``record_heartbeat(detail={...})`` plus one unconditional INFO carrying the
cycle counts as queryable ``extra`` fields — even on a 0-event / 0-contract
cycle. This test pins that contract.

Offline: the RPC/DB wire is stubbed (MagicMock session, patched heartbeat); no
network, no live marker.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

import services.monitoring as monitoring
import services.monitoring.unified_watcher as uw
from services.monitoring import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_TVL,
    emit_monitor_cycle,
)
from utils.logging import log_timed_phase

_CYCLE_FIELDS = {"contracts_scanned", "blocks_scanned", "events_found", "partial", "duration_ms"}


def test_failed_phase_can_log_duration_when_stage_artifact_is_unavailable(caplog):
    logger = logging.getLogger("test.failed_phase")
    with caplog.at_level(logging.INFO, logger=logger.name):
        with pytest.raises(RuntimeError, match="database down"):
            with log_timed_phase(logger, "membership_gate_intake", log_failure=True):
                raise RuntimeError("database down")
    record = next(r for r in caplog.records if r.message.startswith("phase ended with error"))
    assert record.phase == "membership_gate_intake"
    assert record.outcome == "failed"
    assert record.duration_ms >= 0


def test_emit_monitor_cycle_running_heartbeat_and_info(caplog):
    with patch.object(monitoring, "record_heartbeat") as hb:
        with caplog.at_level(logging.INFO, logger="services.monitoring"):
            emit_monitor_cycle(
                HEARTBEAT_PROTOCOL_SCANNER,
                started=0.0,
                contracts_scanned=7,
                blocks_scanned=2000,
                events_found=0,
                partial=False,
            )

    # Heartbeat: a healthy quiet cycle beats as "running" with the counts in detail.
    hb.assert_called_once()
    (process,), kwargs = hb.call_args
    assert process == HEARTBEAT_PROTOCOL_SCANNER
    assert kwargs["status"] == "running"
    assert _CYCLE_FIELDS <= set(kwargs["detail"])
    assert kwargs["detail"]["events_found"] == 0
    assert kwargs["detail"]["contracts_scanned"] == 7
    assert kwargs["detail"]["partial"] is False

    # INFO: facts live in extra={} (queryable), not interpolated into the message.
    rec = next(r for r in caplog.records if r.message == "monitor cycle complete")
    assert rec.levelno == logging.INFO
    assert getattr(rec, "daemon") == HEARTBEAT_PROTOCOL_SCANNER
    assert getattr(rec, "events_found") == 0
    assert getattr(rec, "blocks_scanned") == 2000
    assert getattr(rec, "partial") is False


def test_emit_monitor_cycle_partial_marks_degraded():
    with patch.object(monitoring, "record_heartbeat") as hb:
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_POLLER,
            started=0.0,
            contracts_scanned=3,
            blocks_scanned=0,
            events_found=0,
            partial=True,
            note="batch_rpc_failed",
        )

    _, kwargs = hb.call_args
    # A partial cycle (an RPC chunk failed mid-scan) flips the heartbeat to degraded.
    assert kwargs["status"] == "degraded"
    assert kwargs["detail"]["partial"] is True
    assert kwargs["detail"]["note"] == "batch_rpc_failed"


def test_scan_for_events_zero_active_contracts_still_emits_cycle(caplog):
    # No enrolled contracts: scan_for_events returns [] early but must still
    # beat so a dead watcher is distinguishable from a healthy idle one. The
    # columns-only index load reads ``session.execute(...).all()`` directly.
    session = MagicMock()
    session.execute.return_value.all.return_value = []
    session.execute.return_value.scalars.return_value.all.return_value = []

    with patch.object(monitoring, "record_heartbeat") as hb:
        with caplog.at_level(logging.INFO, logger="services.monitoring"):
            result = uw.scan_for_events(session, "http://stub")

    assert result == []
    hb.assert_called_once()
    (process,), kwargs = hb.call_args
    assert process == HEARTBEAT_PROTOCOL_SCANNER
    assert kwargs["status"] == "running"
    assert kwargs["detail"]["contracts_scanned"] == 0
    assert kwargs["detail"]["note"] == "no_active_contracts"
    assert any(r.message == "monitor cycle complete" for r in caplog.records)


def test_poll_for_state_changes_zero_active_contracts_still_emits_cycle():
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = []

    with patch.object(monitoring, "record_heartbeat") as hb:
        result = uw.poll_for_state_changes(session, "http://stub")

    assert result == []
    (process,), kwargs = hb.call_args
    assert process == HEARTBEAT_PROTOCOL_POLLER
    assert kwargs["detail"]["note"] == "no_active_contracts"


def test_tvl_refresh_all_protocols_emits_cycle_on_empty():
    import services.monitoring.tvl as tvl

    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = []

    with patch.object(monitoring, "record_heartbeat") as hb:
        count = tvl.refresh_all_protocols(session)

    assert count == 0
    (process,), kwargs = hb.call_args
    assert process == HEARTBEAT_PROTOCOL_TVL
    assert kwargs["status"] == "running"
    assert kwargs["detail"]["events_found"] == 0
    assert kwargs["detail"]["partial"] is False
    # The cycle now says what it could not observe, even when that is nothing.
    assert kwargs["detail"]["protocols_failed"] == 0
    assert kwargs["detail"]["protocols_partial"] == 0


# --- the silent-collapse class: one alarm per cycle, then a count -------------


# --- disposition: the per-cycle outcome summary ------------------------------


# --- proxy watcher: a transport failure is not a revert ----------------------


def test_proxy_watcher_unanswered_probe_warns_once_per_resolution(caplog):
    from services.monitoring import proxy_watcher

    def _dead(*_args, **_kwargs):
        raise RuntimeError("RPC request failed for http://stub: connection refused")

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _dead):
        with caplog.at_level(logging.DEBUG, logger="services.monitoring.proxy_watcher"):
            assert proxy_watcher.resolve_current_implementation("0x" + "e" * 40, "http://stub") is None
            # Eight probes failed; the next pass over the SAME proxy carries the
            # repeat at DEBUG (a different proxy has its own alarm — see below).
            assert proxy_watcher.resolve_current_implementation("0x" + "e" * 40, "http://stub") is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1  # one per resolution, never one per probe
    assert warnings[0].probes_unanswered == warnings[0].probes
    assert warnings[0].probes > 1


def test_proxy_watcher_reverting_getter_is_not_a_transport_failure(caplog):
    from services.monitoring import proxy_watcher

    def _reverts(_url, method, _params, **_kwargs):
        if method == "eth_getStorageAt":
            return "0x" + "0" * 64
        # The shape ``rpc_request`` raises for a JSON-RPC error payload: the
        # node's own object, stringified.
        raise RuntimeError(str({"code": -32000, "message": "execution reverted"}))

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _reverts):
        with caplog.at_level(logging.WARNING, logger="services.monitoring.proxy_watcher"):
            assert proxy_watcher.resolve_current_implementation("0x" + "e" * 40, "http://stub") is None

    # Every probe ANSWERED; "no implementation here" is a finding, not a fault.
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


def test_proxy_watcher_treats_an_unrecognised_failure_as_not_determined(caplog):
    """The chain_id guard raises before the wire; it is not a revert."""
    from services.monitoring import proxy_watcher

    def _guard(*_args, **_kwargs):
        raise RuntimeError(
            "eRPC URL/chain_id mismatch: caller declared chain_id=8453 but the RPC URL routes chain_id=1"
        )

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _guard):
        with caplog.at_level(logging.WARNING, logger="services.monitoring.proxy_watcher"):
            assert (
                proxy_watcher.resolve_current_implementation(
                    "0x" + "e" * 40, "http://stub", proxy_type="eip1967", chain_id=8453
                )
                is None
            )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].probes_unanswered == 1


def test_proxy_watcher_rate_limit_payload_is_not_a_proven_absence(caplog):
    """The outage class this split exists for arrives as an error payload too.

    A provider rate limit and a contract revert are both ``error`` objects; only
    the revert says anything about the contract, so only it may read as "no
    implementation here".
    """
    from services.monitoring import proxy_watcher

    def _rate_limited(*_args, **_kwargs):
        raise RuntimeError(str({"code": -32005, "message": "daily request count exceeded"}))

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _rate_limited):
        with caplog.at_level(logging.WARNING, logger="services.monitoring.proxy_watcher"):
            assert (
                proxy_watcher.resolve_current_implementation("0x" + "a1" * 20, "http://stub", proxy_type="custom")
                is None
            )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].probes_unanswered == 1


def test_proxy_watcher_storage_read_error_is_never_an_empty_slot(caplog):
    """A storage read has no revert semantics; every error is a failure to answer."""
    from services.monitoring import proxy_watcher

    def _trie_gone(_url, method, _params, **_kwargs):
        assert method == "eth_getStorageAt"
        raise RuntimeError(str({"code": -32000, "message": "missing trie node"}))

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _trie_gone):
        with caplog.at_level(logging.WARNING, logger="services.monitoring.proxy_watcher"):
            assert (
                proxy_watcher.resolve_current_implementation("0x" + "a2" * 20, "http://stub", proxy_type="eip1967")
                is None
            )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].probes_unanswered == 1


def test_proxy_watcher_warn_once_is_keyed_per_proxy(caplog):
    """One subject's alarm must not stand for another subject's silence."""
    from services.monitoring import proxy_watcher

    def _dead(*_args, **_kwargs):
        raise RuntimeError("RPC request failed for http://stub: connection refused")

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _dead):
        with caplog.at_level(logging.DEBUG, logger="services.monitoring.proxy_watcher"):
            for address in ("0x" + "b1" * 20, "0x" + "b1" * 20, "0x" + "b2" * 20):
                proxy_watcher.resolve_current_implementation(address, "http://stub", proxy_type="eip1967")

    warned = [r.address for r in caplog.records if r.levelno == logging.WARNING]
    assert warned == ["0x" + "b1" * 20, "0x" + "b2" * 20]


# --- the fleet's own liveness signal ----------------------------------------


def test_heartbeat_write_failure_warns_then_rate_limits(caplog, monkeypatch):
    """A silent heartbeat failure shows every daemon dead while they all run."""
    from db.queue import heartbeats as dbq

    def _no_session():
        raise RuntimeError("could not connect to server")

    monkeypatch.setattr(dbq, "SessionLocal", _no_session)
    dbq._heartbeat_last_warned.clear()
    with caplog.at_level(logging.DEBUG, logger="db.queue"):
        for _ in range(4):
            dbq.record_heartbeat("protocol_tvl")

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].daemon == "protocol_tvl"
    assert warnings[0].exc_type == "RuntimeError"
    # The rest are still recorded, just not at a level that storms.
    assert len([r for r in caplog.records if r.levelno == logging.DEBUG]) == 3


# --- scanner / poller: what the pass dropped ---------------------------------


def test_undecodable_tracked_log_is_counted_for_the_scanner_heartbeat():
    """A log that matched an enrolled spec and would not decode left no trace."""
    mc = MagicMock()
    mc.address = "0x" + "a" * 40
    mc.monitoring_config = {"tracked_topics": [{"topic0": "0x" + "1" * 64, "event_type": "x"}]}
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = [mc]

    fetched = MagicMock()
    fetched.raw = {"topics": ["0x" + "1" * 64]}
    fetched.address = mc.address
    fetched.topics = ["0x" + "1" * 64]

    cohort = uw._Cohort(chain="ethereum", member_ids=[], addresses=[mc.address], cursor=0)
    counters: dict[str, int] = {}
    with patch.object(uw, "parse_any_log", lambda _raw: None):
        with patch.object(uw, "parse_tracked_log", lambda _raw, _spec: None):
            events = uw._process_window(session, cohort, [fetched], 1, 2, None, counters)

    assert events == []
    assert counters["undecodable_tracked_logs"] == 1


def test_poller_publishes_the_plan_entries_it_could_not_dispatch(db_session):
    """A plan entry this build cannot dispatch vanished from all accounting."""
    import uuid as _uuid

    from db.models import MonitoredContract

    db_session.add(
        MonitoredContract(
            id=_uuid.uuid4(),
            address="0x" + "5e" * 20,
            chain="ethereum",
            contract_type="regular",
            monitoring_config={
                "polling_plan": [
                    {"field": "owner", "kind": "getter_call", "selector": "0x8da5cb5b", "type_kind": "address"},
                    {"field": "future", "kind": "a_kind_this_build_does_not_know"},
                    "not even a dict",
                ]
            },
            last_known_state={},
            last_scanned_block=0,
            needs_polling=True,
            is_active=True,
        )
    )
    db_session.commit()

    with patch.object(uw, "rpc_batch_request_classified", lambda _url, calls: [(None, "ok") for _ in calls]):
        with patch.object(monitoring, "record_heartbeat") as hb:
            uw.poll_for_state_changes(db_session, "http://stub")

    _process, kwargs = hb.call_args
    assert kwargs["detail"]["entries_unrecognized"] == 2
    # Not a partial: an entry that was never dispatched failed to observe nothing.
    assert kwargs["detail"]["contracts_selected"] == 1


# --- notifier: a rejected post is not a sent one -----------------------------


def test_send_discord_reports_a_rejected_post():
    from services.monitoring import notifier

    # A Discord-host URL, so the SSRF host gate lets the post through and the
    # response-handling path under test actually runs.
    webhook = "https://discord.com/api/webhooks/1/test"
    with patch.object(notifier.requests, "post") as post:
        post.return_value = MagicMock(ok=False, status_code=401, text="unauthorized")
        assert notifier._send_discord(webhook, {"title": "x"}) is False
        post.return_value = MagicMock(ok=True, status_code=204, text="")
        assert notifier._send_discord(webhook, {"title": "x"}) is True
    assert post.call_count == 2
