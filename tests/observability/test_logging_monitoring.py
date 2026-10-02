"""These daemons run outside ``BaseWorker``, so the substitute for ``record_degraded`` is a per-cycle heartbeat plus
one INFO with counts, even on an idle cycle.
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
)
from utils.logging import log_timed_phase


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


def test_scan_for_events_zero_active_contracts_still_emits_cycle(caplog):
    # A dead watcher must be distinguishable from a healthy idle one.
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
    assert kwargs["detail"]["protocols_failed"] == 0
    assert kwargs["detail"]["protocols_partial"] == 0


def test_proxy_watcher_unanswered_probe_warns_once_per_resolution(caplog):
    from services.monitoring import proxy_watcher

    def _dead(*_args, **_kwargs):
        raise RuntimeError("RPC request failed for http://stub: connection refused")

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _dead):
        with caplog.at_level(logging.DEBUG, logger="services.monitoring.proxy_watcher"):
            assert proxy_watcher.resolve_current_implementation("0x" + "e" * 40, "http://stub") is None
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
        raise RuntimeError(str({"code": -32000, "message": "execution reverted"}))

    proxy_watcher.reset_not_determined_warn_state()
    with patch.object(proxy_watcher, "rpc_request", _reverts):
        with caplog.at_level(logging.WARNING, logger="services.monitoring.proxy_watcher"):
            assert proxy_watcher.resolve_current_implementation("0x" + "e" * 40, "http://stub") is None

    # "No implementation here" is a finding, not a fault.
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


def test_proxy_watcher_rate_limit_payload_is_not_a_proven_absence(caplog):
    """Only a revert says anything about the contract."""
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


def test_heartbeat_write_failure_warns_then_rate_limits(caplog, monkeypatch):
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
    assert len([r for r in caplog.records if r.levelno == logging.DEBUG]) == 3


def test_undecodable_tracked_log_is_counted_for_the_scanner_heartbeat():
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
    # An entry never dispatched failed to observe nothing.
    assert kwargs["detail"]["contracts_selected"] == 1


def test_send_discord_reports_a_rejected_post():
    from services.monitoring import notifier

    # So the SSRF host gate lets the post through.
    webhook = "https://discord.com/api/webhooks/1/test"
    with patch.object(notifier.requests, "post") as post:
        post.return_value = MagicMock(ok=False, status_code=401, text="unauthorized")
        assert notifier._send_discord(webhook, {"title": "x"}) is False
        post.return_value = MagicMock(ok=True, status_code=204, text="")
        assert notifier._send_discord(webhook, {"title": "x"}) is True
    assert post.call_count == 2
