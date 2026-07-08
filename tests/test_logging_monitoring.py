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

import services.monitoring as monitoring
import services.monitoring.unified_watcher as uw
from services.monitoring import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_TVL,
    emit_monitor_cycle,
)

_CYCLE_FIELDS = {"contracts_scanned", "blocks_scanned", "events_found", "partial", "duration_ms"}


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
