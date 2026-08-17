"""Offline logging/observability tests for the effects stage (audit part 2, C).

Covers the dark edges the audit named: anvil output is drained into the logger
and its tail survives into the spawn error, the degraded skip/swallow paths pair
a log with ``record_degraded``, and the worker's counters reconcile
(``candidates_in == hits + misses + skipped + probes_failed``) in both the stage
metrics and the completion summary.

No DB / network: every case drives a pure helper, a fake subprocess, or a fake
Slither contract.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.effects import anvil as anvil_mod  # noqa: E402
from services.effects import calldata as calldata_mod  # noqa: E402
from services.effects import orchestrator as orch_mod  # noqa: E402
from services.effects import selection as selection_mod  # noqa: E402
from services.effects.anvil import SubprocessAnvil  # noqa: E402
from services.effects.exceptions import AnvilSpawnError  # noqa: E402
from services.effects.selection import Candidate  # noqa: E402
from utils.logging import degraded_errors_var, stage_metrics_var  # noqa: E402

ANVIL_LOGGER = "services.effects.anvil"
CALLDATA_LOGGER = "services.effects.calldata"
ORCH_LOGGER = "services.effects.orchestrator"
SELECTION_LOGGER = "services.effects.selection"
WORKER_LOGGER = "workers.effects_worker"


def _fake_anvil_bin(tmp_path: Path, body: str) -> str:
    script = tmp_path / "fake_anvil.sh"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)
    return str(script)


# ---------------------------------------------------------------------------
# C1 — anvil output is drained, not discarded
# ---------------------------------------------------------------------------


def test_anvil_command_line_no_longer_silences_the_process():
    assert "--silent" not in anvil_mod._build_anvil_cmd("anvil", 8546, "prague", None, None)


def test_spawn_failure_carries_returncode_and_output_tail(tmp_path, caplog):
    """A fork that dies at startup must be explainable: the exit code and the
    process's own last words ride the exception instead of going to DEVNULL."""
    binary = _fake_anvil_bin(
        tmp_path,
        "echo 'anvil starting'\necho 'error: could not fork: 401 unauthorized' >&2\nexit 3\n",
    )
    with caplog.at_level(logging.DEBUG, logger=ANVIL_LOGGER):
        with pytest.raises(AnvilSpawnError) as excinfo:
            SubprocessAnvil(port=8599, hardfork_name="prague", anvil_bin=binary, startup_timeout=5.0)

    message = str(excinfo.value)
    assert "returncode=3" in message
    assert "401 unauthorized" in message

    drained = [r for r in caplog.records if getattr(r, "source", None) == "anvil" and r.levelno == logging.DEBUG]
    assert drained, "anvil output was not drained into the logger"
    assert any("401 unauthorized" in r.getMessage() for r in drained)

    warning = next(r for r in caplog.records if r.levelno == logging.WARNING)
    assert warning.returncode == 3
    assert any("401 unauthorized" in line for line in warning.output_tail)


def test_output_tail_is_bounded(tmp_path):
    """A long-lived chatty fork must not grow the job's memory line by line."""
    binary = _fake_anvil_bin(tmp_path, 'i=0\nwhile [ $i -lt 200 ]; do echo "line $i"; i=$((i+1)); done\nexit 1\n')
    with pytest.raises(AnvilSpawnError):
        SubprocessAnvil(port=8598, hardfork_name="prague", anvil_bin=binary, startup_timeout=5.0)


def test_close_warns_when_sigterm_is_escalated_to_sigkill(caplog):
    """A killed fork and a clean shutdown used to look identical in the log."""

    class _StubbornProc:
        pid = 4242
        stdout = None
        returncode = None
        killed = False

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired(cmd="anvil", timeout=timeout or 0)
            return -9

        def kill(self):
            self.killed = True

    anvil = SubprocessAnvil.__new__(SubprocessAnvil)
    proc = _StubbornProc()
    anvil._proc = proc  # type: ignore[attr-defined]
    anvil._drain = None  # type: ignore[attr-defined]

    with caplog.at_level(logging.WARNING, logger=ANVIL_LOGGER):
        anvil.close()

    assert proc.killed
    rec = next(r for r in caplog.records if r.name == ANVIL_LOGGER)
    assert rec.levelno == logging.WARNING
    assert rec.pid == 4242
    assert rec.source == "anvil"


def test_close_joins_the_drain_thread(tmp_path):
    """Many fork open/close cycles per job must leak neither threads nor fds."""
    binary = _fake_anvil_bin(tmp_path, "while true; do echo tick; sleep 0.2; done\n")
    anvil = SubprocessAnvil.__new__(SubprocessAnvil)
    cmd = [binary]
    anvil._output_tail = anvil_mod.deque(maxlen=8)  # type: ignore[attr-defined]
    anvil._drain = None  # type: ignore[attr-defined]
    anvil._proc = subprocess.Popen(  # type: ignore[attr-defined]
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    anvil._drain = anvil_mod.threading.Thread(target=anvil._drain_output, daemon=True)  # type: ignore[attr-defined]
    anvil._drain.start()  # type: ignore[attr-defined]
    thread = anvil._drain  # type: ignore[attr-defined]

    anvil.close()

    assert not thread.is_alive()
    assert anvil._drain is None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# C3 — dark swallows in the services
# ---------------------------------------------------------------------------


def test_contract_facts_lookup_failure_warns_and_records_degraded(monkeypatch, caplog):
    """A storage/DB outage here evaporates the whole Tier-1 probe surface into
    ``unknown`` verdicts — it must not read as "this contract has no facts"."""

    def boom(*_args, **_kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr("services.resolution.capability_resolver.find_analysis_job_for_address", boom)
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with caplog.at_level(logging.WARNING, logger=CALLDATA_LOGGER):
            assert calldata_mod._load_contract_facts_uncached(None, "0x" + "ab" * 20) is None
    finally:
        degraded_errors_var.reset(token)

    rec = next(r for r in caplog.records if r.name == CALLDATA_LOGGER)
    assert rec.levelno == logging.WARNING
    assert rec.exc_type == "RuntimeError"
    assert [e.phase for e in accumulator] == ["effects_calldata_facts"]


def test_encode_calldata_failure_logs_debug_with_selector(caplog):
    with caplog.at_level(logging.DEBUG, logger=CALLDATA_LOGGER):
        # A value that cannot encode into the declared type.
        assert calldata_mod.encode_calldata("0xdeadbeef", "f(uint256)", substitutions={0: "not-a-number"}) is None

    rec = next(r for r in caplog.records if r.name == CALLDATA_LOGGER)
    assert rec.levelno == logging.DEBUG
    assert rec.selector == "0xdeadbeef"
    assert rec.exc_type


def test_uint_call_failure_logs_the_zero_it_passes(caplog):
    class _Boom:
        def call(self, _tx):
            raise RuntimeError("fork gone")

    with caplog.at_level(logging.DEBUG, logger=ORCH_LOGGER):
        assert orch_mod._uint_call(_Boom(), "0x" + "11" * 20, "0xf27a0c92") == 0

    rec = next(r for r in caplog.records if r.name == ORCH_LOGGER)
    assert rec.levelno == logging.DEBUG
    assert rec.reason == "call_raised"
    assert rec.exc_type == "RuntimeError"


def test_proxy_without_implementation_records_degraded(monkeypatch, caplog):
    class _Contract:
        is_proxy = True
        implementation = ""

    monkeypatch.setattr(orch_mod, "_contract_row", lambda *_a, **_kw: _Contract())
    candidate = Candidate(
        function_id=7,
        contract_id=3,
        contract_address="0x" + "cd" * 20,
        selector="0x12345678",
        function_name="upgradeTo",
        authority_public=False,
        principal_addresses=(),
    )
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with caplog.at_level(logging.WARNING, logger=ORCH_LOGGER):
            assert orch_mod._hashable_code_address(None, candidate) is None
    finally:
        degraded_errors_var.reset(token)

    rec = next(r for r in caplog.records if r.name == ORCH_LOGGER)
    assert rec.levelno == logging.WARNING
    assert rec.contract_id == 3
    assert rec.function_id == 7
    assert [e.phase for e in accumulator] == ["effects_proxy_without_implementation"]


def test_undecodable_stage_timing_body_pairs_with_record_degraded(monkeypatch, caplog):
    monkeypatch.setattr(selection_mod, "_recorded_stage_status", lambda _body: (_ for _ in ()).throw(ValueError("x")))
    monkeypatch.setattr("db.storage.get_storage_client", lambda: _ClientReturning({"k": b"body"}))
    monkeypatch.setattr("db.storage.deserialize_artifact", lambda body, ct: body)
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with caplog.at_level(logging.WARNING, logger=SELECTION_LOGGER):
            assert selection_mod._resolve_stored_statuses({"k": "application/json"}) == {}
    finally:
        degraded_errors_var.reset(token)

    rec = next(r for r in caplog.records if r.name == SELECTION_LOGGER)
    assert rec.key == "k"
    assert [e.phase for e in accumulator] == ["effects_selection_stage_status"]


class _ClientReturning:
    def __init__(self, bodies: dict) -> None:
        self._bodies = bodies

    def get_many(self, keys):
        return {k: self._bodies.get(k) for k in keys}


def test_static_setter_var_scan_failure_records_degraded():
    """The pure-analysis module has no logger by design, so the failed scan is
    published as a degraded record rather than vanishing into an empty map."""
    from services.static.contract_analysis_pipeline import effects as static_effects

    class _Fn:
        is_constructor = False
        name = "setTreasury"
        full_name = "setTreasury(address)"

        def all_state_variables_written(self):
            raise RuntimeError("slither edge")

    class _Contract:
        name = "Vault"
        functions = [_Fn()]

    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        static_effects._SETTER_VARS.pop(_Contract, None)
        assert static_effects._setter_state_vars(_Contract()) == {}
    finally:
        degraded_errors_var.reset(token)

    assert [e.phase for e in accumulator] == ["static_effects_setter_state_vars"]
    assert accumulator[0].context["functions_unscanned"] == 1


# ---------------------------------------------------------------------------
# C4 — metric reconciliation
# ---------------------------------------------------------------------------


def _candidate(fid: int, value: float) -> Candidate:
    return Candidate(
        function_id=fid,
        contract_id=1,
        contract_address="0x" + "ef" * 20,
        selector=f"0x0000000{fid}",
        function_name=f"f{fid}",
        authority_public=True,
        principal_addresses=(),
        value_at_stake_usd=Decimal(value),
    )


def test_dropped_manifest_is_capped_with_the_full_count(caplog):
    dropped = [_candidate(i, 0) for i in range(25)]
    with caplog.at_level(logging.WARNING, logger=SELECTION_LOGGER):
        selection_mod._log_dropped(9, 1, dropped)

    rec = next(r for r in caplog.records if r.name == SELECTION_LOGGER)
    assert rec.dropped == 25
    assert len(rec.dropped_sample) == selection_mod._DROPPED_SAMPLE
    assert rec.dropped_sample_truncated is True
    assert rec.protocol_id == 9


def test_metrics_publish_the_full_candidate_accounting():
    from workers.effects_worker import EffectsWorker, _Counters

    counters = _Counters(
        candidates_in=10,
        cache_hits_kernel=2,
        cache_hits_projection=1,
        cache_misses=4,
        skipped=2,
        probes_failed=1,
        selection_funnel={"rows_in": 14, "skipped_already_explained": 3, "cap_dropped": 1, "selected": 10},
    )
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        EffectsWorker.__new__(EffectsWorker)._record_metrics(counters)
    finally:
        stage_metrics_var.reset(token)

    assert metrics["skipped"] == 2
    assert metrics["probes_failed"] == 1
    assert "candidates_after_cascade" not in metrics
    assert metrics["selection_rows_in"] == 14
    assert metrics["selection_cap_dropped"] == 1
    # The whole point: the candidate set reconciles.
    assert (
        metrics["candidates_in"]
        == metrics["cache_hits_kernel"]
        + metrics["cache_hits_projection"]
        + metrics["cache_misses"]
        + metrics["skipped"]
        + metrics["probes_failed"]
    )


def test_rss_sample_failure_is_logged_once_per_job(caplog):
    from workers.effects_worker import EffectsWorker, _Counters

    class _Anvil:
        def rss_mb(self):
            raise OSError("/proc gone")

    worker = EffectsWorker.__new__(EffectsWorker)
    worker._anvil = _Anvil()
    worker._rss_sample_failed = False
    counters = _Counters()
    with caplog.at_level(logging.DEBUG, logger=WORKER_LOGGER):
        worker._sample_anvil_rss(counters)
        worker._sample_anvil_rss(counters)

    records = [r for r in caplog.records if r.name == WORKER_LOGGER]
    assert len(records) == 1
    assert records[0].exc_type == "OSError"
    # The counter stays at its unmeasured default — the log is what says so.
    assert counters.peak_anvil_rss_mb == 0
