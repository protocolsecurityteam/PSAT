"""Anvil output survives into the spawn error, degraded paths pair a log with a bounded record, and every worklist
item lands in exactly one counter.
"""

from __future__ import annotations

import logging
import subprocess
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from services.effects import anvil as anvil_mod
from services.effects import calldata as calldata_mod
from services.effects import orchestrator as orch_mod
from services.effects import selection as selection_mod
from services.effects.anvil import SubprocessAnvil
from services.effects.exceptions import AnvilSpawnError
from services.effects.selection import Candidate
from utils.logging import degraded_errors_var, stage_metrics_var

pytestmark = pytest.mark.anvil

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from services.effects.anvil import AnvilTransport

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


def test_spawn_failure_carries_returncode_and_output_tail(tmp_path, caplog):
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


def test_close_warns_when_sigterm_is_escalated_to_sigkill(caplog):

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
    anvil._proc = proc  # pyright: ignore[reportAttributeAccessIssue]
    anvil._drain = None

    with caplog.at_level(logging.WARNING, logger=ANVIL_LOGGER):
        anvil.close()

    assert proc.killed
    rec = next(r for r in caplog.records if r.name == ANVIL_LOGGER)
    assert rec.levelno == logging.WARNING
    assert rec.pid == 4242
    assert rec.source == "anvil"


def test_close_joins_the_drain_thread(tmp_path):
    binary = _fake_anvil_bin(tmp_path, "while true; do echo tick; sleep 0.2; done\n")
    anvil = SubprocessAnvil.__new__(SubprocessAnvil)
    cmd = [binary]
    anvil._output_tail = anvil_mod.deque(maxlen=8)
    anvil._drain = None
    anvil._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    anvil._drain = anvil_mod.threading.Thread(target=anvil._drain_output, daemon=True)
    anvil._drain.start()
    thread = anvil._drain

    anvil.close()

    assert not thread.is_alive()
    assert anvil._drain is None


def test_contract_facts_lookup_failure_warns_and_records_degraded(monkeypatch, caplog):
    """A storage/DB outage here would read as "this contract has no facts"."""

    def boom(*_args, **_kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr("services.resolution.capability_resolver.find_analysis_job_for_address", boom)
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with caplog.at_level(logging.WARNING, logger=CALLDATA_LOGGER):
            assert calldata_mod._load_contract_facts_uncached(cast("Session", None), "0x" + "ab" * 20) is None
    finally:
        degraded_errors_var.reset(token)

    rec = next(r for r in caplog.records if r.name == CALLDATA_LOGGER)
    assert rec.levelno == logging.WARNING
    assert rec.exc_type == "RuntimeError"
    # The formatter drops an extra named ``address``.
    assert rec.contract_address == "0x" + "ab" * 20
    assert not hasattr(rec, "address")
    assert [e.phase for e in accumulator] == ["effects_calldata_facts"]
    assert accumulator[0].context["contract_address"] == "0x" + "ab" * 20


def test_uint_call_failure_logs_the_zero_it_passes(caplog):
    class _Boom:
        def call(self, _tx):
            raise RuntimeError("fork gone")

    with caplog.at_level(logging.DEBUG, logger=ORCH_LOGGER):
        assert orch_mod._uint_call(cast("AnvilTransport", _Boom()), "0x" + "11" * 20, "0xf27a0c92") == 0

    rec = next(r for r in caplog.records if r.name == ORCH_LOGGER)
    assert rec.levelno == logging.DEBUG
    assert rec.reason == "call_raised"
    assert rec.exc_type == "RuntimeError"


def test_proxy_without_implementation_warns_and_leaves_the_record_to_the_worker(monkeypatch, caplog):
    """Recording here too would double every entry of the shortfall."""

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
            assert orch_mod._hashable_code_address(cast("Session", None), candidate) is None
    finally:
        degraded_errors_var.reset(token)

    rec = next(r for r in caplog.records if r.name == ORCH_LOGGER)
    assert rec.levelno == logging.WARNING
    assert rec.contract_id == 3
    assert rec.function_id == 7
    assert accumulator == [], "the refusing helper must not double-record the worker's capped skip"


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
    """The pure-analysis module has no logger by design."""
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
    # The memo is keyed on the contract object.
    contract = _Contract()
    assert contract not in static_effects._SETTER_VARS
    try:
        assert static_effects._setter_state_vars(contract) == {}
    finally:
        degraded_errors_var.reset(token)

    assert [e.phase for e in accumulator] == ["static_effects_setter_state_vars"]
    assert accumulator[0].context["functions_unscanned"] == 1


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


class _FlushOnlySession:
    def flush(self) -> None:
        pass


def _cached_row():
    from types import SimpleNamespace

    return SimpleNamespace(
        verdict="proven",
        tier="tier1",
        transcript_ptr=None,
        details={"supply_delta_sign": "mint"},
        hit_count=0,
        audit_status=None,
    )


def _item(*, cached=None, needs_audit=False, probed=None, scope=None):
    from services.effects.config import SCOPE_KERNEL
    from workers.effects_worker import _Item

    return _Item(
        candidate=_candidate(1, 0),
        effect_class="supply",
        scope=scope or SCOPE_KERNEL,
        gate_ref="",
        behavior_hash="bh",
        surface_hash="",
        run=lambda: None,
        cached=cached,
        needs_audit=needs_audit,
        probed=probed,
    )


def test_every_worklist_item_lands_in_exactly_one_counter():
    """Deleting any increment breaks the identity."""
    from services.effects.config import TIER_HISTORICAL, VERDICT_PROVEN
    from services.effects.harness import ObservedEffect
    from workers.effects_worker import EffectsWorker, _Counters

    worker = EffectsWorker.__new__(EffectsWorker)
    session = _FlushOnlySession()
    counters = _Counters()
    probe = ObservedEffect(effect_class="supply", verdict=VERDICT_PROVEN, tier=TIER_HISTORICAL)
    items = [
        _item(cached=None, probed=None),  # probe failed
        _item(cached=None, probed=probe),  # miss
        _item(cached=_cached_row()),  # plain hit
        _item(cached=_cached_row(), needs_audit=True, probed=None),  # withheld
    ]
    for it in items:
        worker._resolve_item(session, it, counters)  # pyright: ignore[reportArgumentType]

    assert (counters.probes_failed, counters.cache_misses, counters.cache_hits_kernel, counters.withheld) == (
        1,
        1,
        1,
        1,
    )
    assert (
        len(items)
        == counters.cache_hits_kernel
        + counters.cache_hits_projection
        + counters.cache_misses
        + counters.probes_failed
        + counters.withheld
    )

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        worker._record_metrics(counters)
    finally:
        stage_metrics_var.reset(token)

    assert "candidates_after_cascade" not in metrics
    assert (
        len(items)
        == metrics["cache_hits_kernel"]
        + metrics["cache_hits_projection"]
        + metrics["cache_misses"]
        + metrics["probes_failed"]
        + metrics["withheld"]
    )
    assert metrics["skipped"] == counters.skipped


def test_hashless_candidates_record_a_capped_sample_plus_the_exact_total(monkeypatch):
    """stage_errors is uncapped and rewritten per retry, so per-candidate records are bounded."""
    from types import SimpleNamespace

    from workers.effects_worker import _NO_HASH_SAMPLE, EffectsWorker, _Counters

    monkeypatch.setenv("PSAT_EFFECTS_BATCH_PLAN", "0")
    worker = EffectsWorker.__new__(EffectsWorker)
    candidates = [_candidate(i, 0) for i in range(_NO_HASH_SAMPLE * 3)]
    counters = _Counters()
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        items = worker._plan(
            None,  # pyright: ignore[reportArgumentType]
            candidates,
            SimpleNamespace(chain_id=1),  # pyright: ignore[reportArgumentType]
            lambda _s, _c: None,
            counters,
        )
    finally:
        degraded_errors_var.reset(token)

    assert items == []
    assert counters.skipped == len(candidates)
    assert len(accumulator) == _NO_HASH_SAMPLE + 1
    summary = accumulator[-1]
    assert summary.context["candidates_without_hash"] == len(candidates)
    assert len(summary.context["function_ids_sample"]) == _NO_HASH_SAMPLE


def test_selectionless_job_still_reports_a_defined_funnel():
    from workers.effects_worker import EffectsWorker

    class _Job:
        protocol_id = None

    funnel: dict = {}
    assert EffectsWorker.__new__(EffectsWorker)._select(None, _Job(), funnel=funnel) == []  # pyright: ignore[reportArgumentType]
    assert funnel["rows_in"] == 0 and funnel["selected"] == 0
    assert funnel["not_run_reason"] == "job_has_no_protocol"


def _rss_outcome(anvil, caplog):
    from workers.effects_worker import EffectsWorker, _Counters

    worker = EffectsWorker.__new__(EffectsWorker)
    worker._anvil = anvil
    worker._rss_sample_failed = False
    counters = _Counters()
    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with caplog.at_level(logging.DEBUG, logger=WORKER_LOGGER):
            worker._sample_anvil_rss(counters)
            worker._sample_anvil_rss(counters)
    finally:
        degraded_errors_var.reset(token)

    metrics: dict = {}
    mtoken = stage_metrics_var.set(metrics)
    try:
        worker._record_metrics(counters)
    finally:
        stage_metrics_var.reset(mtoken)
    return counters, [r for r in caplog.records if r.name == WORKER_LOGGER], accumulator, metrics


def test_a_dead_fork_publishes_no_rss_peak_at_all(caplog):
    """A dead fork reads 0 bytes from ``rss_bytes_for_pid``; publishing that 0 would be a fallback standing in for a
    witness.
    """
    import os

    class _ExitedProc:
        pid = os.getpid()

        def poll(self):
            return 0

    dead_fork = SubprocessAnvil.__new__(SubprocessAnvil)
    dead_fork._proc = _ExitedProc()  # pyright: ignore[reportAttributeAccessIssue]
    counters, records, accumulator, metrics = _rss_outcome(dead_fork, caplog)

    assert counters.peak_anvil_rss_mb is None
    assert metrics["peak_anvil_rss_measured"] is False
    assert "peak_anvil_rss_mb" not in metrics
    assert len(records) == 1, "the once-per-job guard did not hold"
    assert records[0].levelno == logging.WARNING
    assert records[0].reason == "read_did_not_answer"
    assert [e.phase for e in accumulator] == ["effects_rss_sample"]


def test_raising_sampler_is_still_treated_as_unmeasured(caplog):
    class _Boom:
        def rss_mb(self):
            raise OSError("/proc gone")

    counters, records, accumulator, metrics = _rss_outcome(_Boom(), caplog)

    assert counters.peak_anvil_rss_mb is None
    assert metrics["peak_anvil_rss_measured"] is False
    assert len(records) == 1
    assert records[0].reason == "sampler_raised"
    assert records[0].exc_type == "OSError"
    assert [e.phase for e in accumulator] == ["effects_rss_sample"]
