"""Stage 6 - thread-supervisor + stop-event tests (HR3).

The ``Supervisor`` is driven with injected fast-failing loops (its restart/backoff/heartbeat
policy is what's asserted; the error heartbeat is captured by a pure spy, no DB). The real
``run_scan_loop`` / ``run_poll_loop`` are run briefly with only the RPC wire stubbed to prove
a stop request returns promptly instead of sleeping out the interval.
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import threading
import time

import pytest

from db.queue import (
    HEARTBEAT_PROTOCOL_POLLER,
    HEARTBEAT_PROTOCOL_RESTAKING,
    HEARTBEAT_PROTOCOL_SCANNER,
    HEARTBEAT_PROTOCOL_SCORE,
    HEARTBEAT_PROTOCOL_TVL,
    HEARTBEAT_ROLE_HOLDER_PLANE,
)
from workers import protocol_monitor as pm
from workers.protocol_monitor import Supervisor, _build_default_supervisor, main


class RecordingEvent(threading.Event):
    """Captures the backoff schedule without sleeping."""

    def __init__(self, stop_after_waits: int):
        super().__init__()
        self.waits: list[float | None] = []
        self._stop_after = stop_after_waits

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(timeout)
        if len(self.waits) >= self._stop_after:
            self.set()
        return super().wait(0)


@pytest.mark.parametrize(
    "stop_after,max_backoff_s,healthy_stretch_s,expected_waits",
    [
        # 1e9 means never healthy, so the backoff never resets.
        pytest.param(6, 20.0, 1e9, [5.0, 10.0, 20.0, 20.0, 20.0, 20.0], id="growing_capped"),
        pytest.param(4, 300.0, 0.0, [5.0, 5.0, 5.0, 5.0], id="reset_after_healthy_stretch"),
    ],
)
def test_raising_loop_restart_backoff(stop_after, max_backoff_s, healthy_stretch_s, expected_waits):
    ev = RecordingEvent(stop_after_waits=stop_after)
    sup = Supervisor(
        [],
        stop_event=ev,
        base_backoff_s=5.0,
        max_backoff_s=max_backoff_s,
        healthy_stretch_s=healthy_stretch_s,
    )

    def raiser(_ev):
        raise ValueError("boom")

    sup._supervise("protocol_scanner", raiser)

    assert ev.waits == expected_waits


def test_error_heartbeat_recorded_with_exc_type_on_each_death(monkeypatch):
    calls: list[tuple[str, str, dict | None]] = []

    def spy(process, *, status="running", detail=None):
        calls.append((process, status, detail))

    monkeypatch.setattr(pm, "record_heartbeat", spy)

    ev = RecordingEvent(stop_after_waits=3)
    sup = Supervisor([], stop_event=ev, base_backoff_s=5.0, healthy_stretch_s=1e9)

    def raiser(_ev):
        raise ValueError("boom")

    sup._supervise(HEARTBEAT_PROTOCOL_SCANNER, raiser)

    assert len(calls) == 3
    assert all(process == HEARTBEAT_PROTOCOL_SCANNER for process, _, _ in calls)
    assert all(status == "error" for _, status, _ in calls)
    assert all(detail == {"exc_type": "ValueError"} for _, _, detail in calls)


def test_sibling_runs_uninterrupted_while_one_loop_crash_loops():
    stop = threading.Event()
    deaths = [0]
    healthy_ticks = [0]

    def crasher(_ev):
        deaths[0] += 1
        raise RuntimeError("boom")

    def healthy(ev):
        while not ev.is_set():
            healthy_ticks[0] += 1
            ev.wait(0.005)

    sup = Supervisor(
        [(HEARTBEAT_PROTOCOL_SCANNER, crasher), (HEARTBEAT_PROTOCOL_POLLER, healthy)],
        stop_event=stop,
        base_backoff_s=0.005,
        max_backoff_s=0.02,
        healthy_stretch_s=1e9,
        join_timeout_s=2.0,
    )
    sup.start()
    try:
        time.sleep(0.3)
        assert deaths[0] >= 3, deaths[0]
        assert healthy_ticks[0] >= 5, healthy_ticks[0]
    finally:
        sup.request_stop()
        sup.join()

    assert all(not t.is_alive() for t in sup._threads)


def test_stop_event_joins_all_threads_within_bound():
    stop = threading.Event()
    started = [False, False, False]

    def make(i):
        def loop(ev):
            started[i] = True
            ev.wait()  # block until shutdown

        return loop

    loops = [
        (HEARTBEAT_PROTOCOL_SCANNER, make(0)),
        (HEARTBEAT_PROTOCOL_POLLER, make(1)),
        (HEARTBEAT_PROTOCOL_TVL, make(2)),
    ]
    sup = Supervisor(loops, stop_event=stop, base_backoff_s=0.01, join_timeout_s=2.0)
    sup.start()
    time.sleep(0.1)
    assert all(started)

    t0 = time.monotonic()
    sup.request_stop()
    sup.join()
    elapsed = time.monotonic() - t0

    assert elapsed < 2.0
    assert all(not t.is_alive() for t in sup._threads)


def _stub_scan_wire(monkeypatch, head: int = 100):
    import services.monitoring.unified_watcher as uw
    import services.resolution.repos.event_logs_rpc as elr

    def head_rpc(url, method, params):
        return hex(head)

    def getlogs_rpc(url, method, params):
        return []

    monkeypatch.setattr(uw, "rpc_request", head_rpc)
    monkeypatch.setattr(elr, "rpc_request", getlogs_rpc)


@pytest.mark.parametrize("loop_name", ["run_scan_loop", "run_poll_loop"])
def test_real_loop_honors_stop_event_mid_interval(db_session, monkeypatch, loop_name):
    import services.monitoring.unified_watcher as uw

    loop = getattr(uw, loop_name)
    _stub_scan_wire(monkeypatch)
    stop = threading.Event()
    # Sleeping out the interval would time out the join.
    t = threading.Thread(target=loop, args=("http://stub", 3600.0), kwargs={"stop_event": stop}, daemon=True)
    t.start()
    time.sleep(0.2)  # let it finish one empty-DB pass and enter the inter-pass wait
    t0 = time.monotonic()
    stop.set()
    t.join(timeout=5.0)

    assert not t.is_alive()
    assert time.monotonic() - t0 < 5.0


def test_default_mode_spawns_exactly_six_named_threads():
    sup = _build_default_supervisor("http://stub", 3600.0)
    # Each thread returns before its loop, so only the thread set is asserted.
    sup.stop_event.set()
    sup.start()
    try:
        names = sorted(t.name for t in sup._threads)
        assert names == sorted(
            [
                f"supervise-{HEARTBEAT_PROTOCOL_SCANNER}",
                f"supervise-{HEARTBEAT_PROTOCOL_POLLER}",
                f"supervise-{HEARTBEAT_PROTOCOL_TVL}",
                f"supervise-{HEARTBEAT_PROTOCOL_RESTAKING}",
                f"supervise-{HEARTBEAT_ROLE_HOLDER_PLANE}",
                f"supervise-{HEARTBEAT_PROTOCOL_SCORE}",
            ]
        )
        assert len(sup._threads) == 6
    finally:
        sup.join()


def _monitor_launch_flags(script: str) -> list[str]:
    flags = []
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "-m workers.protocol_monitor" not in stripped:
            continue
        _, _, tail = stripped.partition("-m workers.protocol_monitor")
        mode = [tok for tok in tail.split() if tok.startswith("--")]
        flags.append(mode[0] if mode else "default")
    return flags


def test_start_local_launches_each_monitor_loop_exactly_once():
    """Co-launching a flag mode beside default doubles the loop (the TVL loop has no lease)."""
    root = pathlib.Path(__file__).resolve().parents[2]
    launched = _monitor_launch_flags((root / "deploy/start_local.sh").read_text())

    assert launched == ["default"], f"start_local.sh must launch default mode alone, got {launched}"

    workers_launched = _monitor_launch_flags((root / "deploy/start_workers.sh").read_text())
    assert workers_launched == ["--reconcile"], workers_launched


@pytest.mark.parametrize(
    "argv, patch_targets, expected",
    [
        (
            ["--tvl", "--interval", "7"],
            {"tvl": ("services.monitoring.tvl", "run_tvl_loop")},
            {"tvl": ((7.0,), {})},
        ),
        (
            ["--reconcile", "--rpc-url", "http://x", "--interval", "9"],
            {"rec": ("services.monitoring.reconciler", "run_enrollment_reconciler_loop")},
            {"rec": (("http://x", "ethereum"), {"interval": 9.0})},
        ),
        (
            ["--poll", "--rpc-url", "http://p", "--interval", "3"],
            {"poll": ("services.monitoring.unified_watcher", "run_poll_loop")},
            {"poll": (("http://p", 3.0), {"startup_offset_s": 0.0})},
        ),
        (
            ["--rpc-url", "http://d"],
            {"default": ("workers.protocol_monitor", "_run_supervised_default")},
            {"default": (("http://d", None), {})},
        ),
    ],
)
def test_main_flag_dispatch(monkeypatch, argv, patch_targets, expected):
    seen: dict[str, tuple] = {}

    for label, (mod_path, attr) in patch_targets.items():
        mod = importlib.import_module(mod_path)

        def _rec(*a, _label=label, **k):
            seen[_label] = (a, k)

        monkeypatch.setattr(mod, attr, _rec)

    monkeypatch.setattr(sys, "argv", ["protocol_monitor", *argv])
    main()

    for label, exp in expected.items():
        if label == "rec":
            stop_event = seen[label][1].pop("stop_event")
            assert isinstance(stop_event, threading.Event)
            assert not stop_event.is_set()
        assert seen.get(label) == exp


def test_run_forever_returns_after_stop():
    stop = threading.Event()
    ran = [False]

    def loop(ev):
        ran[0] = True
        ev.wait()

    sup = Supervisor([(HEARTBEAT_PROTOCOL_SCANNER, loop)], stop_event=stop, join_timeout_s=2.0)
    t = threading.Thread(target=sup.run_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    assert ran[0]
    sup.request_stop()
    t.join(timeout=3.0)
    assert not t.is_alive()


def test_clean_return_is_restarted():
    ev = RecordingEvent(stop_after_waits=3)
    sup = Supervisor([], stop_event=ev, base_backoff_s=5.0, healthy_stretch_s=1e9)
    runs = [0]

    def returns_immediately(_ev):
        runs[0] += 1

    sup._supervise(HEARTBEAT_PROTOCOL_SCANNER, returns_immediately)

    assert runs[0] == 3


def test_env_float_reads_and_falls_back(monkeypatch):
    monkeypatch.setenv("PSAT_TEST_FLOAT_KNOB", "12.5")
    assert pm._env_float("PSAT_TEST_FLOAT_KNOB", 1.0) == 12.5
    monkeypatch.setenv("PSAT_TEST_FLOAT_KNOB", "not-a-number")
    assert pm._env_float("PSAT_TEST_FLOAT_KNOB", 1.0) == 1.0
    monkeypatch.delenv("PSAT_TEST_FLOAT_KNOB", raising=False)
    assert pm._env_float("PSAT_TEST_FLOAT_KNOB", 2.0) == 2.0
