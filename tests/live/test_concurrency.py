"""Concurrent /api/analyze submissions — exercises worker pool and DB-pool contention."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from tests.live.conftest import DEFAULT_SINGLE_TIMEOUT, LiveClient

# Mix of proxy (USDC) + non-proxy. Etherscan caches all five aggressively.
# UNI (0x1f9840...) intentionally omitted — Etherscan API v2 returns empty
# SourceCode for it despite the contract being verified in the UI, so it's
# an unreliable fixture for "everything analyzes cleanly" assertions.
PARALLEL_ADDRESSES = [
    "0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2",  # WETH
    "0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48",  # USDC (proxy — also exercises impl spawn)
    "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    "0x514910771AF9Ca656af840dff83E8264EcF986CA",  # LINK
    "0xc00e94Cb662C3520282E6f5717214004A7f26888",  # COMP (MKR was pre-Solidity-0.5 and
    # occasionally trips up Slither's CLI on the preview's compiler combo.)
]


def _submit_and_wait(base_url: str, admin_key: str, address: str) -> dict:
    # Fresh client per thread: requests.Session is not thread-safe.
    client = LiveClient(base_url, admin_key)
    return client.submit_and_wait(address, timeout=DEFAULT_SINGLE_TIMEOUT)


def test_concurrent_analyses_all_complete(live_base_url: str, live_admin_key: str):
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(PARALLEL_ADDRESSES)) as pool:
        futures = {
            pool.submit(_submit_and_wait, live_base_url, live_admin_key, addr): addr for addr in PARALLEL_ADDRESSES
        }
        for fut in as_completed(futures):
            addr = futures[fut]
            results[addr] = fut.result()

    failed = {addr: r for addr, r in results.items() if r["status"] != "completed"}
    assert not failed, "concurrent submissions did not all complete: " + "; ".join(
        f"{a}: status={r['status']} error={(r.get('error') or '')[:120]}" for a, r in failed.items()
    )


def test_concurrent_analyses_parallelism(live_base_url: str, live_admin_key: str):
    """The worker pool runs concurrent submissions in parallel, not serially.

    Wall time ≈ slowest job means parallel; ≈ sum means serialized. 1.5× slack absorbs queueing jitter at the
    static→resolution handoff (PSAT_STATIC_WORKERS=3, PSAT_RESOLUTION_WORKERS=2 in fly.toml). A sum/wall metric
    failed on weight variance (LINK/DAI occasionally 100-150s), not pool health.
    """
    jobs: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(PARALLEL_ADDRESSES)) as pool:
        futures = {
            pool.submit(_submit_and_wait, live_base_url, live_admin_key, addr): addr for addr in PARALLEL_ADDRESSES
        }
        for fut in as_completed(futures):
            addr = futures[fut]
            job = fut.result()
            if job["status"] == "completed":
                jobs[addr] = job

    if len(jobs) < 3:
        pytest.skip(f"need at least 3 successful runs to evaluate parallelism, got {len(jobs)}")

    windows = {a: LiveClient.job_window(j) for a, j in jobs.items()}
    durations = {a: (end - start).total_seconds() for a, (start, end) in windows.items()}
    total_serial = sum(durations.values())
    wall = (max(end for _, end in windows.values()) - min(start for start, _ in windows.values())).total_seconds()
    slowest = max(durations.values())

    # Sub-30s aggregate runs are dominated by submission/poll jitter rather than worker scheduling.
    if total_serial < 30:
        pytest.skip(f"total work {total_serial:.1f}s too short to evaluate parallelism")

    assert wall < slowest * 1.5, (
        f"worker pool serialized concurrent analyses — wall {wall:.1f}s exceeds 1.5× the "
        f"slowest job {slowest:.1f}s (sum={total_serial:.1f}s); per-job durations: "
        f"{ {a: round(d, 1) for a, d in durations.items()} }"
    )
