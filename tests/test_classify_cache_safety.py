"""Regression tests for the classify_resolved_address process-wide cache.

Codex's review of the etherfi LP cascade speedup work flagged two correctness
risks: transient RPC errors getting cached as 'contract' fallbacks, and
those leaking through the per-job classify_cache into the persisted
classified_addresses artifact. Both safety checks are tested here.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from services.resolution import tracking
from services.resolution.tracking import (
    _CLASSIFY_CACHE,
    classify_resolved_address,
    classify_resolved_address_with_status,
    clear_classify_cache,
)


@pytest.fixture(autouse=True)
def _isolated_cache():
    """Each test starts with an empty cache and leaves nothing behind."""
    clear_classify_cache()
    yield
    clear_classify_cache()


@pytest.fixture(autouse=True)
def _stub_batch_probe_rpc(monkeypatch):
    """Offline: the batched classify probe hits the wire. Return all-error so the
    code falls back to the sequential classifier, which uses the per-call probes
    (``_get_code`` / ``_try_eth_call_decoded``) these tests already mock. The
    lazy negative-control probe rides ``_eth_call_raw`` — an empty return means
    the control passes, keeping these cache-behavior tests type-neutral."""
    monkeypatch.setattr(
        tracking,
        "_rpc_batch_request_with_status",
        lambda rpc_url, calls, *a, **k: [(None, True)] * len(calls),
    )
    monkeypatch.setattr(tracking, "_eth_call_raw", lambda *a, **k: "0x")


def test_clear_empties_process_cache(monkeypatch):
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *a, **k: None)
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})
    classify_resolved_address("https://rpc", "0x" + "a" * 40)
    assert _CLASSIFY_CACHE
    clear_classify_cache()
    assert not _CLASSIFY_CACHE


def test_transient_rpc_error_does_not_poison_cache(monkeypatch):
    """The dominant correctness bug v4/v5 fixed: a transient probe failure
    must not cement a wrong 'contract' classification process-wide."""
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(
        tracking,
        "type_authority_contract",
        lambda *a, **k: {},
    )

    # Force every probe to look like a transient RPC error (the sentinel path).
    def boom(*a, **k):
        return tracking._PROBE_ERROR

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", boom)

    kind, _details = classify_resolved_address("https://rpc", "0x" + "b" * 40)
    assert kind == "contract"  # fallback because every probe "errored"
    assert not _CLASSIFY_CACHE  # but NOT cached — transient error path


def test_with_status_reports_uncacheable_on_error(monkeypatch):
    """Per-job/artifact callers (recursive.py BFS, principal labeling)
    must use _with_status to avoid persisting transient-error fallbacks
    via the classified_addresses artifact."""
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *a, **k: tracking._PROBE_ERROR)

    _kind, _details, cacheable = classify_resolved_address_with_status("https://rpc", "0x" + "c" * 40)
    assert cacheable is False


def test_clean_classification_is_cacheable(monkeypatch):
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *a, **k: None)

    _kind, _details, cacheable = classify_resolved_address_with_status("https://rpc", "0x" + "d" * 40)
    assert cacheable is True
    assert _CLASSIFY_CACHE  # populated


def test_cached_details_are_isolated_from_caller_mutation(monkeypatch):
    """Codex iter-2 fix: cached details must not be poisoned by callers
    mutating the returned dict (or its nested lists like Safe.owners)."""
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})

    # Simulate a Safe: owners + threshold both succeed.
    def fake_call(_rpc, _addr, signature, _abi, *_a, **_k):
        if signature == "getOwners()":
            return ["0x" + "1" * 40, "0x" + "2" * 40]
        if signature == "getThreshold()":
            return 2
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_call)

    _kind, details = classify_resolved_address("https://rpc", "0x" + "e" * 40)
    assert details["owners"] == ["0x" + "1" * 40, "0x" + "2" * 40]
    # Caller mutates returned details + nested list:
    cast(list, details["owners"]).append("0xpoisoned")
    details["address"] = "0xchanged"

    # Next call returns a clean copy.
    _kind2, details2 = classify_resolved_address("https://rpc", "0x" + "e" * 40)
    assert details2["owners"] == ["0x" + "1" * 40, "0x" + "2" * 40]
    assert details2["address"] == "0x" + "e" * 40


# ---------------------------------------------------------------------------
# P2.1 — split TTL: immutable classifications keep the long TTL; entries whose
# details carry mutable Safe owners/threshold or timelock delay use a short TTL at
# block_tag='latest' so a changed owner-set / delay re-probes sooner. Tests age the
# cached timestamp directly (no sleeping) to span the short-but-not-long window.
# ---------------------------------------------------------------------------


def test_immutable_classification_keeps_long_ttl(monkeypatch):
    """A plain-contract classification is immutable: aging it past the short (mutable)
    TTL must NOT re-probe — the long TTL still applies."""
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})
    monkeypatch.setattr(tracking, "_try_eth_call_decoded", lambda *a, **k: None)  # all probes empty → "contract"

    addr = "0x" + "b" * 40
    kind1, _ = classify_resolved_address("https://rpc", addr)
    assert kind1 == "contract"

    assert tracking._CLASSIFY_CACHE_MUTABLE_TTL_S < tracking._CLASSIFY_CACHE_TTL_S
    key = ("https://rpc", addr, "latest")
    kind, details, ts = _CLASSIFY_CACHE[key]
    _CLASSIFY_CACHE[key] = (kind, details, ts - (tracking._CLASSIFY_CACHE_MUTABLE_TTL_S + 5))

    # If the entry re-probed it would now look like a Safe; it must NOT — long TTL holds.
    def fake_safe(_rpc, _addr, signature, _abi, *_a, **_k):
        if signature == "getOwners()":
            return ["0x" + "9" * 40]
        if signature == "getThreshold()":
            return 1
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_safe)
    kind2, _ = classify_resolved_address("https://rpc", addr)
    assert kind2 == "contract"  # served from cache, not re-probed


def test_mutable_safe_details_use_short_ttl(monkeypatch):
    """A 'safe' classification carries owners/threshold which mutate on-chain, so aging
    it past the short TTL (still within the long TTL) forces a re-probe."""
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})

    owners = {"v": ["0x" + "1" * 40]}

    def fake_call(_rpc, _addr, signature, _abi, *_a, **_k):
        if signature == "getOwners()":
            return list(owners["v"])
        if signature == "getThreshold()":
            return 1
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_call)

    addr = "0x" + "a" * 40
    kind1, details1 = classify_resolved_address("https://rpc", addr)
    assert kind1 == "safe"
    assert details1["owners"] == ["0x" + "1" * 40]

    key = ("https://rpc", addr, "latest")
    kind, details, ts = _CLASSIFY_CACHE[key]
    _CLASSIFY_CACHE[key] = (kind, details, ts - (tracking._CLASSIFY_CACHE_MUTABLE_TTL_S + 5))

    owners["v"] = ["0x" + "1" * 40, "0x" + "2" * 40]  # owner-set changed on-chain
    _kind2, details2 = classify_resolved_address("https://rpc", addr)
    assert details2["owners"] == ["0x" + "1" * 40, "0x" + "2" * 40]  # short TTL forced a re-probe


def test_erc1967_implementation_is_a_mutable_detail():
    """The ERC-1967 implementation slot moves on every upgrade, so a
    classification witnessing it must age on the short TTL like owners/
    threshold/delay — a long-TTL entry would serve the pre-upgrade
    implementation as current for up to 30 minutes."""
    assert "erc1967_implementation" in tracking._MUTABLE_DETAIL_KEYS


def test_pinned_block_mutable_details_keep_long_ttl(monkeypatch):
    """A pinned-block read is immutable at that block, so even a 'safe' entry keeps the
    long TTL — only block_tag='latest' reads use the short TTL."""
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})

    owners = {"v": ["0x" + "1" * 40]}

    def fake_call(_rpc, _addr, signature, _abi, *_a, **_k):
        if signature == "getOwners()":
            return list(owners["v"])
        if signature == "getThreshold()":
            return 1
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_call)

    addr = "0x" + "c" * 40
    classify_resolved_address("https://rpc", addr, "0x100")
    key = ("https://rpc", addr, "0x100")
    kind, details, ts = _CLASSIFY_CACHE[key]
    _CLASSIFY_CACHE[key] = (kind, details, ts - (tracking._CLASSIFY_CACHE_MUTABLE_TTL_S + 5))

    owners["v"] = ["0x" + "1" * 40, "0x" + "2" * 40]
    _kind2, details2 = classify_resolved_address("https://rpc", addr, "0x100")
    assert details2["owners"] == ["0x" + "1" * 40]  # pinned block → long TTL, served from cache


def test_concurrent_classify_consistent_under_8_threads(monkeypatch):
    """Step 3 fan-out: 8 worker threads classifying overlapping address sets
    must not corrupt the process cache or surface inconsistent values for the
    same address. Every concurrent reader sees identical (kind, details)."""
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Force the sequential probe path so monkeypatching ``_try_eth_call_decoded``
    # actually intercepts every probe (the batched path bypasses it).
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})

    # Per-address signature: a few addresses look like Safes, the rest fall
    # through to "contract". The fake call records every probe so we can
    # assert the cache collapses concurrent misses rather than re-probing
    # the same address from every thread.
    probe_calls: dict[str, int] = {}
    probe_lock = threading.Lock()

    def fake_call(_rpc, address, signature, _abi, *_a, **_k):
        with probe_lock:
            probe_calls[address] = probe_calls.get(address, 0) + 1
        is_safe = address.endswith("aaaa")
        if is_safe and signature == "getOwners()":
            return ["0x" + "1" * 40]
        if is_safe and signature == "getThreshold()":
            return 1
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_call)

    addresses = [f"0x{i:040x}" for i in range(1, 9)]
    addresses += [f"0x{i:036x}aaaa" for i in range(1, 3)]  # safe-shaped

    def _canonicalize(value):
        if isinstance(value, dict):
            return tuple(sorted((k, _canonicalize(v)) for k, v in value.items()))
        if isinstance(value, list):
            return tuple(_canonicalize(v) for v in value)
        return value

    def _classify_round() -> list[tuple[str, str, tuple]]:
        out: list[tuple[str, str, tuple]] = []
        for addr in addresses:
            kind, details = classify_resolved_address("https://rpc", addr)
            out.append((addr, kind, _canonicalize(details)))
        return out

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_classify_round) for _ in range(8)]
        results = [f.result() for f in as_completed(futures)]

    # Every concurrent reader sees the same value for a given address.
    by_addr: dict[str, set] = {}
    for thread_results in results:
        for addr, kind, details in thread_results:
            by_addr.setdefault(addr, set()).add((kind, details))
    for addr, observed in by_addr.items():
        assert len(observed) == 1, f"address {addr} produced inconsistent classifications: {observed}"

    # Cache must collapse repeated probes — racing misses can each issue one
    # full probe set but the per-address total is bounded by num threads
    # times probes-per-classify (5 for "contract", 2 for "safe").
    max_probes_per_address = 8 * len(tracking._CLASSIFY_PROBE_SIGS)
    for addr, count in probe_calls.items():
        assert count <= max_probes_per_address, (
            f"address {addr} re-probed {count} times — cache lock not collapsing concurrent misses"
        )

    # And in aggregate the cache must avoid linear blow-up: 8 threads × 10
    # addresses = 80 lookups; cached path means total probes ≪ 80 × 5.
    total_probes = sum(probe_calls.values())
    assert total_probes < 8 * len(addresses) * len(tracking._CLASSIFY_PROBE_SIGS), (
        f"total probes {total_probes} suggests no caching"
    )
