"""Transient RPC errors must not be cached as 'contract' or leak into the persisted classified_addresses artifact."""

from __future__ import annotations

import pytest

from services.resolution import tracking
from services.resolution.tracking import (
    _CLASSIFY_CACHE,
    classify_resolved_address,
    clear_classify_cache,
)


@pytest.fixture(autouse=True)
def _isolated_cache():
    clear_classify_cache()
    yield
    clear_classify_cache()


@pytest.fixture(autouse=True)
def _stub_batch_probe_rpc(monkeypatch):
    """Batch probes return all-error so the sequential per-call mocks apply."""
    monkeypatch.setattr(
        tracking,
        "_rpc_batch_request_with_status",
        lambda rpc_url, calls, *a, **k: [(None, True)] * len(calls),
    )
    monkeypatch.setattr(tracking, "_eth_call_raw", lambda *a, **k: "0x")


# ---------------------------------------------------------------------------
# Split TTL: immutable classifications keep the long TTL; entries whose
# details carry mutable Safe owners/threshold or timelock delay use a short TTL at
# block_tag='latest' so a changed owner-set / delay re-probes sooner. Tests age the
# cached timestamp directly (no sleeping) to span the short-but-not-long window.
# ---------------------------------------------------------------------------


def test_immutable_classification_keeps_long_ttl(monkeypatch):
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

    def fake_safe(_rpc, _addr, signature, _abi, *_a, **_k):
        if signature == "getOwners()":
            return ["0x" + "9" * 40]
        if signature == "getThreshold()":
            return 1
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_safe)
    kind2, _ = classify_resolved_address("https://rpc", addr)
    assert kind2 == "contract"  # served from cache, not re-probed


_OWNER_1 = "0x" + "1" * 40
_OWNER_2 = "0x" + "2" * 40


@pytest.mark.parametrize(
    "block_tag, expected_owners_after_aging",
    [
        pytest.param("latest", [_OWNER_1, _OWNER_2], id="mutable-safe-details-use-short-ttl"),
        # A pinned-block read is immutable at that block.
        pytest.param("0x100", [_OWNER_1], id="pinned-block-keeps-long-ttl"),
    ],
)
def test_mutable_safe_details_ttl_by_block_tag(monkeypatch, block_tag, expected_owners_after_aging):
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})

    owners = {"v": [_OWNER_1]}

    def fake_call(_rpc, _addr, signature, _abi, *_a, **_k):
        if signature == "getOwners()":
            return list(owners["v"])
        if signature == "getThreshold()":
            return 1
        return None

    monkeypatch.setattr(tracking, "_try_eth_call_decoded", fake_call)

    addr = "0x" + "a" * 40
    kind1, details1 = classify_resolved_address("https://rpc", addr, block_tag)
    assert kind1 == "safe"
    assert details1["owners"] == [_OWNER_1]

    key = ("https://rpc", addr, block_tag)
    kind, details, ts = _CLASSIFY_CACHE[key]
    _CLASSIFY_CACHE[key] = (kind, details, ts - (tracking._CLASSIFY_CACHE_MUTABLE_TTL_S + 5))

    owners["v"] = [_OWNER_1, _OWNER_2]  # owner-set changed on-chain
    _kind2, details2 = classify_resolved_address("https://rpc", addr, block_tag)
    assert details2["owners"] == expected_owners_after_aging


def test_concurrent_classify_consistent_under_8_threads(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # The batched path bypasses ``_try_eth_call_decoded``.
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_get_code", lambda *a, **k: "0x60")
    monkeypatch.setattr(tracking, "type_authority_contract", lambda *a, **k: {})

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

    by_addr: dict[str, set] = {}
    for thread_results in results:
        for addr, kind, details in thread_results:
            by_addr.setdefault(addr, set()).add((kind, details))
    for addr, observed in by_addr.items():
        assert len(observed) == 1, f"address {addr} produced inconsistent classifications: {observed}"

    # Racing misses can each issue one probe set, so the per-address total is bounded by thread count.
    max_probes_per_address = 8 * len(tracking._CLASSIFY_PROBE_SIGS)
    for addr, count in probe_calls.items():
        assert count <= max_probes_per_address, (
            f"address {addr} re-probed {count} times — cache lock not collapsing concurrent misses"
        )

    total_probes = sum(probe_calls.values())
    assert total_probes < 8 * len(addresses) * len(tracking._CLASSIFY_PROBE_SIGS), (
        f"total probes {total_probes} suggests no caching"
    )
