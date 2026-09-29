"""The manual upsert (`POST /api/protocols/{id}/monitoring`) must seed its scan cursor and
enrollment floor from the enrolled contract's OWN chain head.

``_current_head_block`` used to read the mainnet ``DEFAULT_RPC_URL``, so a chain='base'
enrollment got a mainnet-scale, immutable ``enrollment_block``. It now routes through
``rpc_for_chain``; the wire is stubbed and we capture the URL per chain.
"""

from __future__ import annotations

import pytest

from routers import deps, monitored

_ERPC_BASE = "https://erpc.example"


@pytest.fixture()
def captured_url(monkeypatch):
    """Stub the wire and record the RPC URL ``_current_head_block`` targets."""
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    seen: dict[str, str] = {}

    def _fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        seen["url"] = rpc_url
        assert method == "eth_blockNumber"
        return hex(36_108_610)  # a Base-scale head

    monkeypatch.setattr(monitored, "rpc_request", _fake_rpc_request)
    return seen


def test_base_enrollment_seeds_from_base_rpc(captured_url):
    block = monitored._current_head_block("base")
    # Resolved the Base eRPC route (chain 8453) — NOT the mainnet DEFAULT_RPC_URL.
    assert captured_url["url"] == f"{_ERPC_BASE}/main/evm/8453"
    assert captured_url["url"] != deps.DEFAULT_RPC_URL
    assert block == 36_108_610


def test_mainnet_enrollment_uses_default_rpc_verbatim(captured_url):
    # Mainnet (and empty/None) keeps deps.DEFAULT_RPC_URL untouched.
    for chain in ("ethereum", None):
        captured_url.clear()
        monitored._current_head_block(chain)
        assert captured_url["url"] == deps.DEFAULT_RPC_URL


def test_head_block_failure_is_not_determined_not_zero(monkeypatch):
    """An RPC failure reads as not-determined, never block 0: block 0 claims "watching since
    genesis", seeding a cursor 25M blocks behind and a floor letting every historical event
    publish as live. See ``test_upsert_refuses_to_seed_a_floor_zero_row`` in
    tests/monitoring/test_cursor_hygiene.py."""

    def _boom(*_a, **_kw):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(monitored, "rpc_request", _boom)
    assert monitored._current_head_block("base") is None
