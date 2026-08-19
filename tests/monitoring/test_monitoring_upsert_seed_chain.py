"""Fix: the manual monitored-contract upsert (`POST /api/protocols/{id}/monitoring`)
must seed its scan cursor + enrollment floor from the enrolled contract's OWN
chain head, not the mainnet head.

Before the fix ``_current_head_block`` always read ``deps.DEFAULT_RPC_URL`` (a
mainnet eRPC route), so a chain='base' enrollment stamped ``enrollment_block``
with a mainnet-scale block — a wrong, immutable pre-watch floor. It now routes
through ``rpc_for_chain`` (the same registry-derived selection the scanner uses):
mainnet keeps ``deps.DEFAULT_RPC_URL`` verbatim, a second chain resolves its own
eRPC route.

The wire is stubbed (netguard): we capture the RPC URL ``_current_head_block``
would POST to, per chain.
"""

from __future__ import annotations

import pytest

from routers import deps, monitored  # noqa: E402

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
    # Mainnet (and the empty/None default) keeps deps.DEFAULT_RPC_URL untouched, so
    # mainnet enrollment is byte-identical to before the fix.
    for chain in ("ethereum", None):
        captured_url.clear()
        monitored._current_head_block(chain)
        assert captured_url["url"] == deps.DEFAULT_RPC_URL


def test_head_block_failure_is_not_determined_not_zero(monkeypatch):
    """An RPC failure reads as not-determined, never as block 0.

    Block 0 is a claim — "watching this contract since genesis" — that seeds a
    cursor 25M blocks behind head and a floor that lets every historical event
    publish as a live change. The route refuses the enrollment on ``None``
    rather than persist that (``test_upsert_refuses_to_seed_a_floor_zero_row``
    in tests/test_cursor_hygiene.py)."""

    def _boom(*_a, **_kw):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(monitored, "rpc_request", _boom)
    assert monitored._current_head_block("base") is None
