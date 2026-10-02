"""``_current_head_block`` used to read mainnet, so a Base enrollment got a mainnet-scale ``enrollment_block``."""

from __future__ import annotations

import pytest

from routers import deps, monitored

_ERPC_BASE = "https://erpc.example"


@pytest.fixture()
def captured_url(monkeypatch):
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
    assert captured_url["url"] == f"{_ERPC_BASE}/main/evm/8453"
    assert captured_url["url"] != deps.DEFAULT_RPC_URL
    assert block == 36_108_610


@pytest.mark.parametrize("chain", ["ethereum", None])
def test_mainnet_enrollment_uses_default_rpc_verbatim(captured_url, chain):
    monitored._current_head_block(chain)
    assert captured_url["url"] == deps.DEFAULT_RPC_URL


def test_head_block_failure_is_not_determined_not_zero(monkeypatch):
    """Block 0 claims "watching since genesis"; see ``test_upsert_route_refuses_to_seed_a_floor_zero_row``."""

    def _boom(*_a, **_kw):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(monitored, "rpc_request", _boom)
    assert monitored._current_head_block("base") is None
