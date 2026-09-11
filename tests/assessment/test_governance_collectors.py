"""Pinned governance probes classify only supported getter combinations."""

from __future__ import annotations

from eth_abi.abi import encode

from services.assessment import governance_collectors as collectors
from services.clients.rpc import EthCallResult


def _ok(output: str, value) -> EthCallResult:
    return EthCallResult(True, "0x" + encode([output], [value]).hex(), None, None)


def _fail() -> EthCallResult:
    return EthCallResult(False, "0x", "0x", "execution reverted")


def test_oz_governor_timelock_and_safe_are_observed_at_one_block(monkeypatch):
    calls = []
    monkeypatch.setattr(collectors, "rpc_request", lambda *_a, **_k: "0x64")

    def rpc(method_url, method, params, **kwargs):
        if method == "eth_blockNumber":
            return "0x64"
        assert method == "eth_getBlockByNumber"
        return {"number": "0x64", "hash": "0x" + "10" * 32}

    monkeypatch.setattr(collectors, "rpc_request", rpc)

    def batch(_url, payload, block_tag, **_kwargs):
        calls.append((payload, block_tag))
        if len(calls) == 1:
            return [
                _ok("uint256", 1),
                _ok("uint256", 45818),
                _ok("uint256", 1000),
                _ok("uint256", 172800),
                _ok("uint256", 2),
                _ok("address[]", ["0x" + "aa" * 20, "0x" + "bb" * 20]),
            ]
        if len(calls) == 2:
            return [_ok("uint256", 1), _ok("uint256", 90), _ok("uint256", 190), _ok("uint256", 2000)]
        return []

    monkeypatch.setattr(collectors, "eth_call_batch", batch)
    result = collectors.probe_governance(
        rpc_url="http://rpc.invalid",
        chain_id=1,
        address="0x" + "11" * 20,
        proposal_ids=[7],
    )

    assert result.point == {"chain_id": 1, "block_number": 100, "block_hash": "0x" + "10" * 32}
    assert result.families == ["openzeppelin_governor", "openzeppelin_timelock", "safe"]
    assert result.values["getMinDelay()"] == 172800
    assert result.proposals["7"] == {
        "state": collectors.ProposalState.active,
        "snapshot": 90,
        "deadline": 190,
        "eta": 2000,
    }
    assert all(block_tag == "0x64" for _payload, block_tag in calls)


def test_unknown_contract_produces_diagnostic_not_configuration(monkeypatch):
    def rpc(_url, method, _params, **_kwargs):
        return "0x1" if method == "eth_blockNumber" else {"hash": "0x" + "01" * 32}

    monkeypatch.setattr(collectors, "rpc_request", rpc)
    monkeypatch.setattr(collectors, "eth_call_batch", lambda _u, calls, *_a, **_k: [_fail() for _ in calls])
    result = collectors.probe_governance(
        rpc_url="http://rpc.invalid",
        chain_id=1,
        address="0x" + "11" * 20,
    )

    assert result.families == []
    assert result.values == {}
    assert result.diagnostics == [{"code": "unsupported_code", "message": "No supported governance family matched"}]
