"""Multichain (M1.1): chain_id threading through deployer expansion.

The deployer-expansion Etherscan calls (``getcontractcreation`` and
``txlist``) must carry the chain being searched, not a hardcoded mainnet
default. Name resolution still routes through the shared
``get_contract_name`` wrapper (no chain param yet), so these tests set
``resolve_names=False`` to isolate the chain-threaded wire calls.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery import deployer

_SEEDS = ["0x" + f"{n:040x}" for n in (0x11, 0x22, 0x33)]
_DEPLOYER = "0x" + "d" * 40
_NEW_CONTRACT = "0x" + "e" * 40


def _fake_get_factory(seen):
    def fake_get(_module, action, **kwargs):
        seen.append((action, kwargs.get("chain_id")))
        if action == "getcontractcreation":
            # All seeds share one deployer → it clears the qualification bar.
            return {"result": [{"contractAddress": s, "contractCreator": _DEPLOYER} for s in _SEEDS]}
        if action == "txlist":
            return {"result": [{"to": "", "contractAddress": _NEW_CONTRACT}]}
        return {"result": []}

    return fake_get


def test_expand_from_deployers_threads_chain_id(monkeypatch):
    """A non-mainnet chain_id reaches getcontractcreation and txlist."""
    seen: list[tuple[str, int | None]] = []
    monkeypatch.setattr(deployer.etherscan, "get", _fake_get_factory(seen))

    entries = deployer.expand_from_deployers(_SEEDS, resolve_names=False, chain_id=8453)

    assert entries, "expected at least one expanded entry"
    creation_chain_ids = [c for a, c in seen if a == "getcontractcreation"]
    txlist_chain_ids = [c for a, c in seen if a == "txlist"]
    assert creation_chain_ids == [8453]
    assert txlist_chain_ids == [8453]


def test_expand_from_deployers_defaults_to_mainnet(monkeypatch):
    """Absent an explicit chain_id, wire calls carry chain_id=1 (mainnet unchanged)."""
    seen: list[tuple[str, int | None]] = []
    monkeypatch.setattr(deployer.etherscan, "get", _fake_get_factory(seen))

    deployer.expand_from_deployers(_SEEDS, resolve_names=False)

    assert {c for _, c in seen} == {1}
