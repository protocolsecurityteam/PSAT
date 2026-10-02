"""Multichain: chain_id threading through deployer expansion.

Name resolution has no chain param yet, hence ``resolve_names=False``.
"""

from services.discovery import deployer

_SEEDS = ["0x" + f"{n:040x}" for n in (0x11, 0x22, 0x33)]
_DEPLOYER = "0x" + "d" * 40
_NEW_CONTRACT = "0x" + "e" * 40


def _fake_get_factory(seen):
    def fake_get(_module, action, **kwargs):
        seen.append((action, kwargs.get("chain_id")))
        if action == "getcontractcreation":
            return {"result": [{"contractAddress": s, "contractCreator": _DEPLOYER} for s in _SEEDS]}
        if action == "txlist":
            return {"result": [{"to": "", "contractAddress": _NEW_CONTRACT}]}
        return {"result": []}

    return fake_get


def test_explorer_links_follow_the_expansion_chain(monkeypatch):
    monkeypatch.setattr(deployer.etherscan, "get", _fake_get_factory([]))

    base = deployer.expand_from_deployers(_SEEDS, resolve_names=False, chain_id=8453)
    assert base and all("basescan.org/address/" in e["explorer_url"] for e in base)
    assert all("basescan.org/address/" in e["url"] for e in base)

    eth = deployer.expand_from_deployers(_SEEDS, resolve_names=False, chain_id=1)
    assert eth and all("etherscan.io/address/" in e["explorer_url"] for e in eth)

    # Unknown chains fall back to etherscan.
    assert deployer._explorer_base(1) == "https://etherscan.io"
    assert deployer._explorer_base(8453) == "https://basescan.org"
    assert deployer._explorer_base(999999999) == "https://etherscan.io"
