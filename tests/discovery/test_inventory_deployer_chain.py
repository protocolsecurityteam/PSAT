"""F3 — deployer expansion runs on the requested chain, not a mainnet default.

``search_protocol_inventory`` traces deployer wallets via the Etherscan
``getcontractcreation``/``txlist`` endpoints. Those calls must carry the
requested chain's id, or an L2 inventory search silently expands mainnet
deployers. A genuinely chainless search (chain=None) keeps the documented
mainnet fallback.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery import inventory


def _stub_inventory_flow(monkeypatch, captured):
    """Stub every upstream seam so the flow reaches the deployer branch offline."""
    monkeypatch.setattr(inventory, "_tavily_search", lambda *a, **k: [])
    monkeypatch.setattr(inventory, "_llm_select_domain", lambda *a, **k: ("example.com", []))
    monkeypatch.setattr(
        inventory,
        "_discover_contract_inventory_pages",
        lambda *a, **k: ([], ["https://example.com/addresses"]),
    )
    monkeypatch.setattr(
        inventory,
        "extract_inventory_entries_from_pages",
        lambda *a, **k: [{"address": "0x" + "a" * 40, "chain": "unknown"}],
    )
    # Post-deployer processing that could otherwise touch the network.
    monkeypatch.setattr(inventory, "resolve_unknown_chains", lambda contracts, *a, **k: contracts)

    def fake_expand(seed_addresses, *, debug=False, chain_id=1):
        captured["chain_id"] = chain_id
        return []

    monkeypatch.setattr(inventory, "expand_from_deployers", fake_expand)


def test_deployer_expansion_uses_requested_chain(monkeypatch):
    captured: dict[str, int] = {}
    _stub_inventory_flow(monkeypatch, captured)

    inventory.search_protocol_inventory("someco", chain="base", run_deployer=True)

    assert captured.get("chain_id") == 8453


def test_deployer_expansion_defaults_to_mainnet_when_chainless(monkeypatch):
    captured: dict[str, int] = {}
    _stub_inventory_flow(monkeypatch, captured)

    inventory.search_protocol_inventory("someco", chain=None, run_deployer=True)

    assert captured.get("chain_id") == 1
