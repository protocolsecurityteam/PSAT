"""Offline integration tests for the contract inventory pipeline.

Exercises the full scoring, dedup, chain-resolution, and HTML extraction
logic end-to-end with realistic inputs.  No network calls — runs in CI
without API keys.
"""

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery.activity import enrich_with_activity
from services.discovery.chain_resolver import resolve_unknown_chains, validate_claimed_chains
from services.discovery.deployer import expand_from_deployers
from services.discovery.inventory import (
    _build_contracts,
    _group_multi_deployments,
    search_protocol_inventory,
)
from services.discovery.inventory_extract import (
    extract_inventory_entries_from_page_text,
)


@pytest.fixture(autouse=True)
def _stub_inventory_search(monkeypatch):
    """Offline: the orchestrator runs a broad Tavily search + LLM domain pick before
    page extraction. Stub both (no Tavily/OpenRouter); tests that exercise specific
    search/LLM results override these in-body."""
    monkeypatch.setattr("services.discovery.inventory._tavily_search", lambda *a, **k: [])
    monkeypatch.setattr("services.discovery.inventory._llm_select_domain", lambda *a, **k: (None, []))


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _entry(
    address: str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    chain: str = "ethereum",
    name: str | None = "TestContract",
    kind: str = "official_inventory_table",
    url: str = "https://docs.example.com/contracts",
    explorer_url: str | None = "https://etherscan.io/address/0xaaaa",
) -> dict[str, Any]:
    return {
        "name": name,
        "address": address,
        "chain": chain,
        "kind": kind,
        "url": url,
        "explorer_url": explorer_url,
        "chain_from_hint": False,
    }


# ---------------------------------------------------------------------------
# _build_contracts — realistic multi-entry scenarios
# ---------------------------------------------------------------------------


class TestBuildContracts:
    def test_multi_source_merge_and_scoring(self):
        """Multiple entries for the same address from different pages/kinds
        merge into one contract with boosted confidence."""
        addr = "0x" + "a" * 40
        entries = [
            _entry(address=addr, name="Vault", chain="ethereum", kind="official_inventory_table", url="https://a.com"),
            _entry(address=addr, name="Vault", chain="ethereum", kind="official_inventory_link", url="https://b.com"),
        ]
        contracts, sources_map = _build_contracts(entries, limit=10)

        assert len(contracts) == 1
        c = contracts[0]
        assert c["name"] == "Vault"
        assert c["address"] == addr
        assert c["chains"] == ["ethereum"]
        assert c["confidence"] > 0.7
        assert c["source"] == ["ai_inventory"]
        assert len(c["source_ids"]) >= 2
        # Sources map should contain the URLs
        assert len(sources_map) >= 2

    def test_unknown_chain_remapped_and_multi_chain(self):
        """Unknown-chain entry remaps when one specific chain exists;
        multiple specific chains produce chains with both."""
        addr_a = "0x" + "a" * 40
        addr_b = "0x" + "b" * 40
        entries = [
            _entry(address=addr_a, chain="ethereum"),
            _entry(address=addr_a, chain="unknown", url="https://other.com"),
            _entry(address=addr_b, chain="ethereum"),
            _entry(address=addr_b, chain="arbitrum"),
        ]
        contracts, _ = _build_contracts(entries, limit=10)
        by_addr = {c["address"]: c for c in contracts}

        assert by_addr[addr_a]["chains"] == ["ethereum"]
        assert set(by_addr[addr_b]["chains"]) == {"ethereum", "arbitrum"}

    def test_chain_labels_are_canonicalized(self):
        addr = "0x" + "e" * 40
        entries = [
            _entry(address=addr, chain="Ethereum mainnet"),
            _entry(address=addr, chain="Base", url="https://base.example.com"),
        ]
        contracts, _ = _build_contracts(entries, limit=10)
        assert set(contracts[0]["chains"]) == {"ethereum", "base"}

    def test_limit_and_sort_order(self):
        """Higher-confidence contracts sort first; limit is respected."""
        entries = [
            _entry(address=f"0x{i:040x}", name=None, kind="official_inventory_text", explorer_url=None)
            for i in range(5)
        ] + [
            _entry(address="0x" + "f" * 40, name="Best", kind="official_inventory_table"),
        ]
        contracts, _ = _build_contracts(entries, limit=3)

        assert len(contracts) == 3
        assert contracts[0]["address"] == "0x" + "f" * 40
        assert contracts[0]["confidence"] > contracts[-1]["confidence"]

    def test_name_voting_and_aliases(self):
        addr = "0x" + "c" * 40
        entries = [
            _entry(address=addr, name="Alpha", url="https://a.com"),
            _entry(address=addr, name="Alpha", url="https://b.com"),
            _entry(address=addr, name="Beta", url="https://c.com"),
        ]
        contracts, _ = _build_contracts(entries, limit=10)
        assert contracts[0]["name"] == "Alpha"
        assert "Beta" in contracts[0].get("aliases", [])


# ---------------------------------------------------------------------------
# extract_inventory_entries_from_page_text — realistic HTML
# ---------------------------------------------------------------------------


class TestExtractFromPageText:
    def test_table_with_chain_headings_and_explorer_links(self):
        """Realistic docs page with chain headings, a table, and explorer links."""
        html = """
        <h2>Ethereum</h2>
        <table>
            <tr><th>Contract</th><th>Address</th></tr>
            <tr>
                <td>StakingPool</td>
                <td><a href="https://etherscan.io/address/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
                    0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</a></td>
            </tr>
        </table>

        <h2>Arbitrum</h2>
        <p>Router: <a href="https://arbiscan.io/address/0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb">view</a></p>
        """
        entries = extract_inventory_entries_from_page_text(
            "https://docs.example.com/contracts", html, requested_chain=None
        )

        by_addr = {e["address"]: e for e in entries}
        assert "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in by_addr
        assert "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in by_addr

        eth_entry = by_addr["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        assert eth_entry["chain"] == "ethereum"
        assert eth_entry["name"] is not None

        arb_entry = by_addr["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
        assert arb_entry["chain"] == "arbitrum"

    def test_requested_chain_filters_entries(self):
        html = """
        <h2>Ethereum</h2>
        <p>0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</p>
        <h2>Arbitrum</h2>
        <p>0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</p>
        """
        entries = extract_inventory_entries_from_page_text("https://docs.example.com", html, requested_chain="ethereum")
        assert all(e["chain"] == "ethereum" for e in entries)
        assert not any(e["address"] == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" for e in entries)


# ---------------------------------------------------------------------------
# search_protocol_inventory — orchestrator with mocked externals
# ---------------------------------------------------------------------------


class TestSearchProtocolInventoryOffline:
    def test_validation_errors(self):
        with pytest.raises(ValueError, match="must not be empty"):
            search_protocol_inventory("")
        with pytest.raises(ValueError, match="limit must be >= 1"):
            search_protocol_inventory("test", limit=0)

    def test_no_domain_returns_valid_structure(self, monkeypatch):
        monkeypatch.setattr("services.discovery.inventory._tavily_search", lambda *_a, **_kw: [])
        monkeypatch.setattr("services.discovery.inventory._llm_select_domain", lambda *_a, **_kw: (None, []))

        result = search_protocol_inventory("nonexistent_xyz")
        assert result["official_domain"] is None
        assert result["contracts"] == []
        assert any("Could not identify" in n for n in result["notes"])

    def test_full_pipeline_with_mocked_pages(self, monkeypatch):
        """Mocked page extraction feeds through scoring and produces correct output shape."""
        fake_entries = [
            _entry(address="0x" + "a" * 40, name="Vault", chain="ethereum"),
            _entry(address="0x" + "b" * 40, name="Router", chain="arbitrum", kind="official_inventory_link"),
        ]
        # Even with a domain-shaped input, the orchestrator now runs the broad
        # Tavily search + LLM domain selection to surface companion docs/github
        # hosts. Stub them so this test stays offline and deterministic.
        monkeypatch.setattr(
            "services.discovery.inventory._tavily_search",
            lambda *_a, **_kw: [],
        )
        monkeypatch.setattr(
            "services.discovery.inventory._llm_select_domain",
            lambda *_a, **_kw: (None, []),
        )
        monkeypatch.setattr(
            "services.discovery.inventory._discover_contract_inventory_pages",
            lambda *_a, **_kw: ([{"url": "https://docs.example.com"}], ["https://docs.example.com"]),
        )
        monkeypatch.setattr(
            "services.discovery.inventory.extract_inventory_entries_from_pages",
            lambda *_a, **_kw: fake_entries,
        )
        monkeypatch.setattr(
            "services.discovery.inventory.expand_from_deployers",
            lambda *_a, **_kw: [],
        )

        result = search_protocol_inventory("docs.example.com", limit=10)
        assert result["official_domain"] == "docs.example.com"
        assert result["chain"] == "any"
        assert len(result["contracts"]) == 2

        assert "sources" in result  # top-level sources map
        for contract in result["contracts"]:
            for field in ("name", "address", "chains", "confidence", "source", "evidence", "source_ids"):
                assert field in contract
            assert 0 < contract["confidence"] <= 0.99
            assert isinstance(contract["source"], list)

    @pytest.mark.usefixtures("_stub_chain_resolver")  # deployer entries are chain="unknown" → would probe Alchemy
    def test_full_pipeline_with_deployer_expansion(self, monkeypatch):
        """Deployer entries merge with Tavily entries and boost confidence."""
        addr_both = "0x" + "a" * 40
        addr_deployer_only = "0x" + "d" * 40
        tavily_entries = [
            _entry(address=addr_both, name="Vault", chain="ethereum"),
        ]
        deployer_entries = [
            _entry(
                address=addr_both,
                name=None,
                chain="unknown",
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
                explorer_url=f"https://etherscan.io/address/{addr_both}",
            ),
            _entry(
                address=addr_deployer_only,
                name="NewContract",
                chain="unknown",
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
                explorer_url=f"https://etherscan.io/address/{addr_deployer_only}",
            ),
        ]
        monkeypatch.setattr(
            "services.discovery.inventory._discover_contract_inventory_pages",
            lambda *_a, **_kw: ([{"url": "https://docs.example.com"}], ["https://docs.example.com"]),
        )
        monkeypatch.setattr(
            "services.discovery.inventory.extract_inventory_entries_from_pages",
            lambda *_a, **_kw: tavily_entries,
        )
        monkeypatch.setattr(
            "services.discovery.inventory.expand_from_deployers",
            lambda *_a, **_kw: deployer_entries,
        )

        result = search_protocol_inventory("docs.example.com", limit=10)
        contracts = result["contracts"]
        by_addr = {c["address"]: c for c in contracts}

        # Corroborated address gets both sources and deployer confidence boost
        assert addr_both in by_addr
        corroborated = by_addr[addr_both]
        assert "ai_inventory" in corroborated["source"]
        assert "deployer_expansion" in corroborated["source"]
        assert corroborated["evidence"].get("deployer", 0) > 0

        # Deployer-only address appears with deployer source
        assert addr_deployer_only in by_addr
        deployer_only = by_addr[addr_deployer_only]
        assert deployer_only["source"] == ["deployer_expansion"]
        assert deployer_only["name"] == "NewContract"


# ---------------------------------------------------------------------------
# _build_contracts — deployer merge scenarios
# ---------------------------------------------------------------------------


class TestBuildContractsDeployerMerge:
    def test_deployer_unknown_chain_remapped_by_tavily(self):
        """Deployer entries with chain=unknown get remapped when Tavily provides a chain."""
        addr = "0x" + "a" * 40
        entries = [
            _entry(address=addr, name="Vault", chain="ethereum", kind="official_inventory_table"),
            _entry(
                address=addr,
                name=None,
                chain="unknown",
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
                explorer_url=f"https://etherscan.io/address/{addr}",
            ),
        ]
        contracts, _ = _build_contracts(entries, limit=10)
        assert len(contracts) == 1
        assert contracts[0]["chains"] == ["ethereum"]
        assert "deployer_expansion" in contracts[0]["source"]

    def test_deployer_corroboration_boosts_confidence(self):
        """Address found by both sources should have higher confidence than either alone."""
        addr = "0x" + "a" * 40
        tavily_only = [_entry(address=addr, chain="ethereum")]
        combined = [
            _entry(address=addr, chain="ethereum"),
            _entry(
                address=addr,
                chain="unknown",
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
                explorer_url=f"https://etherscan.io/address/{addr}",
            ),
        ]
        tavily_contracts, _ = _build_contracts(tavily_only, limit=10)
        combined_contracts, _ = _build_contracts(combined, limit=10)

        assert combined_contracts[0]["confidence"] > tavily_contracts[0]["confidence"]

    def test_deployer_only_entry_included(self):
        """Address found only by deployer expansion is still included."""
        addr = "0x" + "d" * 40
        entries = [
            _entry(
                address=addr,
                name="DeployerFound",
                chain="unknown",
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
                explorer_url=f"https://etherscan.io/address/{addr}",
            ),
        ]
        contracts, _ = _build_contracts(entries, limit=10)
        assert len(contracts) == 1
        assert contracts[0]["name"] == "DeployerFound"
        assert contracts[0]["source"] == ["deployer_expansion"]


# ---------------------------------------------------------------------------
# expand_from_deployers — mocked Etherscan calls
# ---------------------------------------------------------------------------


class TestExpandFromDeployers:
    def test_empty_seeds_returns_empty(self):
        assert expand_from_deployers([]) == []

    def test_expand_with_mocked_etherscan(self, monkeypatch):
        """Mock Etherscan API to verify the deployer expansion flow."""
        deployer = "0x" + "de" * 20
        # Supply enough seeds from one deployer to pass the min_seed_count threshold
        seeds = [f"0x{i:040x}" for i in range(1, 4)]
        new_contract = "0x" + "b" * 40

        def fake_etherscan_get(module, action, **params):
            if action == "getcontractcreation":
                return {
                    "status": "1",
                    "result": [
                        {"contractAddress": s, "contractCreator": deployer, "txHash": "0x" + "1" * 64} for s in seeds
                    ],
                }
            if action == "txlist":
                return {
                    "status": "1",
                    "result": [
                        *[{"to": "", "contractAddress": s, "hash": "0x" + "1" * 64} for s in seeds],
                        {"to": "", "contractAddress": new_contract, "hash": "0x" + "2" * 64},
                        {"to": "0x" + "c" * 40, "contractAddress": "", "hash": "0x" + "3" * 64},
                    ],
                }
            if action == "getsourcecode":
                addr = params.get("address", "").lower()
                if addr == new_contract:
                    return {"status": "1", "result": [{"ContractName": "DiscoveredToken"}]}
                return {"status": "1", "result": [{"ContractName": ""}]}
            return {"status": "0", "result": []}

        monkeypatch.setattr("services.discovery.deployer.etherscan.get", fake_etherscan_get)

        entries = expand_from_deployers(seeds)

        # 3 seeds + 1 new contract = 4 entries
        assert len(entries) == 4
        addresses = {e["address"] for e in entries}
        assert any(new_contract.lower() in a for a in addresses)

        for entry in entries:
            assert entry["kind"] == "deployer_expansion"
            assert entry["chain"] == "unknown"
            assert entry["explorer_url"] is not None

        # The new contract should have its resolved name
        new_entry = next(e for e in entries if new_contract.lower() in e["address"])
        assert new_entry["name"] == "DiscoveredToken"

    def test_deployer_below_threshold_filtered_out(self, monkeypatch):
        """A deployer that created only 1 seed should be rejected."""
        seed = "0x" + "a" * 40
        deployer = "0x" + "de" * 20

        def fake_get(module, action, **params):
            if action == "getcontractcreation":
                return {
                    "status": "1",
                    "result": [
                        {"contractAddress": seed, "contractCreator": deployer, "txHash": "0x" + "1" * 64},
                    ],
                }
            return {"status": "0", "result": []}

        monkeypatch.setattr("services.discovery.deployer.etherscan.get", fake_get)

        # With default thresholds (min_seed_count=3), 1 seed is not enough
        entries = expand_from_deployers([seed])
        assert entries == []

        # With lowered thresholds, same deployer qualifies
        entries = expand_from_deployers([seed], min_seed_count=1, min_seed_share=0.0)
        assert len(entries) == 0  # txlist not mocked, so no deployments found

    def test_no_creators_found(self, monkeypatch):
        """If getcontractcreation fails for all seeds, return empty."""

        def fake_get(*_a, **_kw):
            raise RuntimeError("No data found")

        monkeypatch.setattr("services.discovery.deployer.etherscan.get", fake_get)

        entries = expand_from_deployers(["0x" + "a" * 40])
        assert entries == []

    def test_deployer_with_no_creations(self, monkeypatch):
        """If deployer txlist has no contract creations, still returns seed entry."""
        seed = "0x" + "a" * 40
        deployer = "0x" + "de" * 20

        def fake_get(module, action, **params):
            if action == "getcontractcreation":
                return {
                    "status": "1",
                    "result": [
                        {"contractAddress": seed, "contractCreator": deployer, "txHash": "0x" + "1" * 64},
                    ],
                }
            if action == "txlist":
                # Deployer has transactions but none are contract creations
                return {
                    "status": "1",
                    "result": [
                        {"to": "0x" + "f" * 40, "contractAddress": "", "hash": "0x" + "2" * 64},
                    ],
                }
            return {"status": "1", "result": [{"ContractName": ""}]}

        monkeypatch.setattr("services.discovery.deployer.etherscan.get", fake_get)

        entries = expand_from_deployers([seed])
        assert entries == []


# ---------------------------------------------------------------------------
# _group_multi_deployments — multi-chain grouping
# ---------------------------------------------------------------------------


class TestGroupMultiDeployments:
    def test_same_name_different_addresses_grouped(self):
        """Contracts with the same name but different addresses get a deployments array."""
        contracts = [
            {
                "name": "Vault",
                "address": "0x" + "a" * 40,
                "chains": ["ethereum"],
                "confidence": 0.9,
                "source": ["ai_inventory"],
                "evidence": {},
                "source_ids": ["s1"],
            },
            {
                "name": "Vault",
                "address": "0x" + "b" * 40,
                "chains": ["arbitrum"],
                "confidence": 0.8,
                "source": ["ai_inventory"],
                "evidence": {},
                "source_ids": ["s2"],
            },
        ]
        result = _group_multi_deployments(contracts)
        assert len(result) == 1
        assert result[0]["name"] == "Vault"
        assert "deployments" in result[0]
        assert len(result[0]["deployments"]) == 2
        assert set(result[0]["chains"]) == {"ethereum", "arbitrum"}
        # Address field removed in favor of deployments
        assert "address" not in result[0]

    def test_same_address_not_grouped(self):
        """Same address listed twice keeps the best entry, no deployments array."""
        contracts = [
            {
                "name": "Vault",
                "address": "0x" + "a" * 40,
                "chains": ["ethereum"],
                "confidence": 0.9,
                "source": ["ai_inventory"],
                "evidence": {},
                "source_ids": ["s1"],
            },
            {
                "name": "Vault",
                "address": "0x" + "a" * 40,
                "chains": ["ethereum"],
                "confidence": 0.7,
                "source": ["ai_inventory"],
                "evidence": {},
                "source_ids": ["s2"],
            },
        ]
        result = _group_multi_deployments(contracts)
        assert len(result) == 1
        assert "deployments" not in result[0]
        assert result[0]["address"] == "0x" + "a" * 40

    def test_unnamed_contracts_not_grouped(self):
        """Unnamed contracts pass through ungrouped."""
        contracts = [
            {
                "name": None,
                "address": "0x" + "a" * 40,
                "chains": ["ethereum"],
                "confidence": 0.5,
                "source": ["deployer_expansion"],
                "evidence": {},
                "source_ids": ["s1"],
            },
            {
                "name": None,
                "address": "0x" + "b" * 40,
                "chains": ["ethereum"],
                "confidence": 0.5,
                "source": ["deployer_expansion"],
                "evidence": {},
                "source_ids": ["s2"],
            },
        ]
        result = _group_multi_deployments(contracts)
        assert len(result) == 2
        assert all("deployments" not in c for c in result)

    def test_activity_data_preserved_in_deployments(self):
        """Activity and rank_score from individual contracts carry into deployments."""
        contracts = [
            {
                "name": "Token",
                "address": "0x" + "a" * 40,
                "chains": ["ethereum"],
                "confidence": 0.9,
                "source": ["ai_inventory"],
                "evidence": {},
                "source_ids": ["s1"],
                "activity": {"last_active": "2026-01-01T00:00:00+00:00", "score": 0.95},
                "rank_score": 0.93,
            },
            {
                "name": "Token",
                "address": "0x" + "b" * 40,
                "chains": ["base"],
                "confidence": 0.8,
                "source": ["ai_inventory"],
                "evidence": {},
                "source_ids": ["s2"],
                "activity": {"last_active": "2026-01-02T00:00:00+00:00", "score": 0.90},
                "rank_score": 0.86,
            },
        ]
        result = _group_multi_deployments(contracts)
        assert len(result) == 1
        for dep in result[0]["deployments"]:
            assert "activity" in dep
            assert "rank_score" in dep


# ---------------------------------------------------------------------------
# resolve_unknown_chains — mocked RPC probing
# ---------------------------------------------------------------------------


class TestResolveUnknownChains:
    def test_resolves_unknown_to_correct_chain(self, monkeypatch):
        """Contracts with chains=["unknown"] get resolved via batch RPC probing."""
        contracts = [
            {"name": "Known", "address": "0x" + "a" * 40, "chains": ["ethereum"]},
            {"name": "Unknown1", "address": "0x" + "b" * 40, "chains": ["unknown"]},
            {"name": "Unknown2", "address": "0x" + "c" * 40, "chains": ["unknown"]},
        ]
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

        # Simulate: Unknown1 found on ethereum, Unknown2 found on arbitrum + base
        def fake_batch_get_code(rpc_url, addresses):
            if rpc_url.endswith("/evm/1"):
                return {addr: ("0x6001" if addr == "0x" + "b" * 40 else "0x") for addr in addresses}
            if rpc_url.endswith("/evm/42161"):
                return {addr: ("0x6001" if addr == "0x" + "c" * 40 else "0x") for addr in addresses}
            if rpc_url.endswith("/evm/8453"):
                return {addr: ("0x6001" if addr == "0x" + "c" * 40 else "0x") for addr in addresses}
            return {addr: "0x" for addr in addresses}

        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)

        result = resolve_unknown_chains(contracts, debug=False)
        by_name = {c["name"]: c for c in result}

        assert by_name["Known"]["chains"] == ["ethereum"]
        assert by_name["Unknown1"]["chains"] == ["ethereum"]
        assert set(by_name["Unknown2"]["chains"]) == {"arbitrum", "base"}

    def test_no_unknowns_is_noop(self, monkeypatch):
        """When all contracts have known chains, nothing is probed."""
        contracts = [{"name": "A", "address": "0x" + "a" * 40, "chains": ["ethereum"]}]
        # _probe_chains would fail if called — proves no probing happens.
        monkeypatch.setattr(
            "services.discovery.chain_resolver._probe_chains",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("should not be called")),
        )
        result = resolve_unknown_chains(contracts)
        assert result[0]["chains"] == ["ethereum"]

    def test_unresolved_stays_unknown(self, monkeypatch):
        """Address not found on any chain keeps chains=["unknown"]."""
        contracts = [{"name": "Ghost", "address": "0x" + "d" * 40, "chains": ["unknown"]}]
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr(
            "services.discovery.chain_resolver._batch_get_code",
            lambda rpc_url, addrs: {a: "0x" for a in addrs},
        )
        result = resolve_unknown_chains(contracts)
        assert result[0]["chains"] == ["unknown"]

    def test_exa_claimed_chain_corrected_when_code_lives_elsewhere(self, monkeypatch):
        addr = "0x" + "e" * 40
        contracts = [{"name": "AI", "address": addr, "chains": ["Ethereum mainnet"], "source": ["exa_deep_research"]}]
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

        def fake_batch_get_code(rpc_url, addresses):
            if rpc_url.endswith("/evm/8453"):
                return {a: "0x6001" for a in addresses}
            return {a: "0x" for a in addresses}

        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)

        result = validate_claimed_chains(contracts)
        assert result[0]["chains"] == ["base"]

    def test_exa_claimed_chain_marked_unknown_when_no_code_found(self, monkeypatch):
        addr = "0x" + "e" * 40
        contracts = [{"name": "AI", "address": addr, "chains": ["Base"], "source": ["exa_deep_research"]}]
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr(
            "services.discovery.chain_resolver._batch_get_code",
            lambda rpc_url, addresses: {a: "0x" for a in addresses},
        )

        result = validate_claimed_chains(contracts)
        assert result[0]["chains"] == ["unknown"]
        assert result[0]["chain_sanity"]["status"] == "unresolved_no_code_on_claimed_or_supported_chains"


# ---------------------------------------------------------------------------
# Evidence-based chain membership (invariant 3): probing may CONFIRM membership
# on the protocol's declared chains, never ORIGINATE it on an arbitrary chain
# an address merely has code on (Permit2/Multicall3/Safe are everywhere).
# ---------------------------------------------------------------------------


class TestEvidenceBasedChainMembership:
    @staticmethod
    def _record_probed_chain_ids(monkeypatch) -> list[str]:
        """Wire-level: record the chain id of every chain that gets probed."""
        probed: list[str] = []

        def fake_batch_get_code(rpc_url, addresses):
            probed.append(rpc_url.rsplit("/evm/", 1)[-1])
            return {a: "0x" for a in addresses}

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)
        return probed

    def test_declared_chains_narrow_the_probe(self, monkeypatch):
        """(a) An unknown-chain entry is probed ONLY on the declared chains."""
        probed = self._record_probed_chain_ids(monkeypatch)
        contracts = [{"name": "U", "address": "0x" + "b" * 40, "chains": ["unknown"]}]
        resolve_unknown_chains(contracts, declared_chains=["ethereum"])
        # No all-chain fan-out: ethereum (chain_id 1) is the only chain touched.
        assert set(probed) == {"1"}

    def test_uncorroborated_hit_is_candidate_only(self, monkeypatch):
        """(b) With no declared evidence a probe hit is a candidate, not membership.

        The address has code on arbitrum but nothing declares any chain — so the
        hit is recorded as a candidate and ``chains`` stays ``["unknown"]``. That
        keeps it out of the ``contracts`` table on arbitrum and off the job queue.
        """

        def fake_batch_get_code(rpc_url, addresses):
            hit = rpc_url.endswith("/evm/42161")
            return {a: ("0x6001" if hit else "0x") for a in addresses}

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)

        contract = {"name": "Ghost", "address": "0x" + "c" * 40, "chains": ["unknown"]}
        resolve_unknown_chains([contract], declared_chains=[])

        assert contract["chains"] == ["unknown"]
        assert contract["chain_candidates"] == ["arbitrum"]

    def test_declared_chain_hit_is_written(self, monkeypatch):
        """(c) A hit on a declared chain is corroborated → written, as today."""

        def fake_batch_get_code(rpc_url, addresses):
            hit = rpc_url.endswith("/evm/1")
            return {a: ("0x6001" if hit else "0x") for a in addresses}

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)

        contract = {"name": "Real", "address": "0x" + "d" * 40, "chains": ["unknown"]}
        resolve_unknown_chains([contract], declared_chains=["ethereum"])

        assert contract["chains"] == ["ethereum"]
        assert "chain_candidates" not in contract

    def test_none_declared_chains_keeps_legacy_all_chain_probe(self, monkeypatch):
        """Backward compat: ``declared_chains=None`` still runs the legacy probe.

        The existing standalone callers (and the tests above in
        ``TestResolveUnknownChains``) pass no declared set — they must keep
        probing every chain and writing hits, unchanged.
        """
        probed = self._record_probed_chain_ids(monkeypatch)
        contracts = [{"name": "U", "address": "0x" + "b" * 40, "chains": ["unknown"]}]
        resolve_unknown_chains(contracts, declared_chains=None)
        # Legacy path fans out across the whole registry, not just one chain.
        assert len(set(probed)) > 1

    def test_search_inventory_narrows_probe_to_declared(self, monkeypatch):
        """End-to-end through the orchestrator: a declared set narrows the probe.

        Bridge has code on arbitrum, but the protocol only declares ethereum, so
        arbitrum is never probed and Bridge is not relabelled onto it.
        """
        addr_known = "0x" + "a" * 40
        addr_unknown = "0x" + "b" * 40
        fake_entries = [
            _entry(address=addr_known, name="Vault", chain="ethereum"),
            _entry(address=addr_unknown, name="Bridge", chain="unknown"),
        ]
        monkeypatch.setattr(
            "services.discovery.inventory._discover_contract_inventory_pages",
            lambda *_a, **_kw: ([{"url": "https://docs.example.com"}], ["https://docs.example.com"]),
        )
        monkeypatch.setattr(
            "services.discovery.inventory.extract_inventory_entries_from_pages",
            lambda *_a, **_kw: fake_entries,
        )
        monkeypatch.setattr("services.discovery.inventory.expand_from_deployers", lambda *_a, **_kw: [])
        probed = self._record_probed_chain_ids(monkeypatch)

        result = search_protocol_inventory("docs.example.com", limit=10, declared_chains=["ethereum"])

        assert set(probed) == {"1"}
        by_name = {c["name"]: c for c in result["contracts"]}
        assert by_name["Bridge"]["chains"] == ["unknown"]
        assert "arbitrum" not in by_name["Bridge"].get("chains", [])

    def test_search_inventory_records_candidate_in_artifact(self, monkeypatch):
        """End-to-end: with no declared evidence, an off-chain hit rides the
        inventory (discovery artifact) as a candidate, not as a membership."""
        addr_unknown = "0x" + "b" * 40
        fake_entries = [_entry(address=addr_unknown, name="Bridge", chain="unknown")]
        monkeypatch.setattr(
            "services.discovery.inventory._discover_contract_inventory_pages",
            lambda *_a, **_kw: ([{"url": "https://docs.example.com"}], ["https://docs.example.com"]),
        )
        monkeypatch.setattr(
            "services.discovery.inventory.extract_inventory_entries_from_pages",
            lambda *_a, **_kw: fake_entries,
        )
        monkeypatch.setattr("services.discovery.inventory.expand_from_deployers", lambda *_a, **_kw: [])

        def fake_batch(rpc_url, addrs):
            hit = rpc_url.endswith("/evm/42161")
            return {a: ("0x6001" if hit else "0x") for a in addrs}

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch)

        result = search_protocol_inventory("docs.example.com", limit=10, declared_chains=[])

        bridge = {c["name"]: c for c in result["contracts"]}["Bridge"]
        assert bridge["chains"] == ["unknown"]
        assert bridge["chain_candidates"] == ["arbitrum"]


# ---------------------------------------------------------------------------
# enrich_with_activity — mocked Etherscan activity lookups
# ---------------------------------------------------------------------------


class TestEnrichWithActivity:
    def test_scores_and_sorts_by_rank(self, monkeypatch):
        """Active contracts rank higher than inactive ones."""
        import time as _time

        now_ts = _time.time()
        contracts = [
            {"name": "Stale", "address": "0x" + "a" * 40, "chains": ["ethereum"], "confidence": 0.9},
            {"name": "Active", "address": "0x" + "b" * 40, "chains": ["ethereum"], "confidence": 0.5},
        ]
        # Active was used today, Stale 365 days ago
        timestamps = {
            "0x" + "a" * 40: now_ts - 365 * 86400,
            "0x" + "b" * 40: now_ts,
        }

        def fake_etherscan_get(module, action, **params):
            addr = params.get("address", "")
            ts = timestamps.get(addr)
            if ts is not None:
                return {"result": [{"timeStamp": str(int(ts))}]}
            return {"result": []}

        monkeypatch.setattr("services.discovery.activity.etherscan.get", fake_etherscan_get)

        result = enrich_with_activity(contracts)
        assert len(result) == 2

        # Both have activity and rank_score
        for c in result:
            assert "activity" in c
            assert "rank_score" in c
            assert c["activity"]["score"] > 0

        # Active contract should rank first despite lower confidence
        assert result[0]["name"] == "Active"
        assert result[0]["rank_score"] > result[1]["rank_score"]
        assert result[0]["activity"]["score"] > result[1]["activity"]["score"]

    def test_missing_activity_gets_neutral_score(self, monkeypatch):
        """Contracts where Etherscan returns no data get score=0.5."""
        contracts = [{"name": "NoData", "address": "0x" + "a" * 40, "chains": ["ethereum"], "confidence": 0.8}]

        def fake_get(*_a, **_kw):
            return {"result": []}

        monkeypatch.setattr("services.discovery.activity.etherscan.get", fake_get)

        result = enrich_with_activity(contracts)
        assert result[0]["activity"]["score"] == 0.5
        assert result[0]["activity"]["last_active"] is None

    def test_unknown_chain_skips_fetch_and_floors_rank(self, monkeypatch):
        """A contract on an unregistered chain must NOT be ranked by mainnet
        activity — querying mainnet's explorer would score it by an unrelated
        address's activity (inv. 12). Instead: no fetch, activity score 0."""
        contracts = [{"name": "X", "address": "0x" + "a" * 40, "chains": ["unknown"], "confidence": 0.5}]
        called_with_chain_id = []

        def fake_get(module, action, **params):
            called_with_chain_id.append(params.get("chain_id"))
            return {"result": []}

        monkeypatch.setattr("services.discovery.activity.etherscan.get", fake_get)

        result = enrich_with_activity(contracts)
        # No explorer fetch for the unregistered chain.
        assert called_with_chain_id == []
        # Ranked at the floor: activity score 0 (not the mainnet-fetched score,
        # not the 0.5 neutral used for a supported chain with no data).
        assert result[0]["activity"]["score"] == 0.0
        assert result[0]["activity"]["last_active"] is None


# ---------------------------------------------------------------------------
# Full orchestrator — chain resolution + activity through search_protocol_inventory
# ---------------------------------------------------------------------------


class TestOrchestratorIntegration:
    def test_pipeline_with_chain_resolution(self, monkeypatch):
        """End-to-end: entries → build → chain resolve → group → output.

        Activity ranking is no longer part of this orchestrator — the
        worker pipeline runs the single authoritative ranking in the
        selection stage, and standalone callers apply
        ``enrich_with_activity`` themselves. This test asserts the new
        shape: chain resolution lands, contracts are returned without
        an ``activity`` / ``rank_score`` payload.
        """
        addr_known = "0x" + "a" * 40
        addr_unknown = "0x" + "b" * 40
        fake_entries = [
            _entry(address=addr_known, name="Vault", chain="ethereum"),
            _entry(
                address=addr_unknown,
                name="Bridge",
                chain="unknown",
                url="https://docs.example.com/contracts",
                explorer_url=f"https://etherscan.io/address/{addr_unknown}",
            ),
        ]
        monkeypatch.setattr(
            "services.discovery.inventory._discover_contract_inventory_pages",
            lambda *_a, **_kw: ([{"url": "https://docs.example.com"}], ["https://docs.example.com"]),
        )
        monkeypatch.setattr(
            "services.discovery.inventory.extract_inventory_entries_from_pages",
            lambda *_a, **_kw: fake_entries,
        )
        monkeypatch.setattr("services.discovery.inventory.expand_from_deployers", lambda *_a, **_kw: [])

        # Chain resolver: Bridge found on arbitrum
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

        def fake_batch(rpc_url, addrs):
            if rpc_url.endswith("/evm/42161"):
                return {a: ("0x6001" if a == addr_unknown else "0x") for a in addrs}
            return {a: "0x" for a in addrs}

        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch)

        result = search_protocol_inventory("docs.example.com", limit=10)

        contracts = result["contracts"]
        assert len(contracts) == 2
        by_name = {c["name"]: c for c in contracts}

        # Chain resolution worked
        assert by_name["Vault"]["chains"] == ["ethereum"]
        assert "arbitrum" in by_name["Bridge"]["chains"]
        assert "unknown" not in by_name["Bridge"]["chains"]

        # Activity ranking is no longer part of the orchestrator.
        for c in contracts:
            assert "activity" not in c
            assert "rank_score" not in c

        # Chain resolution note still fires; activity ranking note is gone.
        notes = " ".join(result["notes"])
        assert "Chain resolution" in notes
        assert "Activity ranking" not in notes
