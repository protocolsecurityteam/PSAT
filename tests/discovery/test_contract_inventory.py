from typing import Any

import pytest

from services.discovery.chain_resolver import resolve_unknown_chains, validate_claimed_chains
from services.discovery.deployer import expand_from_deployers
from services.discovery.inventory import (
    _build_contracts,
    _group_multi_deployments,
    search_protocol_inventory,
)
from services.discovery.inventory_domain import CHAIN_IDS
from services.discovery.inventory_extract import (
    extract_inventory_entries_from_page_text,
)


@pytest.fixture(autouse=True)
def _stub_inventory_search(monkeypatch):
    """The orchestrator runs a broad Tavily search and an LLM domain pick; tests needing specific results override
    in-body.
    """
    monkeypatch.setattr("services.discovery.inventory._tavily_search", lambda *a, **k: [])
    monkeypatch.setattr("services.discovery.inventory._llm_select_domain", lambda *a, **k: (None, []))


@pytest.fixture
def _all_inventory_chains_enabled(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", ",".join(str(i) for i in CHAIN_IDS.values()))


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


class TestBuildContracts:
    def test_multi_source_merge_and_scoring(self):
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
        assert len(sources_map) >= 2

    def test_chain_labels_are_canonicalized(self):
        addr = "0x" + "e" * 40
        entries = [
            _entry(address=addr, chain="Ethereum mainnet"),
            _entry(address=addr, chain="Base", url="https://base.example.com"),
        ]
        contracts, _ = _build_contracts(entries, limit=10)
        assert set(contracts[0]["chains"]) == {"ethereum", "base"}

    def test_limit_does_not_truncate_official_inventory(self):
        entries = [
            _entry(address=f"0x{i:040x}", name=None, kind="official_inventory_text", explorer_url=None)
            for i in range(5)
        ] + [
            _entry(address="0x" + "f" * 40, name="Best", kind="official_inventory_table"),
        ]
        contracts, _ = _build_contracts(entries, limit=3)

        assert len(contracts) == 6
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


class TestExtractFromPageText:
    def test_table_with_chain_headings_and_explorer_links(self):
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


class TestSearchProtocolInventoryOffline:
    def test_no_domain_returns_valid_structure(self, monkeypatch):
        monkeypatch.setattr("services.discovery.inventory._tavily_search", lambda *_a, **_kw: [])
        monkeypatch.setattr("services.discovery.inventory._llm_select_domain", lambda *_a, **_kw: (None, []))

        result = search_protocol_inventory("nonexistent_xyz")
        assert result["official_domain"] is None
        assert result["contracts"] == []
        assert any("Could not identify" in n for n in result["notes"])

    def test_full_pipeline_with_mocked_pages(self, monkeypatch):
        fake_entries = [
            _entry(address="0x" + "a" * 40, name="Vault", chain="ethereum"),
            _entry(address="0x" + "b" * 40, name="Router", chain="arbitrum", kind="official_inventory_link"),
        ]
        # The orchestrator runs the broad search even for a domain-shaped input.
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

        assert addr_both in by_addr
        corroborated = by_addr[addr_both]
        assert "ai_inventory" in corroborated["source"]
        assert "deployer_expansion" in corroborated["source"]
        assert corroborated["evidence"].get("deployer", 0) > 0

        assert addr_deployer_only in by_addr
        deployer_only = by_addr[addr_deployer_only]
        assert deployer_only["source"] == ["deployer_expansion"]
        assert deployer_only["name"] == "NewContract"


class TestBuildContractsDeployerMerge:
    def test_deployer_corroboration_boosts_confidence(self):
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


class TestExpandFromDeployers:
    def test_empty_seeds_returns_empty(self):
        assert expand_from_deployers([]) == []

    def test_expand_with_mocked_etherscan(self, monkeypatch):
        deployer = "0x" + "de" * 20
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

        assert len(entries) == 4
        addresses = {e["address"] for e in entries}
        assert any(new_contract.lower() in a for a in addresses)

        for entry in entries:
            assert entry["kind"] == "deployer_expansion"
            assert entry["chain"] == "unknown"
            assert entry["explorer_url"] is not None

        new_entry = next(e for e in entries if new_contract.lower() in e["address"])
        assert new_entry["name"] == "DiscoveredToken"

    def test_no_creators_found(self, monkeypatch):

        def fake_get(*_a, **_kw):
            raise RuntimeError("No data found")

        monkeypatch.setattr("services.discovery.deployer.etherscan.get", fake_get)

        entries = expand_from_deployers(["0x" + "a" * 40])
        assert entries == []

    def test_deployer_with_no_creations(self, monkeypatch):
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


class TestGroupMultiDeployments:
    def test_same_name_different_addresses_grouped(self):
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
        assert "address" not in result[0]

    def test_same_address_not_grouped(self):
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


@pytest.mark.usefixtures("_all_inventory_chains_enabled")
class TestResolveUnknownChains:
    def test_no_unknowns_is_noop(self, monkeypatch):
        contracts = [{"name": "A", "address": "0x" + "a" * 40, "chains": ["ethereum"]}]
        monkeypatch.setattr(
            "services.discovery.chain_resolver._probe_chains",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("should not be called")),
        )
        result = resolve_unknown_chains(contracts)
        assert result[0]["chains"] == ["ethereum"]

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


# ---------------------------------------------------------------------------
# Evidence-based chain membership: probing may CONFIRM membership
# on the protocol's declared chains, never ORIGINATE it on an arbitrary chain
# an address merely has code on (Permit2/Multicall3/Safe are everywhere).
# ---------------------------------------------------------------------------


def test_resolver_skips_chains_off_the_allowlist(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    probed: list[str] = []

    def fake_batch_get_code(rpc_url, addresses):
        probed.append(rpc_url)
        return {a: "0x" for a in addresses}

    monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)

    resolve_unknown_chains([{"name": "U", "address": "0x" + "b" * 40, "chains": ["unknown"]}])

    assert probed == ["https://erpc-proxy.example/main/evm/1"]


@pytest.mark.usefixtures("_all_inventory_chains_enabled")
class TestEvidenceBasedChainMembership:
    @staticmethod
    def _record_probed_chain_ids(monkeypatch) -> list[str]:
        probed: list[str] = []

        def fake_batch_get_code(rpc_url, addresses):
            probed.append(rpc_url.rsplit("/evm/", 1)[-1])
            return {a: "0x" for a in addresses}

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)
        return probed

    def test_declared_chain_hit_is_written(self, monkeypatch):

        def fake_batch_get_code(rpc_url, addresses):
            hit = rpc_url.endswith("/evm/1")
            return {a: ("0x6001" if hit else "0x") for a in addresses}

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
        monkeypatch.setattr("services.discovery.chain_resolver._batch_get_code", fake_batch_get_code)

        contract = {"name": "Real", "address": "0x" + "d" * 40, "chains": ["unknown"]}
        resolve_unknown_chains([contract], declared_chains=["ethereum"])

        assert contract["chains"] == ["ethereum"]
        assert "chain_candidates" not in contract

    def test_search_inventory_narrows_probe_to_declared(self, monkeypatch):
        """Bridge has code on arbitrum but only ethereum is declared."""
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


@pytest.mark.usefixtures("_all_inventory_chains_enabled")
class TestOrchestratorIntegration:
    def test_pipeline_with_chain_resolution(self, monkeypatch):
        """The selection stage owns activity ranking."""
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

        assert by_name["Vault"]["chains"] == ["ethereum"]
        assert "arbitrum" in by_name["Bridge"]["chains"]
        assert "unknown" not in by_name["Bridge"]["chains"]

        for c in contracts:
            assert "activity" not in c
            assert "rank_score" not in c

        notes = " ".join(result["notes"])
        assert "Chain resolution" in notes
        assert "Activity ranking" not in notes
