from typing import Any

import pytest

from services.discovery.chain_resolver import resolve_unknown_chains, validate_claimed_chains
from services.discovery.deployer import expand_from_deployers
from services.discovery.inventory import (
    _build_contracts,
    inventory_entries,
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
        contracts, sources_map, _ = _build_contracts(entries, limit=10)

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
        contracts, _, _ = _build_contracts(entries, limit=10)
        assert set(contracts[0]["chains"]) == {"ethereum", "base"}

    def test_sort_order(self):
        entries = [
            _entry(address=f"0x{i:040x}", name=None, kind="official_inventory_text", explorer_url=None)
            for i in range(5)
        ] + [
            _entry(address="0x" + "f" * 40, name="Best", kind="official_inventory_table"),
        ]
        contracts, _, dropped = _build_contracts(entries, limit=10)

        assert len(contracts) == 6
        assert contracts[0]["address"] == "0x" + "f" * 40
        assert contracts[0]["confidence"] > contracts[-1]["confidence"]
        assert dropped == {}

    def test_limit_never_cuts_officially_listed_entries(self):
        listed = [
            _entry(address=f"0x{i:040x}", name=f"Listed{i}", kind="official_inventory_text", explorer_url=None)
            for i in range(1, 4)
        ]
        inferred = [
            _entry(
                address=f"0x{0xD00 + i:040x}",
                name=f"Inferred{i}",
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
                explorer_url=f"https://etherscan.io/address/0x{0xD00 + i:040x}",
            )
            for i in range(4)
        ]
        contracts, _, dropped = _build_contracts(listed + inferred, limit=4)

        addresses = {c["address"] for c in contracts}
        assert {e["address"] for e in listed} <= addresses
        assert len(contracts) == 4
        assert sum(c["source"] == ["deployer_expansion"] for c in contracts) == 1
        assert dropped == {"deployer_expansion_over_limit": 3}

    def test_listed_entries_past_the_limit_are_all_kept(self):
        listed = [_entry(address=f"0x{i:040x}", name=f"Listed{i}") for i in range(1, 6)]
        inferred = _entry(
            address="0x" + "d" * 40,
            name="Inferred",
            kind="deployer_expansion",
            url="https://etherscan.io/address/0xdeployer",
            explorer_url="https://etherscan.io/address/0x" + "d" * 40,
        )
        contracts, _, dropped = _build_contracts([*listed, inferred], limit=2)

        assert {c["address"] for c in contracts} == {e["address"] for e in listed}
        assert dropped == {"deployer_expansion_over_limit": 1}

    def test_drops_are_counted_by_reason(self):
        entries = [
            _entry(address="0x" + "1" * 40, url="", explorer_url=None),
            _entry(
                address="0x" + "2" * 40,
                name=None,
                kind="deployer_expansion",
                url="https://etherscan.io/address/0xdeployer",
            ),
            _entry(address="0x" + "3" * 40),
        ]
        contracts, _, dropped = _build_contracts(entries, limit=10)

        assert [c["address"] for c in contracts] == ["0x" + "3" * 40]
        assert dropped == {"no_source_url": 1, "unnamed_deployer_only": 1}

    def test_name_voting_and_aliases(self):
        addr = "0x" + "c" * 40
        entries = [
            _entry(address=addr, name="Alpha", url="https://a.com"),
            _entry(address=addr, name="Alpha", url="https://b.com"),
            _entry(address=addr, name="Beta", url="https://c.com"),
        ]
        contracts, _, _ = _build_contracts(entries, limit=10)
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

    def test_safe_link_with_unknown_prefix_takes_no_heading_chain_and_is_not_evidence(self):
        safe = "0x" + "33" * 20
        html = f"<h2>Ethereum</h2><p>Treasury https://app.safe.global/home?safe=gno:{safe}</p>"

        entries = extract_inventory_entries_from_page_text("https://docs.example.com", html, requested_chain=None)

        assert [(e["address"], e["chain"], e["explorer_url"], e["kind"]) for e in entries] == [
            (safe, "unknown", None, "official_inventory_text")
        ]

    @pytest.mark.parametrize("requested", [None, "ethereum"])
    def test_unknown_prefix_never_borrows_a_requested_chain(self, requested):
        safe = "0x" + "33" * 20
        html = f"<h2>Ethereum</h2><p>Treasury https://app.safe.global/home?safe=gno:{safe}</p>"
        table = (
            "<h2>Ethereum</h2><p>Contract</p><p>Address</p>"
            f"<p>Treasury</p><p>https://app.safe.global/home?safe=gno:{safe}</p>"
        )

        for page in (html, table):
            entries = extract_inventory_entries_from_page_text("https://docs.example.com", page, requested)
            expected = [] if requested else [("unknown", False)]
            assert [(e["chain"], e["chain_from_hint"]) for e in entries] == expected

    def test_safe_link_naming_no_safe_is_not_a_locator(self):
        addr = "0x" + "44" * 20
        html = f"<h2>Ethereum</h2><p>Vault {addr} https://app.safe.global/welcome</p>"

        entries = extract_inventory_entries_from_page_text("https://docs.example.com", html, requested_chain=None)

        assert [(e["address"], e["explorer_url"], e["kind"]) for e in entries] == [
            (addr, None, "official_inventory_text")
        ]

    def test_safe_link_names_only_its_own_safe(self):
        safe, app = "0x" + "33" * 20, "0x" + "44" * 20
        link = f"https://app.safe.global/apps/open?safe=arb1:{safe}&appUrl=https%3A%2F%2Fx.io%2F%3Fa%3D{app}"
        html = f"<h2>Ethereum</h2><p>Ops multisig {link}</p>"

        entries = extract_inventory_entries_from_page_text("https://docs.example.com", html, requested_chain=None)

        assert [(e["address"], e["chain"], e["explorer_url"]) for e in entries] == [(safe, "arbitrum", link)]

    def test_safe_link_in_a_table_cell(self):
        safe, unknown = "0x" + "33" * 20, "0x" + "55" * 20
        html = (
            "<h2>Ethereum</h2><p>Contract</p><p>Address</p>"
            f"<p>Treasury</p><p>https://app.safe.global/home?safe=eth:{safe}</p>"
            f"<p>Other</p><p>https://app.safe.global/home?safe=gno:{unknown}</p>"
        )

        entries = extract_inventory_entries_from_page_text("https://docs.example.com", html, requested_chain=None)

        by_addr = {e["address"]: e for e in entries}
        assert all(e["kind"] == "official_inventory_table" for e in entries)
        assert by_addr[safe]["chain"] == "ethereum" and by_addr[safe]["explorer_url"]
        assert by_addr[unknown]["chain"] == "unknown" and by_addr[unknown]["explorer_url"] is None

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
        tavily_contracts, _, _ = _build_contracts(tavily_only, limit=10)
        combined_contracts, _, _ = _build_contracts(combined, limit=10)

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


def _inventory_row(name: str | None, address: str, chain: str = "ethereum", **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "address": address,
        "chains": [chain],
        "confidence": 1.0,
        "source": ["ai_inventory"],
        "source_ids": ["s1"],
        **extra,
    }


class TestInventoryEntries:
    def test_same_name_contracts_each_stay_an_entry(self):
        rows = [
            _inventory_row("HashConsensus", "0x" + "11" * 20),
            _inventory_row("HashConsensus", "0x" + "22" * 20),
            _inventory_row("HashConsensus", "0x" + "33" * 20, chain="arbitrum"),
            _inventory_row("UniqueContract", "0x" + "44" * 20),
        ]
        entries, missing = inventory_entries(rows)

        assert [(e["address"], e["chains"]) for e in entries] == [(r["address"], r["chains"]) for r in rows]
        assert missing == 0

    def test_legacy_grouped_deployments_expand_with_their_own_chain(self):
        legacy = {
            "name": "Vault",
            "chains": ["ethereum", "arbitrum"],
            "confidence": 0.9,
            "source": ["ai_inventory"],
            "source_ids": ["s1", "s2"],
            "deployments": [
                {"address": "0x" + "AA" * 20, "chains": ["ethereum"]},
                {"address": "0x" + "bb" * 20, "chains": ["arbitrum"], "source_ids": ["s2"]},
                {"address": "0x" + "cc" * 20, "chains": ["ethereum"]},
            ],
        }
        entries, missing = inventory_entries([legacy, _inventory_row("Other", "0x" + "dd" * 20)])

        assert [(e["address"], e["chains"], e["name"]) for e in entries] == [
            ("0x" + "aa" * 20, ["ethereum"], "Vault"),
            ("0x" + "bb" * 20, ["arbitrum"], "Vault"),
            ("0x" + "cc" * 20, ["ethereum"], "Vault"),
            ("0x" + "dd" * 20, ["ethereum"], "Other"),
        ]
        assert all("deployments" not in e for e in entries)
        assert entries[0]["source_ids"] == ["s1", "s2"]
        assert entries[1]["source_ids"] == ["s2"]
        assert missing == 0

    def test_duplicates_dedupe_by_address_and_chain(self):
        addr = "0x" + "ab" * 20
        rows = [
            _inventory_row("Vault", addr, source_ids=["s1"]),
            {**_inventory_row("Vault", addr.upper().replace("0X", "0x"), source_ids=["s2"]), "source": ["exa"]},
            _inventory_row("Vault", addr, chain="base"),
        ]
        entries, _ = inventory_entries(rows)

        assert [(e["address"], e["chains"][0]) for e in entries] == [(addr, "ethereum"), (addr, "base")]
        assert entries[0]["source"] == ["ai_inventory", "exa"]
        assert entries[0]["source_ids"] == ["s1", "s2"]

    def test_an_address_listed_on_several_chains_yields_an_entry_per_chain(self):
        addr = "0x" + "ab" * 20
        entries, _ = inventory_entries([{**_inventory_row("Vault", addr), "chains": ["ethereum", "base"]}])

        assert [(e["chain"], e["chains"]) for e in entries] == [
            ("ethereum", ["ethereum", "base"]),
            ("base", ["ethereum", "base"]),
        ]

    def test_an_entry_already_split_by_chain_stays_on_it(self):
        addr = "0x" + "ab" * 20
        split = {**_inventory_row("Vault", addr), "chains": ["ethereum", "base"], "chain": "base"}
        entries, _ = inventory_entries([split])

        assert [e["chain"] for e in entries] == ["base"]

    def test_chainless_entry_has_no_chain(self):
        entries, _ = inventory_entries([{"name": "X", "address": "0x" + "ab" * 20, "chains": []}])

        assert entries[0]["chain"] is None

    def test_legacy_deployment_keeps_only_sources_that_name_it(self):
        own, other = "0x" + "aa" * 20, "0x" + "bb" * 20
        legacy = {
            "name": "Vault",
            "chains": ["ethereum"],
            "source_ids": ["s1", "s2", "s3", "s4"],
            "deployments": [{"address": own, "chains": ["ethereum"]}],
        }
        sources = {
            "s1": "https://docs.example.com/contracts",
            "s2": f"https://etherscan.io/address/{other}",
            "s3": f"https://etherscan.io/address/{own}",
            "s4": f"https://app.safe.global/home?safe=eth:{other}",
        }

        entries, _ = inventory_entries([legacy], sources)

        assert entries[0]["source_ids"] == ["s1", "s3"]

    def test_entries_without_an_address_are_counted(self):
        rows = [
            _inventory_row("NoAddress", ""),
            {"name": "Group", "chains": ["ethereum"], "deployments": [{"chains": ["ethereum"]}, "junk"]},
            {"name": "EmptyGroup", "chains": ["ethereum"], "deployments": []},
        ]
        entries, missing = inventory_entries(rows)

        assert entries == []
        assert missing == 4

    def test_pipeline_keeps_same_name_deployments(self, monkeypatch):
        page = (
            "<h2>Ethereum</h2>"
            "<p>HashConsensus https://etherscan.io/address/0x" + "11" * 20 + "</p>"
            "<p>HashConsensus https://etherscan.io/address/0x" + "22" * 20 + "</p>"
            "<p>Emergency multisig https://app.safe.global/home?safe=arb1:0x" + "33" * 20 + "</p>"
        )
        monkeypatch.setattr(
            "services.discovery.inventory._discover_contract_inventory_pages",
            lambda *a, **k: ([{"url": "https://docs.example.com/c"}], ["https://docs.example.com/c"]),
        )
        monkeypatch.setattr("services.discovery.inventory_extract._fetch_page", lambda url, debug=False: page)

        result = search_protocol_inventory("docs.example.com", limit=10, run_deployer=False)

        by_addr = {c["address"]: c for c in result["contracts"]}
        assert set(by_addr) == {"0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20}
        assert all(c["name"] == "HashConsensus" for a, c in by_addr.items() if a != "0x" + "33" * 20)
        safe = by_addr["0x" + "33" * 20]
        assert safe["chains"] == ["arbitrum"]
        assert any("app.safe.global" in result["sources"][sid] for sid in safe["source_ids"])
        assert result["dropped"] == {}


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
