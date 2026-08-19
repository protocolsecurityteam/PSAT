import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery.unified_dependencies import build_unified_dependencies, enrich_dependency_metadata


def _get_build_fn():
    return build_unified_dependencies


def _get_enrich_fn():
    return enrich_dependency_metadata


TARGET = "0x1111111111111111111111111111111111111111"
DEP_A = "0x2222222222222222222222222222222222222222"
DEP_B = "0x3333333333333333333333333333333333333333"
DEP_C = "0x4444444444444444444444444444444444444444"
IMPL = "0x5555555555555555555555555555555555555555"


def _static(deps, network="ethereum"):
    return {
        "address": TARGET,
        "dependencies": deps,
        "rpc": "https://rpc.example",
        "network": network,
    }


def _dynamic(deps, provenance=None, graph=None):
    return {
        "address": TARGET,
        "rpc": "https://trace.example",
        "transactions_analyzed": [{"tx_hash": "0xaa", "block_number": 1, "method_selector": "0xdeadbeef"}],
        "trace_methods": ["debug_traceTransaction"],
        "dependencies": deps,
        "provenance": provenance or {},
        "dependency_graph": graph or [],
        "trace_errors": [],
    }


def test_source_tracking():
    """Static-only, dynamic-only, and merged sources are all tracked correctly."""
    build = _get_build_fn()

    # Static only
    r = build(TARGET, _static([DEP_A]), None, None)
    assert r["dependencies"][DEP_A]["source"] == ["static"]
    assert r["network"] == "ethereum"
    assert "dependency_graph" not in r

    # Dynamic only (with graph)
    graph = [
        {
            "from": TARGET,
            "to": DEP_A,
            "op": "CALL",
            "provenance": [{"tx_hash": "0xaa", "block_number": 1}],
        }
    ]
    r = build(TARGET, None, _dynamic([DEP_A], graph=graph), None)
    assert r["dependencies"][DEP_A]["source"] == ["dynamic"]
    # Provenance lives only in dependency_graph, not on dep entries
    assert "provenance" not in r["dependencies"][DEP_A]
    # dependency_graph is keyed by from|to
    key = f"{TARGET}|{DEP_A}"
    assert key in r["dependency_graph"]
    assert r["dependency_graph"][key][0]["op"] == "CALL"
    assert "network" not in r

    # Merged: DEP_A in both, DEP_B static-only, DEP_C dynamic-only
    r = build(TARGET, _static([DEP_A, DEP_B]), _dynamic([DEP_A, DEP_C]), None)
    assert r["dependencies"][DEP_A]["source"] == ["dynamic", "static"]
    assert r["dependencies"][DEP_B]["source"] == ["static"]
    assert r["dependencies"][DEP_C]["source"] == ["dynamic"]

    # Duplicates within a source are deduplicated
    r = build(TARGET, _static([DEP_A, DEP_A]), _dynamic([DEP_A]), None)
    assert r["dependencies"][DEP_A]["source"] == ["dynamic", "static"]


def test_classification_merging():
    """Classification types, target classification, and nested implementations."""
    build = _get_build_fn()
    cls = {
        "address": TARGET,
        "rpc": "https://rpc.example",
        "classifications": {
            TARGET: {
                "address": TARGET,
                "type": "proxy",
                "proxy_type": "eip1967",
                "implementation": IMPL,
            },
            DEP_A: {
                "address": DEP_A,
                "type": "proxy",
                "proxy_type": "eip1967",
                "implementation": IMPL,
            },
            IMPL: {"address": IMPL, "type": "implementation", "proxies": [DEP_A]},
        },
        "discovered_addresses": [IMPL],
    }
    r = build(TARGET, _static([DEP_A]), None, cls)

    # Dep classification
    assert r["dependencies"][DEP_A]["type"] == "proxy"
    assert r["dependencies"][DEP_A]["proxy_type"] == "eip1967"

    # Implementation is nested under its proxy, not a top-level key
    impl = r["dependencies"][DEP_A]["implementation"]
    assert isinstance(impl, dict)
    assert impl["address"] == IMPL
    assert impl["type"] == "implementation"
    assert impl["source"] == ["classification"]
    assert "proxies" not in impl  # reverse link removed

    # IMPL is NOT a top-level dependency
    assert IMPL not in r["dependencies"]

    # discovered_addresses is not stored — derived from source=["classification"]
    assert "discovered_addresses" not in r

    # Target classification included when non-regular
    assert r["target_classification"]["type"] == "proxy"
    assert r["target_classification"]["implementation"] == IMPL

    # Target classification omitted when regular
    cls["classifications"][TARGET]["type"] = "regular"
    r = build(TARGET, _static([DEP_A]), None, cls)
    assert "target_classification" not in r


def test_target_classification_fallback():
    """target_classification kwarg is used when classify_contracts is unavailable."""
    build = _get_build_fn()
    fallback = {"address": TARGET, "type": "proxy", "proxy_type": "eip1967", "implementation": IMPL}

    # No cls_output — fallback fills target_classification
    r = build(TARGET, _static([DEP_A]), None, None, target_classification=fallback)
    assert r["target_classification"]["type"] == "proxy"
    assert r["target_classification"]["proxy_type"] == "eip1967"

    # cls_output present and has target — cls_output wins
    cls = {
        "classifications": {
            TARGET: {"address": TARGET, "type": "proxy", "proxy_type": "beacon_proxy"},
            DEP_A: {"address": DEP_A, "type": "regular"},
        },
        "discovered_addresses": [],
    }
    r = build(TARGET, _static([DEP_A]), None, cls, target_classification=fallback)
    assert r["target_classification"]["proxy_type"] == "beacon_proxy"

    # Regular fallback is ignored
    regular_fallback = {"address": TARGET, "type": "regular"}
    r = build(TARGET, _static([DEP_A]), None, None, target_classification=regular_fallback)
    assert "target_classification" not in r


def test_edge_cases():
    """Empty deps, no classification, and discovered-address deduplication."""
    build = _get_build_fn()

    # Empty deps
    r = build(TARGET, _static([]), None, None)
    assert r["dependencies"] == {}

    # No classification — all regular
    r = build(TARGET, _static([DEP_A, DEP_B]), None, None)
    assert all(d["type"] == "regular" for d in r["dependencies"].values())
    assert "discovered_addresses" not in r

    # Discovered address already in dep list — not duplicated, keeps original source,
    # and gets nested under its proxy
    cls = {
        "address": TARGET,
        "rpc": "https://rpc.example",
        "classifications": {
            TARGET: {"address": TARGET, "type": "regular"},
            DEP_A: {
                "address": DEP_A,
                "type": "proxy",
                "proxy_type": "eip1967",
                "implementation": DEP_B,
            },
            DEP_B: {"address": DEP_B, "type": "implementation", "proxies": [DEP_A]},
        },
        "discovered_addresses": [DEP_B],
    }
    r = build(TARGET, _static([DEP_A, DEP_B]), None, cls)
    # DEP_B is nested under DEP_A (its proxy), not top-level
    assert DEP_B not in r["dependencies"]
    impl = r["dependencies"][DEP_A]["implementation"]
    assert isinstance(impl, dict)
    assert impl["address"] == DEP_B
    assert impl["source"] == ["static"]
    assert impl["type"] == "implementation"


def test_dependency_graph_keyed():
    """dependency_graph is keyed by from|to pair."""
    build = _get_build_fn()

    graph = [
        {
            "from": TARGET,
            "to": DEP_A,
            "op": "CALL",
            "provenance": [{"tx_hash": "0xaa", "block_number": 1}],
            "selector": "0xdeadbeef",
        },
        {
            "from": TARGET,
            "to": DEP_A,
            "op": "CALL",
            "provenance": [{"tx_hash": "0xbb", "block_number": 2}],
            "selector": "0xcafebabe",
        },
        {
            "from": TARGET,
            "to": DEP_B,
            "op": "STATICCALL",
            "provenance": [],
        },
    ]
    r = build(TARGET, None, _dynamic([DEP_A, DEP_B], graph=graph), None)

    dg = r["dependency_graph"]
    assert isinstance(dg, dict)

    # Two edges for TARGET→DEP_A
    key_a = f"{TARGET}|{DEP_A}"
    assert key_a in dg
    assert len(dg[key_a]) == 2
    assert dg[key_a][0]["selector"] == "0xdeadbeef"
    assert dg[key_a][1]["selector"] == "0xcafebabe"
    # from/to not repeated inside entries
    assert "from" not in dg[key_a][0]
    assert "to" not in dg[key_a][0]

    # One edge for TARGET→DEP_B
    key_b = f"{TARGET}|{DEP_B}"
    assert key_b in dg
    assert len(dg[key_b]) == 1
    assert dg[key_b][0]["op"] == "STATICCALL"


def test_enrich_dependency_metadata(monkeypatch):
    """enrich_dependency_metadata resolves contract names and maps selectors to function names."""
    enrich = _get_enrich_fn()
    build = _get_build_fn()

    # Mock get_contract_info to return name + selector map per address
    selector_a = "0xdeadbeef"
    info_map = {
        DEP_A: ("TokenVault", {selector_a: "deposit"}),
        DEP_B: ("PriceOracle", {}),
        IMPL: ("VaultImpl", {}),
    }
    monkeypatch.setattr(
        "services.discovery.unified_dependencies.get_contract_info",
        lambda addr, *, chain_id=1: info_map.get(addr, (None, {})),
    )

    # Build a unified output with a proxy dep (impl nested) and a dependency graph
    cls = {
        "address": TARGET,
        "rpc": "https://rpc.example",
        "classifications": {
            TARGET: {"address": TARGET, "type": "regular"},
            DEP_A: {
                "address": DEP_A,
                "type": "proxy",
                "proxy_type": "eip1967",
                "implementation": IMPL,
            },
            IMPL: {"address": IMPL, "type": "implementation", "proxies": [DEP_A]},
            DEP_B: {"address": DEP_B, "type": "regular"},
        },
        "discovered_addresses": [IMPL],
    }
    graph = [
        {
            "from": TARGET,
            "to": DEP_A,
            "op": "CALL",
            "provenance": [],
            "selector": selector_a,
        },
    ]
    dyn = {
        "address": TARGET,
        "rpc": "https://trace.example",
        "transactions_analyzed": [],
        "trace_methods": [],
        "dependencies": [DEP_A, DEP_B],
        "dependency_graph": graph,
        "trace_errors": [],
    }
    unified = build(TARGET, _static([DEP_A, DEP_B]), dyn, cls)
    enrich(unified, chain_id=1)

    # Contract names resolved
    assert unified["dependencies"][DEP_A]["contract_name"] == "TokenVault"
    assert unified["dependencies"][DEP_B]["contract_name"] == "PriceOracle"

    # Nested implementation name resolved
    impl_entry = unified["dependencies"][DEP_A]["implementation"]
    assert impl_entry["contract_name"] == "VaultImpl"

    # Selector resolved to function name in dependency_graph via impl fallback
    key = f"{TARGET}|{DEP_A}"
    edge = unified["dependency_graph"][key][0]
    assert edge["function_name"] == "deposit"
