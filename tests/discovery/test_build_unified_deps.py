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
    build = _get_build_fn()

    r = build(TARGET, _static([DEP_A]), None, None)
    assert r["dependencies"][DEP_A]["source"] == ["static"]
    assert r["network"] == "ethereum"
    assert "dependency_graph" not in r

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
    key = f"{TARGET}|{DEP_A}"
    assert key in r["dependency_graph"]
    assert r["dependency_graph"][key][0]["op"] == "CALL"
    assert "network" not in r

    r = build(TARGET, _static([DEP_A, DEP_B]), _dynamic([DEP_A, DEP_C]), None)
    assert r["dependencies"][DEP_A]["source"] == ["dynamic", "static"]
    assert r["dependencies"][DEP_B]["source"] == ["static"]
    assert r["dependencies"][DEP_C]["source"] == ["dynamic"]

    r = build(TARGET, _static([DEP_A, DEP_A]), _dynamic([DEP_A]), None)
    assert r["dependencies"][DEP_A]["source"] == ["dynamic", "static"]


def test_classification_merging():
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

    assert r["dependencies"][DEP_A]["type"] == "proxy"
    assert r["dependencies"][DEP_A]["proxy_type"] == "eip1967"

    # Implementation is nested under its proxy, not a top-level key
    impl = r["dependencies"][DEP_A]["implementation"]
    assert isinstance(impl, dict)
    assert impl["address"] == IMPL
    assert impl["type"] == "implementation"
    assert impl["source"] == ["classification"]
    assert "proxies" not in impl  # reverse link removed

    assert IMPL not in r["dependencies"]

    # discovered_addresses is not stored — derived from source=["classification"]
    assert "discovered_addresses" not in r

    assert r["target_classification"]["type"] == "proxy"
    assert r["target_classification"]["implementation"] == IMPL

    cls["classifications"][TARGET]["type"] = "regular"
    r = build(TARGET, _static([DEP_A]), None, cls)
    assert "target_classification" not in r


def test_enrich_dependency_metadata(monkeypatch):
    enrich = _get_enrich_fn()
    build = _get_build_fn()

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

    assert unified["dependencies"][DEP_A]["contract_name"] == "TokenVault"
    assert unified["dependencies"][DEP_B]["contract_name"] == "PriceOracle"

    impl_entry = unified["dependencies"][DEP_A]["implementation"]
    assert impl_entry["contract_name"] == "VaultImpl"

    # Selector resolved to function name in dependency_graph via impl fallback
    key = f"{TARGET}|{DEP_A}"
    edge = unified["dependency_graph"][key][0]
    assert edge["function_name"] == "deposit"
