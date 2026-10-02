import pytest

from services.discovery.dependency_graph_builder import build_dependency_visualization

TARGET = "0x1111111111111111111111111111111111111111"
DEP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
IMPL = "0xcccccccccccccccccccccccccccccccccccccccc"


def _unified(
    deps=None,
    graph=None,
    target_cls=None,
    network="ethereum",
):
    out = {"address": TARGET, "dependencies": deps or {}}
    if graph is not None:
        out["dependency_graph"] = graph
        out["transactions_analyzed"] = []
        out["trace_methods"] = ["debug_traceTransaction"]
        out["trace_errors"] = []
    if target_cls:
        out["target_classification"] = target_cls
    if network:
        out["network"] = network
    return out


def test_basic_nodes_and_static_ref_edges():
    deps = {
        DEP_A: {"type": "regular", "source": ["static"]},
        DEP_B: {"type": "regular", "source": ["static"]},
    }
    result = build_dependency_visualization(_unified(deps=deps))

    assert len(result["nodes"]) == 3  # target + 2 deps
    target_node = next(n for n in result["nodes"] if n["is_target"])
    assert target_node["address"] == TARGET

    assert len(result["edges"]) == 2
    for edge in result["edges"]:
        assert edge["from"] == f"addr:{TARGET}"
        assert edge["op"] == "STATIC_REF"


def test_dynamic_edges_suppress_static_ref():
    deps = {DEP_A: {"type": "regular", "source": ["dynamic"]}}
    graph = {
        f"{TARGET}|{DEP_A}": [
            {"op": "CALL", "provenance": [{"tx_hash": "0xaa", "block_number": 1}]},
        ],
    }
    result = build_dependency_visualization(_unified(deps=deps, graph=graph))

    assert len(result["edges"]) == 1
    assert result["edges"][0]["op"] == "CALL"


_PROXY_GRAPH = {f"{TARGET}|{DEP_A}": [{"op": "CALL", "provenance": []}]}
_NESTED_IMPL_DEPS = {
    DEP_A: {
        "type": "proxy",
        "proxy_type": "eip1967",
        "source": ["dynamic"],
        "contract_name": "TransparentProxy",
        "implementation": {
            "address": IMPL,
            "type": "implementation",
            "source": ["classification"],
            "contract_name": "TokenV2",
        },
    },
}


@pytest.mark.parametrize(
    ("unified_kwargs", "build_kwargs", "expected"),
    [
        pytest.param(
            {
                "deps": {DEP_A: {"type": "regular", "source": ["dynamic"], "contract_name": "WETH9"}},
                "graph": _PROXY_GRAPH,
            },
            {},
            [(DEP_A, "label", "WETH9")],
            id="contract_name_used_as_label",
        ),
        pytest.param(
            {"deps": {DEP_A: {"type": "regular", "source": ["static"]}}},
            {},
            [(DEP_A, "label", f"{DEP_A[:6]}...{DEP_A[-4:]}")],
            id="contract_name_fallback_to_short_address",
        ),
        pytest.param(
            {
                "deps": {DEP_A: {"type": "regular", "source": ["static"]}},
                "target_cls": {"type": "proxy", "proxy_type": "eip1967"},
            },
            {},
            [(TARGET, "type", "proxy")],
            id="target_classification_in_node",
        ),
        pytest.param(
            {"deps": _NESTED_IMPL_DEPS, "graph": _PROXY_GRAPH},
            {},
            [(DEP_A, "label", "TransparentProxy"), (IMPL, "label", "TokenV2")],
            id="nested_implementation_label",
        ),
        pytest.param(
            {"deps": {DEP_A: {"type": "regular", "source": ["static"]}}},
            {"target_label": "LiquidityPool"},
            [(TARGET, "label", "LiquidityPool")],
            id="target_label_from_caller",
        ),
    ],
)
def test_node_fields(unified_kwargs, build_kwargs, expected):
    result = build_dependency_visualization(_unified(**unified_kwargs), **build_kwargs)

    for address, key, value in expected:
        node = next(n for n in result["nodes"] if n["address"] == address)
        assert node[key] == value


def test_metadata_populated():
    deps = {
        DEP_A: {
            "type": "proxy",
            "source": ["dynamic"],
            "implementation": {
                "address": IMPL,
                "type": "implementation",
                "source": ["classification"],
                "contract_name": "ImplV2",
            },
        },
    }
    graph = {f"{TARGET}|{DEP_A}": [{"op": "CALL", "provenance": []}]}
    result = build_dependency_visualization(_unified(deps=deps, graph=graph))

    assert result["metadata"]["target"] == TARGET
    assert result["metadata"]["network"] == "ethereum"
    assert result["metadata"]["trace_methods"] == ["debug_traceTransaction"]
    assert result["metadata"]["discovered_addresses"] == [IMPL]


@pytest.mark.parametrize(
    "unified",
    [pytest.param(_unified(), id="empty_dependencies"), pytest.param({}, id="missing_unified")],
)
def test_empty_inputs_return_no_nodes(unified):
    result = build_dependency_visualization(unified)
    assert result["nodes"] == []
    assert result["edges"] == []


def test_beacon_edge():
    beacon = "0xdddddddddddddddddddddddddddddddddddddd"
    deps = {
        DEP_A: {
            "type": "proxy",
            "proxy_type": "beacon_proxy",
            "source": ["dynamic"],
            "beacon": beacon,
        },
        beacon: {"type": "beacon", "source": ["classification"]},
    }
    graph = {f"{TARGET}|{DEP_A}": [{"op": "CALL", "provenance": []}]}
    result = build_dependency_visualization(_unified(deps=deps, graph=graph))

    ops = {(e["from"], e["to"], e["op"]) for e in result["edges"]}
    assert (f"addr:{DEP_A}", f"addr:{beacon}", "BEACON") in ops


def test_edges_skip_unknown_node_ids():
    unknown = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    deps = {DEP_A: {"type": "regular", "source": ["dynamic"]}}
    graph = {
        f"{TARGET}|{DEP_A}": [{"op": "CALL", "provenance": []}],
        f"{TARGET}|{unknown}": [{"op": "CALL", "provenance": []}],
    }
    result = build_dependency_visualization(_unified(deps=deps, graph=graph))

    assert all(e["to"] != f"addr:{unknown}" for e in result["edges"])
