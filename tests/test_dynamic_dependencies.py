import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery import dynamic_dependencies as ddc

# ---------------------------------------------------------------------------
# Transaction selection
# ---------------------------------------------------------------------------


# Verifies representative tx selection prioritizes unique function selectors and successful calls to target.
def test_pick_representative_transactions_prefers_selector_coverage():
    target = "0x1111111111111111111111111111111111111111"
    txs = [
        {
            "hash": "0xtx1",
            "to": target,
            "isError": "0",
            "blockNumber": "100",
            "input": "0xaaaaaaaa1234",
        },
        {
            "hash": "0xtx2",
            "to": target,
            "isError": "0",
            "blockNumber": "99",
            "input": "0xbbbbbbbb1234",
        },
        {
            "hash": "0xtx3",
            "to": target,
            "isError": "0",
            "blockNumber": "98",
            "input": "0xaaaaaaaa9999",
        },
        {
            "hash": "0xtx4",
            "to": "0x2222222222222222222222222222222222222222",
            "isError": "0",
            "blockNumber": "97",
            "input": "0xcccccccc",
        },
        {
            "hash": "0xtx5",
            "to": target,
            "isError": "1",
            "blockNumber": "96",
            "input": "0xdddddddd",
        },
    ]

    selected = ddc.pick_representative_transactions(target, txs, max_txs=3)
    assert [tx["tx_hash"] for tx in selected] == ["0xtx1", "0xtx2", "0xtx3"]
    assert [tx["method_selector"] for tx in selected] == [
        "0xaaaaaaaa",
        "0xbbbbbbbb",
        "0xaaaaaaaa",
    ]


# Verifies edge extraction handles all call op types (including CALLCODE) for both debug and parity trace formats.
def test_extract_edges_captures_all_op_types():
    def addr(n: int) -> str:
        return "0x" + hex(n)[2:].zfill(40)

    # debug callTracer: nested CALL/DELEGATECALL/CREATE/CALLCODE
    debug_trace = {
        "type": "CALL",
        "from": addr(1),
        "to": addr(2),
        "calls": [
            {"type": "DELEGATECALL", "from": addr(2), "to": addr(3)},
            {"type": "CREATE", "from": addr(2), "to": addr(4)},
            {"type": "CALLCODE", "from": addr(2), "to": addr(5)},
        ],
    }
    debug_edges = ddc.extract_edges_from_trace("debug_traceTransaction", debug_trace, "0xtx", 1)
    assert {e["op"] for e in debug_edges} == {
        "CALL",
        "DELEGATECALL",
        "CREATE",
        "CALLCODE",
    }

    # parity style: all six types including STATICCALL and CREATE2
    parity_entries = [
        {
            "type": "call",
            "action": {"from": addr(1), "to": addr(2), "callType": "call"},
        },
        {
            "type": "call",
            "action": {"from": addr(1), "to": addr(3), "callType": "staticcall"},
        },
        {
            "type": "call",
            "action": {"from": addr(1), "to": addr(4), "callType": "delegatecall"},
        },
        {
            "type": "call",
            "action": {"from": addr(1), "to": addr(5), "callType": "callcode"},
        },
        {
            "type": "create",
            "action": {"from": addr(1), "creationMethod": "create"},
            "result": {"address": addr(6)},
        },
        {
            "type": "create",
            "action": {"from": addr(1), "creationMethod": "create2"},
            "result": {"address": addr(7)},
        },
    ]
    parity_edges = ddc.extract_edges_from_trace("trace_transaction", parity_entries, "0xtx", 1)
    assert {e["op"] for e in parity_edges} == {
        "CALL",
        "STATICCALL",
        "DELEGATECALL",
        "CALLCODE",
        "CREATE",
        "CREATE2",
    }


# Verifies tracer fallback behavior from debug_traceTransaction to trace_transaction.
def test_trace_transaction_falls_back_to_parity_style(monkeypatch):
    calls = []

    def fake_rpc_call(_rpc_url, method, _params, retries=0):
        calls.append(method)
        if method == "debug_traceTransaction":
            raise RuntimeError("method not found")
        return [{"type": "call", "action": {"from": "0x1", "to": "0x2", "callType": "call"}}]

    monkeypatch.setattr(ddc, "rpc_call", fake_rpc_call)

    method, result = ddc.trace_transaction("https://rpc.example", "0xtx")
    assert method == "trace_transaction"
    assert calls == [
        "debug_traceTransaction",
        "debug_traceTransaction",
        "trace_transaction",
    ]


# Shared mock: all traced addresses are contracts
def _mock_code_checks(monkeypatch):
    monkeypatch.setattr(ddc, "get_code", lambda _rpc, _addr: "0x6000")
    monkeypatch.setattr(ddc, "has_deployed_code", lambda code: code not in ("0x", "0x0"))


# Verifies dynamic discovery aggregates dependencies and provenance across traced transactions.
def test_find_dynamic_dependencies_aggregates_graph(monkeypatch):
    target = "0x1111111111111111111111111111111111111111"
    tx1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    tx2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    _mock_code_checks(monkeypatch)
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setattr(
        ddc,
        "fetch_contract_transactions",
        lambda _address, limit=0, start_block=0: [
            {
                "hash": tx1,
                "to": target,
                "isError": "0",
                "blockNumber": "11",
                "input": "0xaaaaaaaa",
            },
            {
                "hash": tx2,
                "to": target,
                "isError": "0",
                "blockNumber": "12",
                "input": "0xbbbbbbbb",
            },
        ],
    )

    def fake_trace(_rpc_url, tx_hash):
        if tx_hash == tx1:
            return "debug_traceTransaction", {
                "type": "CALL",
                "from": target,
                "to": "0x2222222222222222222222222222222222222222",
                "calls": [
                    {
                        "type": "DELEGATECALL",
                        "from": "0x2222222222222222222222222222222222222222",
                        "to": "0x3333333333333333333333333333333333333333",
                    }
                ],
            }
        return "debug_traceTransaction", {
            "type": "CALL",
            "from": target,
            "to": "0x2222222222222222222222222222222222222222",
        }

    monkeypatch.setattr(ddc, "trace_transaction", fake_trace)

    out = ddc.find_dynamic_dependencies(target, tx_limit=2)
    assert out["address"] == target
    # Only direct calls from target are included; the indirect
    # 0x2222→0x3333 DELEGATECALL is filtered out.
    assert out["dependencies"] == [
        "0x2222222222222222222222222222222222222222",
    ]
    assert len(out["transactions_analyzed"]) == 2
    assert len(out["dependency_graph"]) == 1
    assert out["dependency_graph"][0]["from"] == target
    assert isinstance(out["trace_errors"], list) and out["trace_errors"] == []


# Verifies precompiles and EOAs are filtered from dynamic dependencies.
def test_find_dynamic_dependencies_filters_precompiles_and_eoas(monkeypatch):
    target = "0x1111111111111111111111111111111111111111"
    contract = "0x2222222222222222222222222222222222222222"
    precompile = "0x0000000000000000000000000000000000000001"
    eoa = "0x3333333333333333333333333333333333333333"
    tx1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setattr(ddc, "get_code", lambda _rpc, addr: "0x6000" if addr == contract else "0x")
    monkeypatch.setattr(ddc, "has_deployed_code", lambda code: code not in ("0x", "0x0"))
    monkeypatch.setattr(
        ddc,
        "fetch_contract_transactions",
        lambda _addr, limit=0, start_block=0: [
            {"hash": tx1, "to": target, "isError": "0", "blockNumber": "10", "input": "0xaa"},
        ],
    )
    monkeypatch.setattr(
        ddc,
        "trace_transaction",
        lambda _rpc, _tx: (
            "debug_traceTransaction",
            {
                "type": "CALL",
                "from": target,
                "to": contract,
                "calls": [
                    {"type": "STATICCALL", "from": contract, "to": precompile},
                    {"type": "CALL", "from": contract, "to": eoa},
                ],
            },
        ),
    )

    out = ddc.find_dynamic_dependencies(target, tx_limit=1)
    assert out["dependencies"] == [contract]
    assert all(e["to"] == contract for e in out["dependency_graph"])


# Verifies a single failed trace is recorded in trace_errors while remaining transactions still produce results.
def test_find_dynamic_dependencies_continues_on_single_trace_failure(monkeypatch):
    target = "0x1111111111111111111111111111111111111111"
    tx1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    tx2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    _mock_code_checks(monkeypatch)
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setattr(
        ddc,
        "fetch_contract_transactions",
        lambda _address, limit=0, start_block=0: [
            {
                "hash": tx1,
                "to": target,
                "isError": "0",
                "blockNumber": "10",
                "input": "0xaaaaaaaa",
            },
            {
                "hash": tx2,
                "to": target,
                "isError": "0",
                "blockNumber": "11",
                "input": "0xbbbbbbbb",
            },
        ],
    )

    def fake_trace(_rpc_url, tx_hash):
        if tx_hash == tx1:
            raise RuntimeError("RPC error on tx1")
        return "debug_traceTransaction", {
            "type": "CALL",
            "from": target,
            "to": "0x2222222222222222222222222222222222222222",
        }

    monkeypatch.setattr(ddc, "trace_transaction", fake_trace)

    out = ddc.find_dynamic_dependencies(target, tx_limit=2)
    assert "0x2222222222222222222222222222222222222222" in out["dependencies"]
    assert len(out["trace_errors"]) == 1
    assert out["trace_errors"][0]["tx_hash"] == tx1


# Verifies all-trace-failure raises RuntimeError so callers know no results were produced.
def test_find_dynamic_dependencies_raises_if_all_traces_fail(monkeypatch):
    target = "0x1111111111111111111111111111111111111111"
    _mock_code_checks(monkeypatch)
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setattr(
        ddc,
        "fetch_contract_transactions",
        lambda _address, limit=0, start_block=0: [
            {
                "hash": "0xtx1",
                "to": target,
                "isError": "0",
                "blockNumber": "10",
                "input": "0xaaaaaaaa",
            },
        ],
    )
    monkeypatch.setattr(
        ddc,
        "trace_transaction",
        lambda _rpc, _tx: (_ for _ in ()).throw(RuntimeError("all fail")),
    )

    with pytest.raises(RuntimeError, match="All"):
        ddc.find_dynamic_dependencies(target, tx_limit=1)


# Verifies explicit tx_hashes skips Etherscan fetch and traces only the provided hashes.
def test_find_dynamic_dependencies_with_explicit_tx_hashes(monkeypatch):
    target = "0x1111111111111111111111111111111111111111"
    _mock_code_checks(monkeypatch)
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    fetch_called = []
    monkeypatch.setattr(
        ddc,
        "fetch_contract_transactions",
        lambda *a, **kw: fetch_called.append(1) or [],
    )
    monkeypatch.setattr(
        ddc,
        "_fetch_tx_metadata_from_rpc",
        lambda _rpc, tx_hash: {
            "tx_hash": tx_hash,
            "block_number": 1,
            "method_selector": "0xdeadbeef",
        },
    )
    monkeypatch.setattr(
        ddc,
        "trace_transaction",
        lambda _rpc, _tx: (
            "debug_traceTransaction",
            {
                "type": "CALL",
                "from": target,
                "to": "0x2222222222222222222222222222222222222222",
            },
        ),
    )

    out = ddc.find_dynamic_dependencies(target, tx_hashes=["0xtxhash"])
    assert fetch_called == [], "fetch_contract_transactions should not be called when tx_hashes provided"
    assert out["transactions_analyzed"][0]["tx_hash"] == "0xtxhash"


# ---------------------------------------------------------------------------
# resolve_trace_rpc
# ---------------------------------------------------------------------------


def test_resolve_trace_rpc_raises_without_rpc(monkeypatch):
    """resolve_trace_rpc raises RuntimeError when no RPC is available."""
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="requires --dynamic-rpc or eRPC"):
        ddc.resolve_trace_rpc()


def test_resolve_trace_rpc_prefers_arg(monkeypatch):
    """resolve_trace_rpc returns the explicit argument over eRPC."""
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    assert ddc.resolve_trace_rpc("https://arg.example") == "https://arg.example"


def test_resolve_trace_rpc_falls_back_to_erpc(monkeypatch):
    """resolve_trace_rpc falls back to the eRPC mainnet route when no arg is given."""
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    assert ddc.resolve_trace_rpc() == "https://erpc-proxy.example/main/evm/1"


# ---------------------------------------------------------------------------
# _build_graph
# ---------------------------------------------------------------------------


def test_build_graph_deduplicates_and_sorts_none_blocks():
    """_build_graph deduplicates provenance and handles None block_number."""
    a = "0x" + "aa" * 20
    b = "0x" + "bb" * 20
    edges = [
        {"from": a, "to": b, "op": "CALL", "tx_hash": "0xtx1", "block_number": None},
        {"from": a, "to": b, "op": "CALL", "tx_hash": "0xtx1", "block_number": None},
        {"from": a, "to": b, "op": "CALL", "tx_hash": "0xtx2", "block_number": 100},
    ]
    graph = ddc._build_graph(edges)
    assert len(graph) == 1
    prov = graph[0]["provenance"]
    assert len(prov) == 2  # deduplicated
    assert prov[0]["tx_hash"] == "0xtx1"
    assert prov[0]["block_number"] is None
    assert prov[1]["tx_hash"] == "0xtx2"
    assert prov[1]["block_number"] == 100


# ---------------------------------------------------------------------------
# fetch_contract_transactions dual fetch
# ---------------------------------------------------------------------------


def test_fetch_contract_transactions_merges_normal_and_internal(monkeypatch):
    """Both txlist and txlistinternal results are merged; failure of one doesn't block the other."""
    calls = []

    def fake_etherscan_get(_module, action, **_kw):
        calls.append(action)
        if action == "txlist":
            raise RuntimeError("No transactions found")
        return {"result": [{"hash": "0xaa", "to": "0x1", "isError": "0"}]}

    monkeypatch.setattr(ddc, "etherscan_get", fake_etherscan_get)
    txs = ddc.fetch_contract_transactions("0x1")
    assert calls == ["txlist", "txlistinternal"]
    assert len(txs) == 1
    assert txs[0]["hash"] == "0xaa"


# ---------------------------------------------------------------------------
# _fetch_tx_metadata_from_rpc error path
# ---------------------------------------------------------------------------


def test_fetch_tx_metadata_invalid_response(monkeypatch):
    """_fetch_tx_metadata_from_rpc raises on non-dict or missing hash."""
    monkeypatch.setattr(ddc, "rpc_call", lambda *a, **kw: "0x")
    with pytest.raises(RuntimeError, match="Could not fetch"):
        ddc._fetch_tx_metadata_from_rpc("https://rpc.example", "0xbad")


# ---------------------------------------------------------------------------
# find_dynamic_dependencies validation
# ---------------------------------------------------------------------------


def test_find_dynamic_dependencies_rejects_invalid_tx_limit(monkeypatch):
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    with pytest.raises(RuntimeError, match="tx_limit must be >= 1"):
        ddc.find_dynamic_dependencies("0x" + "11" * 20, tx_limit=0)


# ---------------------------------------------------------------------------
# Regression: proxy_address routes tx fetch to proxy, rewrites edges to impl
# ---------------------------------------------------------------------------


def test_proxy_address_fetches_txs_from_proxy_and_rewrites_edges(monkeypatch):
    """Regression: when proxy_address is passed, transactions must be fetched
    from the proxy address (where real traffic goes), not the implementation.
    Edges must be rewritten from proxy->dep to impl->dep, and both proxy and
    impl must be excluded from the dependency list."""
    impl = "0x1111111111111111111111111111111111111111"
    proxy = "0x2222222222222222222222222222222222222222"
    dep = "0x3333333333333333333333333333333333333333"
    tx1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    _mock_code_checks(monkeypatch)
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    fetch_addresses = []

    def fake_fetch_txs(address, limit=0, start_block=0):
        fetch_addresses.append(address)
        return [
            {"hash": tx1, "to": proxy, "isError": "0", "blockNumber": "10", "input": "0xdeadbeef"},
        ]

    monkeypatch.setattr(ddc, "fetch_contract_transactions", fake_fetch_txs)

    monkeypatch.setattr(
        ddc,
        "trace_transaction",
        lambda _rpc, _tx: (
            "debug_traceTransaction",
            {
                "type": "CALL",
                "from": proxy,
                "to": dep,
            },
        ),
    )

    out = ddc.find_dynamic_dependencies(impl, tx_limit=1, proxy_address=proxy)

    # Transactions were fetched for the PROXY, not the implementation
    assert fetch_addresses == [proxy], f"Expected fetch for proxy {proxy}, got {fetch_addresses}"

    # Implementation and proxy are excluded from dependencies
    assert impl not in out["dependencies"]
    assert proxy not in out["dependencies"]
    assert dep in out["dependencies"]

    # Graph edges originate from the proxy (where transactions occur)
    for edge in out["dependency_graph"]:
        assert edge["from"] == proxy, f"Edge source should be proxy {proxy}, got {edge['from']}"


# ---------------------------------------------------------------------------
# Regression: fetch_contract_transactions oldest-first fallback
# ---------------------------------------------------------------------------


def test_fetch_contract_transactions_oldest_first_when_all_eth_transfers(monkeypatch):
    """Regression: when all recent (desc) normal txs are plain ETH transfers
    (input='0x'), a second oldest-first (asc) fetch must be performed to find
    function calls buried under high-volume value transfers."""
    target = "0x1111111111111111111111111111111111111111"
    etherscan_calls = []

    def fake_etherscan_get(_module, action, **kwargs):
        etherscan_calls.append({"action": action, "sort": kwargs.get("sort")})
        if action == "txlistinternal":
            raise RuntimeError("No transactions found")
        if action == "txlist" and kwargs.get("sort") == "desc":
            # Recent txs are all plain ETH transfers (input='0x')
            return {
                "result": [
                    {"hash": "0xeth1", "to": target, "isError": "0", "blockNumber": "100", "input": "0x"},
                    {"hash": "0xeth2", "to": target, "isError": "0", "blockNumber": "99", "input": "0x"},
                ]
            }
        if action == "txlist" and kwargs.get("sort") == "asc":
            # Oldest txs have real function selectors
            return {
                "result": [
                    {"hash": "0xold1", "to": target, "isError": "0", "blockNumber": "1", "input": "0xdeadbeef00"},
                    {"hash": "0xold2", "to": target, "isError": "0", "blockNumber": "2", "input": "0xcafebabe00"},
                ]
            }
        return {"result": []}

    monkeypatch.setattr(ddc, "etherscan_get", fake_etherscan_get)

    txs = ddc.fetch_contract_transactions(target)

    # Verify the second (asc) call was made
    txlist_calls = [c for c in etherscan_calls if c["action"] == "txlist"]
    assert len(txlist_calls) == 2, f"Expected 2 txlist calls (desc + asc), got {len(txlist_calls)}"
    assert txlist_calls[0]["sort"] == "desc"
    assert txlist_calls[1]["sort"] == "asc"

    # Verify the oldest txs with real selectors are included
    hashes = {tx["hash"] for tx in txs}
    assert "0xold1" in hashes, "Oldest tx with function call should be included"
    assert "0xold2" in hashes, "Oldest tx with function call should be included"
    # Original ETH transfers are still present
    assert "0xeth1" in hashes
    assert "0xeth2" in hashes
    # Total should be 4 (2 desc + 2 asc, no duplicates)
    assert len(txs) == 4


def test_fetch_contract_transactions_no_asc_when_selectors_present(monkeypatch):
    """When recent txs already have function selectors, no oldest-first fetch is needed."""
    target = "0x1111111111111111111111111111111111111111"
    etherscan_calls = []

    def fake_etherscan_get(_module, action, **kwargs):
        etherscan_calls.append({"action": action, "sort": kwargs.get("sort")})
        if action == "txlistinternal":
            raise RuntimeError("No transactions found")
        if action == "txlist" and kwargs.get("sort") == "desc":
            return {
                "result": [
                    {"hash": "0xtx1", "to": target, "isError": "0", "blockNumber": "100", "input": "0xdeadbeef00"},
                ]
            }
        return {"result": []}

    monkeypatch.setattr(ddc, "etherscan_get", fake_etherscan_get)

    txs = ddc.fetch_contract_transactions(target)

    # Only one txlist call (desc), no asc follow-up
    txlist_calls = [c for c in etherscan_calls if c["action"] == "txlist"]
    assert len(txlist_calls) == 1
    assert txlist_calls[0]["sort"] == "desc"
    assert len(txs) == 1


# ---------------------------------------------------------------------------
# Trace fan-out parity: parallel + sequential produce identical edge sets
# and identical trace_errors ordering.
# ---------------------------------------------------------------------------


def _trace_parity_helper(monkeypatch, fanout: str):
    """Run ``find_dynamic_dependencies`` over a 5-tx fixture under a given fanout."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
    target = "0x1111111111111111111111111111111111111111"
    deps = [f"0x{i:040x}" for i in range(2, 7)]
    tx_hashes = [f"0x{(0xA + i):064x}" for i in range(5)]

    _mock_code_checks(monkeypatch)
    monkeypatch.setattr(ddc, "load_dotenv", lambda _path: None)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setattr(
        ddc,
        "fetch_contract_transactions",
        lambda _addr, limit=0, start_block=0: [
            {
                "hash": tx_hashes[i],
                "to": target,
                "isError": "0",
                "blockNumber": str(10 + i),
                "input": f"0x{(0xA1 + i):08x}",
            }
            for i in range(5)
        ],
    )

    def fake_trace(_rpc, tx_hash):
        # Tx index 2 fails; the rest yield a CALL edge to a distinct dep.
        idx = tx_hashes.index(tx_hash)
        if idx == 2:
            raise RuntimeError(f"trace failed for tx{idx}")
        return "debug_traceTransaction", {
            "type": "CALL",
            "from": target,
            "to": deps[idx],
        }

    monkeypatch.setattr(ddc, "trace_transaction", fake_trace)
    return ddc.find_dynamic_dependencies(target, tx_limit=5)


def test_find_dynamic_dependencies_parity_parallel_vs_sequential(monkeypatch):
    """Parallel trace fan-out must produce the same dependencies, edges, and trace_errors as sequential."""
    seq = _trace_parity_helper(monkeypatch, "1")
    par = _trace_parity_helper(monkeypatch, "10")

    # Dependencies are sorted in find_dynamic_dependencies output, so an
    # exact equality check is the right assertion here.
    assert seq["dependencies"] == par["dependencies"]
    # trace_errors is appended in input order in both modes; check exact equality.
    assert seq["trace_errors"] == par["trace_errors"]
    # dependency_graph is built via _build_graph which sorts keys, so equality
    # is meaningful.
    assert seq["dependency_graph"] == par["dependency_graph"]
    assert seq["transactions_analyzed"] == par["transactions_analyzed"]
