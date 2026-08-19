from __future__ import annotations

from services.resolution.external_check_materializer import materialize_external_check_from_events


def test_materialize_external_check_probes_event_candidates(monkeypatch):
    import services.resolution.external_check_materializer as mod

    mod._CANDIDATE_CACHE.clear()
    member = "0x" + "aa" * 20
    non_member = "0x" + "bb" * 20

    monkeypatch.setattr(
        mod,
        "_candidate_addresses_from_events",
        lambda **_kwargs: [member, non_member],
    )
    monkeypatch.setattr(mod, "_candidate_addresses_from_hypersync", lambda **_kwargs: [])

    def fake_batch(_rpc_url, calls):
        assert len(calls) == 2
        return [
            ("0x" + "0" * 63 + "1", False),
            ("0x" + "0" * 64, False),
        ]

    monkeypatch.setattr(mod, "rpc_batch_request_with_status", fake_batch)

    cap = materialize_external_check_from_events(
        session=object(),  # pyright: ignore[reportArgumentType]
        rpc_url="http://rpc",
        chain_id=1,
        checker_address="0x" + "11" * 20,
        checker_selector="0xb7009613",
        call_args=[
            {"source": "root_caller"},
            {"source": "constant", "constant_value": "0x" + "22" * 20},
            {"source": "constant", "constant_value": "0x12345678"},
        ],
    )

    assert cap is not None
    assert cap.kind == "finite_set"
    assert cap.members == [member]
    assert cap.membership_quality == "lower_bound"
    assert cap.trace and cap.trace[0]["step"] == "external_check_materialized"


def test_materialize_external_check_multicall_parity(monkeypatch):
    """The Multicall3 candidate-probe path (PSAT_EXTERNAL_CHECK_MULTICALL) must select the same
    allowed set as the JSON-RPC-batch path. The checker takes the candidate as an explicit arg, so
    routing through Multicall3 (which becomes msg.sender) cannot change which candidates pass."""
    from eth_abi.abi import decode, encode

    import services.resolution.external_check_materializer as mod
    import utils.rpc as rpc_mod

    member = "0x" + "aa" * 20
    non_member = "0x" + "bb" * 20
    checker = "0x" + "11" * 20
    checker_selector = "0xb7009613"
    call_args = [
        {"source": "root_caller"},
        {"source": "constant", "constant_value": "0x" + "22" * 20},
        {"source": "constant", "constant_value": "0x12345678"},
    ]
    TRUE = "0x" + "0" * 63 + "1"
    FALSE = "0x" + "0" * 64

    monkeypatch.setattr(mod, "_candidate_addresses_from_events", lambda **_k: [member, non_member])
    monkeypatch.setattr(mod, "_candidate_addresses_from_hypersync", lambda **_k: [])

    # JSON-RPC-batch wire (OFF path): canCall(member) true, canCall(non_member) false, in order.
    def fake_batch(_rpc_url, calls):
        assert len(calls) == 2
        return [(TRUE, False), (FALSE, False)]

    monkeypatch.setattr(mod, "rpc_batch_request_with_status", fake_batch)

    # Multicall3 wire (ON path): decide by the candidate address embedded in each sub-call's calldata.
    def fake_multicall(_rpc_url, method, params, **_kw):
        assert method == "eth_call"
        assert params[0]["to"].lower() == rpc_mod.MULTICALL3_ADDRESS.lower()
        sub_calls = decode(["(address,bool,bytes)[]"], bytes.fromhex(params[0]["data"][10:]))[0]
        out = []
        for _tgt, _allow, calldata in sub_calls:
            is_member = ("aa" * 20) in "0x" + calldata.hex()
            out.append((True, bytes.fromhex((TRUE if is_member else FALSE)[2:])))
        return "0x" + encode(["(bool,bytes)[]"], [out]).hex()

    monkeypatch.setattr(rpc_mod, "rpc_request", fake_multicall)

    def _run():
        mod._CANDIDATE_CACHE.clear()
        return materialize_external_check_from_events(
            session=object(),  # pyright: ignore[reportArgumentType]
            rpc_url="http://rpc",
            chain_id=1,
            checker_address=checker,
            checker_selector=checker_selector,
            call_args=call_args,
        )

    monkeypatch.setattr(mod, "_EXTERNAL_CHECK_MULTICALL_ENABLED", False)
    off = _run()
    monkeypatch.setattr(mod, "_EXTERNAL_CHECK_MULTICALL_ENABLED", True)
    on = _run()

    assert off is not None and on is not None
    assert off.members == on.members == [member]
    assert off.membership_quality == on.membership_quality == "lower_bound"


def test_materialize_external_check_multicall_falls_back_to_batch(monkeypatch):
    """If the aggregate3 call raises, _eval_candidate_calls falls back to the JSON-RPC batch and
    selects the same set — enabling Multicall3 never degrades the result on a chain without it."""
    import services.resolution.external_check_materializer as mod
    import utils.rpc as rpc_mod

    member = "0x" + "aa" * 20
    monkeypatch.setattr(mod, "_candidate_addresses_from_events", lambda **_k: [member])
    monkeypatch.setattr(mod, "_candidate_addresses_from_hypersync", lambda **_k: [])
    monkeypatch.setattr(rpc_mod, "rpc_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no multicall")))
    monkeypatch.setattr(mod, "rpc_batch_request_with_status", lambda _u, _c: [("0x" + "0" * 63 + "1", False)])
    monkeypatch.setattr(mod, "_EXTERNAL_CHECK_MULTICALL_ENABLED", True)
    mod._CANDIDATE_CACHE.clear()

    cap = materialize_external_check_from_events(
        session=object(),  # pyright: ignore[reportArgumentType]
        rpc_url="http://rpc",
        chain_id=1,
        checker_address="0x" + "11" * 20,
        checker_selector="0xb7009613",
        call_args=[{"source": "root_caller"}],
    )
    assert cap is not None
    assert cap.members == [member]


def test_candidate_hypersync_scan_floors_from_block_at_creation_block(monkeypatch):
    """The candidate-enumeration HyperSync scan starts at the checker's creation
    block, not genesis: identical candidate set, no pre-deployment 429-storm."""
    import asyncio

    import hypersync

    import services.resolution.creation_block_floor as floor_mod
    import services.resolution.external_check_materializer as mod

    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 9_000_000)

    captured: dict = {}
    candidate = "0x" + "ab" * 20

    class _FakeResp:
        data = None
        logs = [type("L", (), {"topics": ["0x" + "00" * 32, "0x" + "00" * 12 + candidate[2:]], "data": "0x"})()]
        next_block = None

    class _FakeClient:
        def __init__(self, *_a, **_k):
            pass

        async def get(self, query):
            captured["from_block"] = getattr(query, "from_block", None)
            return _FakeResp()

    monkeypatch.setattr(hypersync, "HypersyncClient", _FakeClient)

    out = asyncio.run(
        mod._candidate_addresses_from_hypersync_async(checker_address="0x" + "11" * 20, limit=8, chain_id=1)
    )

    assert captured["from_block"] == 9_000_000 - 1
    assert candidate in out


def test_candidate_cache_caps_entry_count(monkeypatch):
    """P1.4: the per-checker candidate cache caps the NUMBER of entries (the existing
    _MAX_CANDIDATES caps each value list's length, not the entry count), so a long-lived
    worker probing many distinct checkers stays bounded."""
    import services.resolution.external_check_materializer as mod

    mod.clear_candidate_cache()
    monkeypatch.setattr(mod, "_EXTERNAL_CHECK_MULTICALL_ENABLED", False)
    monkeypatch.setattr(mod, "_CANDIDATE_CACHE_MAX", 8)
    monkeypatch.setattr(mod, "_candidate_addresses_from_events", lambda **_k: ["0x" + "aa" * 20])
    monkeypatch.setattr(mod, "_candidate_addresses_from_hypersync", lambda **_k: [])
    monkeypatch.setattr(mod, "rpc_batch_request_with_status", lambda _u, _c: [("0x" + "0" * 63 + "1", False)])

    for i in range(40):
        materialize_external_check_from_events(
            session=object(),  # pyright: ignore[reportArgumentType]
            rpc_url="http://rpc",
            chain_id=i,  # distinct checker key per call
            checker_address="0x" + "11" * 20,
            checker_selector="0xb7009613",
            call_args=[{"source": "root_caller"}],
        )
    assert len(mod._CANDIDATE_CACHE) <= 8


def test_clear_candidate_cache_empties_and_resets(monkeypatch):
    import services.resolution.external_check_materializer as mod

    monkeypatch.setattr(mod, "_EXTERNAL_CHECK_MULTICALL_ENABLED", False)
    monkeypatch.setattr(mod, "_candidate_addresses_from_events", lambda **_k: ["0x" + "aa" * 20])
    monkeypatch.setattr(mod, "_candidate_addresses_from_hypersync", lambda **_k: [])
    monkeypatch.setattr(mod, "rpc_batch_request_with_status", lambda _u, _c: [("0x" + "0" * 63 + "1", False)])
    materialize_external_check_from_events(
        session=object(),  # pyright: ignore[reportArgumentType]
        rpc_url="http://rpc",
        chain_id=1,
        checker_address="0x" + "11" * 20,
        checker_selector="0xb7009613",
        call_args=[{"source": "root_caller"}],
    )
    assert mod._CANDIDATE_CACHE
    mod.clear_candidate_cache()
    assert not mod._CANDIDATE_CACHE
