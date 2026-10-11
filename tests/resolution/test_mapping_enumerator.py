from __future__ import annotations

import asyncio
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any, cast

import pytest

from services.resolution import mapping_enumerator
from services.resolution.mapping_enumerator import (
    _decode_address_arg_from_data,
    _decode_address_topic,
    _event_topic0,
    clear_enumeration_cache,
    enumerate_mapping_allowlist_sync,
)
from services.resolution.mapping_enumerator import (
    enumerate_mapping_allowlist as _enumerate,
)
from tests.support.hypersync_fakes import _FakeHypersyncModule


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    # These cover L1 only, so they don't need a live DB.
    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "0")
    clear_enumeration_cache()
    yield
    clear_enumeration_cache()


def enumerate_mapping_allowlist(contract_address, writer_specs, **kwargs):
    kwargs.setdefault("from_block", 0)
    result = _enumerate(contract_address, cast(Any, writer_specs), **kwargs)

    async def _run():
        r = await result
        return r["principals"]

    if asyncio.iscoroutine(result):
        return _run()
    return result["principals"]


def _addr(hex_suffix: str) -> str:
    return "0x" + hex_suffix.lower().rjust(40, "0")


def _indexed_topic(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _uint_topic(value: int) -> str:
    return "0x" + f"{value:064x}"


def _address_data(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _log(topic0: str, indexed_args: list[str] | None = None, data: str = "0x", block: int = 1):
    topics = [topic0] + [_indexed_topic(a) for a in (indexed_args or [])]
    return SimpleNamespace(
        topics=topics,
        data=data,
        block_number=block,
        transaction_hash="0x" + "f" * 64,
        log_index=0,
    )


def _fake_client(batches: Sequence[tuple[Sequence[Any], int | None]]):
    calls: dict[str, int] = {"n": 0}

    class _Client:
        async def get(self, _query):
            i = calls["n"]
            calls["n"] += 1
            if i >= len(batches):
                return SimpleNamespace(data=[], next_block=None)
            logs, next_block = batches[i]
            return SimpleNamespace(data=logs, next_block=next_block)

    return _Client(), calls


def _run(coroutine):
    return asyncio.run(coroutine)


# The pinned block a complete scan must read through.
_PIN = 30_000_000
_ALICE_WORD = "0x" + _addr("aa11")[2:].rjust(64, "0")
_BOB_WORD = _addr("bb22")[2:].rjust(64, "0")


@pytest.mark.parametrize(
    ("decode", "args", "expected"),
    [
        pytest.param(
            _decode_address_topic, (_indexed_topic(_addr("dead1234")),), _addr("dead1234"), id="topic-strips-padding"
        ),
        pytest.param(_decode_address_topic, ("0xdead",), "", id="topic-rejects-wrong-length"),
        pytest.param(_decode_address_arg_from_data, (_ALICE_WORD, 0), _addr("aa11"), id="data-position-0"),
        pytest.param(_decode_address_arg_from_data, (_ALICE_WORD + _BOB_WORD, 1), _addr("bb22"), id="data-position-1"),
    ],
)
def test_address_decoders(decode, args, expected):
    assert decode(*args) == expected


def _rely_spec():
    return {
        "mapping_name": "wards",
        "event_signature": "Rely(address)",
        "event_name": "Rely",
        "key_position": 0,
        "indexed_positions": [0],
        "direction": "add",
        "writer_function": "rely(address)",
    }


def _deny_spec():
    return {
        "mapping_name": "wards",
        "event_signature": "Deny(address)",
        "event_name": "Deny",
        "key_position": 0,
        "indexed_positions": [0],
        "direction": "remove",
        "writer_function": "deny(address)",
    }


ALICE = _addr("a11ce")
BOB = _addr("b0b")


@pytest.mark.parametrize(
    ("specs", "events", "expected"),
    [
        pytest.param((_rely_spec,), [("Rely", ALICE, 10)], [(ALICE, ["add"], 10)], id="single-add"),
        pytest.param(
            (_rely_spec, _deny_spec),
            [("Rely", ALICE, 10), ("Deny", ALICE, 20)],
            [],
            id="add-then-remove-leaves-empty",
        ),
        pytest.param(
            (_rely_spec, _deny_spec),
            [("Rely", ALICE, 10), ("Deny", ALICE, 20), ("Rely", ALICE, 30)],
            [(ALICE, ["add", "remove", "add"], 30)],
            id="add-remove-add-ends-present",
        ),
        pytest.param(
            (_rely_spec,),
            [("Rely", ALICE, 10), ("Rely", BOB, 11)],
            [(ALICE, ["add"], 10), (BOB, ["add"], 11)],
            id="multiple-principals-independent",
        ),
    ],
)
def test_event_fold_semantics(specs, events, expected):
    topics = {"Rely": _event_topic0("Rely(address)"), "Deny": _event_topic0("Deny(address)")}
    client, _ = _fake_client(
        [([_log(topics[name], indexed_args=[who], block=block) for name, who, block in events], None)]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [spec() for spec in specs],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert sorted((p["address"], p["direction_history"], p["last_seen_block"]) for p in out) == sorted(expected)


def test_conflicting_directions_for_same_event_topic_are_rejected():
    topic = _event_topic0("WhitelistSet(address,bool)")
    alice = _addr("a11ce")
    client, calls = _fake_client([([_log(topic, data=_address_data(alice), block=10)], None)])
    add_spec = {
        "mapping_name": "whitelist",
        "event_signature": "WhitelistSet(address,bool)",
        "event_name": "WhitelistSet",
        "key_position": 0,
        "indexed_positions": [],
        "direction": "add",
        "writer_function": "setWhitelisted(address,bool)",
    }
    remove_spec = {
        **add_spec,
        "direction": "remove",
        "writer_function": "unsetWhitelisted(address,bool)",
    }
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [add_spec, remove_spec],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert out == []
    assert calls["n"] == 0


def test_non_indexed_key_decodes_from_data_slot():
    topic = _event_topic0("SetAuthorized(address)")
    alice = _addr("a11ce")
    client, _ = _fake_client([([_log(topic, data=_address_data(alice), block=10)], None)])
    spec = {
        "mapping_name": "authorized",
        "event_signature": "SetAuthorized(address)",
        "event_name": "SetAuthorized",
        "key_position": 0,
        "indexed_positions": [],
        "direction": "add",
        "writer_function": "setAuthorized(address)",
    }
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [spec],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert [p["address"] for p in out] == [alice]


def _malformed_topic_log(rely_topic, _alice):
    return SimpleNamespace(
        topics=[rely_topic, "0xdead"],
        data="0x",
        block_number=10,
        transaction_hash="0x" + "f" * 64,
        log_index=0,
    )


@pytest.mark.parametrize(
    "make_noise_log",
    [
        pytest.param(
            lambda rely_topic, alice: _log(_event_topic0("Unrelated(uint256)"), indexed_args=[alice], block=5),
            id="unknown-topic",
        ),
        pytest.param(_malformed_topic_log, id="malformed-address-topic"),
    ],
)
def test_unusable_logs_are_skipped(make_noise_log):
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    good_log = _log(rely_topic, indexed_args=[alice], block=11)
    client, _ = _fake_client([([make_noise_log(rely_topic, alice), good_log], None)])
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert [p["address"] for p in out] == [alice]


# Unbounded pagination blocked the worker for up to 80 minutes on 2017 contracts; truncation must surface via ``status``
# since an old Rely with no later Deny still authorizes.


def test_max_pages_bound_returns_incomplete_status():
    rely_topic = _event_topic0("Rely(address)")
    pages = [([_log(rely_topic, indexed_args=[_addr(f"{i:040x}")], block=10 + i)], 100 + i) for i in range(5)]
    client, _ = _fake_client(pages)
    result = _run(
        _enumerate(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, [_rely_spec()]),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
            timeout_s=10,
            max_pages=2,
        )
    )
    assert result["status"] == "incomplete_max_pages"
    assert result["pages_fetched"] == 2
    assert len(result["principals"]) == 2


def test_rpc_error_surfaces_status_not_silent_fallback():
    """The old caller silently dropped principals on error."""
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")

    class _BoomClient:
        calls = 0

        async def get(self, _query):
            type(self).calls += 1
            if type(self).calls == 1:
                return SimpleNamespace(data=[_log(rely_topic, indexed_args=[alice], block=100)], next_block=200)
            raise RuntimeError("hypersync 503")

    result = _run(
        _enumerate(
            "0x" + "33" * 20,
            cast(Any, [_rely_spec()]),
            from_block=0,
            client=_BoomClient(),
            hypersync_module=_FakeHypersyncModule(),
            timeout_s=10,
            max_pages=10,
        )
    )
    assert result["status"] == "error"
    assert result["error"] == "hypersync 503"
    assert result["pages_fetched"] == 1
    # The caller must not conclude "no admins".
    assert [p["address"] for p in result["principals"]] == [alice]


def test_sync_wrapper_caches_results():
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    pages = [([_log(rely_topic, indexed_args=[alice], block=10)], _PIN + 1)]
    client, calls = _fake_client(pages)

    result1 = enumerate_mapping_allowlist_sync(
        "0x" + "AA" * 20,
        cast(Any, [_rely_spec()]),
        from_block=0,
        to_block=_PIN,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
        timeout_s=10,
        max_pages=10,
    )
    assert result1["status"] == "complete"
    calls_after_first = calls["n"]
    assert calls_after_first >= 1

    result2 = enumerate_mapping_allowlist_sync(
        "0x" + "AA" * 20,
        cast(Any, [_rely_spec()]),
        from_block=0,
        to_block=_PIN,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert result2["status"] == "complete"
    assert result2["principals"] == result1["principals"]
    assert calls["n"] == calls_after_first  # no additional calls


def _owner_set_spec() -> dict[str, Any]:
    return {
        "mapping_name": "owners",
        "event_signature": "OwnerSet(address,uint256)",
        "event_name": "OwnerSet",
        "key_position": 0,
        "value_position": 1,
        "indexed_positions": [0],
        "direction": "set",
        "writer_function": "setOwner(address,uint256)",
    }


def _set_log(topic0: str, key_addr: str, value: int, *, block: int, log_index: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        topics=[topic0, _indexed_topic(key_addr)],
        data=_uint_topic(value),  # 32-byte word in data
        block_number=block,
        transaction_hash="0x" + "f" * 64,
        log_index=log_index,
    )


def test_value_predicate_eq_filters_to_matching_keys():
    from services.resolution.mapping_enumerator import (
        enumerate_mapping_values,
        filter_value_entries,
    )

    topic0 = _event_topic0("OwnerSet(address,uint256)")
    a = _addr("a11ce")
    b = _addr("b0b")
    client, _ = _fake_client(
        [
            (
                [
                    _set_log(topic0, a, 10, block=100, log_index=0),
                    _set_log(topic0, b, 7, block=100, log_index=1),
                ],
                _PIN + 1,
            )
        ]
    )
    result = _run(
        enumerate_mapping_values(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, [_owner_set_spec()]),
            from_block=0,
            to_block=_PIN,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["status"] == "complete"
    assert len(result["entries"]) == 2

    matched = filter_value_entries(
        result["entries"],
        {"op": "eq", "rhs_values": ["10"], "value_type": "uint256"},
    )
    assert matched == [a.lower()]


def test_value_predicate_passes_op_handles_addresses_and_any_nonzero():
    from services.resolution.mapping_enumerator import _value_predicate_passes

    addr_word = "0x" + "00" * 12 + "deadbeef".rjust(40, "0")
    assert _value_predicate_passes(
        addr_word,
        {"op": "eq", "rhs_values": ["0x" + "deadbeef".rjust(40, "0")], "value_type": "address"},
    )
    assert not _value_predicate_passes(
        addr_word,
        {"op": "eq", "rhs_values": ["0x" + "00" * 20], "value_type": "address"},
    )

    one_word = "0x" + "01".rjust(64, "0")
    zero_word = "0x" + "0" * 64
    assert _value_predicate_passes(one_word, {"op": "any_nonzero", "rhs_values": [], "value_type": "uint256"})
    assert not _value_predicate_passes(zero_word, {"op": "any_nonzero", "rhs_values": [], "value_type": "uint256"})


# MasterMinter ``onlyController``: ``controllers[msg.sender] != address(0)`` stores the rhs as decimal ``"0"``.
_CONTROLLER_PREDICATE = {"op": "ne", "rhs_values": ["0"], "value_type": "address"}
_WORKER_WORD = "0x0000000000000000000000005b6122c109b78c6755486966148c1d70a50a47d7"
_ZERO = "0x" + "0" * 64


def _entry(key: str, value_hex: str) -> Any:
    return {"key": key, "mapping_name": "controllers", "value_hex": value_hex, "last_block": 1, "last_log_index": 0}


def test_address_predicate_with_decimal_zero_rhs_keeps_nonzero_workers():
    from services.resolution.mapping_enumerator import _value_predicate_passes, filter_value_entries

    assert _value_predicate_passes(_WORKER_WORD, _CONTROLLER_PREDICATE) is True
    assert _value_predicate_passes(_ZERO, _CONTROLLER_PREDICATE) is False
    live, removed = _addr("79e0946e1c186e745f1352d7c21ab04700c99f71"), _addr("961708aa6bc3b79dff302f3f1525ed1bebc6f35b")
    assert filter_value_entries([_entry(live, _WORKER_WORD), _entry(removed, _ZERO)], _CONTROLLER_PREDICATE) == [live]


@pytest.mark.parametrize(
    "predicate",
    [
        pytest.param({"op": "ne", "rhs_values": ["CONTROLLER_NONE"], "value_type": "address"}, id="named_constant"),
        pytest.param({"op": "eq", "rhs_values": ["keccak256(MINTER)"], "value_type": "bytes32"}, id="expression"),
        pytest.param({"op": "eq", "rhs_values": [], "value_type": "uint256"}, id="no_rhs"),
        pytest.param({"op": "in", "rhs_values": ["1", "TWO"], "value_type": "uint256"}, id="in_partly_unparseable"),
        pytest.param({"op": "eq", "rhs_values": ["1"], "value_type": "uint256", "mask": "FLAG"}, id="mask"),
        pytest.param({"op": "between", "rhs_values": ["1"], "value_type": "uint256"}, id="unknown_op"),
        pytest.param({"op": "eq", "rhs_values": ["1"], "value_type": "string"}, id="dynamic_type"),
        pytest.param({"op": "eq", "rhs_values": ["0x12345678"], "value_type": "bytes4"}, id="left_aligned_bytes4"),
    ],
)
def test_unevaluable_predicate_is_not_determined_never_empty(predicate):
    from services.resolution.mapping_enumerator import filter_value_entries

    assert filter_value_entries([], predicate) is None
    assert filter_value_entries([_entry(_addr("a11ce"), _WORKER_WORD)], predicate) is None


@pytest.mark.parametrize(
    "predicate",
    [
        pytest.param({"op": "eq", "rhs_values": ["0"], "value_type": "uint256"}, id="eq_zero"),
        pytest.param({"op": "lt", "rhs_values": ["10"], "value_type": "uint256"}, id="below_threshold"),
        pytest.param({"op": "in", "rhs_values": ["0", "1"], "value_type": "uint256"}, id="in_with_zero"),
    ],
)
def test_predicate_admitting_unwritten_keys_has_no_finite_answer(predicate):
    from services.resolution.mapping_enumerator import filter_value_entries

    assert filter_value_entries([_entry(_addr("a11ce"), "0x" + "05".rjust(64, "0"))], predicate) is None


def test_value_predicate_reads_bools_signed_ints_and_masks():
    from services.resolution.mapping_enumerator import _value_predicate_passes

    one = "0x" + "1".rjust(64, "0")
    minus_one = "0x" + "f" * 64
    assert _value_predicate_passes(one, {"op": "eq", "rhs_values": ["True"], "value_type": "bool"}) is True
    assert _value_predicate_passes(one, {"op": "eq", "rhs_values": ["False"], "value_type": "bool"}) is False
    assert _value_predicate_passes(minus_one, {"op": "lt", "rhs_values": ["0"], "value_type": "int256"}) is True
    assert _value_predicate_passes(minus_one, {"op": "lt", "rhs_values": ["0"], "value_type": "uint256"}) is False
    flagged = "0x" + "6".rjust(64, "0")
    assert _value_predicate_passes(flagged, {"op": "eq", "rhs_values": ["2"], "value_type": "uint256", "mask": "0x2"})
    assert _value_predicate_passes("0x12", {"op": "any_nonzero", "rhs_values": [], "value_type": "uint256"}) is None


_CONFIGURED_SIG = "ControllerConfigured(address,address)"
_REMOVED_SIG = "ControllerRemoved(address)"


def _controller_specs() -> list[dict[str, Any]]:
    return [
        {
            "mapping_name": "controllers",
            "event_signature": _CONFIGURED_SIG,
            "event_name": "ControllerConfigured",
            "key_position": 0,
            "indexed_positions": [0, 1],
            "direction": "set",
            "writer_function": "configureController(address,address)",
            "value_position": 1,
        },
        {
            "mapping_name": "controllers",
            "event_signature": _REMOVED_SIG,
            "event_name": "ControllerRemoved",
            "key_position": 0,
            "indexed_positions": [0],
            "direction": "remove",
            "writer_function": "removeController(address)",
            "value_position": None,
        },
    ]


def _controller_log(topic0: str, args: list[str], *, block: int, log_index: int) -> SimpleNamespace:
    return SimpleNamespace(
        topics=[topic0] + [_indexed_topic(a) for a in args],
        data="0x",
        block_number=block,
        transaction_hash="0x" + "f" * 64,
        log_index=log_index,
    )


def test_live_value_fold_replays_removals_as_zero():
    from services.resolution.mapping_enumerator import enumerate_mapping_values, filter_value_entries

    configured, removed = _event_topic0(_CONFIGURED_SIG), _event_topic0(_REMOVED_SIG)
    kept = _addr("79e0946e1c186e745f1352d7c21ab04700c99f71")
    dropped = _addr("961708aa6bc3b79dff302f3f1525ed1bebc6f35b")
    logs = [
        _controller_log(
            configured, [kept, _addr("5b6122c109b78c6755486966148c1d70a50a47d7")], block=7933088, log_index=0
        ),
        _controller_log(
            configured, [dropped, _addr("a1e2481a9cd0cb0447eeb1cbc26f1b3fff3bec20")], block=22427099, log_index=0
        ),
        _controller_log(removed, [dropped], block=22427216, log_index=0),
    ]
    client, _ = _fake_client([(logs, _PIN + 1)])
    result = _run(
        enumerate_mapping_values(
            "0xe982615d461dd5cd06575bbea87624fda4e3de17",
            cast(Any, _controller_specs()),
            from_block=0,
            to_block=_PIN,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["status"] == "complete"
    assert filter_value_entries(result["entries"], _CONTROLLER_PREDICATE) == [kept]


def test_bytes32_value_compares_as_its_full_word():
    from services.resolution.mapping_enumerator import _value_predicate_passes

    word = "0x" + "12345678" + "0" * 56
    assert _value_predicate_passes(word, {"op": "eq", "rhs_values": [word], "value_type": "bytes32"}) is True


def test_live_value_fold_takes_a_removal_and_a_set_reading_the_same_word_as_one_reading():
    # ``st[k] = uint8(0); emit StSet(k, 0)`` beside ``st[k] = v; emit StSet(k, v)``: both read the event's value word.
    from services.resolution.mapping_enumerator import enumerate_mapping_values, filter_value_entries

    configured = _event_topic0(_CONFIGURED_SIG)
    specs = [_controller_specs()[0], {**_controller_specs()[0], "direction": "remove"}]
    kept, dropped = _addr("79e0946e1c186e745f1352d7c21ab04700c99f71"), _addr("961708aa6bc3b79dff302f3f1525ed1bebc6f35b")
    logs = [
        _controller_log(configured, [kept, _addr("5b6122c109b78c6755486966148c1d70a50a47d7")], block=1, log_index=0),
        _controller_log(configured, [dropped, _addr("a1e2481a9cd0cb0447eeb1cbc26f1b3fff3bec20")], block=2, log_index=0),
        _controller_log(configured, [dropped, "0x" + "0" * 40], block=3, log_index=0),
    ]
    client, _ = _fake_client([(logs, _PIN + 1)])
    result = _run(
        enumerate_mapping_values(
            "0xe982615d461dd5cd06575bbea87624fda4e3de17",
            cast(Any, specs),
            from_block=0,
            to_block=_PIN,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["status"] == "complete"
    assert filter_value_entries(result["entries"], _CONTROLLER_PREDICATE) == [kept]


def test_live_value_fold_refuses_two_readings_of_one_event():
    from services.resolution.mapping_enumerator import enumerate_mapping_values

    specs = [_controller_specs()[0], {**_controller_specs()[0], "direction": "remove", "value_position": None}]
    client, calls = _fake_client([([], None)])
    result = _run(
        enumerate_mapping_values(
            "0xe982615d461dd5cd06575bbea87624fda4e3de17",
            cast(Any, specs),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["status"] == "incomplete_ambiguous_writer_event"
    assert calls["n"] == 0


def test_live_value_fold_refuses_a_writer_whose_value_it_cannot_read():
    from services.resolution.mapping_enumerator import enumerate_mapping_values

    specs = _controller_specs()
    specs[1]["direction"] = "set"  # the pre-fix hint shape: value written but not in the event
    client, calls = _fake_client([([], None)])
    result = _run(
        enumerate_mapping_values(
            "0xe982615d461dd5cd06575bbea87624fda4e3de17",
            cast(Any, specs),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["status"] == "incomplete_unfoldable_writer_event"
    assert calls["n"] == 0


def test_live_value_fold_marks_an_undecodable_log_incomplete():
    from services.resolution.mapping_enumerator import enumerate_mapping_values

    configured = _event_topic0(_CONFIGURED_SIG)
    truncated = _controller_log(configured, [_addr("79e0946e1c186e745f1352d7c21ab04700c99f71")], block=1, log_index=0)
    client, _ = _fake_client([([truncated], None)])
    result = _run(
        enumerate_mapping_values(
            "0xe982615d461dd5cd06575bbea87624fda4e3de17",
            cast(Any, _controller_specs()[:1]),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["status"] == "incomplete_undecodable_event"


# The old address-only L1 key collided across chains and specs; a same-chain same-specs repeat must still hit.


def test_l1_enumeration_cache_size_capped(monkeypatch):
    """The present-set L1 cache is size-capped — many distinct addresses evict the
    oldest rather than growing unbounded (the lazy per-key TTL del is not a size bound)."""
    monkeypatch.setattr(mapping_enumerator, "_CACHE_MAX", 8)
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    for i in range(40):
        client, _ = _fake_client([([_log(rely_topic, indexed_args=[alice], block=10)], None)])
        enumerate_mapping_allowlist_sync(
            "0x" + f"{i:040x}",
            cast(Any, [_rely_spec()]),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    assert len(mapping_enumerator._CACHE) <= 8


def test_value_cache_rekey_ignores_predicate():
    """Cached entries are predicate-independent."""
    from services.resolution.mapping_enumerator import enumerate_mapping_values_sync

    topic0 = _event_topic0("OwnerSet(address,uint256)")
    a = _addr("a11ce")
    addr = "0x" + "DD" * 20
    client, calls = _fake_client([([_set_log(topic0, a, 10, block=100, log_index=0)], None)])
    r1 = enumerate_mapping_values_sync(
        addr,
        cast(Any, [_owner_set_spec()]),
        from_block=0,
        value_predicate={"op": "eq", "rhs_values": ["10"], "value_type": "uint256"},
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    n_after_first = calls["n"]
    assert n_after_first >= 1
    r2 = enumerate_mapping_values_sync(
        addr,
        cast(Any, [_owner_set_spec()]),
        from_block=0,
        value_predicate={"op": "eq", "rhs_values": ["999"], "value_type": "uint256"},
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert calls["n"] == n_after_first  # HIT despite different predicate
    assert r2["entries"] == r1["entries"]


def _conflicted_specs():
    add_spec = {
        "mapping_name": "whitelist",
        "event_signature": "WhitelistSet(address,bool)",
        "event_name": "WhitelistSet",
        "key_position": 0,
        "indexed_positions": [],
        "direction": "add",
        "writer_function": "setWhitelisted(address,bool)",
    }
    return [add_spec, {**add_spec, "direction": "remove", "writer_function": "unsetWhitelisted(address,bool)"}]


def test_partially_ambiguous_scan_still_folds_clean_topics_but_not_complete():
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    client, _ = _fake_client([([_log(rely_topic, indexed_args=[alice], block=5)], None)])
    specs = _conflicted_specs() + [
        {
            "mapping_name": "wards",
            "event_signature": "Rely(address)",
            "event_name": "Rely",
            "key_position": 0,
            "indexed_positions": [0],
            "direction": "add",
            "writer_function": "rely(address)",
        }
    ]
    result = _run(
        _enumerate(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, specs),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert [p["address"] for p in result["principals"]] == [alice]
    assert result["status"] == "incomplete_ambiguous_writer_event"


def test_no_writer_specs_reports_incomplete_not_complete():
    result = _run(
        _enumerate(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, []),
            from_block=0,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["principals"] == []
    assert result["status"] == "incomplete_no_writer_specs"


class _PagedClient:
    """Serves ``pages`` in order, repeating the last, and records each query's ``to_block``."""

    def __init__(self, pages: Sequence[tuple[Sequence[Any], Any]]) -> None:
        self.pages = list(pages)
        self.to_blocks: list[Any] = []

    async def get(self, query):
        self.to_blocks.append(query.to_block)
        logs, next_block = self.pages[min(len(self.to_blocks), len(self.pages)) - 1]
        return SimpleNamespace(data=list(logs), next_block=next_block)


_ALICE_RELY = [_log(_event_topic0("Rely(address)"), indexed_args=[ALICE], block=10)]


@pytest.mark.parametrize(
    ("pages", "to_block", "status"),
    [
        pytest.param([(_ALICE_RELY, 500), ([], _PIN + 1)], _PIN, "complete", id="reads-past-the-pin"),
        pytest.param([(_ALICE_RELY, _PIN)], _PIN, "incomplete_stalled", id="stops-at-the-pin"),
        pytest.param([(_ALICE_RELY, None)], _PIN, "incomplete_stalled", id="no-next-block"),
        pytest.param([(_ALICE_RELY, 0)], _PIN, "incomplete_stalled", id="next-block-not-advancing"),
        pytest.param([(_ALICE_RELY, None)], None, "incomplete_unpinned", id="unpinned"),
    ],
)
def test_a_scan_is_complete_only_once_hypersync_reads_past_its_block(pages, to_block, status):
    client = _PagedClient(pages)

    result = _run(
        _enumerate(
            "0x" + "aa" * 20,
            cast(Any, [_rely_spec()]),
            from_block=0,
            to_block=to_block,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )

    assert result["status"] == status
    # The members read so far stay, as a lower bound when the scan proves no end.
    assert [p["address"] for p in result["principals"]] == [ALICE]
    assert set(client.to_blocks) == {None if to_block is None else to_block + 1}
    if status == "complete":
        assert result["last_block_scanned"] == _PIN


@pytest.mark.parametrize(
    ("next_block", "status"), [(_PIN + 1, "complete"), (None, "incomplete_stalled"), (_PIN, "incomplete_stalled")]
)
def test_a_value_fold_is_complete_only_once_hypersync_reads_past_its_block(next_block, status):
    from services.resolution.mapping_enumerator import enumerate_mapping_values

    client = _PagedClient([([_set_log(_event_topic0("OwnerSet(address,uint256)"), ALICE, 10, block=100)], next_block)])

    result = _run(
        enumerate_mapping_values(
            "0x" + "cc" * 20,
            cast(Any, [_owner_set_spec()]),
            from_block=0,
            to_block=_PIN,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )

    assert result["status"] == status
    assert [e["key"] for e in result["entries"]] == [ALICE.lower()]
    assert set(client.to_blocks) == {_PIN + 1}
