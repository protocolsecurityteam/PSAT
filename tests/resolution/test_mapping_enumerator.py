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


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    # Tests in this file exercise the in-process L1 cache only; the L2
    # (Postgres-backed) cache lives in db.mapping_enumeration_cache and
    # has its own test file. Disable L2 here so these tests don't depend
    # on a live DB connection or the migrated mapping_enumeration_cache
    # table being present.
    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "0")
    clear_enumeration_cache()
    yield
    clear_enumeration_cache()


def enumerate_mapping_allowlist(contract_address, writer_specs, **kwargs):
    """Test helper. The function now returns an EnumerationResult dict;
    legacy tests below expect the bare principal list, so this helper
    unwraps result["principals"] to keep the legacy tests focused on
    the per-event semantics they were written for.

    ``from_block`` is now a required enumerator arg; these per-event unit
    tests replay over the full stub-log range, so default it to genesis here."""
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


class _FakeFieldEnumMeta(type):
    _members = ("address", "topic0", "data", "block_number")

    def __iter__(cls):
        for name in cls._members:
            yield cls(name)


class _FakeFieldEnum(metaclass=_FakeFieldEnumMeta):
    def __init__(self, name: str):
        self.value = name


class _FakeHypersyncModule:
    Query = SimpleNamespace
    LogSelection = SimpleNamespace
    FieldSelection = SimpleNamespace
    LogField = _FakeFieldEnum


def _run(coroutine):
    return asyncio.run(coroutine)


def test_event_topic0_hashes_canonical_signature():
    expected = "0xdd0e34038ac38b2a1ce960229778ac48a8719bc900b6c4f8d0475c6e8b385a60"
    assert _event_topic0("Rely(address)") == expected


def test_decode_address_topic_strips_padding():
    padded = _indexed_topic(_addr("dead1234"))
    assert _decode_address_topic(padded) == _addr("dead1234")


def test_decode_address_topic_rejects_wrong_length():
    assert _decode_address_topic("0xdead") == ""


def test_decode_address_arg_from_data_position_0():
    a = _addr("aa11")
    padded = "0x" + a[2:].rjust(64, "0")
    assert _decode_address_arg_from_data(padded, 0) == a


def test_decode_address_arg_from_data_position_1():
    a = _addr("aa11")
    b = _addr("bb22")
    data = "0x" + a[2:].rjust(64, "0") + b[2:].rjust(64, "0")
    assert _decode_address_arg_from_data(data, 1) == b


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


def test_single_add_appears_in_output():
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    client, _ = _fake_client(
        [
            ([_log(rely_topic, indexed_args=[alice], block=10)], None),
        ]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    addresses = [p["address"] for p in out]
    assert addresses == [alice]
    assert out[0]["direction_history"] == ["add"]
    assert out[0]["last_seen_block"] == 10


def test_add_then_remove_leaves_empty():
    rely_topic = _event_topic0("Rely(address)")
    deny_topic = _event_topic0("Deny(address)")
    alice = _addr("a11ce")
    client, _ = _fake_client(
        [
            (
                [
                    _log(rely_topic, indexed_args=[alice], block=10),
                    _log(deny_topic, indexed_args=[alice], block=20),
                ],
                None,
            ),
        ]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec(), _deny_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert out == []


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


def test_add_remove_add_ends_present():
    rely_topic = _event_topic0("Rely(address)")
    deny_topic = _event_topic0("Deny(address)")
    alice = _addr("a11ce")
    client, _ = _fake_client(
        [
            (
                [
                    _log(rely_topic, indexed_args=[alice], block=10),
                    _log(deny_topic, indexed_args=[alice], block=20),
                    _log(rely_topic, indexed_args=[alice], block=30),
                ],
                None,
            ),
        ]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec(), _deny_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert [p["address"] for p in out] == [alice]
    assert out[0]["direction_history"] == ["add", "remove", "add"]
    assert out[0]["last_seen_block"] == 30


def test_multiple_principals_independent():
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    bob = _addr("b0b")
    client, _ = _fake_client(
        [
            (
                [
                    _log(rely_topic, indexed_args=[alice], block=10),
                    _log(rely_topic, indexed_args=[bob], block=11),
                ],
                None,
            ),
        ]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    addresses = sorted(p["address"] for p in out)
    assert addresses == sorted([alice, bob])


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


def test_indexed_argument_before_non_indexed_key_uses_data_slot_zero():
    topic = _event_topic0("Foo(uint256,address)")
    alice = _addr("a11ce")
    log = SimpleNamespace(
        topics=[topic, _uint_topic(42)],
        data=_address_data(alice),
        block_number=10,
        transaction_hash="0x" + "f" * 64,
        log_index=0,
    )
    client, _ = _fake_client([([log], None)])
    spec = {
        "mapping_name": "authorized",
        "event_signature": "Foo(uint256,address)",
        "event_name": "Foo",
        "key_position": 1,
        "indexed_positions": [0],
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


def test_empty_history_returns_empty():
    client, _ = _fake_client([])
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert out == []


def test_no_specs_returns_empty_without_client():
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [],
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert out == []


def test_pagination_via_next_block():
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    bob = _addr("b0b")
    carol = _addr("ca201")
    client, calls = _fake_client(
        [
            ([_log(rely_topic, indexed_args=[alice], block=10)], 11),
            ([_log(rely_topic, indexed_args=[bob], block=50)], 51),
            ([_log(rely_topic, indexed_args=[carol], block=99)], None),
        ]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    addresses = sorted(p["address"] for p in out)
    assert addresses == sorted([alice, bob, carol])
    assert calls["n"] == 3


def test_unknown_topic_ignored():
    rely_topic = _event_topic0("Rely(address)")
    other_topic = _event_topic0("Unrelated(uint256)")
    alice = _addr("a11ce")
    client, _ = _fake_client(
        [
            (
                [
                    _log(other_topic, indexed_args=[alice], block=5),
                    _log(rely_topic, indexed_args=[alice], block=10),
                ],
                None,
            ),
        ]
    )
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert [p["address"] for p in out] == [alice]


def test_malformed_address_topic_skipped():
    rely_topic = _event_topic0("Rely(address)")
    bad_log = SimpleNamespace(
        topics=[rely_topic, "0xdead"],
        data="0x",
        block_number=10,
        transaction_hash="0x" + "f" * 64,
        log_index=0,
    )
    alice = _addr("a11ce")
    good_log = _log(rely_topic, indexed_args=[alice], block=11)
    client, _ = _fake_client([([bad_log, good_log], None)])
    out = _run(
        enumerate_mapping_allowlist(
            "0xCC00000000000000000000000000000000000001",
            [_rely_spec()],
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert [p["address"] for p in out] == [alice]


# ---------------------------------------------------------------------------
# Bound + cache + status regression tests (PSAT-speedup #1).
#
# Background: the original `while True` pagination loop had no max_pages,
# no timeout, and no lookback bound. For 2017-deployed contracts
# (LinkToken etc.) that's ~190 pages × 25s = 80 min of sync work blocking
# the resolution worker — heartbeat misses, reclaim_stuck_jobs releases
# the row, live tests time out at 600s.
#
# Naive truncation that returns an empty list silently is a CORRECTNESS
# regression: a Rely(alice) in 2017 with no later Deny means alice is
# still authorized. These tests pin the bound + the requirement that
# truncation is surfaced via `result["status"]` rather than swallowed.
# ---------------------------------------------------------------------------


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
    # Bound hit at page 2; status surfaces it.
    assert result["status"] == "incomplete_max_pages"
    assert result["pages_fetched"] == 2
    # Partial principals returned — not silent empty.
    assert len(result["principals"]) == 2


def test_timeout_returns_incomplete_status():
    """Wall-clock bound: each page sleeps 0.05s, timeout is 0.12s, so
    we expect ~2 pages then a timeout (definitely <20)."""
    rely_topic = _event_topic0("Rely(address)")

    class _SlowClient:
        def __init__(self, n):
            self._n = n
            self.calls = 0

        async def get(self, _query):
            await asyncio.sleep(0.05)
            self.calls += 1
            if self.calls > self._n:
                return SimpleNamespace(data=[], next_block=None)
            return SimpleNamespace(
                data=[_log(rely_topic, indexed_args=[_addr(f"{self.calls:040x}")], block=10)],
                next_block=100 + self.calls,
            )

    result = _run(
        _enumerate(
            "0x" + "22" * 20,
            cast(Any, [_rely_spec()]),
            from_block=0,
            client=_SlowClient(20),
            hypersync_module=_FakeHypersyncModule(),
            timeout_s=0.12,
            max_pages=100,
        )
    )
    assert result["status"] == "incomplete_timeout"
    assert result["pages_fetched"] >= 1
    assert result["pages_fetched"] < 20  # bound stopped us well before n=20
    # Partial principals — not silent empty.
    assert len(result["principals"]) >= 1


def test_rpc_error_surfaces_status_not_silent_fallback():
    """The original recursive.py caller had `except Exception:
    enumerated = []` which silently dropped principals. Now an
    underlying RPC error must surface as status='error' with whatever
    partial data was already collected."""
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
    # Page 1 principal still surfaced — caller must NOT see an empty list
    # and conclude "no admins".
    assert [p["address"] for p in result["principals"]] == [alice]


def test_complete_result_carries_status_complete():
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    client, _ = _fake_client([([_log(rely_topic, indexed_args=[alice], block=10)], None)])
    result = _run(
        _enumerate(
            "0x" + "44" * 20,
            cast(Any, [_rely_spec()]),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
            timeout_s=10,
            max_pages=10,
        )
    )
    assert result["status"] == "complete"
    assert result["error"] is None
    assert len(result["principals"]) == 1


def test_sync_wrapper_caches_results():
    """Sibling cascade jobs enumerating the same contract within the TTL
    must share results without re-running the pagination loop."""
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    pages = [([_log(rely_topic, indexed_args=[alice], block=10)], None)]
    client, calls = _fake_client(pages)

    result1 = enumerate_mapping_allowlist_sync(
        "0x" + "AA" * 20,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
        timeout_s=10,
        max_pages=10,
    )
    assert result1["status"] == "complete"
    calls_after_first = calls["n"]
    assert calls_after_first >= 1

    # Second call — cache hit, no new client.get invocations.
    result2 = enumerate_mapping_allowlist_sync(
        "0x" + "AA" * 20,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert result2["status"] == "complete"
    assert result2["principals"] == result1["principals"]
    assert calls["n"] == calls_after_first  # no additional calls


def test_clear_enumeration_cache_drops_entries():
    rely_topic = _event_topic0("Rely(address)")
    client, _ = _fake_client([([_log(rely_topic, indexed_args=[_addr("aa")], block=10)], None)])
    enumerate_mapping_allowlist_sync(
        "0x" + "BB" * 20,
        cast(Any, [_rely_spec()]),
        from_block=0,
        client=client,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert mapping_enumerator._CACHE  # populated
    clear_enumeration_cache()
    assert not mapping_enumerator._CACHE


# ---------------------------------------------------------------------------
# D.2 — value-aware fold (latest-value-per-key, filter by ValuePredicate)
# ---------------------------------------------------------------------------


def _owner_set_spec() -> dict[str, Any]:
    """``OwnerSet(address indexed key, uint256 value)``.
    key_position=0, value_position=1, only key is indexed.
    """
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
    """``OwnerSet(addr indexed, uint256)`` — key is topic1, value lives in data."""
    return SimpleNamespace(
        topics=[topic0, _indexed_topic(key_addr)],
        data=_uint_topic(value),  # 32-byte word in data
        block_number=block,
        transaction_hash="0x" + "f" * 64,
        log_index=log_index,
    )


def test_value_predicate_eq_filters_to_matching_keys():
    """``OwnerSet(a, 10), OwnerSet(b, 7)`` → predicate ``eq 10`` returns ``[a]``.

    Validates the core D.2 fold: latest-value-per-key, then filter by
    op + rhs_values.
    """
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
                None,
            )
        ]
    )
    result = _run(
        enumerate_mapping_values(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, [_owner_set_spec()]),
            from_block=0,
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


def test_value_predicate_latest_value_wins_over_older_assignment():
    """``OwnerSet(a, 10)`` then ``OwnerSet(a, 5)`` — only the second
    value participates in filtering. ``eq 10`` returns empty.
    """
    from services.resolution.mapping_enumerator import (
        enumerate_mapping_values,
        filter_value_entries,
    )

    topic0 = _event_topic0("OwnerSet(address,uint256)")
    a = _addr("a11ce")
    client, _ = _fake_client(
        [
            (
                [
                    _set_log(topic0, a, 10, block=100, log_index=0),
                    _set_log(topic0, a, 5, block=110, log_index=0),
                ],
                None,
            )
        ]
    )
    result = _run(
        enumerate_mapping_values(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, [_owner_set_spec()]),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert filter_value_entries(result["entries"], {"op": "eq", "rhs_values": ["10"], "value_type": "uint256"}) == []
    # And 5 matches.
    assert filter_value_entries(result["entries"], {"op": "eq", "rhs_values": ["5"], "value_type": "uint256"}) == [
        a.lower()
    ]


def test_value_predicate_passes_op_handles_addresses_and_any_nonzero():
    """Cover the address compare path + ``any_nonzero``."""
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


# ---------------------------------------------------------------------------
# P1.3 — L1 re-key on (chain, address, specs_hash) + size cap.
#
# The old address-only L1 key collided across chains and writer-spec sets,
# defeating L2's careful (chain, address, specs_hash) keying. These pin the
# re-key (distinct specs/chain MISS) AND the parity requirement (the common
# single-chain/single-specs repeat must still HIT — no extra hypersync scan).
# The autouse _isolated_cache fixture sets DB cache OFF and clears L1/L2.
# ---------------------------------------------------------------------------


def test_l1_rekey_parity_same_chain_single_specs():
    """PARITY: a repeat with the same chain + specs must still HIT L1 (the re-key must
    not introduce a miss that re-pays the hypersync scan)."""
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    client, calls = _fake_client([([_log(rely_topic, indexed_args=[alice], block=10)], None)])
    addr = "0x" + "CC" * 20
    r1 = enumerate_mapping_allowlist_sync(
        addr, cast(Any, [_rely_spec()]), from_block=0, client=client, hypersync_module=_FakeHypersyncModule()
    )
    n_after_first = calls["n"]
    assert n_after_first >= 1
    r2 = enumerate_mapping_allowlist_sync(
        addr, cast(Any, [_rely_spec()]), from_block=0, client=client, hypersync_module=_FakeHypersyncModule()
    )
    assert calls["n"] == n_after_first  # HIT — no re-scan
    assert r2["principals"] == r1["principals"]


def test_l1_rekey_distinguishes_specs():
    """Two different writer-spec sets on the SAME address must not collide in L1 — the
    old address-only key returned the first specs' principals for the second specs."""
    rely_topic = _event_topic0("Rely(address)")
    auth_topic = _event_topic0("Auth(address)")
    alice = _addr("a11ce")
    bob = _addr("b0b")
    addr = "0x" + "AA" * 20

    client1, _ = _fake_client([([_log(rely_topic, indexed_args=[alice], block=10)], None)])
    r1 = enumerate_mapping_allowlist_sync(
        addr, cast(Any, [_rely_spec()]), from_block=0, client=client1, hypersync_module=_FakeHypersyncModule()
    )
    assert [p["address"] for p in r1["principals"]] == [alice]

    other_spec = {**_rely_spec(), "event_signature": "Auth(address)", "mapping_name": "auths"}
    client2, calls2 = _fake_client([([_log(auth_topic, indexed_args=[bob], block=20)], None)])
    r2 = enumerate_mapping_allowlist_sync(
        addr, cast(Any, [other_spec]), from_block=0, client=client2, hypersync_module=_FakeHypersyncModule()
    )
    assert calls2["n"] >= 1  # distinct specs → distinct key → real scan
    assert [p["address"] for p in r2["principals"]] == [bob]


def test_l1_rekey_distinguishes_chain():
    """The same address on two chains must not collide in L1 (the original cross-chain
    correctness bug where L1 defeated L2's chain dimension)."""
    rely_topic = _event_topic0("Rely(address)")
    alice = _addr("a11ce")
    bob = _addr("b0b")
    addr = "0x" + "BB" * 20

    client1, _ = _fake_client([([_log(rely_topic, indexed_args=[alice], block=10)], None)])
    enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        chain="ethereum",
        from_block=0,
        client=client1,
        hypersync_module=_FakeHypersyncModule(),
    )
    client2, calls2 = _fake_client([([_log(rely_topic, indexed_args=[bob], block=20)], None)])
    r2 = enumerate_mapping_allowlist_sync(
        addr,
        cast(Any, [_rely_spec()]),
        chain="base",
        from_block=0,
        client=client2,
        hypersync_module=_FakeHypersyncModule(),
    )
    assert calls2["n"] >= 1  # different chain → distinct key → real scan
    assert [p["address"] for p in r2["principals"]] == [bob]


def test_l1_enumeration_cache_size_capped(monkeypatch):
    """P1.3: the present-set L1 cache is size-capped — many distinct addresses evict the
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
    """The value-fold L1 key is (chain, address, specs_hash) WITHOUT the predicate: the
    cached entries are predicate-independent (filter_value_entries applies the predicate
    downstream), so a re-run with a different predicate HITs instead of re-paginating."""
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


def test_value_cache_rekey_distinguishes_specs():
    """Different value specs on the same address must not collide in the value-fold L1."""
    from services.resolution.mapping_enumerator import enumerate_mapping_values_sync

    owner_topic = _event_topic0("OwnerSet(address,uint256)")
    member_topic = _event_topic0("MemberSet(address,uint256)")
    a = _addr("a11ce")
    b = _addr("b0b")
    addr = "0x" + "EE" * 20

    client1, _ = _fake_client([([_set_log(owner_topic, a, 10, block=100, log_index=0)], None)])
    enumerate_mapping_values_sync(
        addr, cast(Any, [_owner_set_spec()]), from_block=0, client=client1, hypersync_module=_FakeHypersyncModule()
    )
    other = {**_owner_set_spec(), "event_signature": "MemberSet(address,uint256)", "mapping_name": "members"}
    client2, calls2 = _fake_client([([_set_log(member_topic, b, 7, block=110, log_index=0)], None)])
    r2 = enumerate_mapping_values_sync(
        addr, cast(Any, [other]), from_block=0, client=client2, hypersync_module=_FakeHypersyncModule()
    )
    assert calls2["n"] >= 1  # distinct specs → distinct key → real scan
    assert [e["key"] for e in r2["entries"]] == [b.lower()]


# ---------------------------------------------------------------------------
# G2 HIT 2: a knowingly incomplete fold must not report status="complete".
# ---------------------------------------------------------------------------


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


def test_all_ambiguous_writer_events_report_incomplete_not_complete():
    client, calls = _fake_client([])
    result = _run(
        _enumerate(
            "0xCC00000000000000000000000000000000000001",
            cast(Any, _conflicted_specs()),
            from_block=0,
            client=client,
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    assert result["principals"] == []
    assert result["status"] == "incomplete_ambiguous_writer_event"
    assert calls["n"] == 0


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
