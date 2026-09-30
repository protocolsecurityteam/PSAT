"""Shared multi-address getLogs on ``RpcEventLogFetcher``.

The monitoring scanner needs one ``eth_getLogs`` for a whole cohort of contracts, per-emitter attribution, and a raw
log dict for ``services/monitoring/event_topics.parse_any_log``. Pins the multi-address filter shape, bisect-on-reject
with an address list, single-address back-compat, and the end-to-end governance decode. Only ``rpc_request`` is stubbed.
"""

from __future__ import annotations

import pytest

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from services.monitoring.event_topics import (
    OWNERSHIP_TRANSFERRED_TOPIC0,
    parse_any_log,
)
from services.resolution.repos.event_logs_rpc import (
    RpcEventLogFetcher,
    normalize_topic_filter,
)

TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

_ADDR_A = "0x" + "1a" * 20
_ADDR_B = "0x" + "2b" * 20
_TOPIC_A = "0x" + "aa" * 32
_TOPIC_B = "0x" + "bb" * 32


def _topic_addr(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0").lower()


def _raw_log(
    *,
    address: str,
    topic0: str,
    block: int,
    log_index: int = 0,
    topics_tail: tuple[str, ...] = (),
    data: str = "0x",
) -> dict:
    return {
        "address": address,
        "transactionHash": "0x" + f"{block:064x}",
        "blockHash": "0x" + f"{block:064x}",
        "logIndex": hex(log_index),
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
        "topics": [topic0, *topics_tail],
        "data": data,
    }


def test_multi_address_filter_shape_and_attribution(monkeypatch):
    calls: list[list] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        calls.append(params)
        return [
            _raw_log(address=_ADDR_A.upper(), topic0=_TOPIC_A, block=100),
            _raw_log(address=_ADDR_B, topic0=_TOPIC_B, block=101),
            _raw_log(address=_ADDR_A, topic0=_TOPIC_A, block=102),
        ]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test")
    logs = fetcher.fetch_logs(
        event_address=[_ADDR_A, _ADDR_B],
        topics=[_TOPIC_A, _TOPIC_B],
        from_block=100,
        to_block=102,
    )

    assert len(calls) == 1
    assert calls[0][0]["address"] == [_ADDR_A, _ADDR_B]
    assert calls[0][0]["topics"] == [[_TOPIC_A, _TOPIC_B]]
    assert [(log.address, log.block_number) for log in logs] == [
        (_ADDR_A, 100),
        (_ADDR_B, 101),
        (_ADDR_A, 102),
    ]
    # Attribution is exact: bucketing by emitter partitions the cohort's logs.
    by_emitter: dict[str, list[int]] = {}
    for log in logs:
        by_emitter.setdefault(log.address, []).append(log.block_number)
    assert by_emitter == {_ADDR_A: [100, 102], _ADDR_B: [101]}


def test_multi_address_bisects_on_rejection(monkeypatch):
    calls: list[tuple[int, int]] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        assert params[0]["address"] == [_ADDR_A, _ADDR_B]
        from_block = int(params[0]["fromBlock"], 16)
        to_block = int(params[0]["toBlock"], 16)
        calls.append((from_block, to_block))
        if to_block - from_block + 1 > 100_000:
            raise RuntimeError("{'code': -32005, 'message': 'Limit exceeded: More than 50000 logs returned'}")
        # Two emitters at the two ends of each surviving sub-window.
        return [
            _raw_log(address=_ADDR_A, topic0=_TOPIC_A, block=from_block),
            _raw_log(address=_ADDR_B, topic0=_TOPIC_A, block=to_block),
        ]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    logs = fetcher.fetch_logs(
        event_address=[_ADDR_A, _ADDR_B],
        topics=[_TOPIC_A],
        from_block=0,
        to_block=399_999,
    )

    # 400k fails → 2×200k fail → 4×100k succeed: 7 requests.
    assert len(calls) == 7
    assert [log.block_number for log in logs] == [
        0,
        99_999,
        100_000,
        199_999,
        200_000,
        299_999,
        300_000,
        399_999,
    ]
    assert [log.address for log in logs] == [
        _ADDR_A,
        _ADDR_B,
        _ADDR_A,
        _ADDR_B,
        _ADDR_A,
        _ADDR_B,
        _ADDR_A,
        _ADDR_B,
    ]


def test_multi_address_bisect_floor_re_raises(monkeypatch):
    calls: list[int] = []

    def fake_rpc(url, method, params, *, chain_id=None):
        assert params[0]["address"] == [_ADDR_A, _ADDR_B]
        span = int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1
        calls.append(span)
        raise RuntimeError("{'code': -32603, 'message': 'Internal error: Query timed out'}")

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="Query timed out"):
        fetcher.fetch_logs(event_address=[_ADDR_A, _ADDR_B], topics=[_TOPIC_A], from_block=0, to_block=19_999)

    assert calls == [20_000, 10_000]


def test_raw_dict_decodes_through_governance_parser(monkeypatch):
    """A realistic OwnershipTransferred log round-trips through the production ``parse_any_log`` to the
    decoded owner rotation, keyed to the emitter the fetcher attributed it to."""
    old_owner = "0x" + "de" * 20
    new_owner = "0x" + "ad" * 20
    raw = _raw_log(
        address=_ADDR_A,
        topic0=OWNERSHIP_TRANSFERRED_TOPIC0,
        block=18_000_000,
        log_index=7,
        topics_tail=(_topic_addr(old_owner), _topic_addr(new_owner)),
        data="0x",
    )

    def fake_rpc(url, method, params, *, chain_id=None):
        return [raw]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test")
    (log,) = fetcher.fetch_logs(
        event_address=[_ADDR_A],
        topics=[OWNERSHIP_TRANSFERRED_TOPIC0],
        from_block=18_000_000,
        to_block=18_000_000,
    )

    assert log.address == _ADDR_A
    assert log.raw is not None
    parsed = parse_any_log(log.raw)
    assert parsed is not None
    assert parsed["event_type"] == "ownership_transferred"
    assert parsed["block_number"] == 18_000_000
    assert parsed["log_index"] == 7
    assert parsed["old_owner"].lower() == old_owner.lower()
    assert parsed["new_owner"].lower() == new_owner.lower()


HOLDER = "0x00000000000000000000000000000000000ho1de"[:42].ljust(42, "1")
TOKEN = "0x000000000000000000000000000000000000c0de"


def _pad(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


class _StubRpc:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, url, method, params, **kwargs):
        assert method == "eth_getLogs"
        self.calls.append(params[0])
        answer = self.responses.pop(0) if self.responses else []
        if isinstance(answer, Exception):
            raise answer
        return answer


class TestTopicFilter:
    @pytest.mark.parametrize(
        ("topics", "expected"),
        [
            pytest.param(["0xAA", "0xBB"], [["0xaa", "0xbb"]], id="flat_sequence_is_topic0_or_set"),
            # ``[[]]`` and ``[]`` are different filters; the historical shape wins.
            pytest.param([], [[]], id="empty_flat_sequence_keeps_historical_payload"),
            pytest.param(
                [["0xAA"], None, ["0xBB", "0xCC"]],
                [["0xaa"], None, ["0xbb", "0xcc"]],
                id="positional_array_keeps_none_slots",
            ),
        ],
    )
    def test_normalize_topic_filter(self, topics, expected):
        assert normalize_topic_filter(topics) == expected

    def test_an_empty_slot_is_refused_rather_than_sent(self):
        # An empty list in a topic slot matches nothing at some upstreams and
        # everything at others, so a batch that came out empty would silently read
        # as either answer.
        with pytest.raises(ValueError):
            normalize_topic_filter([["0xAA"], None, []])


class TestFetchLogsShapes:
    def test_the_address_key_is_omitted_when_no_emitter_is_known(self, monkeypatch):
        rpc = _StubRpc([[]])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        fetcher = RpcEventLogFetcher("http://rpc.invalid", chain_id=1)
        fetcher.fetch_logs(
            event_address=None, topics=[[TRANSFER_TOPIC0], None, [_pad(HOLDER)]], from_block=0, to_block=9
        )
        assert "address" not in rpc.calls[0]
        assert rpc.calls[0]["topics"] == [[TRANSFER_TOPIC0], None, [_pad(HOLDER)]]

    def test_a_filter_that_constrains_nothing_is_refused(self, monkeypatch):
        rpc = _StubRpc([[]])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        fetcher = RpcEventLogFetcher("http://rpc.invalid", chain_id=1)
        with pytest.raises(ValueError):
            fetcher.fetch_logs(event_address=None, topics=[None, None], from_block=0, to_block=9)
        assert rpc.calls == []
