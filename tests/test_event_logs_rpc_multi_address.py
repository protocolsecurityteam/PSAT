"""Shared multi-address getLogs on ``RpcEventLogFetcher``.

The monitoring scanner (a later stage) needs one ``eth_getLogs`` to serve a
whole cohort of monitored contracts, attribute each returned log back to the
contract that emitted it, and hand a raw log dict to the existing decode
pipeline (``services/monitoring/event_topics.parse_any_log``). It shares the
indexer's single bisect-on-reject implementation. These pin:

* the multi-address filter shape on the wire + per-emitter attribution;
* bisect-on-rejection with an address list (window halves, results in block
  order) and the floor re-raise;
* single-address back-compat — byte-identical request to today;
* the raw-dict carried on each result decodes end-to-end through the real
  governance parser.

Only the wire (``rpc_request``) is stubbed; the fetcher and the parser are the
production code under test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.resolution.repos.event_logs_rpc as event_logs_rpc  # noqa: E402
from services.monitoring.event_topics import (  # noqa: E402
    OWNERSHIP_TRANSFERRED_TOPIC0,
    parse_any_log,
)
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher  # noqa: E402

_ADDR_A = "0x" + "1a" * 20
_ADDR_B = "0x" + "2b" * 20
_TOPIC_A = "0x" + "aa" * 32
_TOPIC_B = "0x" + "bb" * 32


def _topic_addr(addr: str) -> str:
    """A 20-byte address left-padded to a 32-byte indexed-topic word."""
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
    """A list of addresses goes on the wire as the JSON-RPC ``address`` list in
    one request, and each result is attributed to its emitter via ``.address``
    (normalized lowercase, independent of the checksum casing the node returns)."""
    calls: list[list] = []

    def fake_rpc(url, method, params):
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
    """An address-list window that the upstream rejects halves and retries; the
    sub-window results concatenate in block order — same bisect core as the
    single-address path, exercised through the list branch."""
    calls: list[tuple[int, int]] = []

    def fake_rpc(url, method, params):
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
    """A rejection that persists down to ``min_bisect_span`` is a real error, not
    a sizing problem — it propagates on the address-list path too."""
    calls: list[int] = []

    def fake_rpc(url, method, params):
        assert params[0]["address"] == [_ADDR_A, _ADDR_B]
        span = int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1
        calls.append(span)
        raise RuntimeError("{'code': -32603, 'message': 'Internal error: Query timed out'}")

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="Query timed out"):
        fetcher.fetch_logs(event_address=[_ADDR_A, _ADDR_B], topics=[_TOPIC_A], from_block=0, to_block=19_999)

    assert calls == [20_000, 10_000]


def test_single_address_request_shape_unchanged(monkeypatch):
    """Existing per-cursor callers pass a single string: the wire ``address`` is
    that bare string (not a one-element list), identical to today."""
    calls: list[dict] = []

    def fake_rpc(url, method, params):
        calls.append(params[0])
        return [_raw_log(address=_ADDR_A, topic0=_TOPIC_A, block=42)]

    monkeypatch.setattr(event_logs_rpc, "rpc_request", fake_rpc)
    fetcher = RpcEventLogFetcher("http://unit.test")
    logs = fetcher.fetch_logs(
        event_address=_ADDR_A,
        topics=[_TOPIC_A, _TOPIC_B],
        from_block=100,
        to_block=100 + 499_999,
    )

    assert len(calls) == 1
    assert calls[0]["address"] == _ADDR_A
    assert isinstance(calls[0]["address"], str)
    assert calls[0]["topics"] == [[_TOPIC_A, _TOPIC_B]]
    assert calls[0]["fromBlock"] == hex(100)
    assert calls[0]["toBlock"] == hex(100 + 499_999)
    assert [log.block_number for log in logs] == [42]


def test_raw_dict_decodes_through_governance_parser(monkeypatch):
    """The raw dict carried on each result feeds the scanner's decode pipeline.
    A realistic OwnershipTransferred log (two indexed address topics, empty
    data) round-trips through the production ``parse_any_log`` to the decoded
    owner rotation, keyed to the emitter the fetcher attributed it to."""
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

    def fake_rpc(url, method, params):
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
