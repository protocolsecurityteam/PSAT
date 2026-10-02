"""One ``eth_getLogs`` per contract cohort for the monitoring scanner, with per-emitter attribution and raw logs for
``parse_any_log``.
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
