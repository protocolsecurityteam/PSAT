"""One ``eth_getLogs`` per contract cohort for the monitoring scanner, with per-emitter attribution and raw logs for
``parse_any_log``.
"""

from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest
import requests

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from services.clients import rpc, rpc_limits
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


@pytest.mark.parametrize("method", ["fetch_logs", "visit_logs", "coordinated"])
@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize(
    "failure", ["timeout", "range", "billing", "wrapped_billing", "http_billing", "throttle", "json_throttle"]
)
def test_multi_address_bisect_floor_re_raises(monkeypatch, method, scoped, failure):
    calls: list[int] = []
    wire: list[int] = []

    def post(_url, **kwargs):
        request = kwargs["json"]
        query = request["params"][0]
        assert query["address"] == [_ADDR_A, _ADDR_B]
        span = int(query["toBlock"], 16) - int(query["fromBlock"], 16) + 1
        wire.append(span)
        error = {"code": -32603, "message": "Internal error: Query timed out"}
        if failure == "range":
            error = {"code": -32005, "message": "query returned more than 10000 results"}
        elif "billing" in failure:
            error = {"code": -32005, "message": "Monthly capacity limit exceeded"}
            if failure == "wrapped_billing":
                error = {"code": "ErrUpstreamsExhausted", "message": "upstreams exhausted", "cause": [error]}
        elif "throttle" in failure:
            error = {"code": 429 if failure == "throttle" else -32005, "message": "Rate limit exceeded"}
        payload = {"id": request["id"], "error": error}
        if failure == "range" and span <= 10_000:
            payload = {"id": request["id"], "result": []}
        response = requests.Response()
        response.status_code = 429 if failure in ("http_billing", "throttle") else 200
        response._content = json.dumps(payload).encode()
        return response

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    fetcher = RpcEventLogFetcher(
        "http://unit.test", max_block_range=1_000_000, min_bisect_span=10_000, result_cap=50_000
    )
    request_logs = fetcher._request_logs

    def counted(params):
        calls.append(int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1)
        return request_logs(params)

    monkeypatch.setattr(fetcher, "_request_logs", counted)
    consume = []

    def scan():
        with rpc_limits.rpc_scope("log-scan") if scoped else nullcontext():
            kwargs: dict[str, Any] = dict(
                event_address=[_ADDR_A, _ADDR_B], topics=[_TOPIC_A], from_block=0, to_block=19_999
            )
            if method == "fetch_logs":
                assert fetcher.fetch_logs(**kwargs) == []
            else:
                fetcher.visit_logs(**kwargs, consume=consume.append, bisect=method != "coordinated")

    if failure == "range" and method != "coordinated":
        scan()
        assert calls == wire == [20_000, 10_000, 10_000]
    else:
        with pytest.raises(RuntimeError) as caught:
            scan()
        if "billing" in failure:
            from workers.retry_policy import classify

            assert type(caught.value).__name__ == "RpcBillingLimitExceeded"
            assert classify(caught.value) == "terminal"
            assert calls == wire == [20_000]
        elif "throttle" in failure:
            from workers.retry_policy import classify

            assert isinstance(caught.value, rpc_limits.RpcBackpressure)
            assert classify(caught.value) == "transient"
            assert calls == wire == [20_000]
        elif method == "coordinated":
            assert isinstance(caught.value, event_logs_rpc.RpcRangeTooLarge)
            assert calls == wire == [20_000]
        else:
            assert "Query timed out" in str(caught.value)
            assert calls == wire == [20_000, 10_000]

    assert not consume


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
