"""How ``_build_indexer_fetchers`` configures the indexer's eth_getLogs fetchers, and the settings they read."""

from __future__ import annotations

import dataclasses

import services.resolution.repos.event_logs_rpc as event_logs_rpc
from services.resolution import indexer_settings
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher
from workers.event_log_indexer import _build_indexer_fetchers

_ADDRESS = "0x" + "4d" * 20
_TOPIC = "0x" + "aa" * 32


def _raw_log(block: int) -> dict:
    return {
        "address": _ADDRESS,
        "transactionHash": "0x" + f"{block:064x}",
        "blockHash": "0x" + f"{block + 1:064x}",
        "logIndex": "0x3",
        "blockNumber": hex(block),
        "transactionIndex": "0x1",
        "topics": [_TOPIC, "0x" + "00" * 31 + "07"],
        "data": "0x" + "00" * 31 + "2a",
        "removed": False,
    }


def test_indexer_fetcher_drops_the_raw_dict_and_keeps_every_field(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
    monkeypatch.setattr(event_logs_rpc, "rpc_request", lambda *a, **k: [_raw_log(42)])
    fetchers, _, _ = _build_indexer_fetchers()
    indexer_fetcher = fetchers[1]
    assert isinstance(indexer_fetcher, RpcEventLogFetcher)

    (lean,) = indexer_fetcher.fetch_logs(event_address=_ADDRESS, topics=[_TOPIC], from_block=40, to_block=50)
    (full,) = RpcEventLogFetcher("http://unit.test").fetch_logs(
        event_address=_ADDRESS, topics=[_TOPIC], from_block=40, to_block=50
    )

    assert lean.raw is None
    assert full.raw == _raw_log(42)
    assert {f.name: getattr(lean, f.name) for f in dataclasses.fields(lean) if f.name != "raw"} == {
        f.name: getattr(full, f.name) for f in dataclasses.fields(full) if f.name != "raw"
    }


def test_new_knobs_have_their_documented_defaults():
    assert indexer_settings.TARGET_PAGE_LOGS == 25_000
    assert indexer_settings.MAX_PAGE_LOGS == 100_000
    assert indexer_settings.INITIAL_SPAN == 50_000
    assert indexer_settings.WARM_BATCH_ADDRESSES == 50
    assert indexer_settings.WARM_BATCH_MAX_LAG == 1_000
    assert indexer_settings.GROUP_BUDGET_S == 30
    assert indexer_settings.PASS_BUDGET_S == 120
    assert indexer_settings.GETLOGS_TIMEOUT_S == 35
