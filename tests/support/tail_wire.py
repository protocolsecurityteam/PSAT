"""A canned ``eth_getLogs`` wire for event-fold tail scans (``services.resolution.event_tail.rpc_request``)."""

from __future__ import annotations

from typing import Any


def raw_log(
    address: str,
    topics: list[str],
    block: int,
    *,
    data_words: list[str] | None = None,
    log_index: int = 0,
    transaction_index: int = 0,
) -> dict[str, Any]:
    data = "0x" + "".join(w.removeprefix("0x").rjust(64, "0") for w in (data_words or []))
    return {
        "address": address.lower(),
        "topics": [t.lower() for t in topics],
        "data": data,
        "blockNumber": hex(block),
        "blockHash": "0x" + block.to_bytes(32, "big").hex(),
        "transactionHash": "0x" + (block * 1000 + log_index + 7).to_bytes(32, "big").hex(),
        "transactionIndex": hex(transaction_index),
        "logIndex": hex(log_index),
        "removed": False,
    }


class TailLogWire:
    """Answers ``eth_getLogs`` from ``logs`` by address, topic0 slot and block range; ``fail`` raises instead."""

    def __init__(self, logs: list[dict[str, Any]], *, fail: bool = False) -> None:
        self.logs = logs
        self.fail = fail
        self.calls: list[tuple[int, int]] = []

    def __call__(self, url, method, params, chain_id=None, **_kw):
        assert method == "eth_getLogs", method
        query = params[0]
        lo, hi = int(query["fromBlock"], 16), int(query["toBlock"], 16)
        self.calls.append((lo, hi))
        if self.fail:
            raise RuntimeError("stubbed tail upstream failure")
        address = query.get("address")
        addresses = {address.lower()} if isinstance(address, str) else {a.lower() for a in address or []}
        slot0 = {t.lower() for t in (query.get("topics") or [[]])[0] or []}
        return [
            log
            for log in self.logs
            if lo <= int(log["blockNumber"], 16) <= hi
            and (not addresses or log["address"] in addresses)
            and (not slot0 or log["topics"][0] in slot0)
        ]


def install_tail_wire(monkeypatch, logs: list[dict[str, Any]] | None = None, *, fail: bool = False) -> TailLogWire:
    wire = TailLogWire(list(logs or []), fail=fail)
    monkeypatch.setattr("services.resolution.event_tail.rpc_request", wire)
    return wire
