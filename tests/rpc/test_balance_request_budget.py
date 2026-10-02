"""Physical retries consume one shared pass budget; decoding does not invent coverage."""

from types import SimpleNamespace

import pytest

from services.clients import etherscan, rpc
from services.clients.request_budget import RequestBudget, RequestBudgetExceeded, request_budget


def test_rpc_transport_retries_stop_at_pass_budget(monkeypatch):
    calls = []

    def post(*args, **kwargs):
        calls.append(1)
        raise rpc.requests.Timeout("offline timeout")

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    monkeypatch.setattr(rpc.time, "sleep", lambda _: None)
    budget = RequestBudget(limit=2)
    with request_budget(budget), pytest.raises(RequestBudgetExceeded):
        rpc.rpc_request("http://erpc.invalid/1", "eth_blockNumber", [], retries=8, chain_id=1)
    assert len(calls) == 2 and budget.attempts == {"rpc": 2}


def test_etherscan_outside_collection_keeps_existing_retry_policy(monkeypatch):
    calls, waits = [], []

    def get(*args, **kwargs):
        calls.append(1)
        result = {"status": "0", "result": "rate limit"} if len(calls) <= 3 else {"status": "1", "result": []}
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: result)

    monkeypatch.setattr(etherscan.requests, "get", get)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "test-key")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: waits.append(1))
    monkeypatch.setattr(etherscan.time, "sleep", lambda _: None)
    with request_budget(RequestBudget(limit=0)), pytest.raises(RequestBudgetExceeded):
        etherscan.get("account", "balance", chain_id=1, address="0x" + "1" * 40)
    waits.clear()
    assert etherscan.get("account", "balance", chain_id=1, address="0x" + "1" * 40)["status"] == "1"
    assert len(calls) == len(waits) == 4


@pytest.mark.parametrize("invalid", [None, "garbage", {"TokenAddress": "0x" + "2" * 40}])
def test_malformed_entry_keeps_valid_prefix_explicitly_partial(monkeypatch, invalid):
    good = {"TokenAddress": "0x" + "1" * 40, "TokenQuantity": "3", "TokenDivisor": "0", "TokenPriceUSD": "2"}
    monkeypatch.setattr(etherscan, "get", lambda *a, **kw: {"result": [good, invalid]})
    page = etherscan.get_token_balances_page("0x" + "a" * 40, chain_id=1)
    assert page.status == "at_page_cap"
    assert len(page.rows) == 1 and page.rows[0]["usd_value"] == 6
