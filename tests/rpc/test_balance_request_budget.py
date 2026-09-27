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


def test_etherscan_throttle_retries_each_need_a_permit_and_budget(monkeypatch):
    import services.clients.provider_permits as permits

    calls, quotas = [], []

    def get(*args, **kwargs):
        calls.append(1)
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"status": "0", "result": "rate limit"})

    monkeypatch.setattr(etherscan.requests, "get", get)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "test-key")
    monkeypatch.setattr(etherscan.time, "sleep", lambda _: None)
    monkeypatch.setattr(permits, "wait_etherscan_permit", lambda *a, **kw: quotas.append(kw))
    budget = RequestBudget(limit=2)
    with request_budget(budget), pytest.raises(RequestBudgetExceeded):
        etherscan.get("account", "addresstokenbalance", chain_id=1, address="0x" + "1" * 40)
    assert len(calls) == 2 and budget.attempts == {"etherscan": 2}
    assert all(q["token_page"] for q in quotas)


@pytest.mark.parametrize("invalid", [None, "garbage", {"TokenAddress": "0x" + "2" * 40}])
def test_malformed_entry_keeps_valid_prefix_explicitly_partial(monkeypatch, invalid):
    good = {"TokenAddress": "0x" + "1" * 40, "TokenQuantity": "3", "TokenDivisor": "0", "TokenPriceUSD": "2"}
    monkeypatch.setattr(etherscan, "get", lambda *a, **kw: {"result": [good, invalid]})
    page = etherscan.get_token_balances_page("0x" + "a" * 40, chain_id=1)
    assert page.status == "at_page_cap"
    assert len(page.rows) == 1 and page.rows[0]["usd_value"] == 6


@pytest.mark.parametrize("failure", [etherscan.requests.Timeout("timeout"), etherscan.requests.HTTPError("502")])
def test_later_transport_failure_preserves_acquired_prefix(monkeypatch, failure):
    good = {"TokenAddress": "0x" + "1" * 40, "TokenQuantity": "3", "TokenDivisor": "0", "TokenPriceUSD": "2"}
    monkeypatch.setattr(etherscan, "TOKEN_BALANCE_PAGE_SIZE", 1)

    def get(*args, **kwargs):
        if kwargs["page"] == "1":
            return {"result": [good]}
        raise failure

    monkeypatch.setattr(etherscan, "get", get)
    page = etherscan.get_token_balances_page("0x" + "a" * 40, chain_id=1)
    assert page.status == "at_page_cap" and page.pages_read == 1
    assert len(page.rows) == 1 and page.rows[0]["balance"] == 3
