"""``status=0 / 'No token found' / []`` is the endpoint answering "no tokens"; filing it as ``fetch_failed``
discarded the cheap trigger to check the chain (1,027 attempts over 142 contracts). Only a short page proves the
list ended; anything else is a lower bound.
"""

from __future__ import annotations

import pytest

import services.clients.etherscan as etherscan
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
)

ADDRESS = "0x00000000000000000000000000000000000000a1"


def _entry(index: int) -> dict:
    return {
        "TokenAddress": f"0x{index:040x}",
        "TokenName": f"T{index}",
        "TokenSymbol": f"T{index}",
        "TokenQuantity": "1000",
        "TokenDivisor": "18",
        "TokenPriceUSD": "0",
    }


@pytest.fixture(autouse=True)
def _no_throttle(monkeypatch):
    monkeypatch.setattr(etherscan, "_throttle_token_balance_call", lambda: None)


class _Wire:
    def __init__(self, pages):
        self.pages = list(pages)
        self.requested: list[str] = []

    def __call__(self, module, action, chain_id, empty_result_ok=False, **params):
        self.requested.append(str(params.get("page")))
        answer = self.pages.pop(0) if self.pages else []
        if isinstance(answer, Exception):
            raise answer
        return {"status": "1", "message": "OK", "result": answer}


class TestTheEmptyAnswerIsNotAFailure:
    @pytest.mark.parametrize(
        "message",
        ["No token found", "No transactions found"],
    )
    def test_exactly_the_empty_triple_comes_back_as_data(self, monkeypatch, message):
        payload = {"status": "0", "message": message, "result": []}
        monkeypatch.setattr(etherscan.requests, "get", lambda *a, **kw: _Response(payload))
        monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
        assert etherscan.get("account", "addresstokenbalance", chain_id=1, empty_result_ok=True) == payload

    @pytest.mark.parametrize(
        "payload",
        [
            {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"},
            {"status": "0", "message": "No token found", "result": "No token found"},
            {"status": "0", "message": "No transactions found", "result": "No transactions found"},
            {"status": "0", "message": "No records found", "result": ""},
            {"status": "0", "message": "NOTOK", "result": "No records found"},
            {"status": "0", "message": "No token found", "result": [{"TokenAddress": "0x1"}]},
        ],
    )
    def test_every_other_status_zero_shape_still_fails(self, monkeypatch, payload):
        monkeypatch.setattr(etherscan.requests, "get", lambda *a, **kw: _Response(payload))
        monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
        monkeypatch.setattr(etherscan, "_RATE_LIMIT_RETRIES", 0)
        monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
        with pytest.raises(RuntimeError):
            etherscan.get("account", "addresstokenbalance", chain_id=1, empty_result_ok=True)


class TestWhereTheListEnds:
    def test_a_short_page_ends_the_list_in_one_request(self, monkeypatch):
        wire = _Wire([[_entry(i) for i in range(3)]])
        monkeypatch.setattr(etherscan, "get", wire)
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert result.status == ASSET_SET_STATUS_RETURNED_ASSETS
        assert wire.requested == ["1"]
        assert "ended on a short page" in result.basis

    def test_a_failure_on_page_one_learns_nothing(self, monkeypatch):
        monkeypatch.setattr(etherscan, "get", _Wire([RuntimeError("boom")]))
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert result.status == ASSET_SET_STATUS_FETCH_FAILED
        assert result.page_length is None

    def test_a_failure_mid_paging_keeps_the_prefix_and_says_so(self, monkeypatch):
        size = etherscan.TOKEN_BALANCE_PAGE_SIZE
        monkeypatch.setattr(etherscan, "get", _Wire([[_entry(i) for i in range(size)], RuntimeError("boom")]))
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert result.status == ASSET_SET_STATUS_AT_PAGE_CAP
        assert result.page_length == size
        assert "page 2 failed" in result.basis


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class TestGetNativePrice:
    @pytest.mark.parametrize(
        "chain_id,result,action,expected_price",
        [
            # Only bare ``*usd`` is the price.
            pytest.param(
                1,
                {"ethbtc": "0.05", "ethbtc_timestamp": "1", "ethusd": "1841.99", "ethusd_timestamp": "2"},
                "ethprice",
                1841.99,
                id="eth",
            ),
            # Must not infer "ETH" from the key.
            pytest.param(
                137,
                {"ethbtc": "0", "ethusd": "0.0826", "ethusd_timestamp": "1"},
                "ethprice",
                0.0826,
                id="polygon_pol_under_lying_ethusd_key",
            ),
            # BSC rejects "ethprice"; bnbprice's value comes back mislabeled under "ethusd".
            pytest.param(56, {"ethusd": "567.97"}, "bnbprice", 567.97, id="bsc_uses_bnbprice"),
        ],
    )
    def test_native_price_per_chain(self, monkeypatch, chain_id, result, action, expected_price):
        import services.clients.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(module=module, action=action, chain_id=chain_id)
            return {"result": result}

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(chain_id)

        assert price == expected_price
        assert captured == {"module": "stats", "action": action, "chain_id": chain_id}
