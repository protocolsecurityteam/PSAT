"""The Etherscan asset-list read: the empty answer, and where the list ends.

Two states used to be one. ``status=0 / 'No token found' / []`` is the endpoint
ANSWERING that its index holds no tokens for an address; every other ``status=0``
is a failure. Filing both as ``fetch_failed`` threw away the only cheap trigger
this pipeline has for looking at the chain — and 1,027 attempts over 142
contracts had been throwing it away for days.

The second state is the end of the list. One page proves nothing about a holder
with more assets than fit in it; only a SHORT page does. Anything else — the page
budget, a mid-paging failure, an endpoint that re-serves page 1 — leaves a prefix,
which is a lower bound and must never read as an at-most.
"""

from __future__ import annotations

import pytest

import services.clients.etherscan as etherscan
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
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
    """The endpoint's 1 req/s limiter is real; these arms replay the wire."""
    monkeypatch.setattr(etherscan, "_throttle_token_balance_call", lambda: None)


class _Wire:
    """``get``, scripted per page."""

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
    def test_exactly_the_empty_triple_comes_back_as_data(self, monkeypatch):
        payload = {"status": "0", "message": "No token found", "result": []}
        monkeypatch.setattr(etherscan.requests, "get", lambda *a, **kw: _Response(payload))
        monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
        assert etherscan.get("account", "addresstokenbalance", chain_id=1, empty_result_ok=True) == payload

    @pytest.mark.parametrize(
        "payload",
        [
            {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"},
            {"status": "0", "message": "No token found", "result": "No token found"},
            {"status": "0", "message": "No transactions found", "result": []},
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

    def test_the_triple_still_raises_for_a_caller_that_did_not_opt_in(self, monkeypatch):
        payload = {"status": "0", "message": "No token found", "result": []}
        monkeypatch.setattr(etherscan.requests, "get", lambda *a, **kw: _Response(payload))
        monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
        monkeypatch.setattr(etherscan, "_RATE_LIMIT_RETRIES", 0)
        monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
        with pytest.raises(RuntimeError):
            etherscan.get("account", "balance", chain_id=1)

    def test_an_empty_list_is_recorded_as_the_answer_it_is(self, monkeypatch):
        monkeypatch.setattr(etherscan, "get", _Wire([[]]))
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert result.status == ASSET_SET_STATUS_RETURNED_EMPTY
        assert result.page_length == 0 and result.pages_read == 1
        assert "empty list" in result.basis


class TestWhereTheListEnds:
    def test_a_short_page_ends_the_list_in_one_request(self, monkeypatch):
        wire = _Wire([[_entry(i) for i in range(3)]])
        monkeypatch.setattr(etherscan, "get", wire)
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert result.status == ASSET_SET_STATUS_RETURNED_ASSETS
        assert wire.requested == ["1"]
        assert "ended on a short page" in result.basis

    def test_a_full_page_is_followed_until_a_short_one(self, monkeypatch):
        size = etherscan.TOKEN_BALANCE_PAGE_SIZE
        wire = _Wire([[_entry(i) for i in range(size)], [_entry(size + i) for i in range(4)]])
        monkeypatch.setattr(etherscan, "get", wire)
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert wire.requested == ["1", "2"]
        assert result.status == ASSET_SET_STATUS_RETURNED_ASSETS
        assert result.page_length == size + 4
        assert len(result.rows) == size + 4

    def test_an_exhausted_page_budget_keeps_the_list_a_prefix(self, monkeypatch):
        size = etherscan.TOKEN_BALANCE_PAGE_SIZE
        monkeypatch.setenv("PSAT_TOKEN_BALANCE_MAX_PAGES", "2")
        wire = _Wire([[_entry(i) for i in range(size)], [_entry(size + i) for i in range(size)]])
        monkeypatch.setattr(etherscan, "get", wire)
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert wire.requested == ["1", "2"]
        assert result.status == ASSET_SET_STATUS_AT_PAGE_CAP
        assert "page budget" in result.basis

    def test_an_endpoint_that_ignores_paging_is_not_read_as_a_whole_list(self, monkeypatch):
        size = etherscan.TOKEN_BALANCE_PAGE_SIZE
        first = [_entry(i) for i in range(size)]
        wire = _Wire([first, list(first)])
        monkeypatch.setattr(etherscan, "get", wire)
        result = etherscan.get_token_balances_page(ADDRESS, chain_id=1)
        assert result.status == ASSET_SET_STATUS_AT_PAGE_CAP
        assert "paging not honoured" in result.basis
        assert result.page_length == size

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

    def test_a_budget_below_one_is_refused_rather_than_defaulted(self, monkeypatch):
        monkeypatch.setenv("PSAT_TOKEN_BALANCE_MAX_PAGES", "0")
        with pytest.raises(ValueError):
            etherscan.token_balance_page_budget()


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class TestGetNativePrice:
    """``get_native_price`` picks the per-chain stats action and reads the price
    from the ``*usd`` field, never inferring the asset from the response key."""

    def test_eth_native_uses_ethprice_action(self, monkeypatch):
        import services.clients.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(module=module, action=action, chain_id=chain_id)
            # ethprice carries ethbtc + ethusd + *_timestamp siblings; only the
            # bare ``*usd`` field is the price.
            return {
                "result": {
                    "ethbtc": "0.05",
                    "ethbtc_timestamp": "1",
                    "ethusd": "1841.99",
                    "ethusd_timestamp": "2",
                }
            }

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(1)

        assert price == 1841.99
        assert captured == {"module": "stats", "action": "ethprice", "chain_id": 1}

    def test_polygon_pol_priced_under_lying_ethusd_key(self, monkeypatch):
        # Polygon's POL price comes back under "ethusd"; generic *usd parse must
        # read it without inferring "ETH" from the key.
        import services.clients.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(action=action, chain_id=chain_id)
            return {"result": {"ethbtc": "0", "ethusd": "0.0826", "ethusd_timestamp": "1"}}

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(137)

        assert price == 0.0826
        assert captured == {"action": "ethprice", "chain_id": 137}

    def test_bsc_uses_bnbprice_action(self, monkeypatch):
        # BSC rejects "ethprice": the registry override must drive the call to
        # "bnbprice", whose value is (mislabeled) under "ethusd".
        import services.clients.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(module=module, action=action, chain_id=chain_id)
            return {"result": {"ethusd": "567.97"}}

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(56)

        assert price == 567.97
        assert captured == {"module": "stats", "action": "bnbprice", "chain_id": 56}

    def test_missing_usd_field_raises(self, monkeypatch):
        import services.clients.etherscan as es

        monkeypatch.setattr(es, "get", lambda *a, **k: {"result": {"ethbtc": "0.05"}})
        with pytest.raises(RuntimeError):
            es.get_native_price(1)

    def test_get_eth_price_delegates_to_native(self, monkeypatch):
        import services.clients.etherscan as es

        monkeypatch.setattr(es, "get", lambda *a, **k: {"result": {"ethusd": "2000.0"}})
        assert es.get_eth_price(1) == 2000.0
