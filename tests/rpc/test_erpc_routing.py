from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from services.clients import rpc


def _reset_thread_session() -> None:
    if hasattr(rpc._session_local, "session"):
        del rpc._session_local.session


def _response(payload):
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


@pytest.mark.parametrize(
    "call, expected",
    [
        pytest.param(
            lambda: rpc.erpc_url_for_chain_id(8453), "https://erpc-proxy.example/main/evm/8453", id="erpc-url-for-chain"
        ),
        pytest.param(
            lambda: rpc.rpc_url_for_chain_id(1, "http://127.0.0.1:8545"),
            "http://127.0.0.1:8545",
            id="explicit-rpc-url-preserved",
        ),
        pytest.param(
            lambda: rpc.default_rpc_url(chain="base"),
            "https://erpc-proxy.example/main/evm/8453",
            id="default-prefers-erpc-over-legacy-eth-rpc",
        ),
        # A local node URL (Anvil / test fork) is the one explicit override allowed to win over eRPC.
        pytest.param(
            lambda: rpc.default_rpc_url(explicit_rpc_url="http://127.0.0.1:8545", chain_id=1),
            "http://127.0.0.1:8545",
            id="default-honors-local-explicit-url",
        ),
    ],
)
def test_erpc_url_routing(monkeypatch, call, expected):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setenv("ETH_RPC", "https://legacy.example")

    assert call() == expected


def test_rpc_batch_request_merges_erpc_directive_headers(monkeypatch):
    _reset_thread_session()
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setenv("ERPC_SECRET", "secret-token")
    session = rpc._get_session()

    with patch.object(session, "post", return_value=_response([{"id": 0, "result": "0x1"}])) as mocked_post:
        result = rpc.rpc_batch_request(
            "https://erpc-proxy.example/main/evm/1",
            [("eth_chainId", [])],
            headers={"X-ERPC-Skip-Cache-Read": "true"},
        )

    assert result == ["0x1"]
    headers = mocked_post.call_args.kwargs["headers"]
    assert headers[rpc.ERPC_SECRET_HEADER] == "secret-token"
    assert headers["X-ERPC-Skip-Cache-Read"] == "true"
