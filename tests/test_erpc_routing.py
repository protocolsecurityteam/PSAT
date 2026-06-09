from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils import rpc


def _reset_thread_session() -> None:
    if hasattr(rpc._session_local, "session"):
        del rpc._session_local.session


def _response(payload):
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def test_erpc_url_for_chain_id_uses_configured_route(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    assert rpc.erpc_url_for_chain_id(8453) == "https://erpc-proxy.example/main/evm/8453"


def test_rpc_url_for_chain_id_preserves_explicit_rpc_url(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    assert rpc.rpc_url_for_chain_id(1, "http://127.0.0.1:8545") == "http://127.0.0.1:8545"


def test_default_rpc_url_prefers_erpc_for_known_chain(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setenv("ETH_RPC", "https://legacy.example")

    assert rpc.default_rpc_url(chain="base") == "https://erpc-proxy.example/main/evm/8453"


def test_default_rpc_url_does_not_invent_mainnet_for_unknown_chain(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    # A genuinely-named but unsupported chain has no eRPC route and is never
    # silently mapped to mainnet — the caller gets None and fails loud.
    assert rpc.default_rpc_url(chain="fantom") is None


def test_default_rpc_url_treats_unknown_sentinel_as_mainnet(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    # Discovery's "unknown" chain sentinel (and a hosted rpc_url pin) must fall
    # back to the mainnet eRPC route — not raise. Regression: a chain="unknown"
    # job otherwise resolved to no route once the ETH_RPC fallback was removed.
    assert rpc.default_rpc_url(chain="unknown") == "https://erpc-proxy.example/main/evm/1"
    assert (
        rpc.default_rpc_url(explicit_rpc_url="https://eth-mainnet.g.alchemy.com/v2/key", chain="unknown")
        == "https://erpc-proxy.example/main/evm/1"
    )


def test_default_rpc_url_returns_none_without_erpc(monkeypatch):
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)

    # No eRPC configured and no local override → no route. There is no ETH_RPC
    # or public-node fallback.
    assert rpc.default_rpc_url() is None


def test_default_rpc_url_ignores_hosted_explicit_url_in_favor_of_erpc(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    # Regression: a pinned hosted provider URL must NOT shadow eRPC — that is
    # exactly what let a direct-Alchemy 429 storm bypass the proxy.
    assert (
        rpc.default_rpc_url(explicit_rpc_url="https://eth-mainnet.g.alchemy.com/v2/key", chain_id=1)
        == "https://erpc-proxy.example/main/evm/1"
    )


def test_default_rpc_url_honors_local_explicit_url(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    # A local node URL (Anvil / test fork) is the one explicit override allowed
    # to win over eRPC.
    assert rpc.default_rpc_url(explicit_rpc_url="http://127.0.0.1:8545", chain_id=1) == "http://127.0.0.1:8545"


def test_require_rpc_url_raises_without_route(monkeypatch):
    monkeypatch.delenv("ERPC_BASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="No eRPC route"):
        rpc.require_rpc_url()


def test_is_local_rpc_url_discriminates_local_from_hosted():
    assert rpc.is_local_rpc_url("http://127.0.0.1:8545")
    assert rpc.is_local_rpc_url("http://localhost:8545")
    assert not rpc.is_local_rpc_url("https://eth-mainnet.g.alchemy.com/v2/key")
    assert not rpc.is_local_rpc_url(None)


def test_rpc_headers_add_erpc_secret_only_for_erpc_url(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setenv("ERPC_SECRET", "secret-token")

    erpc_headers = rpc.rpc_headers("https://erpc-proxy.example/main/evm/1")
    public_headers = rpc.rpc_headers("https://ethereum-rpc.publicnode.com")

    assert erpc_headers[rpc.ERPC_SECRET_HEADER] == "secret-token"
    assert rpc.ERPC_SECRET_HEADER not in public_headers


def test_rpc_request_sends_erpc_auth_header(monkeypatch):
    _reset_thread_session()
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.setenv("ERPC_SECRET", "secret-token")
    session = rpc._get_session()

    with patch.object(session, "post", return_value=_response({"result": "0x1"})) as mocked_post:
        result = rpc.rpc_request("https://erpc-proxy.example/main/evm/1", "eth_chainId", [])

    assert result == "0x1"
    headers = mocked_post.call_args.kwargs["headers"]
    assert headers["Content-Type"] == "application/json"
    assert headers[rpc.ERPC_SECRET_HEADER] == "secret-token"


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


def test_erpc_healthcheck_urls(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example/")

    assert rpc.erpc_healthcheck_url() == "https://erpc-proxy.example/healthcheck"
    assert (
        rpc.erpc_healthcheck_url(1, eval_chain_id=True)
        == "https://erpc-proxy.example/main/evm/1/healthcheck?eval=all:evm:eth_chainId"
    )
