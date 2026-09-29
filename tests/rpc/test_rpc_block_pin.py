"""``PSAT_PIN_BLOCKS``: eRPC reads are rewritten to a fixed finalized height."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from services.clients import rpc

ERPC = "https://erpc-proxy.example"
MAINNET = f"{ERPC}/main/evm/1"
PIN = 20_850_000


@pytest.fixture
def sent(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", ERPC)
    monkeypatch.setenv(rpc.PIN_BLOCKS_ENV, f"1:{PIN},8453:30000000")
    bodies: list = []

    def post(url, json=None, **_kwargs):
        bodies.append(json)
        response = MagicMock(status_code=200)
        response.raise_for_status.return_value = None
        if isinstance(json, list):
            response.json.return_value = [{"jsonrpc": "2.0", "id": item["id"], "result": "0x"} for item in json]
        else:
            response.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": "0x"}
        return response

    session = MagicMock()
    session.post.side_effect = post
    monkeypatch.setattr(rpc, "_get_session", lambda: session)
    return bodies


def test_moving_tag_is_pinned(sent):
    rpc.rpc_request(MAINNET, "eth_getStorageAt", ["0xabc", "0x0", "latest"])
    assert sent[0]["params"] == ["0xabc", "0x0", hex(PIN)]


def test_omitted_optional_block_is_pinned(sent):
    rpc.rpc_request(MAINNET, "eth_call", [{"to": "0xabc", "data": "0x"}])
    assert sent[0]["params"][1] == hex(PIN)


def test_explicit_block_is_left_alone(sent):
    rpc.rpc_request(MAINNET, "eth_getCode", ["0xabc", "0x10"])
    assert sent[0]["params"] == ["0xabc", "0x10"]


def test_block_number_is_answered_locally(sent):
    assert rpc.rpc_request(MAINNET, "eth_blockNumber", []) == hex(PIN)
    assert sent == []


def test_get_logs_range_is_capped_at_the_pin(sent):
    rpc.rpc_request(MAINNET, "eth_getLogs", [{"address": "0xabc", "fromBlock": "0x1", "toBlock": hex(PIN + 5)}])
    rpc.rpc_request(MAINNET, "eth_getLogs", [{"address": "0xabc", "fromBlock": "0x1"}])
    assert [body["params"][0]["toBlock"] for body in sent] == [hex(PIN), hex(PIN)]
    assert sent[0]["params"][0]["fromBlock"] == "0x1"


def test_batches_are_pinned(sent):
    rpc.rpc_batch_request(MAINNET, [("eth_getCode", ["0xabc", "latest"])])
    rpc.rpc_batch_request_classified(MAINNET, [("eth_getBalance", ["0xabc", "safe"])])
    rpc.eth_call_batch(MAINNET, [{"to": "0xabc", "data": "0x"}])
    assert sent[0][0]["params"] == ["0xabc", hex(PIN)]
    assert sent[1][0]["params"] == ["0xabc", hex(PIN)]
    assert sent[2][0]["params"][1] == hex(PIN)


def test_per_chain_pin(sent):
    rpc.rpc_request(f"{ERPC}/main/evm/8453", "eth_getCode", ["0xabc", "latest"])
    rpc.rpc_request(f"{ERPC}/main/evm/10", "eth_getCode", ["0xabc", "latest"])
    assert sent[0]["params"][1] == hex(30_000_000)
    assert sent[1]["params"][1] == "latest"


def test_local_fork_is_never_pinned(sent):
    rpc.rpc_request("http://127.0.0.1:8545", "eth_getCode", ["0xabc", "latest"])
    assert sent[0]["params"][1] == "latest"


def test_unset_env_leaves_requests_alone(sent, monkeypatch):
    monkeypatch.delenv(rpc.PIN_BLOCKS_ENV)
    rpc.rpc_request(MAINNET, "eth_getCode", ["0xabc", "latest"])
    assert sent[0]["params"][1] == "latest"


def test_pinned_requests_carry_their_own_user_agent(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", ERPC)
    monkeypatch.setenv(rpc.PIN_BLOCKS_ENV, f"1:{PIN}")
    assert rpc.rpc_headers(MAINNET, {"User-Agent": "other/1"})["User-Agent"] == rpc.PINNED_USER_AGENT
    assert "User-Agent" not in rpc.rpc_headers("http://127.0.0.1:8545")
    monkeypatch.delenv(rpc.PIN_BLOCKS_ENV)
    assert "User-Agent" not in rpc.rpc_headers(MAINNET)
