from types import SimpleNamespace

import pytest
import requests

from services.clients import rpc
from services.clients.fork_gateway import ForkGateway
from services.clients.rpc_limits import RpcBudgetExceeded, rpc_scope
from tests.rpc.test_rpc_limits import response


def test_fork_reads_consume_parent_stage_budget_and_mutations_cannot_forward(monkeypatch):
    sent = []

    def post(*args, **kwargs):
        sent.extend(kwargs["json"])
        return response([{"id": item["id"], "result": "0x"} for item in kwargs["json"]])

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    monkeypatch.setenv("PSAT_RPC_STAGE_LIMIT", "2")
    with pytest.raises(RpcBudgetExceeded):
        with rpc_scope("fork-job") as scope:
            gateway = ForkGateway("https://rpc.example")
            try:
                denied = requests.post(
                    gateway.url, json={"id": 9, "method": "eth_sendRawTransaction", "params": []}, timeout=5
                )
                assert denied.status_code == 400 and not sent
                calls = [{"id": i, "method": "eth_getCode", "params": ["0x" + str(i) * 40, "0x64"]} for i in [1, 2]]
                r = requests.post(gateway.url, json=calls, timeout=5)
                assert r.status_code == 200 and len(r.json()) == 2
                assert scope.sent == 2
                r = requests.post(
                    gateway.url,
                    json={"id": 3, "method": "eth_getCode", "params": ["0x" + "33" * 20, "0x64"]},
                    timeout=5,
                )
                assert r.status_code == 429
                assert len(sent) == 2
            finally:
                gateway.close()
            assert not gateway.thread.is_alive()
