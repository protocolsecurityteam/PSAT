from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests
from eth_utils.crypto import keccak

from services.policy import principal_history
from services.policy.principal_history import (
    build_principal_history,
    build_role_authority_history,
)
from utils.logging import bind_trace_context, degraded_errors_var, stage_metrics_var

AUTHORITY = "0x" + "aa" * 20
TARGET = "0x" + "bb" * 20
USER = "0x" + "cc" * 20
SELECTOR = "0x12345678"
_SOLMATE_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "solmate"


def _topic(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


def _address_topic(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def _uint_topic(value: int) -> str:
    return "0x" + hex(value)[2:].rjust(64, "0")


def _bytes4_topic(selector: str) -> str:
    return "0x" + selector[2:].ljust(64, "0")


def _bool_word(value: bool) -> str:
    return "0x" + ("1" if value else "0").rjust(64, "0")


def _log(topic0: str, topics: list[str], enabled: bool, block: int, log_index: int) -> dict:
    return {
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
        "logIndex": hex(log_index),
        "transactionHash": "0x" + f"{block:064x}",
        "topics": [topic0, *topics],
        "data": _bool_word(enabled),
    }


def test_role_authority_history_uses_event_shapes_not_names():
    abi = [
        {
            "type": "event",
            "name": "WhateverA",
            "inputs": [
                {"type": "address", "indexed": True},
                {"type": "uint8", "indexed": True},
                {"type": "bool", "indexed": False},
            ],
        },
        {
            "type": "event",
            "name": "WhateverB",
            "inputs": [
                {"type": "uint8", "indexed": True},
                {"type": "address", "indexed": True},
                {"type": "bytes4", "indexed": True},
                {"type": "bool", "indexed": False},
            ],
        },
        {
            "type": "event",
            "name": "WhateverC",
            "inputs": [
                {"type": "address", "indexed": True},
                {"type": "bytes4", "indexed": True},
                {"type": "bool", "indexed": False},
            ],
        },
    ]
    user_role_topic = _topic("WhateverA(address,uint8,bool)")
    role_cap_topic = _topic("WhateverB(uint8,address,bytes4,bool)")
    public_cap_topic = _topic("WhateverC(address,bytes4,bool)")

    logs_by_topic = {
        user_role_topic: [
            _log(user_role_topic, [_address_topic(USER), _uint_topic(5)], True, 12, 0),
            _log(user_role_topic, [_address_topic(USER), _uint_topic(5)], False, 20, 0),
            _log(user_role_topic, [_address_topic(USER), _uint_topic(5)], True, 25, 0),
        ],
        role_cap_topic: [
            _log(role_cap_topic, [_uint_topic(5), _address_topic(TARGET), _bytes4_topic(SELECTOR)], True, 10, 0),
            _log(role_cap_topic, [_uint_topic(5), _address_topic(TARGET), _bytes4_topic(SELECTOR)], False, 30, 0),
        ],
        public_cap_topic: [],
    }

    payload = build_role_authority_history(
        authority_address=AUTHORITY,
        chain_id=1,
        functions={(TARGET, SELECTOR): "pause()"},
        abi=abi,
        logs_by_topic=logs_by_topic,
    )

    assert payload["source"]["status"] == "ok"
    assert payload["source"]["event_topics"] == {
        "user_role": user_role_topic,
        "role_capability": role_cap_topic,
        "public_capability": public_cap_topic,
    }

    permissions = payload["function_permissions"]
    assert len(permissions) == 2
    assert permissions[0]["function"] == "pause()"
    assert permissions[0]["principal"] == USER
    assert permissions[0]["roles"] == [5]
    assert permissions[0]["granted_at_block"] == 12
    assert permissions[0]["revoked_at_block"] == 20
    assert permissions[0]["status"] == "revoked"
    assert permissions[1]["granted_at_block"] == 25
    assert permissions[1]["revoked_at_block"] == 30

    role_intervals = payload["role_membership"]
    assert [item["status"] for item in role_intervals] == ["revoked", "active"]
    assert role_intervals[1]["principal"] == USER
    assert role_intervals[1]["role"] == 5


_ROLES_AUTHORITY_ABI = [
    {
        "type": "event",
        "name": "UserRoleUpdated",
        "inputs": [
            {"type": "address", "indexed": True},
            {"type": "uint8", "indexed": True},
            {"type": "bool", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "RoleCapabilityUpdated",
        "inputs": [
            {"type": "uint8", "indexed": True},
            {"type": "address", "indexed": True},
            {"type": "bytes4", "indexed": True},
            {"type": "bool", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "PublicCapabilityUpdated",
        "inputs": [
            {"type": "address", "indexed": True},
            {"type": "bytes4", "indexed": True},
            {"type": "bool", "indexed": False},
        ],
    },
]

_ADDASSET_SELECTOR = "0x298410e5"
_TELLER_AUTHORITY = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"


class _FakeEtherscanResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


@pytest.fixture(autouse=True)
def _clear_principal_history_caches():
    # The module memoizes authority logs process-wide.
    principal_history._LOG_CACHE.clear()
    yield
    principal_history._LOG_CACHE.clear()


def _teller_predicate_trees() -> tuple[str, dict]:
    data = json.loads((_SOLMATE_FIXTURES / "teller_predicate_trees.json").read_text())
    # The static stage records the lowered form of every contract-typed signature.
    return data["contract"], {
        "trees": {"addAsset(ERC20)": data["trees"]["addAsset(ERC20)"]},
        "canonical_signatures": {"addAsset(ERC20)": "addAsset(address)"},
    }


def test_build_principal_history_ok_path_records_summary_metrics(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    contract, predicate_trees = _teller_predicate_trees()

    user_role_topic = _topic("UserRoleUpdated(address,uint8,bool)")
    role_cap_topic = _topic("RoleCapabilityUpdated(uint8,address,bytes4,bool)")
    public_cap_topic = _topic("PublicCapabilityUpdated(address,bytes4,bool)")
    logs_by_topic = {
        user_role_topic: [_log(user_role_topic, [_address_topic(USER), _uint_topic(5)], True, 12, 0)],
        role_cap_topic: [
            _log(
                role_cap_topic,
                [_uint_topic(5), _address_topic(contract), _bytes4_topic(_ADDASSET_SELECTOR)],
                True,
                10,
                0,
            )
        ],
        public_cap_topic: [],
    }

    monkeypatch.setattr("services.clients.etherscan.get", lambda *a, **k: {"result": _ROLES_AUTHORITY_ABI})

    def _fake_requests_get(url, params=None, timeout=None):
        topic0 = (params or {}).get("topic0")
        batch = logs_by_topic.get(topic0, []) if isinstance(topic0, str) else []
        payload = {"status": "1", "result": batch} if batch else {"status": "0", "result": "No records found"}
        return _FakeEtherscanResponse(payload)

    monkeypatch.setattr(requests, "get", _fake_requests_get)

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        with bind_trace_context(stage="policy", job_id="job-ph-ok", worker_id="PolicyWorker-test"):
            result = build_principal_history(
                contract_address=contract,
                chain_id=1,
                predicate_trees=predicate_trees,
                state_var_values={"authority": _TELLER_AUTHORITY},
            )
    finally:
        stage_metrics_var.reset(token)

    assert result["status"] == "ok"
    assert len(result["sources"]) == 1
    assert result["sources"][0]["status"] == "ok"
    assert result["sources"][0]["authority_address"] == _TELLER_AUTHORITY
    assert any(
        perm["principal"] == USER and perm["function"] == "addAsset(ERC20)" and perm["roles"] == [5]
        for perm in result["function_permissions"]
    )
    assert metrics["principal_history_authorities"] == 1
    assert metrics["principal_history_role_events"] == 2


def test_build_principal_history_degraded_on_authority_fetch_failure(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    contract, predicate_trees = _teller_predicate_trees()

    def _boom(*a, **k):
        raise RuntimeError("etherscan 500")

    monkeypatch.setattr("services.clients.etherscan.get", _boom)

    metrics: dict = {}
    errors: list = []
    metrics_token = stage_metrics_var.set(metrics)
    errors_token = degraded_errors_var.set(errors)
    try:
        with bind_trace_context(stage="policy", job_id="job-ph-err", worker_id="PolicyWorker-test"):
            result = build_principal_history(
                contract_address=contract,
                chain_id=1,
                predicate_trees=predicate_trees,
                state_var_values={"authority": _TELLER_AUTHORITY},
            )
    finally:
        degraded_errors_var.reset(errors_token)
        stage_metrics_var.reset(metrics_token)

    assert result["status"] == "unsupported"
    assert len(result["sources"]) == 1
    assert result["sources"][0]["status"] == "error"
    assert "etherscan 500" in result["sources"][0]["reason"]
    assert len(errors) == 1
    assert errors[0].phase == "principal_history_authority"
    assert errors[0].severity == "degraded"
    assert errors[0].context.get("authority_address") == _TELLER_AUTHORITY
    assert metrics["principal_history_authorities"] == 1
    assert metrics["principal_history_role_events"] == 0


# The process-global cache must stay bounded and eventually re-read later grants.


def _no_records_get(url, params=None, timeout=None):
    return _FakeEtherscanResponse({"status": "0", "result": "No records found"})


def test_log_cache_evicts_oldest_when_bounded(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr(principal_history, "_LOG_CACHE_MAX", 4)
    monkeypatch.setattr(requests, "get", _no_records_get)

    last_authority = ""
    for i in range(12):
        last_authority = "0x" + f"{i:040x}"
        principal_history._fetch_logs(authority_address=last_authority, chain_id=1, topic0=SELECTOR)

    assert len(principal_history._LOG_CACHE) <= principal_history._LOG_CACHE_MAX
    assert (1, last_authority.lower(), SELECTOR.lower()) in principal_history._LOG_CACHE
    principal_history.clear_log_cache()


def test_log_cache_ttl_expiry_refetches(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    calls: list = []

    def _counting_get(url, params=None, timeout=None):
        calls.append((params or {}).get("topic0"))
        return _FakeEtherscanResponse({"status": "0", "result": "No records found"})

    monkeypatch.setattr(requests, "get", _counting_get)

    principal_history._fetch_logs(authority_address=AUTHORITY, chain_id=1, topic0=SELECTOR)
    assert len(calls) == 1
    principal_history._fetch_logs(authority_address=AUTHORITY, chain_id=1, topic0=SELECTOR)
    assert len(calls) == 1
    monkeypatch.setattr(principal_history, "_LOG_CACHE_TTL_S", -1.0)
    principal_history._fetch_logs(authority_address=AUTHORITY, chain_id=1, topic0=SELECTOR)
    assert len(calls) == 2
