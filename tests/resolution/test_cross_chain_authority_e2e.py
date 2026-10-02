"""Cross-chain authority POSITIVE arm, end-to-end through the real labeling path.

Unlike ``test_cross_chain_authority.py`` (which monkeypatches the classifier), only the
wire (``services.resolution.tracking._rpc_request``) is stubbed so the genuine
``classify_resolved_address_with_status`` runs. That proves an aliased/bridge principal is
recognised BEFORE any RPC, and native Base owners are typed ``eoa``/``contract``, never
``cross_chain_authority``.

Anchors (docs.base.org "Base Contracts"): L1 ProxyAdminOwner Safe
0x7bB41C3008B3f03FE483B28b8DB90e19Cf07595c, its L2 alias (+0x1111...1111 mod 2**160,
asserted below), and predeploys 0x4200...0007 / 0x4200...0010. The L1 Safe must be in the
run's known-address scope for the alias to resolve; strip it and the label must vanish.
"""

from types import SimpleNamespace
from typing import Any

import pytest

import services.resolution.tracking as tracking
from services.concurrency import RpcExecutor
from services.policy.principal_enrichment import build_principal_labels
from services.resolution.cross_chain_authority import (
    CROSS_CHAIN_AUTHORITY_TYPE,
    make_cross_chain_recognizer,
    undo_l1_to_l2_alias,
)
from services.resolution.tracking import clear_classify_cache
from workers.policy_worker import (
    _chain_id_for_job,
    _known_addresses_for_scope,
    _make_principal_type_resolver,
)

BASE_CHAIN_ID = 8453
BASE_MESSENGER = "0x4200000000000000000000000000000000000007"
BASE_BRIDGE = "0x4200000000000000000000000000000000000010"
L1_PROXY_ADMIN_OWNER = "0x7bb41c3008b3f03fe483b28b8db90e19cf07595c"
# Pinned as a literal and cross-checked, so fixture and code can't drift.
ALIASED_L1_OWNER = "0x8cc51c3008b3f03fe483b28b8db90e19cf076a6d"
assert undo_l1_to_l2_alias(ALIASED_L1_OWNER) == L1_PROXY_ADMIN_OWNER

NATIVE_EOA_OWNER = "0x" + "ab" * 20
NATIVE_CONTRACT_OWNER = "0x" + "cd" * 20

TARGET = "0x1111111111111111111111111111111111111111"
_CONTRACT_ADDRS = {NATIVE_CONTRACT_OWNER.lower()}
_SOME_BYTECODE = "0x60806040"


@pytest.fixture(autouse=True)
def _reset_executor():
    RpcExecutor.reset_for_tests()
    clear_classify_cache()
    yield
    RpcExecutor.reset_for_tests()
    clear_classify_cache()


@pytest.fixture
def wire(monkeypatch):
    """Forces the sequential classify path and records every ``eth_getCode`` address."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", "1")
    monkeypatch.setattr(tracking, "_CLASSIFY_BATCH_ENABLED", False)
    monkeypatch.setattr(tracking, "_CLASSIFY_MULTICALL_ENABLED", False)

    getcode_addrs: list[str] = []

    def fake_rpc(rpc_url, method, params, *, chain_id=None):
        if method == "eth_getCode":
            addr = str(params[0]).lower()
            getcode_addrs.append(addr)
            return _SOME_BYTECODE if addr in _CONTRACT_ADDRS else "0x"
        if method == "eth_call":
            return "0x"
        if method == "eth_blockNumber":
            return "0x1"
        raise AssertionError(f"unexpected wire call: {method}")

    monkeypatch.setattr(tracking, "_rpc_request", fake_rpc)
    return getcode_addrs


def _role_fn(name: str, role: int, principal: str) -> dict:
    return {
        "function": name,
        "effect_labels": ["ownership_transfer"],
        "authority_public": False,
        "authority_roles": [
            {"role": role, "principals": [{"address": principal, "resolved_type": "unknown", "details": {}}]}
        ],
        "direct_owner": None,
    }


def _base_effective_permissions() -> dict:
    return {
        "contract_address": TARGET,
        "contract_name": "L2Vault",
        "functions": [
            _role_fn("setOwner(address)", 1, ALIASED_L1_OWNER),
            _role_fn("relay(bytes)", 2, BASE_MESSENGER),
            _role_fn("finalizeBridge(address,uint256)", 3, BASE_BRIDGE),
            _role_fn("setKeeper(address)", 4, NATIVE_EOA_OWNER),
            _role_fn("setModule(address)", 5, NATIVE_CONTRACT_OWNER),
        ],
    }


def _scope_graph() -> dict:
    """The L1 owner must be in scope for the alias to resolve."""
    return {
        "nodes": [
            {
                "id": "address:" + TARGET,
                "address": TARGET,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "L2Vault",
                "contract_name": "L2Vault",
                "depth": 0,
                "analyzed": True,
                "details": {"address": TARGET},
                "artifacts": {},
            },
            {
                "id": "address:" + L1_PROXY_ADMIN_OWNER,
                "address": L1_PROXY_ADMIN_OWNER,
                "node_type": "principal",
                "resolved_type": "unknown",
                "label": "l1Owner",
                "contract_name": None,
                "depth": 1,
                "analyzed": False,
                "details": {"address": L1_PROXY_ADMIN_OWNER},
                "artifacts": {},
            },
        ],
        "edges": [],
    }


def test_base_positive_arm_native_true_negative_and_no_wire_for_recognized(wire):
    ep = _base_effective_permissions()
    graph = _scope_graph()
    recognizer = make_cross_chain_recognizer(BASE_CHAIN_ID, _known_addresses_for_scope(graph, TARGET))

    payload = build_principal_labels(
        ep,
        resolved_control_graph=graph,
        rpc_url="http://base.rpc.example",
        classify_cache={},
        cross_chain_recognizer=recognizer,
    )
    principals = {p["address"]: p for p in payload["principals"]}

    aliased = principals[ALIASED_L1_OWNER]
    assert aliased["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert aliased["details"]["role"] == "aliased_l1_owner"
    assert aliased["details"]["implied_l1_address"] == L1_PROXY_ADMIN_OWNER
    assert aliased["display_name"] == f"Aliased L1 owner ({L1_PROXY_ADMIN_OWNER})"
    assert "cross_chain_authority" in aliased["labels"]

    assert principals[BASE_MESSENGER]["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principals[BASE_MESSENGER]["details"]["role"] == "cross_domain_messenger"
    assert principals[BASE_BRIDGE]["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principals[BASE_BRIDGE]["details"]["role"] == "bridge_executor"

    assert principals[NATIVE_EOA_OWNER]["resolved_type"] == "eoa"
    assert "cross_chain_authority" not in principals[NATIVE_EOA_OWNER]["labels"]
    assert principals[NATIVE_CONTRACT_OWNER]["resolved_type"] == "contract"
    assert "cross_chain_authority" not in principals[NATIVE_CONTRACT_OWNER]["labels"]

    assert principals[L1_PROXY_ADMIN_OWNER]["resolved_type"] != CROSS_CHAIN_AUTHORITY_TYPE

    probed = set(wire)
    assert ALIASED_L1_OWNER not in probed
    assert BASE_MESSENGER not in probed
    assert BASE_BRIDGE not in probed
    assert NATIVE_EOA_OWNER in probed
    assert NATIVE_CONTRACT_OWNER in probed
    assert L1_PROXY_ADMIN_OWNER in probed


def test_mainnet_run_classifies_everything_through_the_wire(wire):
    ep = _base_effective_permissions()
    graph = _scope_graph()
    recognizer = make_cross_chain_recognizer(1, _known_addresses_for_scope(graph, TARGET))
    assert recognizer is None

    payload = build_principal_labels(
        ep,
        resolved_control_graph=graph,
        rpc_url="http://eth.rpc.example",
        classify_cache={},
        cross_chain_recognizer=recognizer,
    )
    principals = {p["address"]: p for p in payload["principals"]}

    for addr in (ALIASED_L1_OWNER, BASE_MESSENGER, BASE_BRIDGE):
        assert principals[addr]["resolved_type"] != CROSS_CHAIN_AUTHORITY_TYPE
        assert "cross_chain_authority" not in principals[addr]["labels"]

    probed = set(wire)
    assert {ALIASED_L1_OWNER, BASE_MESSENGER, BASE_BRIDGE} <= probed


def test_fp_resolver_labels_bridge_without_wire_and_types_native(wire):
    recognize = _make_principal_type_resolver({}, "http://base.rpc.example", make_cross_chain_recognizer(BASE_CHAIN_ID))

    kind, details = recognize(BASE_BRIDGE)
    assert kind == CROSS_CHAIN_AUTHORITY_TYPE
    assert details is not None and details["role"] == "bridge_executor"
    assert BASE_BRIDGE.lower() not in set(wire)

    kind, _details = recognize(NATIVE_CONTRACT_OWNER)
    assert kind == "contract"
    assert NATIVE_CONTRACT_OWNER.lower() in set(wire)


def _job(*, chain_id, chain=None, address=TARGET) -> Any:
    return SimpleNamespace(id="j", chain_id=chain_id, address=address, request={"chain": chain} if chain else {})


def test_base_job_yields_live_recognizer_mainnet_job_yields_none():
    base_by_id = _job(chain_id=BASE_CHAIN_ID)
    assert _chain_id_for_job(base_by_id) == BASE_CHAIN_ID
    rec = make_cross_chain_recognizer(_chain_id_for_job(base_by_id), _known_addresses_for_scope({}, TARGET))
    assert rec is not None
    assert rec(BASE_MESSENGER) == (
        CROSS_CHAIN_AUTHORITY_TYPE,
        {"address": BASE_MESSENGER, "role": "cross_domain_messenger"},
    )

    base_by_name = _job(chain_id=None, chain="base")
    assert _chain_id_for_job(base_by_name) == BASE_CHAIN_ID
    assert make_cross_chain_recognizer(_chain_id_for_job(base_by_name)) is not None

    mainnet_job = _job(chain_id=1)
    assert _chain_id_for_job(mainnet_job) == 1
    assert make_cross_chain_recognizer(_chain_id_for_job(mainnet_job), _known_addresses_for_scope({}, TARGET)) is None
