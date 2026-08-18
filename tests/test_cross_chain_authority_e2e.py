"""Cross-chain authority POSITIVE arm, exercised end-to-end through the real
resolution/labeling path (MULTICHAIN_INVARIANTS.md invariant 15).

``tests/test_cross_chain_authority.py`` covers the recognizer and its wiring by
monkeypatching the *classifier function*. These tests instead stub only the
*wire* (``services.resolution.tracking._rpc_request``) — the repo's
integration-test convention — so the genuine
``classify_resolved_address_with_status`` runs. That proves two properties the
unit tests cannot:

  * the recognizer short-circuits an aliased/bridge principal BEFORE any RPC is
    issued for it (recognition needs no wire), and
  * a native Base owner that reaches the real classifier is typed by it
    (``eoa``/``contract``), never mislabeled ``cross_chain_authority``.

Real-target anchoring (Base mainnet, from docs.base.org "Base Contracts"):
  L1 ProxyAdminOwner (Ethereum Gnosis Safe): 0x7bB41C3008B3f03FE483B28b8DB90e19Cf07595c
  → its L2 alias (L1 + 0x1111…1111):         0x8cc51c…cf076a6d   (arithmetic, asserted below)
  L2CrossDomainMessenger (registry predeploy): 0x4200000000000000000000000000000000000007
  L2StandardBridge / bridge executor:          0x4200000000000000000000000000000000000010

On Base the L2 ``ProxyAdmin`` is owned by the *aliased* L1 ProxyAdminOwner — the
default L2 ownership pattern invariant 15 exists to label. The L1 owner Safe is
placed in the run's known-address scope (a same-address on-chain reference is the
documented trigger), so the alias resolves; strip it from scope and the label
must vanish (guarded in ``tests/test_cross_chain_authority.py``).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from types import SimpleNamespace
from typing import Any

import pytest

import services.resolution.tracking as tracking
from services.policy.principal_enrichment import build_principal_labels
from services.resolution.cross_chain_authority import (
    CROSS_CHAIN_AUTHORITY_TYPE,
    make_cross_chain_recognizer,
    undo_l1_to_l2_alias,
)
from services.resolution.tracking import clear_classify_cache
from utils.concurrency import RpcExecutor
from workers.policy_worker import (
    _chain_id_for_job,
    _known_addresses_for_scope,
    _make_principal_type_resolver,
)

BASE_CHAIN_ID = 8453
# Real Base-mainnet OP-stack predeploys (utils/chains.py registry constants).
BASE_MESSENGER = "0x4200000000000000000000000000000000000007"
BASE_BRIDGE = "0x4200000000000000000000000000000000000010"
# Real Base-mainnet L1 ProxyAdminOwner (Ethereum Gnosis Safe, docs.base.org).
L1_PROXY_ADMIN_OWNER = "0x7bb41c3008b3f03fe483b28b8db90e19cf07595c"
# The L2 alias is arithmetic (L1 + 0x1111…1111 mod 2**160); pinned as a literal
# and cross-checked against the recognizer's own transform so the fixture and the
# code under test cannot silently drift.
ALIASED_L1_OWNER = "0x8cc51c3008b3f03fe483b28b8db90e19cf076a6d"
assert undo_l1_to_l2_alias(ALIASED_L1_OWNER) == L1_PROXY_ADMIN_OWNER

# Native Base principals (arbitrary Base-local addresses, NOT cross-chain).
NATIVE_EOA_OWNER = "0x" + "ab" * 20
NATIVE_CONTRACT_OWNER = "0x" + "cd" * 20

TARGET = "0x1111111111111111111111111111111111111111"
_CONTRACT_ADDRS = {NATIVE_CONTRACT_OWNER.lower()}
_SOME_BYTECODE = "0x60806040"


@pytest.fixture(autouse=True)
def _reset_executor():
    """``PSAT_RPC_FANOUT`` flips per test must rebuild the shared pool; the
    process-wide classify cache must not leak addresses across tests."""
    RpcExecutor.reset_for_tests()
    clear_classify_cache()
    yield
    RpcExecutor.reset_for_tests()
    clear_classify_cache()


@pytest.fixture
def wire(monkeypatch):
    """Stub the classify wire (``_rpc_request``) — never the classifier. Forces
    the sequential single-call classify path (batch/Multicall3 off) and records
    every address ``eth_getCode`` is issued for, so a test can assert which
    principals reached the wire and which were recognized before it.

    ``eth_getCode`` returns bytecode for ``_CONTRACT_ADDRS`` (→ ``contract``) and
    ``0x`` otherwise (→ ``eoa``); every ``eth_call`` probe is absent (``0x``)."""
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
    """A Base L2Vault whose five authorities span every cross-chain arm plus two
    native controls (the same-harness true-negative)."""
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
    """Resolved control graph carrying the target and the L1 owner Safe as an
    in-scope on-chain reference (so ``_known_addresses_for_scope`` surfaces it,
    which is what lets the aliased-owner arithmetic resolve)."""
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


# --- build_principal_labels, real classify wire ------------------------------


def test_base_positive_arm_and_native_true_negative_through_real_classify(wire):
    """Base run: aliased L1 owner, messenger, and bridge classify as
    ``cross_chain_authority`` with no RPC; native owners fall through to the
    real classifier (stubbed wire) and are typed ``eoa``/``contract``."""
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

    # Aliased L1 owner: labelled, with the implied L1 address as a hint only.
    aliased = principals[ALIASED_L1_OWNER]
    assert aliased["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert aliased["details"]["role"] == "aliased_l1_owner"
    assert aliased["details"]["implied_l1_address"] == L1_PROXY_ADMIN_OWNER
    assert aliased["display_name"] == f"Aliased L1 owner ({L1_PROXY_ADMIN_OWNER})"
    assert "cross_chain_authority" in aliased["labels"]

    # Bridge predeploys: labelled from the registry.
    assert principals[BASE_MESSENGER]["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principals[BASE_MESSENGER]["details"]["role"] == "cross_domain_messenger"
    assert principals[BASE_BRIDGE]["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principals[BASE_BRIDGE]["details"]["role"] == "bridge_executor"

    # Native owners: typed by the REAL classifier, never cross-chain.
    assert principals[NATIVE_EOA_OWNER]["resolved_type"] == "eoa"
    assert "cross_chain_authority" not in principals[NATIVE_EOA_OWNER]["labels"]
    assert principals[NATIVE_CONTRACT_OWNER]["resolved_type"] == "contract"
    assert "cross_chain_authority" not in principals[NATIVE_CONTRACT_OWNER]["labels"]

    # The in-scope L1 reference is not itself an alias of anything in scope, so
    # it is classified natively — the hint is a hint, not a control edge.
    assert principals[L1_PROXY_ADMIN_OWNER]["resolved_type"] != CROSS_CHAIN_AUTHORITY_TYPE


def test_recognized_principals_never_touch_the_wire(wire):
    """The recognizer runs before classification, so an aliased/bridge principal
    issues zero RPCs; only the native owners (and the L1 reference) do."""
    ep = _base_effective_permissions()
    graph = _scope_graph()
    recognizer = make_cross_chain_recognizer(BASE_CHAIN_ID, _known_addresses_for_scope(graph, TARGET))

    build_principal_labels(
        ep,
        resolved_control_graph=graph,
        rpc_url="http://base.rpc.example",
        classify_cache={},
        cross_chain_recognizer=recognizer,
    )
    probed = set(wire)

    assert ALIASED_L1_OWNER not in probed
    assert BASE_MESSENGER not in probed
    assert BASE_BRIDGE not in probed
    # Native principals + the L1 reference reach the real classifier.
    assert NATIVE_EOA_OWNER in probed
    assert NATIVE_CONTRACT_OWNER in probed
    assert L1_PROXY_ADMIN_OWNER in probed


def test_mainnet_run_classifies_everything_through_the_wire(wire):
    """chain_id=1 → recognizer is None: the Base predeploy / aliased addresses
    carry no special meaning and are classified by the real wire path, so none
    is labelled cross-chain and each is probed."""
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


# --- FunctionPrincipal type resolver, real classify wire ---------------------


def test_fp_resolver_labels_bridge_without_wire_and_types_native(wire):
    """The FunctionPrincipal writer's resolver (policy_worker line ~513): the
    recognizer wins for the bridge with no RPC; a native contract falls through
    to the real classifier."""
    recognize = _make_principal_type_resolver({}, "http://base.rpc.example", make_cross_chain_recognizer(BASE_CHAIN_ID))

    kind, details = recognize(BASE_BRIDGE)
    assert kind == CROSS_CHAIN_AUTHORITY_TYPE
    assert details is not None and details["role"] == "bridge_executor"
    assert BASE_BRIDGE.lower() not in set(wire)

    kind, _details = recognize(NATIVE_CONTRACT_OWNER)
    assert kind == "contract"
    assert NATIVE_CONTRACT_OWNER.lower() in set(wire)


# --- policy_worker chain-id → recognizer wiring (inertness) ------------------


def _job(*, chain_id, chain=None, address=TARGET) -> Any:
    """A ``_chain_id_for_job``-shaped stand-in (it reads only ``chain_id`` /
    ``address`` / ``request``), typed ``Any`` so the helper's ``Job`` param
    accepts it without a DB row."""
    return SimpleNamespace(id="j", chain_id=chain_id, address=address, request={"chain": chain} if chain else {})


def test_base_job_yields_live_recognizer_mainnet_job_yields_none():
    """The exact policy_worker derivation: a Base job (first-class chain_id or a
    request chain name) binds a recognizer; a mainnet job binds None so the
    classification path is byte-identical to pre-multichain main."""
    base_by_id = _job(chain_id=BASE_CHAIN_ID)
    assert _chain_id_for_job(base_by_id) == BASE_CHAIN_ID
    rec = make_cross_chain_recognizer(_chain_id_for_job(base_by_id), _known_addresses_for_scope({}, TARGET))
    assert rec is not None
    assert rec(BASE_MESSENGER) == (
        CROSS_CHAIN_AUTHORITY_TYPE,
        {"address": BASE_MESSENGER, "role": "cross_domain_messenger"},
    )

    # Chain derived from the request JSONB when the column is unset.
    base_by_name = _job(chain_id=None, chain="base")
    assert _chain_id_for_job(base_by_name) == BASE_CHAIN_ID
    assert make_cross_chain_recognizer(_chain_id_for_job(base_by_name)) is not None

    mainnet_job = _job(chain_id=1)
    assert _chain_id_for_job(mainnet_job) == 1
    assert make_cross_chain_recognizer(_chain_id_for_job(mainnet_job), _known_addresses_for_scope({}, TARGET)) is None
