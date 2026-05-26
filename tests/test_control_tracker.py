import sys
import threading
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from eth_abi.abi import encode

from schemas.control_tracking import ControlTrackingPlan, TrackedController
from services.resolution.tracking import build_control_snapshot, clear_classify_cache
from services.resolution.tracking import (
    classify_resolved_address as _classify_resolved_address,
)
from services.resolution.tracking_plan import is_primitive_scalar_read_spec
from utils.rpc import selector


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    # Process-wide classify cache leaks across test files when xdist/pytest-cov
    # serializes them in worker order — clear before each test so mocked RPC
    # responses aren't shadowed by a stale entry from a sibling file.
    clear_classify_cache()
    yield
    clear_classify_cache()


def test_build_control_snapshot(monkeypatch):
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": None,
                "tracking_mode": "event_plus_state",
                "event_watch": {
                    "transport": "wss_logs",
                    "contract_address": "0x1111111111111111111111111111111111111111",
                    "events": [
                        {
                            "name": "OwnershipTransferred",
                            "signature": "OwnershipTransferred(address,address)",
                            "topic0": "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                            "inputs": [
                                {"name": "user", "type": "address", "indexed": True},
                                {"name": "newOwner", "type": "address", "indexed": True},
                            ],
                        }
                    ],
                    "writer_functions": ["transferOwnership(address)"],
                },
                "polling_fallback": {
                    "contract_address": "0x1111111111111111111111111111111111111111",
                    "polling_sources": ["owner"],
                    "cadence": "realtime_confirm",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    state = {"owner": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

    def fake_rpc(_rpc_url, method, params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            return "0x" + "00" * 12 + state["owner"]
        if method == "eth_getCode":
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method} {params}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    first = build_control_snapshot(plan, "https://rpc.example")
    state["owner"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    second = build_control_snapshot(plan, "https://rpc.example")

    assert first["controller_values"]["state_variable:owner"]["value"] == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert first["controller_values"]["state_variable:owner"]["resolved_type"] == "eoa"
    assert second["controller_values"]["state_variable:owner"]["value"] == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_build_control_snapshot_decodes_projected_struct_address(monkeypatch):
    payout = "0x2222222222222222222222222222222222222222"
    raw_struct = "0x" + encode(["address", "uint96", "bool"], [payout, 123, False]).hex()
    contract_address = "0x1111111111111111111111111111111111111111"
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": contract_address,
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:accountantState.payoutAddress",
                "label": "accountantState.payoutAddress",
                "source": "accountantState.payoutAddress",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "accountantState",
                    "kind": "state_variable",
                    "state_variable_name": "accountantState",
                    "type": "address",
                    "type_kind": "address",
                    "parent_type": "Mock.AccountantState",
                    "member_path": ["payoutAddress"],
                    "components": [
                        {"name": "payoutAddress", "type": "address", "abi_type": "address", "type_kind": "address"},
                        {"name": "highwaterMark", "type": "uint96", "abi_type": "uint96", "type_kind": "primitive"},
                        {"name": "isPaused", "type": "bool", "abi_type": "bool", "type_kind": "primitive"},
                    ],
                },
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": contract_address,
                    "polling_sources": ["accountantState"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    def fake_rpc(_rpc_url, method, params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            call = params[0]
            if call.get("to") == contract_address:
                return raw_struct
            return "0x"
        if method == "eth_getCode":
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method} {params}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    snapshot = build_control_snapshot(plan, "https://rpc.example")

    value = snapshot["controller_values"]["state_variable:accountantState.payoutAddress"]
    assert value["value"] == payout
    assert value["resolved_type"] == "eoa"


def test_build_control_snapshot_heartbeats_while_reading_latest_block(monkeypatch):
    monkeypatch.setenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "0.01")
    release = threading.Event()
    counter = {"n": 0}
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [],
    }

    def slow_current_block(_rpc_url: str) -> int:
        assert release.wait(timeout=2)
        return 16

    def heartbeat() -> None:
        counter["n"] += 1
        release.set()

    monkeypatch.setattr("services.resolution.tracking._current_block_number", slow_current_block)

    snapshot = build_control_snapshot(plan, "https://rpc.example", heartbeat=heartbeat)

    assert snapshot["block_number"] == 16
    assert counter["n"] >= 1


def test_build_control_snapshot_handles_reverting_getter(monkeypatch):
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": None,
                "tracking_mode": "event_plus_state",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": "0x1111111111111111111111111111111111111111",
                    "polling_sources": ["owner"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    def fake_rpc(_rpc_url, method, _params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            raise RuntimeError("{'code': 3, 'message': 'execution reverted', 'data': '0x'}")
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    snapshot = build_control_snapshot(plan, "https://rpc.example")
    value = snapshot["controller_values"]["state_variable:owner"]

    assert value["value"] is None
    assert value["observed_via"] == "eth_call_error"
    assert value["resolved_type"] == "unknown"
    assert "execution reverted" in str(value["details"]["error"])


def test_build_control_snapshot_recovers_immutable_getter_via_impl_fallback(monkeypatch):
    """Regression mirroring real EtherFi data (EtherFiNode): authority addresses
    declared ``immutable`` live in the implementation bytecode, not proxy
    storage. EtherFiNode's runtime/proxy address (0x3c55986c) does not
    delegatecall to its analyzed impl (0xa91f8a52) — its EIP-1967/beacon slots
    are zero — so ``etherFiNodesManager()`` reverts there but resolves on the
    impl. The snapshot must fall back to the impl address so the controller is
    recovered, not recorded null (which left 13 EtherFiNode functions ownerless
    on the Surface, with the EtherFiNodesManager controller missing entirely).
    """
    proxy = "0x3c55986cfee455e2533f4d29006634ecf9b7c03f"  # runtime addr — getter reverts here
    impl = "0xa91f8a52f0c1b4d3fdc256fc5bebca4d627da392"  # immutable lives in this bytecode
    manager = "8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"  # EtherFiNodesManager
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": proxy,
        "contract_name": "EtherFiNode",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:etherFiNodesManager",
                "label": "etherFiNodesManager",
                "source": "etherFiNodesManager",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "etherFiNodesManager",
                    "kind": "state_variable",
                    "type": "address",
                    "type_kind": "address",
                },
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": proxy,
                    "polling_sources": ["etherFiNodesManager"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    def fake_rpc(_rpc_url, method, params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            to = params[0]["to"].lower()
            if to == proxy:  # immutable getter reverts on the non-delegating proxy
                raise RuntimeError("{'code': 3, 'message': 'execution reverted', 'data': '0x'}")
            if to == impl:  # resolves on the implementation where the immutable lives
                return "0x" + "00" * 12 + manager
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)
    monkeypatch.setattr(
        "services.resolution.tracking.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest": ("contract", {"address": address}),
    )

    # With the impl fallback, the reverting proxy read recovers from the impl.
    recovered = build_control_snapshot(plan, "https://rpc.example", getter_fallback_address=impl)
    cv = recovered["controller_values"]["state_variable:etherFiNodesManager"]
    assert cv["value"] == "0x" + manager, f"expected impl-fallback to recover the manager; got {cv}"
    assert cv["observed_via"] == "eth_call_impl_fallback"
    assert cv["resolved_type"] == "contract"

    # Without a fallback (the default), the prior behavior holds: recorded null.
    nulled = build_control_snapshot(plan, "https://rpc.example")
    cv2 = nulled["controller_values"]["state_variable:etherFiNodesManager"]
    assert cv2["value"] is None
    assert cv2["observed_via"] == "eth_call_error"


def test_build_control_snapshot_preserves_role_identifier_for_capability_resolver(monkeypatch):
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "role_identifier:PAUSE_ROLE",
                "label": "PAUSE_ROLE",
                "source": "PAUSE_ROLE",
                "kind": "role_identifier",
                "read_spec": None,
                "tracking_mode": "manual_review",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": "0x1111111111111111111111111111111111111111",
                    "polling_sources": ["PAUSE_ROLE"],
                    "cadence": "periodic_reconciliation",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    def fake_rpc(_rpc_url, method, _params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            return "0x" + "11" * 32
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    snapshot = build_control_snapshot(plan, "https://rpc.example")
    value = snapshot["controller_values"]["role_identifier:PAUSE_ROLE"]

    assert value["value"] == "0x" + "11" * 32
    assert value["observed_via"] == "eth_call"
    assert value["details"] == {
        "source": "PAUSE_ROLE",
        "role_id": "0x" + "11" * 32,
        "authority_contract": "0x1111111111111111111111111111111111111111",
        "principal_source": "capability_expr",
    }


def test_classify_resolved_address_detects_safe(monkeypatch):
    def fake_rpc(_rpc_url, method, params):
        if method == "eth_getCode":
            return "0x6000"
        if method == "eth_call":
            data = params[0]["data"]
            if data == "0xa0e67e2b":
                encoded = (
                    "0000000000000000000000000000000000000000000000000000000000000020"
                    "0000000000000000000000000000000000000000000000000000000000000002"
                    "0000000000000000000000001111111111111111111111111111111111111111"
                    "0000000000000000000000002222222222222222222222222222222222222222"
                )
                return "0x" + encoded
            if data == "0xe75235b8":
                return "0x" + "0" * 63 + "2"
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method} {params}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    resolved_type, details = _classify_resolved_address(
        "https://rpc.example",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )

    assert resolved_type == "safe"
    assert details == {
        "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "owners": [
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        ],
        "threshold": 2,
    }


def test_classify_resolved_address_detects_timelock(monkeypatch):
    def fake_rpc(_rpc_url, method, params):
        if method == "eth_getCode":
            return "0x6000"
        if method == "eth_call":
            data = params[0]["data"]
            if data == "0xf27a0c92":
                return "0x" + "0" * 60 + "2a30"
            if data == "0x8da5cb5b":
                return "0x" + "00" * 12 + "3333333333333333333333333333333333333333"
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method} {params}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    resolved_type, details = _classify_resolved_address(
        "https://rpc.example",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )

    assert resolved_type == "timelock"
    assert details == {
        "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "delay": 10800,
        "owner": "0x3333333333333333333333333333333333333333",
    }


def test_classify_resolved_address_detects_proxy_admin(monkeypatch):
    def fake_rpc(_rpc_url, method, params):
        if method == "eth_getCode":
            return "0x6000"
        if method == "eth_call":
            data = params[0]["data"]
            if data == "0xad3cb1cc":
                encoded = (
                    "0000000000000000000000000000000000000000000000000000000000000020"
                    "0000000000000000000000000000000000000000000000000000000000000001"
                    "3500000000000000000000000000000000000000000000000000000000000000"
                )
                return "0x" + encoded
            if data == "0x8da5cb5b":
                return "0x" + "00" * 12 + "4444444444444444444444444444444444444444"
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method} {params}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    resolved_type, details = _classify_resolved_address(
        "https://rpc.example",
        "0xcccccccccccccccccccccccccccccccccccccccc",
    )

    assert resolved_type == "proxy_admin"
    assert details == {
        "address": "0xcccccccccccccccccccccccccccccccccccccccc",
        "upgrade_interface_version": "5",
        "owner": "0x4444444444444444444444444444444444444444",
    }


# ---------------------------------------------------------------------------
# build_control_snapshot parity: parallel + sequential produce identical output.
# ---------------------------------------------------------------------------


def _snapshot_parity_helper(monkeypatch, fanout: str):
    """Run a multi-controller fixture under the given fanout."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
    target = "0x1111111111111111111111111111111111111111"

    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": target,
        "contract_name": "MockMultiController",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:registry",
                "label": "registry",
                "source": "registry",
                "kind": "state_variable",
                "read_spec": None,
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": target,
                    "polling_sources": ["registry"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            },
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": None,
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": target,
                    "polling_sources": ["owner"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            },
            {
                "controller_id": "state_variable:guardian",
                "label": "guardian",
                "source": "guardian",
                "kind": "state_variable",
                "read_spec": None,
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": target,
                    "polling_sources": ["guardian"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            },
        ],
    }

    def fake_rpc(_rpc_url, method, params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            to = params[0]["to"].lower()
            data = params[0]["data"]
            if to == target:
                if data[:10] == "0x7b103999":  # registry()
                    return "0x" + "00" * 12 + "22" * 20
                if data[:10] == "0x8da5cb5b":  # owner()
                    return "0x" + "00" * 12 + "33" * 20
                if data[:10] == "0x452a9320":  # guardian()
                    return "0x" + "00" * 12 + "44" * 20
                return "0x" + "00" * 32
            return "0x" + "00" * 32
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)
    monkeypatch.setattr(
        "services.resolution.tracking.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest": ("contract", {"address": address}),
    )
    return build_control_snapshot(plan, "https://rpc.example")


def test_build_control_snapshot_parity_parallel_vs_sequential(monkeypatch):
    """Controller polling should resolve identically in both modes."""
    seq = _snapshot_parity_helper(monkeypatch, "1")
    par = _snapshot_parity_helper(monkeypatch, "8")

    # Compare canonicalised form: sort controller_values by key for stable
    # comparison (dict iteration order in CPython is insertion order, which
    # may differ between sequential and parallel paths).
    def _canon(snapshot):
        return {
            "block_number": snapshot["block_number"],
            "contract_address": snapshot["contract_address"],
            "contract_name": snapshot["contract_name"],
            "controller_values": dict(sorted(snapshot["controller_values"].items())),
        }

    assert _canon(seq) == _canon(par)


# ---------------------------------------------------------------------------
# Phantom-EOA regression. tracking_plan admits non-address state vars (uints,
# bools, mappings) so the *event* pathway can watch them, on the documented
# promise that "the poller filters by type_kind itself". build_control_snapshot
# is that poller for the resolution pathway — and the single choke point whose
# controller_values feed the ControllerValue table, the recursive control graph
# (recursive.py:911), and effective_permissions, all of which read ``value`` as
# a 0x-address. Before the fix it read every tracked controller's slot and ran
# classify_resolved_address on it: a scalar < 2**160 (e.g. uint _minDelay ==
# 864000) coerces to a no-code address, classifies "eoa", and is promoted to a
# controller of every contract declaring that variable. These are the real
# etherfi phantoms observed on the PR95 live DB.
# ---------------------------------------------------------------------------


def test_build_control_snapshot_skips_non_address_state_vars(monkeypatch):
    """Primitive-scalar state vars must not enter the value snapshot as principals.

    Uses the exact live PR95 read_specs (``type_kind="primitive"``,
    ``strategy="getter_call"`` with a target getter) and the real scalar values
    those getters return, driving the real snapshot builder (block read,
    parallel_map, decode, classify). Only the address-typed ``owner`` should
    survive; if the guard regresses, the scalar getters get polled + classified
    "eoa" and the set-equality assertion below fails.
    """
    target = "0x1111111111111111111111111111111111111111"
    owner_addr = "cc" * 20

    def _sv(source: str, read_spec: Any) -> TrackedController:
        return {
            "controller_id": f"state_variable:{source}",
            "label": source,
            "source": source,
            "kind": "state_variable",
            "read_spec": read_spec,
            "tracking_mode": "event_plus_state",
            "event_watch": None,
            "polling_fallback": {
                "contract_address": target,
                "polling_sources": [source],
                "cadence": "state_only",
                "notes": [],
            },
            "notes": [],
        }

    def _primitive(getter: str, sol_type: str) -> dict[str, str]:
        # Verbatim shape the static stage emits for a primitive state var.
        return {
            "strategy": "getter_call",
            "target": getter,
            "kind": "state_variable",
            "type": sol_type,
            "type_kind": "primitive",
        }

    # (source, read_spec, scalar the getter returns) — verbatim live PR95
    # phantoms. Each scalar is < 2**160, so absent the guard it coerces to a
    # no-code address and classifies "eoa".
    scalars = [
        ("_minDelay", _primitive("getMinDelay", "uint256"), 864_000),
        ("threshold", _primitive("threshold", "uint256"), 3),
        ("maxBidAmount", _primitive("maxBidAmount", "uint64"), 5 * 10**18),
        ("BEACON_GENESIS_TIME", _primitive("beaconGenesisTimestamp", "uint32"), 1_606_824_023),
        ("executorRequired", _primitive("executorRequired", "bool"), 1),
        ("eapMerkleRoot", _primitive("eapMerkleRoot", "bytes32"), 0x894CDDB13B9795954D6DA83044AF04D85F90A179),
    ]

    owner_spec = {
        "strategy": "getter_call",
        "target": "owner",
        "kind": "state_variable",
        "type": "address",
        "type_kind": "address",
    }
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": target,
        "contract_name": "MockMixedTypes",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [_sv("owner", owner_spec), *[_sv(src, rs) for src, rs, _v in scalars]],
    }

    # Map each getter selector (keyed by read_spec target) to its 32-byte word,
    # so that *if the guard were removed* the scalars would be read + coerced.
    word_by_selector = {selector(f"{rs['target']}()"): "0x" + format(val, "064x") for _src, rs, val in scalars}
    word_by_selector[selector("owner()")] = "0x" + "00" * 12 + owner_addr

    def fake_rpc(_rpc_url, method, params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            data = params[0]["data"]
            if data not in word_by_selector:
                raise AssertionError(f"Unexpected getter selector: {data}")
            return word_by_selector[data]
        if method == "eth_getCode":
            return "0x"  # no code anywhere -> scalars would all classify "eoa"
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    snapshot = build_control_snapshot(plan, "https://rpc.example")
    cvs = snapshot["controller_values"]

    # The address-typed controller survives and resolves normally...
    assert set(cvs) == {"state_variable:owner"}
    assert cvs["state_variable:owner"]["value"] == "0x" + owner_addr
    assert cvs["state_variable:owner"]["resolved_type"] == "eoa"

    # ...and not one primitive slot produced a (phantom) controller value, so no
    # downstream consumer can mint an "eoa" principal from them.
    for src, _rs, _v in scalars:
        assert f"state_variable:{src}" not in cvs


def test_build_control_snapshot_keeps_address_var_with_missing_type(monkeypatch):
    """The guard is conservative: a state var with no/unknown type info is
    still classified, so real address principals are never dropped when the
    static stage failed to record a type_kind."""
    target = "0x1111111111111111111111111111111111111111"
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": target,
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": None,  # no type info recorded
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": target,
                    "polling_sources": ["owner"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    def fake_rpc(_rpc_url, method, _params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            return "0x" + "00" * 12 + "ab" * 20
        if method == "eth_getCode":
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    snapshot = build_control_snapshot(plan, "https://rpc.example")
    assert snapshot["controller_values"]["state_variable:owner"]["value"] == "0x" + "ab" * 20


def test_build_control_snapshot_keeps_non_primitive_controllers(monkeypatch):
    """The guard skips ONLY primitive scalars. A mapping-typed state var
    (e.g. an OZ AccessControl ``_roles`` / etherfi ``registered`` role map,
    type_kind="mapping") must pass through untouched — a bare getter reverts on
    it (value=None) and its members are enumerated elsewhere — so the real Safe
    principals enumerated from those maps are never dropped.
    """
    target = "0x1111111111111111111111111111111111111111"
    plan: ControlTrackingPlan = {
        "schema_version": "0.1",
        "contract_address": target,
        "contract_name": "Mock",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:registered",
                "label": "registered",
                "source": "registered",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "registered",
                    "kind": "state_variable",
                    "type": "mapping(address => bool)",
                    "type_kind": "mapping",
                },
                "tracking_mode": "event_plus_state",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": target,
                    "polling_sources": ["registered"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }

    def fake_rpc(_rpc_url, method, _params):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_call":
            raise RuntimeError("execution reverted")  # bare mapping getter reverts
        raise AssertionError(f"Unexpected RPC call: {method}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    cvs = build_control_snapshot(plan, "https://rpc.example")["controller_values"]
    # Not skipped: the mapping controller still appears (as a reverting/unknown
    # entry), exactly as before the fix — so mapping enumeration is untouched.
    assert "state_variable:registered" in cvs
    assert cvs["state_variable:registered"]["value"] is None
    assert cvs["state_variable:registered"]["resolved_type"] == "unknown"


@pytest.mark.parametrize(
    "read_spec, expected",
    [
        # Primitive scalars (the phantom source) -> True == skip from snapshot.
        ({"type_kind": "primitive"}, True),  # the live shape for uint/bool/bytes
        ({"type_kind": "primitive", "type": "uint64"}, True),
        ({"type": "uint256"}, True),  # type-only fallback (no type_kind)
        ({"type": "bool"}, True),
        ({"type": "bytes32"}, True),
        ({"type": "int128"}, True),
        # Real principals / enumerated refs -> False == keep.
        ({"type_kind": "address"}, False),
        ({"type_kind": "contract"}, False),
        ({"type_kind": "mapping"}, False),  # role maps -> real Safe members
        ({"type_kind": "array"}, False),
        ({"type_kind": "struct"}, False),
        ({"type_kind": "unknown"}, False),  # ambiguous -> conservatively kept
        ({"type": "address"}, False),
        (None, False),  # missing read_spec -> kept
        ({}, False),  # no type info -> kept
    ],
)
def test_is_primitive_scalar_read_spec(read_spec, expected):
    assert is_primitive_scalar_read_spec(read_spec) is expected
