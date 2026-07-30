"""D6-reject: which ``bytes32`` constants may be minted as role names.

``role_definitions`` carried two rows that are not roles at all —
``AccessControlDefaultAdminRulesStorageLocation`` (contract 454) and
``OwnableStorageLocation`` (contract 623) — because leaf admission accepted any
``bytes32 constant`` operand of a caller-authority leaf. Both are ERC-7201
storage-layout pointers.

The fix is structural, in two arms, and neither reads an identifier:

* **mapping** — ``kind="membership"`` + ``mapping_membership`` descriptor.
* **external** — ``kind="external_bool"`` + ``external_set`` descriptor whose
  callee is exactly ``hasRole(bytes32,address)`` and whose argument POSITIONS
  witness which operand is the role and which is the subject.

Both require an empty ``member_path``.

A first attempt admitted **any** ``external_set`` descriptor. That is a defaulted
witness: ``_build_external_bool_leaf`` fills ``key_sources`` from every call
argument, so "is an argument of a gate-shaped view call" stood in for key-ness.
``TestExternalArmHostileShapes`` compiles the three counter-examples that
produced through the real pipeline — a slot constant, a merkle root and a CREATE2
salt, all minted as roles — and pins them at zero.

Every leaf below marked REAL is verbatim from the persisted predicate_trees
blobs of the PR-161 run (MinIO ``pr-161/artifacts/<job>/predicate_trees``):
contract 454 CumulativeMerkleDrop, 623 EtherfiL1SyncPoolETH, 599
WithdrawalQueueERC721.

The two suffix HOSTILE fixtures are the ones the name-suffix guard
``tracking._is_storage_layout_constant`` gets wrong in BOTH directions; it is
banned as the fix for exactly that reason, and ``test_name_suffix_guard_*``
below pins the misclassification so the ban stays evidence-backed.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _HAS_ROLE_SELECTOR,
    _role_names_from_predicate_trees,
    _role_names_from_tree,
)
from services.static.contract_analysis_pipeline.tracking import _is_storage_layout_constant  # noqa: E402


class _Bytes32Constant:
    """The two facts ``_is_bytes32_constant`` reads off a Slither state var."""

    type = "bytes32"
    is_constant = True


def _vars(*names: str) -> dict[str, _Bytes32Constant]:
    return {name: _Bytes32Constant() for name in names}


def _leaf(node: dict) -> dict:
    return {"op": "LEAF", "leaf": node}


# --- REAL leaves, verbatim from the persisted blobs ------------------------

# contract 454, pause() — PAUSER_ROLE. The RoleGranted/RoleRevoked
# enumeration_hint is reproduced because its PRESENCE must not be what admits
# the leaf (see test_role_leaf_without_enumeration_hint_is_still_admitted).
REAL_PAUSER_ROLE_LEAF = {
    "kind": "membership",
    "operator": "truthy",
    "authority_role": "caller_authority",
    "operands": [
        {"source": "state_variable", "state_variable_name": "PAUSER_ROLE"},
        {"source": "msg_sender"},
    ],
    "references_msg_sender": True,
    "parameter_indices": [],
    "expression": "return REF_665",
    "basis": ["if-revert via always-reverting branch"],
    "set_descriptor": {
        "kind": "mapping_membership",
        "key_sources": [
            {"source": "state_variable", "state_variable_name": "PAUSER_ROLE"},
            {"source": "msg_sender"},
        ],
        "storage_var": "_roles",
        "enumeration_hint": [
            {
                "topic0": "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",
                "topics_to_keys": {"1": 0, "2": 1},
                "data_to_keys": {},
                "direction": "add",
                "event_signature": "RoleGranted(bytes32,address,address)",
                "event_name": "RoleGranted",
                "mapping_name": "_roles",
                "key_position": 1,
                "indexed_positions": [0, 1, 2],
                "value_position": None,
                "writer_function": "_grantRole(bytes32,address)",
            },
            {
                "topic0": "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b",
                "topics_to_keys": {"1": 0, "2": 1},
                "data_to_keys": {},
                "direction": "remove",
                "event_signature": "RoleRevoked(bytes32,address,address)",
                "event_name": "RoleRevoked",
                "mapping_name": "_roles",
                "key_position": 1,
                "indexed_positions": [0, 1, 2],
                "value_position": None,
                "writer_function": "_revokeRole(bytes32,address)",
            },
        ],
    },
    "confidence": "high",
}

# contract 599, finalize(uint256,uint256) — FINALIZE_ROLE. NOTE: storage_var is
# the compiler temporary ``TMP_1189``, not ``_roles``, and there is NO
# enumeration_hint. Gating on either would drop this and the other four Lido
# roles on 599 (MANAGE_TOKEN_URI / ORACLE / PAUSE / RESUME).
REAL_FINALIZE_ROLE_LEAF = {
    "kind": "membership",
    "operator": "truthy",
    "authority_role": "caller_authority",
    "operands": [
        {"source": "state_variable", "state_variable_name": "FINALIZE_ROLE"},
        {"source": "msg_sender"},
    ],
    "references_msg_sender": True,
    "parameter_indices": [],
    "expression": "return REF_555",
    "basis": ["if-revert via always-reverting branch"],
    "set_descriptor": {
        "kind": "mapping_membership",
        "key_sources": [
            {"source": "state_variable", "state_variable_name": "FINALIZE_ROLE"},
            {"source": "msg_sender"},
        ],
        "storage_var": "TMP_1189",
    },
    "confidence": "high",
}

# contract 623, setTokenOut(address) — the OZ-v5 Ownable slot pointer, mis-minted
# as role_definitions id 19.
REAL_OWNABLE_SLOT_LEAF = {
    "kind": "equality",
    "operator": "eq",
    "authority_role": "caller_authority",
    "operands": [
        {
            "source": "state_variable",
            "state_variable_name": "OwnableStorageLocation",
            "member_path": ["_owner"],
        },
        {"source": "msg_sender"},
    ],
    "references_msg_sender": True,
    "parameter_indices": [],
    "expression": "owner() != _msgSender()",
    "basis": ["if-revert via always-reverting branch"],
    "confidence": "high",
}

# contract 454, acceptDefaultAdminTransfer() — mis-minted as role_definitions id 1.
REAL_DEFAULT_ADMIN_RULES_SLOT_LEAF = {
    "kind": "equality",
    "operator": "eq",
    "authority_role": "caller_authority",
    "operands": [
        {"source": "msg_sender"},
        {
            "source": "state_variable",
            "state_variable_name": "AccessControlDefaultAdminRulesStorageLocation",
            "member_path": ["_pendingDefaultAdmin"],
        },
    ],
    "references_msg_sender": True,
    "parameter_indices": [],
    "expression": "_msgSender() != newDefaultAdmin",
    "basis": ["if-revert via always-reverting branch"],
    "confidence": "high",
}


def test_real_role_leaves_are_admitted():
    """The two REAL measured role leaves mint their role names."""
    trees = {"trees": {"pause()": _leaf(REAL_PAUSER_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("PAUSER_ROLE")) == {"PAUSER_ROLE"}

    trees = {"trees": {"finalize(uint256,uint256)": _leaf(REAL_FINALIZE_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("FINALIZE_ROLE")) == {"FINALIZE_ROLE"}


# A cross-contract ``registry.hasRole(ROLE, msg.sender)`` gate, as the lowering
# emits it (compiled from the source in
# tests/test_semantic_control_summary.py::test_role_definitions_from_predicate_role_keys).
# The set is external rather than an in-contract mapping, but the constant is
# still a KEY of the set being tested — and here the compiler even resolved the
# keccak preimage onto the operand.
REAL_EXTERNAL_REGISTRY_ROLE_LEAF = {
    "kind": "external_bool",
    "operator": "truthy",
    "authority_role": "delegated_authority",
    "operands": [
        {
            "source": "state_variable",
            "state_variable_name": "MINTER_ROLE",
            "constant_value": "0xf0887ba65ee2024ea881d91b74c2450ef19e1557f03bed3ea9f16b037cbe2dc9",
        },
        {"source": "msg_sender"},
    ],
    "references_msg_sender": True,
    "parameter_indices": [],
    "expression": "hasRole(...)",
    "basis": ["require(TMP_0)"],
    "callee_state_mutability": "view",
    "gate_kind": "require",
    "callee_signature": "hasRole(bytes32,address)",
    "set_descriptor": {
        "kind": "external_set",
        "key_sources": [
            {
                "source": "state_variable",
                "state_variable_name": "MINTER_ROLE",
                "constant_value": "0xf0887ba65ee2024ea881d91b74c2450ef19e1557f03bed3ea9f16b037cbe2dc9",
            },
            {"source": "msg_sender"},
        ],
        "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}},
        "callee_function": "hasRole",
        "callee_signature": "hasRole(bytes32,address)",
        "callee_selector": "0x91d14854",
    },
    "confidence": "medium",
}


def test_external_registry_role_leaf_is_admitted():
    """A delegated ``hasRole`` gate names a real role. Admitted on the SELECTOR
    (exactly ``hasRole(bytes32,address)``) plus the argument POSITIONS — the
    constant in arg 0, a caller-tainted operand in arg 1 — never on "the leaf has
    an external_set descriptor"."""
    assert REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"]["callee_selector"] == _HAS_ROLE_SELECTOR
    trees = {"trees": {"mint()": _leaf(REAL_EXTERNAL_REGISTRY_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("MINTER_ROLE")) == {"MINTER_ROLE"}


def test_external_arm_rejects_a_non_hasrole_selector():
    """Same descriptor kind, same key positions, different callee ⇒ nothing. The
    ABI is what makes argument 0 a role identifier."""
    descriptor = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"], "callee_selector": "0xdeadbeef"}
    leaf = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("MINTER_ROLE")) == set()


def test_external_arm_rejects_a_missing_selector():
    descriptor = {k: v for k, v in REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"].items() if k != "callee_selector"}
    leaf = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("MINTER_ROLE")) == set()


def test_external_arm_rejects_the_constant_outside_the_role_position():
    """The bytes32 constant sitting in the ACCOUNT argument is not a role, even
    under the right selector."""
    swapped = list(reversed(REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"]["key_sources"]))
    descriptor = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"], "key_sources": swapped}
    leaf = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("MINTER_ROLE")) == set()


def test_external_arm_rejects_an_uncaller_tainted_account_argument():
    """``registry.hasRole(ROLE, someStoredAddress)`` does not gate on the caller,
    so the constant is not witnessed as gating THIS function's caller."""
    keys = [
        REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"]["key_sources"][0],
        {"source": "state_variable", "state_variable_name": "treasury"},
    ]
    descriptor = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"], "key_sources": keys}
    leaf = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("MINTER_ROLE")) == set()


def test_external_arm_rejects_a_single_argument_callee():
    descriptor = {
        **REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"],
        "key_sources": REAL_EXTERNAL_REGISTRY_ROLE_LEAF["set_descriptor"]["key_sources"][:1],
    }
    leaf = {**REAL_EXTERNAL_REGISTRY_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("MINTER_ROLE")) == set()


def test_real_slot_constant_leaves_are_rejected():
    """The two REAL measured slot-constant leaves — role_definitions ids 19 and
    1 — mint nothing."""
    trees = {"trees": {"setTokenOut(address)": _leaf(REAL_OWNABLE_SLOT_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("OwnableStorageLocation")) == set()

    trees = {"trees": {"acceptDefaultAdminTransfer()": _leaf(REAL_DEFAULT_ADMIN_RULES_SLOT_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("AccessControlDefaultAdminRulesStorageLocation")) == set()


def test_real_mixed_contract_admits_only_the_roles():
    """Contract 454 carries both shapes; the three roles survive, the pointer does not."""
    admin_leaf = {
        **REAL_PAUSER_ROLE_LEAF,
        "operands": [
            {"source": "state_variable", "state_variable_name": "DEFAULT_ADMIN_ROLE"},
            {"source": "msg_sender"},
        ],
    }
    operating_leaf = {
        **REAL_PAUSER_ROLE_LEAF,
        "operands": [
            {"source": "state_variable", "state_variable_name": "OPERATING_ADMIN_ROLE"},
            {"source": "msg_sender"},
        ],
    }
    trees = {
        "trees": {
            "pause()": _leaf(REAL_PAUSER_ROLE_LEAF),
            "setOperator(address)": _leaf(operating_leaf),
            "grantRole(bytes32,address)": _leaf(admin_leaf),
            "acceptDefaultAdminTransfer()": _leaf(REAL_DEFAULT_ADMIN_RULES_SLOT_LEAF),
        }
    }
    names = _vars(
        "PAUSER_ROLE",
        "OPERATING_ADMIN_ROLE",
        "DEFAULT_ADMIN_ROLE",
        "AccessControlDefaultAdminRulesStorageLocation",
    )
    assert _role_names_from_predicate_trees(trees, names) == {
        "PAUSER_ROLE",
        "OPERATING_ADMIN_ROLE",
        "DEFAULT_ADMIN_ROLE",
    }


# --- HOSTILE fixtures: the two the name-suffix guard gets wrong -------------

# A genuine AccessControl role whose constant is named with a slot-locator
# suffix. Structure says role; the suffix rule says storage pointer.
HOSTILE_ROLE_WITH_BANNED_SUFFIX = {
    **REAL_PAUSER_ROLE_LEAF,
    "operands": [
        {"source": "state_variable", "state_variable_name": "GOVERNOR_SLOT"},
        {"source": "msg_sender"},
    ],
    "set_descriptor": {
        **REAL_PAUSER_ROLE_LEAF["set_descriptor"],
        "key_sources": [
            {"source": "state_variable", "state_variable_name": "GOVERNOR_SLOT"},
            {"source": "msg_sender"},
        ],
    },
}

# An ERC-7201 storage pointer with an innocent name. Structure says pointer;
# the suffix rule sees nothing to reject.
HOSTILE_SLOT_WITH_INNOCENT_NAME = {
    **REAL_OWNABLE_SLOT_LEAF,
    "operands": [
        {
            "source": "state_variable",
            "state_variable_name": "MAIN_POINTER",
            "member_path": ["_owner"],
        },
        {"source": "msg_sender"},
    ],
}


def test_hostile_role_with_banned_suffix_is_kept():
    trees = {"trees": {"setGovernor(address)": _leaf(HOSTILE_ROLE_WITH_BANNED_SUFFIX)}}
    assert _role_names_from_predicate_trees(trees, _vars("GOVERNOR_SLOT")) == {"GOVERNOR_SLOT"}


def test_hostile_slot_with_innocent_name_is_dropped():
    trees = {"trees": {"setTokenOut(address)": _leaf(HOSTILE_SLOT_WITH_INNOCENT_NAME)}}
    assert _role_names_from_predicate_trees(trees, _vars("MAIN_POINTER")) == set()


def test_name_suffix_guard_misclassifies_both_hostile_fixtures():
    """Why ``_is_storage_layout_constant`` is banned as the D6 fix: it is wrong
    in both directions on exactly these two inputs, while the structural rule
    above is right on both."""
    assert _is_storage_layout_constant("GOVERNOR_SLOT") is True  # a real role it would drop
    assert _is_storage_layout_constant("MAIN_POINTER") is False  # a real pointer it would keep


# --- fail-closed arms ------------------------------------------------------


def test_membership_leaf_without_set_descriptor_is_rejected():
    """No descriptor ⇒ the mapping was not witnessed ⇒ not a role key."""
    leaf = {k: v for k, v in REAL_PAUSER_ROLE_LEAF.items() if k != "set_descriptor"}
    assert _role_names_from_tree(_leaf(leaf), _vars("PAUSER_ROLE")) == set()


def test_membership_leaf_with_unmeasured_descriptor_kind_is_rejected():
    """``array_contains`` / ``bitwise_role_flag`` / ``diamond_facet_acl``: no
    measured role arrives in those shapes, and an unmeasured shape is not
    evidence."""
    for kind in ("array_contains", "bitwise_role_flag", "diamond_facet_acl"):
        leaf = {**REAL_PAUSER_ROLE_LEAF, "set_descriptor": {"kind": kind}}
        assert _role_names_from_tree(_leaf(leaf), _vars("PAUSER_ROLE")) == set()


def test_mapping_membership_operand_with_member_path_is_rejected():
    """A dereferenced constant is a struct base, not a key — even inside a
    mapping_membership leaf."""
    leaf = {
        **REAL_PAUSER_ROLE_LEAF,
        "operands": [
            {
                "source": "state_variable",
                "state_variable_name": "PAUSER_ROLE",
                "member_path": ["_slotField"],
            },
            {"source": "msg_sender"},
        ],
    }
    assert _role_names_from_tree(_leaf(leaf), _vars("PAUSER_ROLE")) == set()


def test_non_bytes32_constant_operand_is_rejected():
    """The compiler type gate survives the structural one."""

    class _AddressVar:
        type = "address"
        is_constant = False

    assert _role_names_from_tree(_leaf(REAL_PAUSER_ROLE_LEAF), {"PAUSER_ROLE": _AddressVar()}) == set()


def test_unknown_state_var_is_rejected():
    """No state var in scope ⇒ the ``bytes32 constant`` fact was never
    established ⇒ nothing is minted."""
    assert _role_names_from_tree(_leaf(REAL_PAUSER_ROLE_LEAF), {}) == set()
    assert _role_names_from_tree(_leaf(REAL_PAUSER_ROLE_LEAF), None) == set()


def test_role_leaf_without_enumeration_hint_is_still_admitted():
    """The 599 shape: mapping_membership with no enumeration_hint and a
    temporary storage_var. Gating on either would silently drop five real
    roles."""
    descriptor = {k: v for k, v in REAL_FINALIZE_ROLE_LEAF["set_descriptor"].items() if k != "storage_var"}
    leaf = {**REAL_FINALIZE_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("FINALIZE_ROLE")) == {"FINALIZE_ROLE"}


def test_non_authority_membership_leaf_is_rejected():
    leaf = {**REAL_PAUSER_ROLE_LEAF, "authority_role": "business"}
    assert _role_names_from_tree(_leaf(leaf), _vars("PAUSER_ROLE")) == set()


# --- second use-site: the resolution plane's slot-locator route -------------
#
# ``_canonical_authority_selector_for_slot`` reroutes a storage-slot constant to
# the contract's canonical public getter. Reached from ``_resolve_equality_principal``
# for a bare (member_path-less) state-variable operand and gated on the same
# name-suffix guard banned above, so a role constant carrying a slot-locator
# suffix would resolve to a real ``governor()`` address and be published as the
# authorized caller of a role-gated function. The structural refusal closes that
# without touching the guard. Both planes now answer "is this constant a role?"
# the same way, so no constant can be a role in one and a slot in the other.


def test_slot_route_refuses_a_mapping_membership_role_operand():
    from services.resolution.predicate_evaluator import _canonical_authority_selector_for_slot

    # Same hostile fixture as above: a genuine role key named ``GOVERNOR_SLOT``.
    assert _canonical_authority_selector_for_slot("GOVERNOR_SLOT", HOSTILE_ROLE_WITH_BANNED_SUFFIX) is None


def test_slot_route_still_accepts_a_real_slot_locator_leaf():
    from services.resolution.predicate_evaluator import _canonical_authority_selector_for_slot

    assert _canonical_authority_selector_for_slot("_GOVERNOR_SLOT", REAL_OWNABLE_SLOT_LEAF) is not None
    assert _canonical_authority_selector_for_slot("OwnableStorageLocation", REAL_OWNABLE_SLOT_LEAF) is not None


def test_slot_route_leafless_call_is_unchanged():
    """Callers with no leaf in hand keep the pre-existing behaviour; the new
    gate only ever narrows."""
    from services.resolution.predicate_evaluator import _canonical_authority_selector_for_slot

    assert _canonical_authority_selector_for_slot("OwnableStorageLocation") is not None
    assert _canonical_authority_selector_for_slot("PAUSER_ROLE") is None
    assert _canonical_authority_selector_for_slot(None) is None


# --- external arm: the three hostile shapes, through the REAL pipeline --------
#
# Compiled with Slither and run through build_predicate_artifacts →
# build_effects → _build_semantic_control_summary, i.e. the production static
# path, not a hand-built leaf. Under the rejected "any external_set descriptor"
# rule each of these minted a role name; each must now mint nothing.

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)


def _role_names_from_source(tmp_path: Path, source: str) -> list[str]:
    path = tmp_path / "C.sol"
    path.write_text(textwrap.dedent(source).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == "C")
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    return [r.get("role") for r in semantic.get("role_definitions", [])]


class TestExternalArmHostileShapes:
    """Three gate-shaped external view calls that take a ``bytes32 constant``
    which is NOT a role. All three reach an ``external_set`` descriptor with the
    constant among ``key_sources``; none carries the ``hasRole`` selector."""

    def test_erc7201_slot_constant_through_a_slot_lens(self, tmp_path):
        """The D6 defect class itself, re-entering through the external arm: an
        ERC-7201 pointer handed to ``readBool(address,bytes32)``."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface ISlotLens { function readBool(address target, bytes32 slot) external view returns (bool); }
            contract C {
                ISlotLens public lens;
                bytes32 public constant PausedStorageLocation =
                    0xcd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300;
                uint256 public value;
                constructor(ISlotLens l) { lens = l; }
                function unpause() external {
                    require(lens.readBool(msg.sender, PausedStorageLocation), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_merkle_root_in_a_membership_proof(self, tmp_path):
        """``isInTree(bytes32,address)`` has hasRole's exact argument ORDER and is
        still not a role check — which is why the selector gate is load-bearing."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface ITree { function isInTree(bytes32 root, address account) external view returns (bool); }
            contract C {
                ITree public tree;
                bytes32 public constant AIRDROP_ROOT = keccak256("AIRDROP");
                uint256 public value;
                constructor(ITree t) { tree = t; }
                function claim() external {
                    require(tree.isInTree(AIRDROP_ROOT, msg.sender), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_create2_salt_in_a_factory_authorisation(self, tmp_path):
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface IFactory { function isAuthorized(address account, bytes32 salt) external view returns (bool); }
            contract C {
                IFactory public factory;
                bytes32 public constant DEPLOY_SALT = keccak256("SALT");
                uint256 public value;
                constructor(IFactory f) { factory = f; }
                function deploy() external {
                    require(factory.isAuthorized(msg.sender, DEPLOY_SALT), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_a_genuine_hasrole_gate_still_mints(self, tmp_path):
        """The positive control, same pipeline: the surviving external arm is not
        vacuous."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface IRoleRegistry {
                function hasRole(bytes32 role, address account) external view returns (bool);
            }
            contract C {
                IRoleRegistry public roleRegistry;
                bytes32 public constant MINTER_ROLE = keccak256("MINTER");
                uint256 public value;
                constructor(IRoleRegistry rr) { roleRegistry = rr; }
                function mint() external {
                    require(roleRegistry.hasRole(MINTER_ROLE, msg.sender), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == ["MINTER_ROLE"]
