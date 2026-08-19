"""D6-reject: which ``bytes32`` constants may be minted as role names.

``role_definitions`` carried two rows that are not roles at all —
``AccessControlDefaultAdminRulesStorageLocation`` (contract 454) and
``OwnableStorageLocation`` (contract 623) — because leaf admission accepted any
``bytes32 constant`` operand of a caller-authority leaf. Both are ERC-7201
storage-layout pointers.

The surviving rule is one arm, structural, reading no identifier:
``kind == "membership"`` + a ``mapping_membership`` descriptor + an empty
``member_path`` — the constant indexes a mapping the lowering actually saw.

**Cross-contract checks are not admitted at all**, including a genuine
``registry.hasRole(ROLE, msg.sender)``. Two attempts to keep an external arm
failed and are pinned here as regression fixtures:

* admitting any ``external_set`` descriptor — ``_build_external_bool_leaf``
  fills ``key_sources`` from every call argument, so a slot constant, a merkle
  root and a CREATE2 salt all minted as roles (``TestExternalArmHostileShapes``);
* narrowing to the ``hasRole(bytes32,address)`` selector plus argument
  positions — the signature comes from ``ir.function.full_name``
  (``predicates.py:2338``), the CALLER's declaration, so any contract declared
  under that name lowers identically (``TestCallerDeclaredInterfaceShapes``).

The external arm's measured population on the persisted corpus was **zero**: all
surviving rows across the six role-bearing contracts are mapping-arm and the
``external_set`` descriptor count is 0. Cross-contract roles publish as
``not_determined`` under the B4c coverage caveat, never as "no roles".

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
# emits it. The constant IS a real role here — and it is still not admitted; see
# ``test_external_registry_role_leaf_is_not_admitted``.
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


def test_external_registry_role_leaf_is_not_admitted():
    """A GENUINE cross-contract role check mints nothing, and that is the
    intended outcome.

    ``callee_signature`` / ``callee_selector`` come from
    ``ir.function.full_name`` (``predicates.py:2338``) — the interface the CALLER
    declared, not the deployed callee's ABI. A slot lens or a merkle-tree
    contract declared under the name ``hasRole(bytes32,address)`` lowers to a
    byte-identical descriptor (``TestCallerDeclaredInterfaceShapes``), so the
    signature is an unverified claim about someone else's code. Argument position
    adds nothing: ``_build_external_bool_leaf`` fills ``key_sources`` from every
    argument.

    The measured cost is zero — across all six role-bearing contracts in the
    persisted corpus every surviving row is mapping-arm and the
    ``external_set`` descriptor count is 0. These roles publish as
    ``not_determined`` under the B4c coverage caveat, **never** as "no roles".
    """
    trees = {"trees": {"mint()": _leaf(REAL_EXTERNAL_REGISTRY_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("MINTER_ROLE")) == set()


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

    def test_a_genuine_hasrole_gate_mints_nothing_either(self, tmp_path):
        """The honest cost of the excision, pinned: a real cross-contract role
        check publishes NO row. Not "this contract has no roles" — the role is
        ``not_determined`` under B4c's coverage caveat, alongside the 50
        role-keyed gates that carry the role as a view_call/parameter operand."""
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
        assert roles == []

    def test_in_contract_accesscontrol_still_mints(self, tmp_path):
        """The positive control for the SURVIVING arm, same pipeline: an
        in-contract ``_roles[ROLE][account]`` membership read still mints, so the
        excision did not empty the rule."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            contract C {
                mapping(bytes32 => mapping(address => bool)) internal _roles;
                bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");
                uint256 public value;
                function pause() external {
                    require(_roles[PAUSER_ROLE][msg.sender], "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == ["PAUSER_ROLE"]


class TestCallerDeclaredInterfaceShapes:
    """The round-2 refutation of the selector+position arm, pinned.

    ``callee_signature``/``callee_selector`` are read off ``ir.function.full_name``
    (``predicates.py:2338``) — the interface the CALLING contract declared. Any
    contract can be declared under the name ``hasRole(bytes32,address)``, so the
    selector is not a proven property of the deployed callee, and the bodies that
    refute these gates are sometimes visible in the very same unit."""

    def test_h1_slot_lens_declared_as_hasrole(self, tmp_path):
        """H1 — an ERC-7201 pointer read through a slot lens whose interface is
        *declared* ``hasRole(bytes32,address)``. Byte-identical descriptor to a
        real registry gate."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface ISlotLens { function hasRole(bytes32 slot, address target) external view returns (bool); }
            contract C {
                ISlotLens public lens;
                bytes32 public constant PausedStorageLocation =
                    0xcd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300;
                uint256 public value;
                constructor(ISlotLens l) { lens = l; }
                function unpause() external {
                    require(lens.hasRole(PausedStorageLocation, msg.sender), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_h2_merkle_tree_declared_as_hasrole(self, tmp_path):
        """H2 — a merkle root under a ``hasRole``-named tree interface."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface ITree { function hasRole(bytes32 root, address account) external view returns (bool); }
            contract C {
                ITree public tree;
                bytes32 public constant AIRDROP_ROOT = keccak256("AIRDROP");
                uint256 public value;
                constructor(ITree t) { tree = t; }
                function claim() external {
                    require(tree.hasRole(AIRDROP_ROOT, msg.sender), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_h4_same_unit_hasrole_that_ignores_the_account(self, tmp_path):
        """H4 — the refuting body is in the unit and the gate never looks: this
        ``hasRole`` returns ``salts[salt]`` and drops its ``account`` argument
        entirely, so it gates on nothing about the caller."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            contract Registry {
                mapping(bytes32 => bool) public salts;
                function hasRole(bytes32 salt, address) external view returns (bool) {
                    return salts[salt];
                }
            }
            contract C {
                Registry public registry;
                bytes32 public constant DEPLOY_SALT = keccak256("SALT");
                uint256 public value;
                constructor(Registry r) { registry = r; }
                function deploy() external {
                    require(registry.hasRole(DEPLOY_SALT, msg.sender), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_h5_recovered_signer_is_not_the_caller(self, tmp_path):
        """H5 — ``signature_recovery`` was admitted as caller-taint, but a
        recovered signer is not this function's caller; anyone holding a
        signature can call. Moot with the arm gone, pinned anyway."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface IRoleRegistry {
                function hasRole(bytes32 role, address account) external view returns (bool);
            }
            contract C {
                IRoleRegistry public roleRegistry;
                bytes32 public constant RELAYER_ROLE = keccak256("RELAYER");
                uint256 public value;
                constructor(IRoleRegistry rr) { roleRegistry = rr; }
                function relay(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
                    address signer = ecrecover(digest, v, r, s);
                    require(roleRegistry.hasRole(RELAYER_ROLE, signer), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []

    def test_h7_library_forwarded_hasrole_with_a_slot_constant(self, tmp_path):
        """H7 — the call reaches the declared ``hasRole`` through a library
        forwarder, carrying an ERC-7201 slot constant."""
        roles = _role_names_from_source(
            tmp_path,
            """
            pragma solidity ^0.8.19;
            interface ILens { function hasRole(bytes32 slot, address target) external view returns (bool); }
            library LensLib {
                function check(ILens lens, bytes32 slot, address who) internal view returns (bool) {
                    return lens.hasRole(slot, who);
                }
            }
            contract C {
                using LensLib for ILens;
                ILens public lens;
                bytes32 public constant OwnableStorageLocation =
                    0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
                uint256 public value;
                constructor(ILens l) { lens = l; }
                function setValue() external {
                    require(lens.check(OwnableStorageLocation, msg.sender), "no");
                    value = 1;
                }
            }
            """,
        )
        assert roles == []
