"""D6-reject: which ``bytes32`` constants may be minted as role names.

``role_definitions`` carried two rows that are not roles at all —
``AccessControlDefaultAdminRulesStorageLocation`` (contract 454) and
``OwnableStorageLocation`` (contract 623) — because leaf admission accepted any
``bytes32 constant`` operand of a caller-authority leaf. Both are ERC-7201
storage-layout pointers.

The fix is structural: admit only from a keyed-set membership leaf — a
``membership``/``external_bool`` leaf carrying a ``mapping_membership`` or
``external_set`` descriptor — whose operand has an empty ``member_path``, i.e.
the constant is the set KEY. Nothing here reads an identifier.

Every leaf below marked REAL is verbatim from the persisted predicate_trees
blobs of the PR-161 run (MinIO ``pr-161/artifacts/<job>/predicate_trees``):
contract 454 CumulativeMerkleDrop, 623 EtherfiL1SyncPoolETH, 599
WithdrawalQueueERC721.

The two HOSTILE fixtures are the ones the name-suffix guard
``tracking._is_storage_layout_constant`` gets wrong in BOTH directions; it is
banned as the fix for exactly that reason, and ``test_name_suffix_guard_*``
below pins the misclassification so the ban stays evidence-backed.
"""

from __future__ import annotations

import sys
from pathlib import Path

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
    """A delegated ``hasRole`` gate names a real role. The set is external, not an
    in-contract mapping, but the constant is still a key of the tested set —
    narrowing admission to ``mapping_membership`` alone would silently withdraw
    every cross-contract role the pipeline publishes today."""
    trees = {"trees": {"mint()": _leaf(REAL_EXTERNAL_REGISTRY_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("MINTER_ROLE")) == {"MINTER_ROLE"}


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
