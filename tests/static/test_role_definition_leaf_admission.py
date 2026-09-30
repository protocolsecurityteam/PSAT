"""D6-reject: ``role_definitions`` minted ERC-7201 storage pointers (contracts 454, 623) as roles because any
``bytes32 constant`` operand was admitted. The surviving rule is structural: a membership leaf, a
``mapping_membership`` descriptor, and an empty ``member_path``. Cross-contract checks aren't admitted at all;
both external-arm attempts are pinned as fixtures, and such roles publish ``not_determined`` (B4c), never
"no roles". REAL leaves are verbatim from PR-161 blobs; the HOSTILE fixtures defeat the banned name-suffix rule
in both directions.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from services.static.contract_analysis_pipeline.summaries import (
    _role_names_from_predicate_trees,
    _role_names_from_tree,
)


class _Bytes32Constant:
    type = "bytes32"
    is_constant = True


def _vars(*names: str) -> dict[str, _Bytes32Constant]:
    return {name: _Bytes32Constant() for name in names}


def _leaf(node: dict) -> dict:
    return {"op": "LEAF", "leaf": node}


# The enumeration_hint is reproduced because its presence must not be what admits the leaf.
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

# storage_var is ``TMP_1189`` and there's no enumeration_hint; gating on either drops five Lido roles.
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
    trees = {"trees": {"pause()": _leaf(REAL_PAUSER_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("PAUSER_ROLE")) == {"PAUSER_ROLE"}

    trees = {"trees": {"finalize(uint256,uint256)": _leaf(REAL_FINALIZE_ROLE_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("FINALIZE_ROLE")) == {"FINALIZE_ROLE"}


def test_real_slot_constant_leaves_are_rejected():
    trees = {"trees": {"setTokenOut(address)": _leaf(REAL_OWNABLE_SLOT_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("OwnableStorageLocation")) == set()

    trees = {"trees": {"acceptDefaultAdminTransfer()": _leaf(REAL_DEFAULT_ADMIN_RULES_SLOT_LEAF)}}
    assert _role_names_from_predicate_trees(trees, _vars("AccessControlDefaultAdminRulesStorageLocation")) == set()


def test_real_mixed_contract_admits_only_the_roles():
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


class _AddressVar:
    type = "address"
    is_constant = False


def _pauser_leaf_with(**overrides) -> dict:
    return {**REAL_PAUSER_ROLE_LEAF, **overrides}


_PAUSER_VARS = _vars("PAUSER_ROLE")

_REJECTED_LEAVES = [
    pytest.param(
        {k: v for k, v in REAL_PAUSER_ROLE_LEAF.items() if k != "set_descriptor"},
        _PAUSER_VARS,
        id="membership-leaf-without-set-descriptor",
    ),
    *[
        pytest.param(
            _pauser_leaf_with(set_descriptor={"kind": kind}), _PAUSER_VARS, id=f"unmeasured-descriptor-kind-{kind}"
        )
        for kind in ("array_contains", "bitwise_role_flag", "diamond_facet_acl")
    ],
    pytest.param(
        _pauser_leaf_with(
            operands=[
                {"source": "state_variable", "state_variable_name": "PAUSER_ROLE", "member_path": ["_slotField"]},
                {"source": "msg_sender"},
            ]
        ),
        _PAUSER_VARS,
        id="mapping-membership-operand-with-member-path",
    ),
    pytest.param(REAL_PAUSER_ROLE_LEAF, {"PAUSER_ROLE": _AddressVar()}, id="non-bytes32-constant-operand"),
    pytest.param(REAL_PAUSER_ROLE_LEAF, {}, id="unknown-state-var-empty-scope"),
    pytest.param(REAL_PAUSER_ROLE_LEAF, None, id="unknown-state-var-no-scope"),
    pytest.param(_pauser_leaf_with(authority_role="business"), _PAUSER_VARS, id="non-authority-membership-leaf"),
]


@pytest.mark.parametrize("leaf, state_vars", _REJECTED_LEAVES)
def test_leaf_is_rejected(leaf, state_vars):
    assert _role_names_from_tree(_leaf(leaf), state_vars) == set()


def test_role_leaf_without_enumeration_hint_is_still_admitted():
    descriptor = {k: v for k, v in REAL_FINALIZE_ROLE_LEAF["set_descriptor"].items() if k != "storage_var"}
    leaf = {**REAL_FINALIZE_ROLE_LEAF, "set_descriptor": descriptor}
    assert _role_names_from_tree(_leaf(leaf), _vars("FINALIZE_ROLE")) == {"FINALIZE_ROLE"}


# ``_canonical_authority_selector_for_slot`` used the same suffix guard, so a role named like a slot resolved to
# ``governor()`` and was published as the caller.


def test_slot_route_refuses_a_mapping_membership_role_operand():
    from services.resolution.predicate_evaluator import _canonical_authority_selector_for_slot

    assert _canonical_authority_selector_for_slot("GOVERNOR_SLOT", HOSTILE_ROLE_WITH_BANNED_SUFFIX) is None


def test_slot_route_still_accepts_a_real_slot_locator_leaf():
    from services.resolution.predicate_evaluator import _canonical_authority_selector_for_slot

    assert _canonical_authority_selector_for_slot("_GOVERNOR_SLOT", REAL_OWNABLE_SLOT_LEAF) is not None
    assert _canonical_authority_selector_for_slot("OwnableStorageLocation", REAL_OWNABLE_SLOT_LEAF) is not None


def test_slot_route_leafless_call_is_unchanged():
    from services.resolution.predicate_evaluator import _canonical_authority_selector_for_slot

    assert _canonical_authority_selector_for_slot("OwnableStorageLocation") is not None
    assert _canonical_authority_selector_for_slot("PAUSER_ROLE") is None
    assert _canonical_authority_selector_for_slot(None) is None


# Through the production path; each minted a role name under the rejected external_set rule.

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
    def test_erc7201_slot_constant_through_a_slot_lens(self, tmp_path):
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

    def test_a_genuine_hasrole_gate_mints_nothing_either(self, tmp_path):
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
    """Round 2: the selector comes from the caller's declared interface, so any contract declared
    ``hasRole(bytes32,address)`` looks identical.
    """

    def test_h5_recovered_signer_is_not_the_caller(self, tmp_path):
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
