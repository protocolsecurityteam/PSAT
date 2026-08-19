"""``apply_solmate_authority_hint_pass`` attaches RolesAuthority event hints to
``canCall`` external_set leaves so the event-log indexer enrolls the authority's
role events (which the Solmate adapter then folds). canCall carries an
``authority_contract`` but no events from the base static stage.
"""

from __future__ import annotations

from typing import cast

from eth_utils.crypto import keccak  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    apply_solmate_authority_hint_pass,
)
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree  # noqa: E402


def _t0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


_EXPECTED_TOPICS = {
    _t0("RoleCapabilityUpdated(uint8,address,bytes4,bool)"),
    _t0("PublicCapabilityUpdated(address,bytes4,bool)"),
    _t0("UserRoleUpdated(address,uint8,bool)"),
}


def _cancall_leaf_tree() -> dict:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "operator": "truthy",
            "authority_role": "delegated_authority",
            "operands": [{"source": "msg_sender"}, {"source": "self_address"}, {"source": "computed"}],
            "set_descriptor": {
                "kind": "external_set",
                "callee_signature": "canCall(address,address,bytes4)",
                "callee_selector": "0xb7009613",
                "authority_contract": {
                    "address_source": {"source": "state_variable", "state_variable_name": "authority"}
                },
            },
        },
    }


def test_solmate_hints_attached_to_cancall_descriptor():
    trees = {"pause()": _cancall_leaf_tree()}
    apply_solmate_authority_hint_pass(None, cast(dict[str, PredicateTree], trees))
    descriptor = trees["pause()"]["leaf"]["set_descriptor"]
    hints = descriptor.get("enumeration_hint")
    assert hints is not None
    assert {h["topic0"] for h in hints} == _EXPECTED_TOPICS


def test_non_cancall_external_set_untouched():
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "set_descriptor": {"kind": "external_set", "callee_signature": "permitted(address,bytes32)"},
        },
    }
    apply_solmate_authority_hint_pass(None, cast(dict[str, PredicateTree], {"f()": tree}))
    assert tree["leaf"]["set_descriptor"].get("enumeration_hint") is None


def test_hint_pass_is_idempotent():
    trees = {"pause()": _cancall_leaf_tree()}
    apply_solmate_authority_hint_pass(None, cast(dict[str, PredicateTree], trees))
    apply_solmate_authority_hint_pass(None, cast(dict[str, PredicateTree], trees))
    hints = trees["pause()"]["leaf"]["set_descriptor"]["enumeration_hint"]
    assert len(hints) == 3
