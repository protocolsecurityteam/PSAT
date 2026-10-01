"""The base static stage gives ``canCall`` an ``authority_contract`` but no events; this pass attaches the
RolesAuthority hints the indexer enrolls.
"""

from __future__ import annotations

from typing import cast

from services.static.contract_analysis_pipeline.predicate_artifacts import (
    apply_solmate_authority_hint_pass,
)
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree


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
