"""The ``msg.sender == X`` caller-authority predicate leaf the authority-resolution
tests build their trees from; each of those modules previously carried a private copy.

The copies differed only in the ``expression`` string, which is descriptive text
carried through to the witness — hence the parameter rather than a fixed literal.
"""

from __future__ import annotations

from typing import Any, cast

from services.static.contract_analysis_pipeline.predicate_types import PredicateTree


def eq_tree(operand: dict[str, Any], expression: str = "msg.sender == X") -> PredicateTree:
    return cast(
        PredicateTree,
        {
            "op": "LEAF",
            "leaf": {
                "kind": "equality",
                "operator": "eq",
                "authority_role": "caller_authority",
                "operands": [{"source": "msg_sender"}, operand],
                "references_msg_sender": True,
                "parameter_indices": [],
                "expression": expression,
                "basis": [],
            },
        },
    )
