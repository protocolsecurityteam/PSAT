"""The ``msg.sender == X`` leaf the authority-resolution tests build trees from.

``expression`` is descriptive text carried to the witness, hence a parameter.
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
