"""Predicate-tree artifact for a Solmate ``Auth`` contract whose ``pause()``
gate delegates to ``authority.canCall``. Shared by the event-indexer enrollment
tests that assert the indexer follows the delegated authority."""

from __future__ import annotations

_SOLMATE_CANCALL_TREES = {
    "trees": {
        "pause()": {
            "op": "LEAF",
            "leaf": {
                "set_descriptor": {
                    "kind": "external_set",
                    "callee_signature": "canCall(address,address,bytes4)",
                    "authority_contract": {
                        "address_source": {"source": "state_variable", "state_variable_name": "authority"}
                    },
                }
            },
        }
    }
}
