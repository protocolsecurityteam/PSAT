"""A Solmate ``Auth`` tree whose ``pause()`` delegates to ``authority.canCall``."""

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
