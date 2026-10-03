"""Exact source identity for the Safe implementation whose signature and module gates we model.

Selectors alone cannot license this interpretation: an authentication-free twin has the same ABI. Source identity
includes inherited storage/getters and signature helpers, and rejects overrides declared outside the verified set.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .predicate_types import PredicateTree


@lru_cache(maxsize=1)
def _sources() -> dict[str, str]:
    return json.loads(Path(__file__).with_name("safe_v1_4_1_sources.json").read_text())["sha256"]


def safe_source_identity(contract: Any) -> str | None:
    if contract is None:
        return None
    sources = getattr(getattr(getattr(contract, "compilation_unit", None), "core", None), "source_code", {})
    expected = _sources()
    root_file = getattr(getattr(getattr(contract, "source_mapping", None), "filename", None), "absolute", None)
    root_body = sources.get(root_file)
    if root_body is None:
        return None
    root_hash = hashlib.sha256(root_body.encode()).hexdigest()
    if root_hash != expected["contracts/Safe.sol"]:
        return None
    hashes = {name: hashlib.sha256(body.encode()).hexdigest() for name, body in sources.items()}
    if not set(expected.values()).issubset(hashes.values()):
        return None
    # A subclass/override cannot borrow the canonical base's identity; every effective declaration must be witnessed.
    declarations = [contract, *contract.inheritance, *contract.all_functions_called]
    for declaration in declarations:
        source = getattr(declaration, "source_mapping", None)
        if source is not None and hashes.get(source.filename.absolute) not in expected.values():
            return None
    return root_hash


def apply_safe_authentication_pass(contract: Any, trees: dict[str, PredicateTree]) -> None:
    gates = {
        "execTransaction(address,uint256,bytes,Enum.Operation,uint256,uint256,uint256,address,address,bytes)": (
            "signatures"
        ),
        "execTransactionFromModule(address,uint256,bytes,Enum.Operation)": "modules",
        "execTransactionFromModuleReturnData(address,uint256,bytes,Enum.Operation)": "modules",
    }
    identity = safe_source_identity(contract)
    if identity is None:
        signature = next(iter(gates))
        tree = trees.get(signature)
        if _has_signature_gate(tree):
            # Partial recovery of this multi-mode verifier is not proof of a public alternative. Unknown versions or
            # source variations need a future source witness; the authentication-free twin has no signature gate.
            trees[signature] = {
                "op": "LEAF",
                "leaf": {
                    "kind": "unsupported",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [],
                    "references_msg_sender": False,
                    "parameter_indices": [9],
                    "expression": "Safe signature authorization not fully resolved",
                    "basis": ["partial_safe_signature_gate"],
                    "unsupported_reason": "safe_signature_authority_not_determined",
                },
            }
        return
    for signature, gate in gates.items():
        # Source-proven threshold authorization must replace the generic OR/denylist approximation, which loses the
        # recovered-owner loop. Module entries have a different gate and must never inherit the signer threshold.
        trees[signature] = {
            "op": "LEAF",
            "leaf": {
                "kind": "signature_auth" if gate == "signatures" else "membership",
                "operator": "truthy",
                "authority_role": "caller_authority",
                "confidence": "high",
                "operands": [],
                "references_msg_sender": gate == "modules",
                "parameter_indices": [9] if gate == "signatures" else [],
                "expression": "threshold owner signatures" if gate == "signatures" else "enabled module caller",
                "basis": ["safe_v1_4_1_source_identity"],
                "set_descriptor": {
                    "kind": "external_set",
                    "key_sources": [{"source": "msg_sender"}] if gate == "modules" else [],
                    "authority_contract": {
                        "address_source": {"source": "self_address"},
                        "abi_hint": "safe_v1_4_1_" + gate,
                    },
                    "source_identity": identity,
                },
            },
        }


def _has_signature_gate(tree: PredicateTree | None) -> bool:
    if not tree:
        return False
    leaf = tree.get("leaf") or {}
    return (
        leaf.get("kind") == "signature_auth"
        or any(op.get("source") == "signature_recovery" for op in leaf.get("operands") or [])
        or any(_has_signature_gate(child) for child in tree.get("children") or [])
    )
