"""Permit-family signature shapes."""

from __future__ import annotations

import logging
from typing import Any

from services.static.static_analysis.predicate_types import (
    LeafPredicate,
)

logger = logging.getLogger("services.resolution.predicate_evaluator")

# Canonical signature-verification callees: the EVM ``ecrecover`` builtin, the
# OZ ECDSA library (``recover``/``tryRecover``), and OZ SignatureChecker /
# EIP-1271 (``isValidSignature``/``isValidSignatureNow``). Standard library
# entry points, not user identifiers.
_SIGNATURE_VERIFIER_CALLEES = frozenset(
    {"ecrecover", "recover", "tryRecover", "isValidSignature", "isValidSignatureNow"}
)

# EIP-2612 / DAI-style permit and EIP-3009 authorization ABI signatures — the
# canonical self-authorizing token entry points a void statement call gates on.
_PERMIT_FAMILY_SIGNATURES = frozenset(
    {
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
        "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)",
        "receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)",
        "cancelAuthorization(address,bytes32,uint8,bytes32,bytes32)",
    }
)


def _leaf_is_permit_shape(leaf: LeafPredicate) -> bool:
    """Structural permit witness on a side-condition leaf: an operand carrying
    ``signature_recovery`` provenance, a canonical signature-verifier callee,
    or a void call into the EIP-2612/3009 permit family."""
    for op in leaf.get("operands") or []:
        if op.get("source") == "signature_recovery":
            return True
        callee = op.get("callee")
        if isinstance(callee, str) and callee in _SIGNATURE_VERIFIER_CALLEES:
            return True
    return _is_permit_family_signature(leaf.get("callee_signature"))


def _is_permit_family_signature(signature: Any) -> bool:
    if not isinstance(signature, str) or "(" not in signature:
        return False
    return signature.replace(" ", "") in _PERMIT_FAMILY_SIGNATURES
