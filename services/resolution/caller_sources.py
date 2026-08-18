"""The caller-identity operand sources, in every frame representation.

Resolution-side vocabulary: the static plane's ``OperandSource`` members that
name the caller (``msg_sender`` / ``tx_origin`` / ``signature_recovery`` —
a recovered signer checked against a contract-governed set is delegated
authority) plus ``root_caller``, the frame-rewritten root ``msg.sender``
inside an inlined callee tree, which only the resolution plane mints.

A leaf module (imports nothing) so every resolution consumer shares one copy.
"""

from __future__ import annotations

CALLER_SOURCES: frozenset[str] = frozenset({"msg_sender", "tx_origin", "signature_recovery", "root_caller"})
