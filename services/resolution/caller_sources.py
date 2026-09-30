"""The caller-identity operand sources across frame representations.

The static ``OperandSource`` members naming the caller (``msg_sender``, ``tx_origin``, ``signature_recovery``) plus
``root_caller``, the frame-rewritten root ``msg.sender`` inside an inlined callee. A leaf module so every consumer
shares one copy.
"""

from __future__ import annotations

CALLER_SOURCES: frozenset[str] = frozenset({"msg_sender", "tx_origin", "signature_recovery", "root_caller"})
