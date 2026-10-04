"""Which clock a predicate-tree leaf compares against: the one definition the static pause matcher and the effects
pause-window reader share.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# ``now`` is ``block.timestamp``. ``block.number`` advances on its own too, but counts blocks, not seconds.
SECONDS_CLOCK_KINDS = frozenset({"timestamp", "now"})
CLOCK_KINDS = frozenset({"timestamp", "now", "number"})


def operand_clock_kind(operand: Mapping[str, Any]) -> str | None:
    kind = operand.get("block_context_kind")
    return kind if isinstance(kind, str) and kind in CLOCK_KINDS else None


def clock_kinds(operands: Iterable[Mapping[str, Any]]) -> frozenset[str]:
    """The clocks among a leaf's compared operands; empty when the comparison reads no clock."""
    return frozenset(kind for op in operands if (kind := operand_clock_kind(op)) is not None)
