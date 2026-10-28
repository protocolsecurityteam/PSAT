"""Explicit, separately budgeted expansion of already-generated formulas."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .model import Analysis, Formula, Limits, Reads, encode
from .solver import Translation, project


@dataclass(frozen=True)
class Selection:
    callers: bool = True
    effect_indices: tuple[int, ...] = ()

    def validate(self, formula: Formula) -> None:
        if type(self.callers) is not bool or not (self.callers or self.effect_indices):
            raise ValueError("select callers or at least one effect")
        if len(set(self.effect_indices)) != len(self.effect_indices) or any(
            type(i) is not int or not 0 <= i < len(formula.effects) for i in self.effect_indices
        ):
            raise ValueError("invalid or repeated effect index")


def formula_hash(formula: Formula) -> str:
    return hashlib.sha256(json.dumps(encode(formula), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def expand_formula(
    formula: Formula, reads: Reads, contracts: Any, *, selection: Selection = Selection(), limits: Limits = Limits()
) -> Analysis:
    """No lowering or compilation here. The reader must use the formula's original block."""
    selection.validate(formula)
    if reads.block != formula.block:
        raise ValueError("expansion must use the formula's pinned block")

    def solve(predicate):
        return project(predicate, Translation(reads, contracts, formula.address, formula.selector, limits))

    return Analysis(
        formula,
        solve(formula.success) if selection.callers else None,
        tuple(solve(formula.effects[i].guard) for i in selection.effect_indices),
        selection.effect_indices,
    )
