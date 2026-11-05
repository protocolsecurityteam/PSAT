"""Explicit, separately budgeted expansion of already-generated formulas."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .model import Analysis, Formula, Limits, Reads, encode
from .power import write_power
from .solver import Translation, project


@dataclass(frozen=True)
class Selection:
    callers: bool = True
    effect_indices: tuple[int, ...] = ()
    power_indices: tuple[int, ...] = ()

    def validate(self, formula: Formula) -> None:
        if type(self.callers) is not bool or not (self.callers or self.effect_indices):
            raise ValueError("select callers or at least one effect")
        if len(set(self.effect_indices)) != len(self.effect_indices) or any(
            type(i) is not int or not 0 <= i < len(formula.effects) for i in self.effect_indices
        ):
            raise ValueError("invalid or repeated effect index")
        if len(set(self.power_indices)) != len(self.power_indices) or any(
            type(i) is not int or i not in self.effect_indices or formula.effects[i].kind != "write"
            for i in self.power_indices
        ):
            raise ValueError("power scope requires selected storage-write effects")


def formula_hash(formula: Formula) -> str:
    return hashlib.sha256(json.dumps(encode(formula), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def expand_formula(
    formula: Formula,
    reads: Reads,
    contracts: Any,
    *,
    selection: Selection = Selection(),
    limits: Limits = Limits(),
    accounting: dict | None = None,
) -> Analysis:
    """No lowering or compilation here. The reader must use the formula's original block."""
    selection.validate(formula)
    if reads.block != formula.block:
        raise ValueError("expansion must use the formula's pinned block")

    def solve(predicate, scope):
        translation = Translation(reads, contracts, formula.address, formula.selector, limits)
        result = project(predicate, translation)
        if accounting is not None:
            accounting[scope] = list(translation.storage.work.values()) if translation.storage is not None else []
        return result

    return Analysis(
        formula,
        solve(formula.success, "callers") if selection.callers else None,
        tuple(
            solve(
                write_power(formula.effects[i]) if i in selection.power_indices else formula.effects[i].guard,
                f"effect:{i}",
            )
            for i in selection.effect_indices
        ),
        selection.effect_indices,
        selection.power_indices,
    )
