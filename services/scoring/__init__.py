"""Protocol scoring: per-function signal distillation and the grade fold.

Two layers with different integration shapes. Layer 1 distils one job's planes
into per-function :class:`~services.scoring.schema.FunctionSignal` rows,
incrementally, at the end of the effects stage. Layer 2 re-folds ALL of a
protocol's persisted signals into a
:class:`~services.scoring.schema.ScoreDocument` on every trigger — a full
recompute rather than a running total, because value is MAX per (entity, asset),
principal units are re-keyed by later evidence, and subsumption is only
decidable with every finding present.

This module exports the contract between them. The fold consumes signal rows and
nothing else, so the offline CLI (distil every job in memory, then fold) and the
persisted pipeline (distil at end-of-effects, fold from the table) run the
identical code.
"""

from __future__ import annotations

from services.scoring.distill import distill_contract_signals, distill_job_signals
from services.scoring.fold import compute_protocol_score
from services.scoring.population import (
    current_signal_rows,
    current_signals_for_protocol,
    replace_contract_signals,
)
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    PrincipalRef,
    ScoreDocument,
    Tri,
    coalesce_chain,
    entity_key,
    is_entity_key,
    not_determined_signal_defaults,
    signal_from_row,
    signal_to_row_kwargs,
)

__all__ = [
    "NOT_DETERMINED",
    "FunctionSignal",
    "PrincipalRef",
    "ScoreDocument",
    "Tri",
    "coalesce_chain",
    "compute_protocol_score",
    "current_signal_rows",
    "current_signals_for_protocol",
    "distill_contract_signals",
    "distill_job_signals",
    "entity_key",
    "is_entity_key",
    "not_determined_signal_defaults",
    "replace_contract_signals",
    "signal_from_row",
    "signal_to_row_kwargs",
]
