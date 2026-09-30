"""Protocol scoring: per-function signal distillation and the grade fold.

Layer 1 distils one job's planes into :class:`~services.scoring.schema.FunctionSignal` rows at the end of the effects
stage. Layer 2 re-folds all of a protocol's signals into a :class:`~services.scoring.schema.ScoreDocument` on every
trigger, a full recompute because value is max per (entity, asset), principal units re-key, and subsumption needs every
finding. The fold reads only signal rows, so the offline CLI and the persisted pipeline run identical code.
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
