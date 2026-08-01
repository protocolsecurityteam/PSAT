"""The fold's population read — one pinned query, no job-currency filtering.

``function_score_signals`` is a current-state plane: the distiller
delete+reinserts a contract's signals wholesale, so every row present IS
current and there is nothing to filter. This module exists so that fact has a
single implementation. A hand-rolled query in the fold could reintroduce a
job-scoped filter, and the moment it did, a protocol's signals would be
partitioned by job and the fold would either double-count re-analysed contracts
or drop them entirely — the two failure modes the lifecycle ruling closed.

The ordering is part of the contract, not a convenience. Inv. 11/12 require the
same DB state to produce a byte-identical document, and a fold over an
unordered population is only deterministic by luck.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from services.scoring.schema import FunctionSignal, signal_from_row

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from db.models import FunctionScoreSignal


def current_signal_rows(session: Session, protocol_id: int) -> list[FunctionScoreSignal]:
    """Every current signal ORM row for one protocol, in a stable order."""
    from db.models import FunctionScoreSignal

    return list(
        session.query(FunctionScoreSignal)
        .filter(FunctionScoreSignal.protocol_id == protocol_id)
        .order_by(
            FunctionScoreSignal.chain,
            FunctionScoreSignal.deployment_address,
            FunctionScoreSignal.contract_id,
            FunctionScoreSignal.selector,
            FunctionScoreSignal.claim_id,
        )
        .all()
    )


def current_signals_for_protocol(session: Session, protocol_id: int) -> list[FunctionSignal]:
    """The fold's input: every current signal for one protocol, typed and ordered.

    Ordered by the identity key, so the sequence is total — two rows can never
    tie — and the fold is replayable per inv. 11/12.
    """
    return [signal_from_row(row) for row in current_signal_rows(session, protocol_id)]


def replace_contract_signals(
    session: Session,
    *,
    contract_id: int,
    signals: list[FunctionSignal],
    job_id: object = None,
) -> int:
    """Delete+reinsert one contract's signals. The writer half of the currency contract.

    Wholesale per contract, in the caller's transaction, mirroring
    ``write_effective_function_rows``. Wholesale because a distillation's rows
    ARE the set it derived: a capability the contract no longer has must
    disappear, and an upsert would leave the stale row behind to keep charging
    exposure forever.

    Scoped by ``contract_id`` and NOT by job: re-analysis mints a new job, so a
    job-scoped delete would never reach the previous job's rows and each
    re-analysis would add a second full signal set for the same contract.

    The caller commits. Returns the number of rows deleted, so a writer can log
    the replacement rather than infer it.
    """
    from db.models import FunctionScoreSignal
    from services.scoring.schema import signal_to_row_kwargs

    deleted = (
        session.query(FunctionScoreSignal)
        .filter(FunctionScoreSignal.contract_id == contract_id)
        .delete(synchronize_session=False)
    )
    session.flush()
    for signal in signals:
        if signal.contract_id != contract_id:
            raise ValueError(f"signal for contract {signal.contract_id} passed to replace of {contract_id}")
        session.add(FunctionScoreSignal(**signal_to_row_kwargs(signal, job_id=job_id)))
    session.flush()
    return int(deleted)
