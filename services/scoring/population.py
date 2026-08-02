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

from sqlalchemy import event
from sqlalchemy.orm import Session

from services.scoring.schema import FunctionSignal, coalesce_chain, signal_from_row

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from db.models import FunctionScoreSignal

# Contracts already replaced in the current transaction. A second replace of the
# same contract means the caller grouped its signals by something finer than
# ``contract_id`` — the delete would drop the first call's rows and the contract
# would end up carrying only its last group. That is silent recall loss, so it
# raises. Cleared when the transaction ends, because the invariant is per-pass.
_REPLACED_KEY = "_scoring_replaced_contract_ids"


def _replaced_contract_ids(session: Session) -> set[int]:
    return session.info.setdefault(_REPLACED_KEY, set())


@event.listens_for(Session, "after_commit")
@event.listens_for(Session, "after_rollback")
def _clear_replaced_contract_ids(session: Session) -> None:
    session.info.pop(_REPLACED_KEY, None)


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


def current_signals_with_faults(
    session: Session, protocol_id: int
) -> tuple[list[FunctionSignal], list[dict[str, object]]]:
    """The fold's input, plus the rows that could not be typed at all.

    ``function_score_signals`` carries several list- and object-shaped JSONB
    columns with no CHECK behind their INTERIOR: the entity-key format and the
    principal-reference envelope are Python-enforced, so a row written by
    anything but the sanctioned writer can hold a shape the typed reader
    rejects. Those checks are right and stay — what changes is the blast radius.
    A row that fails one withholds ITSELF and names the column; the rest of the
    protocol still scores, because one malformed row is not evidence about any
    other row.

    Callers that want the strict behaviour keep using
    :func:`current_signals_for_protocol`.
    """
    signals: list[FunctionSignal] = []
    faults: list[dict[str, object]] = []
    for row in current_signal_rows(session, protocol_id):
        # Shape first, then typing. Two of these columns type cleanly and only
        # fail where the FOLD walks them, so checking the shape at the boundary
        # is what keeps the failure here rather than three layers downstream.
        column = _shape_fault(row)
        detail = f"{column} does not hold its declared shape"
        if column is None:
            try:
                signals.append(signal_from_row(row))
                continue
            except Exception as exc:
                column, detail = "unknown", f"{type(exc).__name__}: {exc}"
        faults.append(
            {
                "entity": f"{coalesce_chain(row.chain)}::{str(row.deployment_address or '').lower()}",
                "function_name": row.function_name,
                "claim_id": row.claim_id,
                "column": column,
                "detail": detail,
            }
        )
    return signals, faults


def _shape_fault(row: FunctionScoreSignal) -> str | None:
    """The first column that does not hold its declared shape, or ``None``.

    Named, never guessed at, and checked in the order a reader walks them.
    ``witness_notes`` and ``severity_basis`` type cleanly and blow up only where
    the fold iterates them, which is why the shape is checked here instead of
    being left to the first consumer that trips over it.
    """
    from services.scoring.schema import is_entity_key

    def _string_list(value: object) -> bool:
        return value is None or (isinstance(value, list) and all(isinstance(item, str) for item in value))

    if not _string_list(row.severity_basis):
        return "severity_basis"
    refs = row.principal_refs
    if refs is not None:
        if not isinstance(refs, list):
            return "principal_refs"
        for ref in refs:
            if not isinstance(ref, dict):
                return "principal_refs"
            try:
                int(ref["function_principal_id"])
            except (KeyError, TypeError, ValueError):
                return "principal_refs"
    keys = row.value_entity_keys
    if keys is not None and (not isinstance(keys, list) or not all(is_entity_key(k) for k in keys)):
        return "value_entity_keys"
    if not _string_list(row.witness_notes):
        return "witness_notes"
    if row.citations is not None and (
        not isinstance(row.citations, list) or not all(isinstance(c, dict) for c in row.citations)
    ):
        return "citations"
    if row.gate_inputs is not None and not isinstance(row.gate_inputs, dict):
        return "gate_inputs"
    return None


def order_signals(signals: list[FunctionSignal]) -> list[FunctionSignal]:
    """The population order, for signals that never went through the database.

    The offline CLI distils every contract in memory and folds the result, so it
    has no query to inherit an ORDER BY from. The fold's replayability rests on a
    total order over the population, and the only order that keeps the two
    feeding modes identical is the one :func:`current_signal_rows` pins.
    """
    return sorted(
        signals,
        key=lambda s: (s.chain, s.deployment_address, s.contract_id, s.selector, s.claim_id),
    )


def replace_contract_signals(
    session: Session,
    *,
    contract_id: int,
    signals: list[FunctionSignal],
    job_id: object = None,
) -> int:
    """Delete+reinsert one contract's signals. The writer half of the currency contract.

    **The caller passes the contract's COMPLETE signal set.** A partial call
    silently drops the omitted deployment's signals: the delete is scoped by
    ``contract_id`` alone, so signals this call does not carry are removed and
    not restored. Distillation must therefore group by ``contract_id`` and never
    by ``(contract_id, deployment_address)`` — a contract whose functions appear
    at two deployment addresses must arrive in ONE call. The double-replace
    guard below makes the wrong grouping raise instead of silently truncating.

    Wholesale per contract, in the caller's transaction, mirroring
    ``write_effective_function_rows``. Wholesale because a distillation's rows
    ARE the set it derived: a capability the contract no longer has must
    disappear, and an upsert would leave the stale row behind to keep charging
    exposure forever.

    Scoped by ``contract_id`` and NOT by job: re-analysis mints a new job, so a
    job-scoped delete would never reach the previous job's rows and each
    re-analysis would add a second full signal set for the same contract.

    Every signal is validated BEFORE the delete, so the operation is
    all-or-nothing regardless of caller discipline. Validating during the insert
    loop would leave a half-replaced contract behind whenever the caller catches
    the raise — and the distillation call site is fail-forward by spec, so it
    does exactly that. A partially replaced contract is worse than an
    unreplaced one: it charges a subset of its exposure with no trace.

    The caller commits. Returns the number of rows deleted, so a writer can log
    the replacement rather than infer it.
    """
    from db.models import FunctionScoreSignal
    from services.scoring.schema import signal_to_row_kwargs

    _validate_replacement(session, contract_id=contract_id, signals=signals)

    replaced = _replaced_contract_ids(session)
    if contract_id in replaced:
        raise ValueError(
            f"contract {contract_id} was already replaced in this transaction; "
            "distillation must pass the contract's complete signal set in one call, "
            "grouped by contract_id and never by (contract_id, deployment_address)"
        )

    deleted = (
        session.query(FunctionScoreSignal)
        .filter(FunctionScoreSignal.contract_id == contract_id)
        .delete(synchronize_session=False)
    )
    session.flush()
    for signal in signals:
        session.add(FunctionScoreSignal(**signal_to_row_kwargs(signal, job_id=job_id)))
    session.flush()
    replaced.add(contract_id)
    return int(deleted)


def _validate_replacement(session: Session, *, contract_id: int, signals: list[FunctionSignal]) -> None:
    """Every signal agrees with the contract row it claims. Raises before any write.

    ``protocol_id`` is the load-bearing one: a signal carrying the wrong
    protocol inserts happily and is then read by that protocol's fold — a
    finding charged against a protocol it was never derived from, invisible
    until the next distillation overwrites it.

    ``deployment_address`` is checked for canonical form but NOT against the
    contract row: for a proxy child the deployment address is the PROXY's, and
    ``contracts`` carries no column naming its parent proxy, so there is nothing
    to compare against. Asserting equality with ``contract.address`` would
    reject the split-proxy case this schema exists to support.
    """
    from db.models import Contract

    contract = session.get(Contract, contract_id)
    if contract is None:
        raise ValueError(f"contract {contract_id} does not exist; refusing to write signals against it")
    if contract.protocol_id is None:
        raise ValueError(f"contract {contract_id} has no protocol_id; its signals could not be attributed")

    contract_chain = coalesce_chain(contract.chain)
    for signal in signals:
        if signal.contract_id != contract_id:
            raise ValueError(f"signal for contract {signal.contract_id} passed to replace of {contract_id}")
        if signal.protocol_id != contract.protocol_id:
            raise ValueError(
                f"signal claims protocol {signal.protocol_id} but contract {contract_id} "
                f"belongs to protocol {contract.protocol_id}"
            )
        if coalesce_chain(signal.chain) != contract_chain:
            raise ValueError(
                f"signal claims chain {signal.chain!r} but contract {contract_id} is on {contract.chain!r}"
            )
        if not signal.deployment_address or signal.deployment_address != signal.deployment_address.lower():
            raise ValueError(f"deployment_address must be a lowercased address, got {signal.deployment_address!r}")
