"""The fold's population read: one pinned query, no job-currency filtering.

``function_score_signals`` is replaced wholesale per contract, so every present row is current. Centralizing the query
prevents a job-scoped filter that would double-count or drop re-analysed contracts. The order is part of the contract:
inv. 11/12 require byte-identical documents.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import event
from sqlalchemy.orm import Session

from services.scoring.schema import FunctionSignal, coalesce_chain, signal_from_row

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from db.models import FunctionScoreSignal

# Contracts already replaced this transaction. A second replace means signals were grouped finer than ``contract_id``
# and the first group's rows would be silently deleted, so it raises.
_REPLACED_KEY = "_scoring_replaced_contract_ids"


def _replaced_contract_ids(session: Session) -> set[int]:
    return session.info.setdefault(_REPLACED_KEY, set())


@event.listens_for(Session, "after_transaction_end")
def _clear_replaced_contract_ids(session: Session, transaction: object) -> None:
    """Disarm the guard when the outermost transaction ends, and only then.

    ``after_commit``/``after_rollback`` also fire for savepoints, which the distiller uses per contract, so they'd clear
    the set every contract. ``not nested`` isn't enough either: ``Session.flush()`` opens a non-nested subtransaction.
    Only the session-level transaction has ``parent is None``.
    """
    if getattr(transaction, "parent", None) is None:
        session.info.pop(_REPLACED_KEY, None)


def current_signal_rows(session: Session, protocol_id: int) -> list[FunctionScoreSignal]:
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
    """The fold's input: every current signal for one protocol, typed and totally ordered by identity key (inv.

    11/12).
    """
    return [signal_from_row(row) for row in current_signal_rows(session, protocol_id)]


def current_signals_with_faults(
    session: Session, protocol_id: int
) -> tuple[list[FunctionSignal], list[dict[str, object]]]:
    """The fold's input, plus the rows that couldn't be typed.

    Several JSONB columns have Python-only shape checks, so a row not written by the sanctioned writer can fail them.
    Such a row withholds itself and names the column; the rest of the protocol still scores.
    :func:`current_signals_for_protocol` keeps the strict behaviour.
    """
    signals: list[FunctionSignal] = []
    faults: list[dict[str, object]] = []
    for row in current_signal_rows(session, protocol_id):
        # Shape before typing: two columns type cleanly and only fail when the fold walks them.
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
    """The first column not holding its declared shape, or ``None``.

    ``witness_notes`` and ``severity_basis`` type cleanly but break when iterated, hence the check here.
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
    """The population order for in-memory signals (offline CLI), matching :func:`current_signal_rows` so both feeding
    modes fold identically.
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

    The caller must pass the contract's complete signal set: the delete is scoped by ``contract_id``, so grouping by
    deployment address would drop rows. The double-replace guard makes that raise.

    Wholesale (like ``write_effective_function_rows``) so capabilities that disappeared stop charging; not job-scoped,
    since re-analysis mints new jobs. All signals are validated before the delete so a caught raise can't leave a
    half-replaced contract.

    The caller commits. Returns the number of rows deleted.
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

    ``protocol_id`` matters most: a wrong one would be charged to another protocol's fold. ``deployment_address`` is
    only checked for form, since for a proxy child it's the proxy's address and ``contracts`` has no parent-proxy
    column.
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
