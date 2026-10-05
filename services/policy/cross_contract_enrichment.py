"""Storage and ordering for cross-contract ``policy_derived`` claims; the derivations live in
``services.static.cross_contract``.

A derivation joins a target with one sibling, so its output must depend only on stored facts, never on which job
finished first:

- A sibling's facts are its ``effects`` (static) and ``control_snapshot`` (resolution) artifacts. Siblings are gated
  on both being stored, not on job completion.
- Each sibling's contribution is independent and the merge is commutative, so the target can be enriched from the
  full sibling set (its own pass) or from one sibling at a time (a dependent pass) with the same result.
- Both passes, and the effects-stage claim bridge, hold the target contract's claims-writer lock while they read and
  write its claims. The target publishes its ``effective_permissions`` artifact before its own pass; a sibling's
  policy stage, whose facts were stored earlier, takes the target's lock before checking for that artifact. So either
  the target's pass sees the sibling, or the sibling's dependent pass sees the target.

A sibling with no stored facts, or one that never reaches its policy stage after the target ran, contributes nothing:
a claim it would have produced is absent, not disproven.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import exists, or_, select, text
from sqlalchemy.orm import Session

from db.deployment import deployment_scope
from db.models import Artifact, EffectiveFunction, Job
from db.queue import get_artifact
from services.concurrency import parallel_map
from services.static.claims import Claim, resolve_claim_precedence
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

FACT_ARTIFACTS = ("effects", "control_snapshot")


def claims_writer_lock_key(contract_id: int) -> int:
    h = hashlib.sha256(f"cross_contract_claims:{int(contract_id)}".encode()).digest()
    return int.from_bytes(h[:8], "big") & ((1 << 63) - 1)


def lock_contract_claims(session: Session, contract_ids: Iterable[int]) -> None:
    """Take each contract's claims-writer lock for the rest of the transaction, in id order so writers never
    deadlock.
    """
    for contract_id in sorted({int(c) for c in contract_ids}):
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": claims_writer_lock_key(contract_id)})


def _claim_sort_key(claim: Claim) -> str:
    return json.dumps(claim, sort_keys=True, default=str)


def merge_claims(existing: Iterable[Claim] | None, additions: Iterable[Claim]) -> list[Claim]:
    """Precedence merge whose tie-break between equal tiers doesn't depend on which side arrived first."""
    return resolve_claim_precedence(sorted([*(existing or []), *additions], key=_claim_sort_key))


def apply_claims_to_payload(payload: dict, enriched: dict[str, list[Claim]]) -> bool:
    """Merge into an ``effective_permissions`` payload's function records; returns whether any record changed."""
    changed = False
    for fn in payload.get("functions", []):
        fn_sig = fn.get("function") or fn.get("abi_signature")
        additions = enriched.get(fn_sig) if fn_sig else None
        if not additions:
            continue
        existing = list(fn.get("claims") or [])
        merged = merge_claims(existing, additions)
        if merged != existing:
            fn["claims"] = merged
            changed = True
    return changed


def write_claims_to_rows(
    session: Session,
    *,
    contract_id: int,
    deployment_address: str | None,
    selector_for: dict[str, str],
    enriched: dict[str, list[Claim]],
    job_id: Any,
) -> bool:
    """Merge into the deployment's ``effective_functions`` rows; returns whether any row changed. Doesn't commit.

    A function must match exactly one row: the scope includes legacy untagged rows, and an ambiguous match would raise
    and lose the whole pass.
    """
    changed = False
    for fn_sig, new_claims in sorted(enriched.items()):
        stmt = select(EffectiveFunction).where(
            EffectiveFunction.contract_id == contract_id,
            deployment_scope(EffectiveFunction.deployment_address, deployment_address),
        )
        selector = selector_for.get(fn_sig)
        if selector:
            stmt = stmt.where(EffectiveFunction.selector == selector)
        else:
            stmt = stmt.where(EffectiveFunction.abi_signature == fn_sig)
        # NO KEY UPDATE: effect verdicts hold KEY SHARE on these rows while their stage waits for the writer lock.
        stmt = stmt.order_by(EffectiveFunction.id).with_for_update(key_share=True)
        matches = session.execute(stmt.execution_options(populate_existing=True)).scalars().all()
        if len(matches) != 1:
            logger.warning(
                "Job %s: cross-contract claims for %s matched %d effective_function rows; skipped",
                job_id,
                fn_sig,
                len(matches),
                extra={
                    "phase": "cross_contract_enrichment",
                    "function": fn_sig,
                    "matched_rows": len(matches),
                },
            )
            continue
        ef = matches[0]
        existing = list(ef.claims or [])
        merged = merge_claims(existing, new_claims)
        if merged != existing:
            ef.claims = merged
            changed = True
    return changed


def selector_by_function_key(function_records: list[dict] | None) -> dict[str, str]:
    """``{function key -> selector}`` from the effective-permissions payload, keyed by both Slither ``full_name`` and
    canonical ABI signature (they differ for contract/struct/enum params). The selector is taken from the payload
    so it matches what the writer stored.
    """
    out: dict[str, str] = {}
    for record in function_records or []:
        if not isinstance(record, dict):
            continue
        selector = record.get("selector")
        if not isinstance(selector, str) or not selector:
            continue
        for key in (record.get("function"), record.get("abi_signature")):
            if isinstance(key, str) and key:
                out.setdefault(key, selector.lower())
    return out


def _parent_job_uuid(job: Job) -> uuid.UUID | None:
    request = job.request if isinstance(job.request, dict) else {}
    raw = request.get("parent_job_id")
    if not raw:
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError:
        return None


def related_jobs_with_facts(session: Session, job: Job, *, chain_id: int) -> list[tuple[Any, str]]:
    """``[(job_id, address)]`` of the job's siblings on its chain that have both fact artifacts, oldest first.

    Sibling is symmetric: same company, same parent, or parent and child. The child direction matters because a
    child's facts can feed its parent's derivation.
    """
    parent_id = _parent_job_uuid(job)
    related = [Job.request["parent_job_id"].astext == str(job.id)]
    if job.company:
        related.append(Job.company == job.company)
    if parent_id is not None:
        related.append(Job.request["parent_job_id"].astext == str(parent_id))
        related.append(Job.id == parent_id)

    def _has(name: str):
        return exists().where(Artifact.job_id == Job.id, Artifact.name == name)

    rows = session.execute(
        select(Job.id, Job.address)
        .where(
            Job.id != job.id,
            Job.address.isnot(None),
            Job.chain_id == chain_id,
            or_(*related),
            *(_has(name) for name in FACT_ARTIFACTS),
        )
        .order_by(Job.created_at, Job.id)
    ).all()
    return [(job_id, address.lower()) for job_id, address in rows if address]


@dataclass
class SiblingFacts:
    effects: dict[str, dict] = field(default_factory=dict)
    snapshots: dict[str, dict] = field(default_factory=dict)
    # The job whose facts are held for each address; the newest wins when an address has several.
    job_for_address: dict[str, Any] = field(default_factory=dict)


def fetch_sibling_facts(
    targets: list[tuple[Any, str]],
    *,
    session_factory: Callable[[], Session],
) -> SiblingFacts:
    def _fetch(target: tuple[Any, str]) -> tuple[Any, Any]:
        job_id, _addr = target
        with session_factory() as s:
            return get_artifact(s, job_id, "effects"), get_artifact(s, job_id, "control_snapshot")

    facts = SiblingFacts()
    for (job_id, addr), outcome in parallel_map(_fetch, targets, max_workers=8):
        if isinstance(outcome, BaseException):
            record_degraded(
                phase="cross_contract_enrichment",
                exc=outcome,
                context={"sibling_address": addr, "sibling_job_id": str(job_id)},
            )
            logger.warning("sibling artifact fetch failed for %s: %s", addr, outcome)
            continue
        effects_payload, snapshot_payload = outcome
        if not isinstance(effects_payload, dict) or not isinstance(snapshot_payload, dict):
            continue
        facts.effects[addr] = effects_payload
        facts.snapshots[addr] = snapshot_payload
        facts.job_for_address[addr] = job_id
    return facts


def _redistill_signals(session: Session, job: Job) -> None:
    """Refresh the job's score signals from claims that landed after its effects stage distilled them."""
    from services.scoring.dirty import SCORE_DIRTY_CROSS_CONTRACT, mark_protocol_score_dirty
    from services.scoring.distill import distill_job_signals
    from services.scoring.population import replace_contract_signals

    session.flush()
    try:
        with session.begin_nested():
            grouped = distill_job_signals(session, job)
            for contract_id, signals in grouped.items():
                replace_contract_signals(session, contract_id=contract_id, signals=signals, job_id=job.id)
    except Exception as exc:
        record_degraded(
            phase="cross_contract_score_distillation",
            exc=exc,
            context={"job_id": str(job.id), "protocol_id": job.protocol_id},
        )
        logger.warning(
            "Job %s: score-signal refresh after cross-contract claims failed",
            job.id,
            exc_info=True,
            extra={"phase": "cross_contract_dependents", "protocol_id": job.protocol_id},
        )
        return
    mark_protocol_score_dirty(session, job.protocol_id, SCORE_DIRTY_CROSS_CONTRACT)


def enrich_dependent(
    session: Session,
    *,
    dependent_job_id: Any,
    enriched: dict[str, list[Claim]],
    source_job_id: Any,
    redistill: bool,
) -> bool:
    """Merge one sibling's contribution into a job that already ran its own pass; returns whether anything changed.

    Ends the session's transaction. A job without a published ``effective_permissions`` artifact is skipped: its own
    pass hasn't taken the lock yet and will see the sibling.
    """
    from db.deployment import normalize_deployment
    from db.models import Contract
    from db.queue import store_artifact

    job = session.get(Job, dependent_job_id)
    contract_ids = list(session.execute(select(Contract.id).where(Contract.job_id == dependent_job_id)).scalars())
    if job is None or not contract_ids:
        session.commit()
        return False
    lock_contract_claims(session, contract_ids)
    payload = get_artifact(session, dependent_job_id, "effective_permissions")
    if not isinstance(payload, dict):
        session.commit()
        return False

    request = job.request if isinstance(job.request, dict) else {}
    # The same contract row the policy writer chose.
    contract_row = session.execute(select(Contract).where(Contract.job_id == dependent_job_id).limit(1)).scalar_one()
    rows_changed = write_claims_to_rows(
        session,
        contract_id=contract_row.id,
        deployment_address=normalize_deployment(request.get("proxy_address")),
        selector_for=selector_by_function_key(payload.get("functions")),
        enriched=enriched,
        job_id=dependent_job_id,
    )
    payload_changed = apply_claims_to_payload(payload, enriched)
    if rows_changed or payload_changed:
        logger.info(
            "Job %s: cross-contract enrichment added policy claims from sibling job %s: %s",
            dependent_job_id,
            source_job_id,
            {fn_sig: [c["claim_id"] for c in claims] for fn_sig, claims in enriched.items()},
            extra={"phase": "cross_contract_dependents", "sibling_job_id": str(source_job_id)},
        )
    if rows_changed and redistill and isinstance(job.protocol_id, int):
        _redistill_signals(session, job)
    if payload_changed:
        # Commits the rows with it.
        store_artifact(session, dependent_job_id, "effective_permissions", data=payload)
    session.commit()
    return rows_changed or payload_changed
