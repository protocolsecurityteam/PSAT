"""Storage and invalidation for cross-contract ``policy_derived`` claims; the derivations live in
``services.static.cross_contract``.

A derivation joins a target with one sibling, so its output must depend only on stored facts, never on which job
finished first:

- A sibling's facts are its ``effects`` (static) and ``control_snapshot`` (resolution) artifacts. Siblings are gated
  on both being stored, not on job completion.
- The target's own pass in its policy stage is the only writer of these claims. It clears the target's stale mark
  (``services.policy.stale_policy``), then reads every sibling's facts.
- After its own pass, a job checks each sibling it contributes to. If the stored claims disagree with what its facts
  now derive (a claim to add, or one it no longer supports), the sibling is marked stale and its policy re-runs with
  every stage after it, so every consumer of the claims sees them.

A sibling with no stored facts contributes nothing: a claim it would have produced is absent, not disproven.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import cast, exists, func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import Artifact, Contract, EffectiveFunction, Job, JobStage, JobStatus
from db.queue import get_artifact
from services.concurrency import parallel_map
from services.policy.stale_policy import mark_policy_stale
from services.static.claims import Claim, resolve_claim_precedence
from services.static.cross_contract import (
    build_callee_claim_map,
    claim_sort_key,
    derive_cross_contract_claims,
    sibling_transfer_hook_links,
)
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

FACT_ARTIFACTS = ("effects", "control_snapshot")


def merge_claims(existing: Iterable[Claim] | None, additions: Iterable[Claim]) -> list[Claim]:
    """Precedence merge whose tie-break between equal tiers doesn't depend on which side arrived first."""
    return resolve_claim_precedence(sorted([*(existing or []), *additions], key=claim_sort_key))


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
        matches = session.execute(stmt.order_by(EffectiveFunction.id)).scalars().all()
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


def _fact_holders(chain_id: int, *filters: Any):
    """Per address on ``chain_id``, the job whose facts are read: among jobs with both fact artifacts, the one owning
    the address's contract row (the rows the claims land on), else the newest.
    """

    def _has(name: str):
        return exists().where(Artifact.job_id == Job.id, Artifact.name == name)

    address = func.lower(Job.address)
    owns_contract = exists().where(Contract.job_id == Job.id)
    return (
        select(Job.id, address)
        .where(
            Job.address.isnot(None),
            Job.chain_id == chain_id,
            Job.request["effects_resume_work_id"].astext.is_(None),
            *filters,
            *(_has(name) for name in FACT_ARTIFACTS),
        )
        .distinct(address)
        .order_by(address, owns_contract.desc(), Job.created_at.desc(), Job.id.desc())
    )


def _related_to(job: Job) -> Any:
    """Sibling is symmetric: same protocol, same company, same parent, or parent and child. Discovery doesn't stamp a
    company on every job, so the protocol is the main scope; the links cover jobs without one.
    """
    parent_id = _parent_job_uuid(job)
    related = [Job.request["parent_job_id"].astext == str(job.id)]
    if job.protocol_id is not None:
        related.append(Job.protocol_id == job.protocol_id)
    if job.company:
        related.append(Job.company == job.company)
    if parent_id is not None:
        related.append(Job.request["parent_job_id"].astext == str(parent_id))
        related.append(Job.id == parent_id)
    return or_(*related)


def related_jobs_with_facts(session: Session, job: Job, *, chain_id: int) -> list[tuple[Any, str]]:
    """``[(job_id, address)]`` of the job's siblings on its chain, one fact holder per address."""
    rows = session.execute(
        _fact_holders(
            chain_id,
            Job.id != job.id,
            func.lower(Job.address) != (job.address or "").lower(),
            _related_to(job),
        )
    ).all()
    return [(job_id, addr) for job_id, addr in rows if addr]


def holds_facts_for_its_address(session: Session, job: Job, *, chain_id: int) -> bool:
    """Whether siblings read this job's facts for its address, rather than another sibling's."""
    row = session.execute(
        _fact_holders(
            chain_id, func.lower(Job.address) == (job.address or "").lower(), or_(Job.id == job.id, _related_to(job))
        )
    ).first()
    return row is not None and row[0] == job.id


@dataclass
class SiblingFacts:
    effects: dict[str, dict] = field(default_factory=dict)
    snapshots: dict[str, dict] = field(default_factory=dict)
    job_for_address: dict[str, Any] = field(default_factory=dict)
    # Addresses whose stored facts couldn't be read, with the read's exception (``None``: not a JSON object).
    unreadable: dict[str, BaseException | None] = field(default_factory=dict)


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
        facts.job_for_address[addr] = job_id
        if isinstance(outcome, BaseException):
            record_degraded(
                phase="cross_contract_enrichment",
                exc=outcome,
                context={"sibling_address": addr, "sibling_job_id": str(job_id)},
            )
            logger.warning("sibling artifact fetch failed for %s: %s", addr, outcome)
            facts.unreadable[addr] = outcome
            continue
        effects_payload, snapshot_payload = outcome
        if not isinstance(effects_payload, dict) or not isinstance(snapshot_payload, dict):
            record_degraded(
                phase="cross_contract_enrichment",
                exc=ValueError("sibling facts are not JSON objects"),
                context={"sibling_address": addr, "sibling_job_id": str(job_id)},
            )
            facts.unreadable[addr] = None
            continue
        facts.effects[addr] = effects_payload
        facts.snapshots[addr] = snapshot_payload
    return facts


def _attributed_to(claim: Any, source_address: str) -> bool:
    """A stored ``policy_derived`` claim the source's facts produced: its witness names the source."""
    if not isinstance(claim, dict) or claim.get("tier") != "policy_derived":
        return False
    witness = claim.get("witness")
    if not isinstance(witness, dict):
        return False
    return any(str(witness.get(key) or "").lower() == source_address for key in ("callee", "configures"))


def jobs_holding_claims_from(session: Session, job_ids: Iterable[Any], source_address: str) -> set[Any]:
    """Which of ``job_ids`` own rows carrying a ``policy_derived`` claim attributed to ``source_address``."""
    ids = list(job_ids)
    if not ids:
        return set()
    attributed = [
        EffectiveFunction.claims.op("@>")(cast([{"tier": "policy_derived", "witness": {key: source_address}}], JSONB))
        for key in ("callee", "configures")
    ]
    return set(
        session.execute(
            select(Contract.job_id)
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .where(Contract.job_id.in_(ids), or_(*attributed))
            .distinct()
        ).scalars()
    )


def contribution_is_stale(
    session: Session,
    *,
    target_job_id: Any,
    source_address: str,
    contribution: dict[str, list[Claim]],
) -> bool:
    """Whether the target's stored claims disagree with the source's current contribution: merging it would change a
    row, or a row holds a claim attributed to the source that the contribution no longer derives.

    Rows are matched as the own pass writes them. A target that hasn't published ``effective_permissions`` hasn't
    reached its own pass, which will read the source's facts.
    """
    job = session.get(Job, target_job_id)
    payload = get_artifact(session, target_job_id, "effective_permissions")
    contract_id = session.execute(
        select(Contract.id).where(Contract.job_id == target_job_id).order_by(Contract.id).limit(1)
    ).scalar_one_or_none()
    if job is None or contract_id is None or not isinstance(payload, dict):
        return False
    request = job.request if isinstance(job.request, dict) else {}
    deployment_address = normalize_deployment(request.get("proxy_address"))
    rows = (
        session.execute(
            select(EffectiveFunction)
            .where(
                EffectiveFunction.contract_id == contract_id,
                deployment_scope(EffectiveFunction.deployment_address, deployment_address),
            )
            .order_by(EffectiveFunction.id)
        )
        .scalars()
        .all()
    )
    selector_for = selector_by_function_key(payload.get("functions"))
    derived: dict[int, list[Claim]] = {}
    for fn_sig, claims in sorted(contribution.items()):
        selector = selector_for.get(fn_sig)
        matches = [row for row in rows if (row.selector == selector if selector else row.abi_signature == fn_sig)]
        if len(matches) != 1:
            continue
        row = matches[0]
        derived.setdefault(row.id, []).extend(claims)
        if merge_claims(row.claims, claims) != merge_claims(row.claims, []):
            return True
    return any(
        _attributed_to(claim, source_address) and claim not in derived.get(row.id, [])
        for row in rows
        for claim in row.claims or []
    )


def mark_stale_dependents(
    session: Session,
    job: Job,
    *,
    chain_id: int,
    session_factory: Callable[[], Session],
    replaced_facts: bool = False,
) -> int:
    """Run once this job's facts are stored: mark stale every sibling whose stored claims disagree with what these
    facts derive for it. Returns the count marked. ``replaced_facts``: this job stored facts before.

    A sibling whose facts can't be read, or whose check fails, is marked anyway: a spurious re-run is cheap and can't
    loop (a re-run stores no facts), a missed one leaves its claims wrong. If the pass itself fails, every sibling is.
    """
    try:
        return _mark_stale_dependents(
            session, job, chain_id=chain_id, session_factory=session_factory, replaced_facts=replaced_facts
        )
    except Exception as exc:
        session.rollback()
        record_degraded(phase="cross_contract_dependents", exc=exc, context={"job_id": str(job.id)})
        # A sibling that hasn't published reads these facts in its own pass.
        published = [
            target_job_id
            for target_job_id, _address in related_jobs_with_facts(session, job, chain_id=chain_id)
            if session.execute(
                select(Artifact.id).where(Artifact.job_id == target_job_id, Artifact.name == "effective_permissions")
            ).first()
            is not None
        ]
        for target_job_id in published:
            mark_policy_stale(session, target_job_id)
        session.commit()
        return len(published)


def _mark_stale_dependents(
    session: Session,
    job: Job,
    *,
    chain_id: int,
    session_factory: Callable[[], Session],
    replaced_facts: bool,
) -> int:
    source_address = (job.address or "").lower()
    if not source_address or not holds_facts_for_its_address(session, job, chain_id=chain_id):
        return 0
    source_effects = get_artifact(session, job.id, "effects")
    source_snapshot = get_artifact(session, job.id, "control_snapshot")
    if not isinstance(source_effects, dict) or not isinstance(source_snapshot, dict):
        return 0
    source_job_id = job.id
    targets = related_jobs_with_facts(session, job, chain_id=chain_id)
    facts = fetch_sibling_facts(targets, session_factory=session_factory)
    callee_claim_map = build_callee_claim_map({source_address: source_effects})
    target_ids = [job_id for job_id, _ in targets]
    holding = jobs_holding_claims_from(session, target_ids, source_address)
    # A target mid-policy has wiped its rows but may be writing claims derived from the facts these replaced; only a
    # mark makes it re-read them.
    replacing = replaced_facts or _other_job_held_facts(session, job, chain_id=chain_id)
    in_policy = _jobs_processing_policy(session, target_ids) if replacing else set()

    marked = 0
    for target_job_id, address in targets:
        if address in facts.unreadable:
            stale = True
        else:
            snapshot = facts.snapshots[address]
            contribution = derive_cross_contract_claims(
                facts.effects[address],
                snapshot.get("controller_values", {}),
                callee_claim_map,
                sibling_transfer_hooks=sibling_transfer_hook_links(
                    address, {source_address: source_effects}, {source_address: source_snapshot}
                ),
            )
            if not contribution and target_job_id not in holding:
                if target_job_id not in in_policy:
                    continue
                stale = True
            else:
                try:
                    stale = target_job_id in in_policy or contribution_is_stale(
                        session,
                        target_job_id=target_job_id,
                        source_address=source_address,
                        contribution=contribution,
                    )
                except Exception as exc:
                    session.rollback()
                    record_degraded(
                        phase="cross_contract_dependents",
                        exc=exc,
                        context={"sibling_address": address, "sibling_job_id": str(target_job_id)},
                    )
                    stale = True
        if not stale:
            continue
        mark_policy_stale(session, target_job_id)
        session.commit()
        marked += 1
        logger.info(
            "Job %s: marked sibling job %s stale for cross-contract claims",
            source_job_id,
            target_job_id,
            extra={"phase": "cross_contract_dependents", "sibling_job_id": str(target_job_id)},
        )
    return marked


def _other_job_held_facts(session: Session, job: Job, *, chain_id: int) -> bool:
    return (
        session.execute(
            _fact_holders(
                chain_id, func.lower(Job.address) == (job.address or "").lower(), Job.id != job.id, _related_to(job)
            )
        ).first()
        is not None
    )


def _jobs_processing_policy(session: Session, job_ids: list[Any]) -> set[Any]:
    if not job_ids:
        return set()
    return set(
        session.execute(
            select(Job.id).where(Job.id.in_(job_ids), Job.stage == JobStage.policy, Job.status == JobStatus.processing)
        ).scalars()
    )
