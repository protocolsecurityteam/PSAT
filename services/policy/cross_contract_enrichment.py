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

Facts are keyed by the address a call reaches. A call to a proxy runs its current implementation's code against the
proxy's storage, which is what that implementation's proxy-context job analysed, so that job's facts sit under the
proxy's address. A proxy whose current implementation has no such job has no facts.

A body call whose callee resolves to an address with no readable facts is recorded on the function as a
``cross_contract_gaps`` entry: its claims are not determined, never "none". The callee's facts landing marks the job
stale, so the gap heals. A sibling the target can't know about (a hook pointing at it from an unanalysed contract)
leaves no gap.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import and_, case, cast, exists, false, func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import Artifact, Contract, ControllerValue, EffectiveFunction, Job, JobStage, JobStatus
from db.queue import failed_semantic_artifact, get_artifact, usable_semantic_artifact
from services.concurrency import parallel_map
from services.policy.stale_policy import mark_policy_stale
from services.static.claims import Claim, resolve_claim_precedence
from services.static.cross_contract import (
    ProxyCoverage,
    build_callee_claim_map,
    claim_sort_key,
    controller_addresses,
    derive_cross_contract_claims,
    function_selectors,
    sibling_transfer_hook_links,
)
from utils.chains import UnknownChainError, chain_by_id
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

FACT_ARTIFACTS = ("effects", "control_snapshot")
DIAMOND_PROXY_TYPE = "eip2535"


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


def _on_chain(chain_id: int) -> Any:
    try:
        name = chain_by_id(chain_id).name
    except UnknownChainError:
        return false()
    return func.lower(func.coalesce(Contract.chain, "ethereum")) == name


def _proxy_address() -> Any:
    return func.lower(Job.request["proxy_address"].astext)


def _runs_behind_proxy(chain_id: int) -> Any:
    """The job analyses the implementation a proxy on ``chain_id`` currently delegates to. A secondary implementation
    runs only for calls the primary doesn't take, a diamond routes each selector to its own facet, and a beacon's
    ``proxy_address`` is the beacon itself.
    """
    return and_(
        Job.request["proxy_address"].astext.isnot(None),
        Job.request["discovery_relationship"].astext.is_distinct_from("secondary_implementation"),
        exists().where(
            Contract.address == _proxy_address(),
            Contract.is_proxy.is_(True),
            Contract.proxy_type.is_distinct_from(DIAMOND_PROXY_TYPE),
            func.lower(Contract.implementation) == func.lower(Job.address),
            _on_chain(chain_id),
        ),
    )


def _call_address(chain_id: int) -> Any:
    """The address whose calls run the job's analysed code against the storage its facts were read from."""
    return case((_runs_behind_proxy(chain_id), _proxy_address()), else_=func.lower(Job.address))


def call_address(session: Session, job: Job, *, chain_id: int) -> str:
    """The address siblings reach this job's contract at: its proxy when it is the proxy's current implementation."""
    return session.execute(select(_call_address(chain_id)).where(Job.id == job.id)).scalar_one_or_none() or ""


def _fact_holders(chain_id: int, *filters: Any):
    """Per call address on ``chain_id``, the job whose facts are read: among jobs with both fact artifacts, a proxy's
    current implementation first, then the one owning its contract row (the rows the claims land on), else the newest.
    ``filters`` may compare ``_call_address(chain_id)``.
    """

    def _has(name: str):
        return exists().where(Artifact.job_id == Job.id, Artifact.name == name)

    candidates = (
        select(
            Job.id.label("job_id"),
            _call_address(chain_id).label("address"),
            _runs_behind_proxy(chain_id).label("behind_proxy"),
            exists().where(Contract.job_id == Job.id).label("owns_contract"),
            Job.created_at,
        )
        .where(
            Job.address.isnot(None),
            Job.chain_id == chain_id,
            Job.request["effects_resume_work_id"].astext.is_(None),
            *filters,
            *(_has(name) for name in FACT_ARTIFACTS),
        )
        .subquery()
    )
    return (
        select(candidates.c.job_id, candidates.c.address)
        .distinct(candidates.c.address)
        .order_by(
            candidates.c.address,
            candidates.c.behind_proxy.desc(),
            candidates.c.owns_contract.desc(),
            candidates.c.created_at.desc(),
            candidates.c.job_id.desc(),
        )
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
    """``[(job_id, call address)]`` of the job's siblings on its chain, one fact holder per address."""
    rows = session.execute(
        _fact_holders(
            chain_id,
            Job.id != job.id,
            _call_address(chain_id) != call_address(session, job, chain_id=chain_id),
            _related_to(job),
        )
    ).all()
    return [(job_id, addr) for job_id, addr in rows if addr]


def holds_facts_for_its_address(session: Session, job: Job, *, chain_id: int) -> bool:
    """Whether siblings read this job's facts for its call address, rather than another sibling's."""
    row = session.execute(
        _fact_holders(
            chain_id,
            _call_address(chain_id) == call_address(session, job, chain_id=chain_id),
            or_(Job.id == job.id, _related_to(job)),
        )
    ).first()
    return row is not None and row[0] == job.id


def relevant_siblings(
    session: Session, job: Job, targets: list[tuple[Any, str]], *, snapshot: Any, chain_id: int
) -> list[tuple[Any, str]]:
    """The siblings a derivation between this job and them can involve: one side's state variables hold the other's
    address. A sibling without a contract row has no controller-value rows to consult, so it's kept.
    """
    ids = [job_id for job_id, _ in targets]
    if not ids:
        return []
    named_here = controller_addresses(snapshot.get("controller_values") if isinstance(snapshot, dict) else None)
    owning = set(session.execute(select(Contract.job_id).where(Contract.job_id.in_(ids))).scalars())
    naming_this = set(
        session.execute(
            select(Contract.job_id)
            .join(ControllerValue, ControllerValue.contract_id == Contract.id)
            .where(
                Contract.job_id.in_(ids),
                func.lower(ControllerValue.value) == call_address(session, job, chain_id=chain_id),
            )
            .distinct()
        ).scalars()
    )
    return [
        (job_id, address)
        for job_id, address in targets
        if address in named_here or job_id in naming_this or job_id not in owning
    ]


@dataclass
class SiblingFacts:
    effects: dict[str, dict] = field(default_factory=dict)
    snapshots: dict[str, dict] = field(default_factory=dict)
    job_for_address: dict[str, Any] = field(default_factory=dict)
    # Call addresses whose facts are a proxy's implementation's, with that implementation's address.
    implementations: dict[str, str] = field(default_factory=dict)
    # Addresses whose stored facts couldn't be read, with the read's exception (``None``: not a JSON object).
    unreadable: dict[str, BaseException | None] = field(default_factory=dict)


def fetch_sibling_facts(
    targets: list[tuple[Any, str]],
    *,
    session_factory: Callable[[], Session],
) -> SiblingFacts:
    def _fetch(target: tuple[Any, str]) -> tuple[Any, Any, str]:
        job_id, _addr = target
        with session_factory() as s:
            analysed = (s.execute(select(Job.address).where(Job.id == job_id)).scalar_one_or_none() or "").lower()
            return get_artifact(s, job_id, "effects"), get_artifact(s, job_id, "control_snapshot"), analysed

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
        effects_payload, snapshot_payload, analysed = outcome
        if failed_semantic_artifact("effects", effects_payload):
            # A failed effects build is no facts, not a callee whose functions make no claims.
            record_degraded(
                phase="cross_contract_enrichment",
                exc=ValueError("sibling effects artifact is a failed build"),
                context={"sibling_address": addr, "sibling_job_id": str(job_id)},
            )
            facts.unreadable[addr] = None
            continue
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
        if analysed and analysed != addr:
            facts.implementations[addr] = analysed
    return facts


def proxy_coverage(session: Session, facts: SiblingFacts, *, chain_id: int) -> dict[str, ProxyCoverage]:
    """Which calls through each proxy among the callees with facts run the implementation those facts describe."""
    proxies = sorted(facts.implementations)
    if not proxies:
        return {}
    split = set(
        session.execute(
            select(Contract.address).where(
                Contract.address.in_(proxies),
                Contract.is_proxy.is_(True),
                func.cardinality(Contract.secondary_implementations) > 0,
                _on_chain(chain_id),
            )
        ).scalars()
    )
    return {
        address: ProxyCoverage(frozenset(function_selectors(facts.effects.get(address))), address in split)
        for address in proxies
    }


def _gap_reason(session: Session, callee: str, *, chain_id: int, facts: SiblingFacts) -> tuple[str, Any]:
    """Why the callee had no facts to derive from, with the job that tells (the newest) or ``None``."""
    if callee in facts.unreadable:
        return "facts_unreadable", facts.job_for_address.get(callee)
    if callee in facts.effects:
        # A selector the proxy's implementation doesn't take.
        return "selector_outside_implementation", facts.job_for_address.get(callee)

    holder = session.execute(
        _fact_holders(
            chain_id,
            or_(func.lower(Job.address) == callee, _proxy_address() == callee),
            _call_address(chain_id) == callee,
        )
    ).first()
    if holder is not None:
        return "outside_sibling_scope", holder[0]

    def _has(name: str):
        return exists().where(Artifact.job_id == Job.id, Artifact.name == name)

    proxy = session.execute(
        select(Contract.implementation, Contract.proxy_type)
        .where(Contract.address == callee, Contract.is_proxy.is_(True), _on_chain(chain_id))
        .order_by(Contract.id)
        .limit(1)
    ).first()
    if proxy is not None and proxy[1] == DIAMOND_PROXY_TYPE:
        return "callee_is_diamond", None
    if proxy is not None:
        implementation = (proxy[0] or "").lower()
        if not implementation:
            return "implementation_unknown", None
        analyses = and_(
            func.lower(Job.address) == implementation,
            _proxy_address() == callee,
            Job.request["discovery_relationship"].astext.is_distinct_from("secondary_implementation"),
        )
    else:
        analyses = func.lower(Job.address) == callee
    jobs = session.execute(
        select(Job.id, Job.status, _has("effects") & _has("control_snapshot"))
        .where(analyses, Job.chain_id == chain_id, Job.request["effects_resume_work_id"].astext.is_(None))
        .order_by(Job.created_at.desc(), Job.id.desc())
    ).all()
    if not jobs:
        return ("implementation_not_analyzed" if proxy is not None else "not_analyzed"), None
    for job_id, _status, has_facts in jobs:
        # Facts read against a proxy's storage, which don't describe the implementation's own address.
        if has_facts:
            return "callee_is_implementation", job_id
    for job_id, status, _has_facts in jobs:
        if status in (JobStatus.queued, JobStatus.processing):
            return "analysis_pending", job_id
    for job_id, status, _has_facts in jobs:
        if status in (JobStatus.failed, JobStatus.failed_terminal):
            return "analysis_failed", job_id
    return "facts_not_stored", jobs[0][0]


def describe_gaps(
    session: Session,
    gaps_by_function: dict[str, list[dict[str, Any]]],
    *,
    chain_id: int,
    facts: SiblingFacts,
) -> dict[str, list[dict[str, Any]]]:
    """Each gap with the reason its callee had no facts, as observed now; it heals when the callee's facts land. A call
    whose selector isn't determined to a callee that has facts is ``selector_not_determined``; it doesn't heal.
    """
    reasons = {
        callee: _gap_reason(session, callee, chain_id=chain_id, facts=facts)
        for callee in sorted({gap["callee"] for gaps in gaps_by_function.values() for gap in gaps})
    }

    def _reason(gap: dict[str, Any]) -> str:
        if gap["selector"] is None and gap["callee"] in facts.effects:
            return "selector_not_determined"
        return reasons[gap["callee"]][0]

    return {
        fn_sig: sorted(
            (
                {
                    **gap,
                    "reason": _reason(gap),
                    "callee_job_id": str(reasons[gap["callee"]][1]) if reasons[gap["callee"]][1] else None,
                }
                for gap in gaps
            ),
            key=lambda gap: (str(gap.get("sink_id")), gap["selector"] or "", gap["callee"]),
        )
        for fn_sig, gaps in gaps_by_function.items()
    }


def write_gaps(
    session: Session,
    *,
    contract_id: int,
    deployment_address: str | None,
    function_records: list[dict] | None,
    gaps: dict[str, list[dict[str, Any]]],
    payload: dict | None,
) -> None:
    """Set each evaluated row's and payload record's ``cross_contract_gaps``: its function's gaps, ``[]`` when it has
    none. A row no payload record names stays NULL (not evaluated). Doesn't commit.
    """
    selector_for = selector_by_function_key(function_records)
    by_selector: dict[str, list[dict[str, Any]]] = {}
    for fn_sig, fn_gaps in gaps.items():
        selector = selector_for.get(fn_sig)
        if selector:
            by_selector.setdefault(selector, []).extend(fn_gaps)
    evaluated_selectors = set(selector_for.values())
    evaluated_signatures = {
        key for record in function_records or [] for key in (record.get("function"), record.get("abi_signature")) if key
    }
    rows = session.execute(
        select(EffectiveFunction).where(
            EffectiveFunction.contract_id == contract_id,
            deployment_scope(EffectiveFunction.deployment_address, deployment_address),
        )
    ).scalars()
    for row in rows:
        selector = (row.selector or "").lower()
        if selector in evaluated_selectors:
            row.cross_contract_gaps = by_selector.get(selector, [])
        elif row.abi_signature in evaluated_signatures:
            row.cross_contract_gaps = gaps.get(row.abi_signature or "", [])
    for record in (payload or {}).get("functions", []):
        fn_sig = record.get("function") or record.get("abi_signature")
        record["cross_contract_gaps"] = gaps.get(fn_sig, []) if fn_sig else []


def jobs_with_gaps_on(session: Session, job_ids: Iterable[Any], callee: str) -> set[Any]:
    """Which of ``job_ids`` own rows recording a gap on ``callee``."""
    ids = list(job_ids)
    if not ids:
        return set()
    return set(
        session.execute(
            select(Contract.job_id)
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .where(
                Contract.job_id.in_(ids),
                EffectiveFunction.cross_contract_gaps.op("@>")(cast([{"callee": callee}], JSONB)),
            )
            .distinct()
        ).scalars()
    )


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
    # Rows the own pass can't single out; it leaves them alone, so they're no evidence either way.
    unjudged: set[int] = set()
    for fn_sig, claims in sorted(contribution.items()):
        selector = selector_for.get(fn_sig)
        matches = [row for row in rows if (row.selector == selector if selector else row.abi_signature == fn_sig)]
        if len(matches) != 1:
            unjudged.update(row.id for row in matches)
            continue
        row = matches[0]
        derived.setdefault(row.id, []).extend(claims)
        if merge_claims(row.claims, claims) != merge_claims(row.claims, []):
            return True
    return any(
        _attributed_to(claim, source_address) and claim not in derived.get(row.id, [])
        for row in rows
        if row.id not in unjudged
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
    source_address = call_address(session, job, chain_id=chain_id)
    if not source_address or not holds_facts_for_its_address(session, job, chain_id=chain_id):
        return 0
    source_effects = usable_semantic_artifact("effects", get_artifact(session, job.id, "effects"))
    source_snapshot = get_artifact(session, job.id, "control_snapshot")
    if not isinstance(source_effects, dict) or not isinstance(source_snapshot, dict):
        return 0
    source_job_id = job.id
    targets = related_jobs_with_facts(session, job, chain_id=chain_id)
    target_ids = [job_id for job_id, _ in targets]
    relevant = {
        job_id for job_id, _ in relevant_siblings(session, job, targets, snapshot=source_snapshot, chain_id=chain_id)
    }
    holding = jobs_holding_claims_from(session, target_ids, source_address)
    # A gap on this address is now answerable.
    awaiting = jobs_with_gaps_on(session, target_ids, source_address)
    # A target mid-policy may have read its siblings before these facts landed, and its rows hold neither the claims nor
    # the gaps it is about to write; only a mark makes it read again. When these facts replace earlier ones, any
    # target mid-policy may be writing claims derived from them.
    replacing = replaced_facts or _other_job_held_facts(session, job, chain_id=chain_id)
    in_policy = {
        job_id
        for job_id in _jobs_processing_policy(session, target_ids)
        if replacing or job_id in relevant or job_id in holding
    }
    to_check = [
        (job_id, address)
        for job_id, address in targets
        if job_id in relevant or job_id in holding or job_id in awaiting or job_id in in_policy
    ]
    facts = fetch_sibling_facts(to_check, session_factory=session_factory)
    callee_claim_map = build_callee_claim_map({source_address: source_effects})
    analysed = (job.address or "").lower()
    implementations = {source_address: analysed} if analysed != source_address else {}

    marked = 0
    for target_job_id, address in to_check:
        reason: str | None = None
        if address in facts.unreadable:
            reason = "facts_unreadable"
        elif target_job_id in awaiting:
            reason = "gap_answerable"
        elif target_job_id in in_policy:
            reason = "target_mid_policy"
        else:
            snapshot = facts.snapshots[address]
            contribution = derive_cross_contract_claims(
                facts.effects[address],
                snapshot.get("controller_values", {}),
                callee_claim_map,
                sibling_transfer_hooks=sibling_transfer_hook_links(
                    address, {source_address: source_effects}, {source_address: source_snapshot}
                ),
                callee_implementations=implementations,
            )
            if not contribution and target_job_id not in holding:
                continue
            try:
                if contribution_is_stale(
                    session, target_job_id=target_job_id, source_address=source_address, contribution=contribution
                ):
                    reason = "claims_changed"
            except Exception as exc:
                session.rollback()
                record_degraded(
                    phase="cross_contract_dependents",
                    exc=exc,
                    context={"sibling_address": address, "sibling_job_id": str(target_job_id)},
                )
                reason = "check_failed"
        if reason is None:
            continue
        mark_policy_stale(session, target_job_id)
        session.commit()
        marked += 1
        logger.info(
            "Job %s: marked sibling job %s stale for cross-contract claims (%s)",
            source_job_id,
            target_job_id,
            reason,
            extra={"phase": "cross_contract_dependents", "sibling_job_id": str(target_job_id), "reason": reason},
        )
    return marked


def _other_job_held_facts(session: Session, job: Job, *, chain_id: int) -> bool:
    return (
        session.execute(
            _fact_holders(
                chain_id,
                _call_address(chain_id) == call_address(session, job, chain_id=chain_id),
                Job.id != job.id,
                _related_to(job),
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
