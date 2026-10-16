"""Read-only census of missing effect observations; queue drainage is not coverage."""

from __future__ import annotations

from collections import Counter

from sqlalchemy import or_, select

from db.models import Contract, EffectiveFunction, EffectVerdict, PendingEffectsWork
from services.effects.selection import _carries_public_admission_claim, _enrolled_families, _has_effect_evidence
from utils.chains import UnknownChainError, chain_by_name


def effects_coverage(session, protocol_id: int) -> dict:
    # Use the selector's eligibility rules without its job-ownership prediction, expensive
    # value ordering, or capability trees. An in-flight/failed sibling must not hide a gap.
    rows = session.execute(
        select(
            EffectiveFunction.id,
            Contract.chain,
            Contract.address,
            EffectiveFunction.deployment_address,
            EffectiveFunction.selector,
            EffectiveFunction.claims,
            EffectiveFunction.authority_public,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(
            Contract.protocol_id == protocol_id,
            _has_effect_evidence(),
            or_(EffectiveFunction.authority_public.is_(False), _carries_public_admission_claim()),
        )
        .order_by(EffectiveFunction.id)
    ).all()
    identities, required = {}, {}
    for fid, chain, address, deployment, selector, claims, public in rows:
        families = _enrolled_families(claims, public=bool(public))
        if families == frozenset():
            continue
        try:
            chain_id = chain_by_name(chain or "ethereum").chain_id
        except UnknownChainError:
            chain_id = None
        identities[fid] = (chain_id, (deployment or address).lower(), selector or "")
        required[fid] = families
    observations = {fid: {} for fid in identities}
    unmatched = 0
    if identities:
        for fid, chain_id, address, selector, family, verdict in session.execute(
            select(
                EffectVerdict.function_id,
                EffectVerdict.chain_id,
                EffectVerdict.contract_address,
                EffectVerdict.selector,
                EffectVerdict.effect_class,
                EffectVerdict.verdict,
            )
            .where(EffectVerdict.function_id.in_(identities))
            .order_by(EffectVerdict.id)
        ):
            if identities[fid] != (chain_id, address.lower(), selector):
                unmatched += 1
                continue
            observations[fid][family] = verdict
    pending = Counter()
    if identities:
        for fid, chain_id, address, state in session.execute(
            select(
                PendingEffectsWork.function_id,
                PendingEffectsWork.chain_id,
                PendingEffectsWork.deployment_address,
                PendingEffectsWork.state,
            ).where(PendingEffectsWork.protocol_id == protocol_id, PendingEffectsWork.function_id.in_(identities))
        ):
            if identities[fid][:2] == (chain_id, address.lower()):
                pending[state] += 1
    counts = Counter()
    gaps = []
    for fid, families in required.items():
        observed = observations[fid]
        counts["functions_with_verdicts" if observed else "functions_without_verdicts"] += 1
        counts["families_not_determined"] += int(families is None)
        missing = set(families or ()) - set(observed)
        counts["missing_required_families"] += len(missing)
        for verdict in observed.values():
            counts["proven_verdicts" if verdict == "proven" else "unknown_verdicts"] += 1
        if not observed or missing or families is None or any(v != "proven" for v in observed.values()):
            counts["functions_with_gaps"] += 1
            if len(gaps) < 8:
                gaps.append(
                    {
                        "function_id": fid,
                        "chain_id": identities[fid][0],
                        "deployment": identities[fid][1],
                        "missing_families": sorted(missing),
                        "families_not_determined": families is None,
                        "observations": observed,
                    }
                )
    return {
        "state": "incomplete" if counts["functions_with_gaps"] else "not_determined",
        "eligible_functions": len(required),
        **{
            key: counts[key]
            for key in (
                "functions_with_verdicts",
                "functions_without_verdicts",
                "functions_with_gaps",
                "missing_required_families",
                "families_not_determined",
                "proven_verdicts",
                "unknown_verdicts",
            )
        },
        "pending_work_by_state": dict(sorted(pending.items())),
        "mismatched_deployment_verdicts": unmatched,
        "gap_sample": gaps,
        "reading": "Stored-function/deployment observations, not an assessment-completeness or freshness proof. "
        "Missing observations remain visible even with zero queued work. Unknown verdicts are not negatives. "
        "Blank claims leave required synthesis families undetermined; per-job selection artifacts disclose cap drops. "
        "Code, block, analyzer and input freshness are not revalidated by this census.",
    }
