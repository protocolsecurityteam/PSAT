"""Provenance loaders: perimeter, ledgers, audits, row counts, reach census."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sqlalchemy import false as sql_false
from sqlalchemy import func as sql_func
from sqlalchemy import or_ as sql_or
from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from services.scoring.planes._shared import CONTROL_RELATIONS, NATIVE_ASSET
from services.scoring.planes.value import ValuePlane, load_proven_eoa_entities
from services.scoring.schema import Tri, entity_key
from utils.scoring_status import (
    PERIMETER_NOT_DETERMINED,
    PERIMETER_SETTLED,
    PERIMETER_UNSETTLED,
)

# Only the I/O-edge loaders log: compute paths publish refusals into the document (the fold must replay from it alone).
# No ``record_degraded``: nothing binds an accumulator on the score loop or the CLI.
logger = logging.getLogger("services.scoring.planes")


# Reasons per relation; the published set comes from the database plus every relation the graph writer can emit, so
# unclassified relations are still published with counts.
UNCONSUMED_REACH_REASONS: dict[str, str] = {
    "safe_owner": (
        "one owner is not the unit that can act: a k-of-n Safe's authority is folded at "
        "the Safe, and a single owner edge would publish reach that owner cannot exercise "
        "alone. The Safe itself reaches through its own controller_value edges"
    ),
    "controller_value_unattributed": (
        "the principal is real but the authority RELATION behind it was never established "
        "— the label names a value the anchor holds (including dotted paths like "
        "'accountantState.payoutAddress'), not a proven authority over the anchor. An "
        "unestablished relation is a confidence item, never an edge"
    ),
    "external_call_target": (
        "direction: the anchor CALLS the target. Being called is not being controlled, so "
        "walking it as reach would invert the authority arrow"
    ),
    "capability_principal": (
        "a FUNCTION-level claim — this address is a resolved principal of a gated function "
        "on the anchor — not proof of authority over the anchor ENTITY, which is what this "
        "closure walks. Declining it costs confidence rather than earning it: the perimeter "
        "counts the relation whether or not the walk consumes it. The rationale published "
        "before model_version 1.1.0 — that the population is materialization-budget gated "
        "(PSAT_FP_MATERIALIZE_LIMIT) — is WITHDRAWN as refuted: the limit is not reached on "
        "any corpus measured, and the same spawn budget gates every relation equally, so it "
        "never distinguished this one"
    ),
    "timelock_owner": (
        "in the graph writer's authority allowlist (db.CONTROL_EDGE_RELATIONS) but not in "
        "this scorer's consumed set. It carries no rows on any corpus measured; this entry "
        "exists so the day it does, the exclusion is a stated one and not a silent drop"
    ),
    "proxy_admin_owner": (
        "in the graph writer's authority allowlist (db.CONTROL_EDGE_RELATIONS) but not in "
        "this scorer's consumed set. It carries no rows on any corpus measured; this entry "
        "exists so the day it does, the exclusion is a stated one and not a silent drop"
    ),
}

UNCONSUMED_REASON_UNCLASSIFIED = (
    "present in this protocol's control_graph_edges but classified by neither this scorer's "
    "consumed set nor its exclusion register — published with its count so an unrecognised "
    "relation is visible rather than silently unwalked"
)


def unconsumed_reach_relations(session: Session, protocol_id: int) -> dict[str, Any]:
    """Every edge not walked as reach, and why.

    Enumerated from the database (``GROUP BY relation``) plus ``db.CONTROL_EDGE_RELATIONS``, not from what this scorer
    names, so an unclassified or newly populated relation can't go silently unwalked. A zero count is a named exclusion.
    """
    from db.models import CONTROL_EDGE_RELATIONS as WRITER_RELATIONS
    from db.models import Contract, ControlGraphEdge, EffectiveFunction, FunctionPrincipal
    from services.governance.control_graph_types import FP_MATERIALIZE_LIMIT

    counts: dict[str, int] = {
        str(relation): int(total or 0)
        for relation, total in session.query(ControlGraphEdge.relation, sql_func.count(ControlGraphEdge.id))
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .group_by(ControlGraphEdge.relation)
        .order_by(ControlGraphEdge.relation)
        .all()
    }
    excluded = sorted((set(counts) | set(WRITER_RELATIONS)) - set(CONTROL_RELATIONS))
    relations = {
        relation: {
            "edges": counts.get(relation, 0),
            "reason": UNCONSUMED_REACH_REASONS.get(relation, UNCONSUMED_REASON_UNCLASSIFIED),
            "classified": relation in UNCONSUMED_REACH_REASONS,
        }
        for relation in excluded
    }
    # The materialization budget and headroom behind ``capability_principal``'s exclusion are published, so "the
    # perimeter is complete" is a checkable number.
    per_anchor = [
        int(total or 0)
        for _, _, total in session.query(
            EffectiveFunction.contract_id,
            EffectiveFunction.deployment_address,
            sql_func.count(sql_func.distinct(sql_func.lower(FunctionPrincipal.address))),
        )
        .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .group_by(EffectiveFunction.contract_id, EffectiveFunction.deployment_address)
        .order_by(EffectiveFunction.contract_id, EffectiveFunction.deployment_address)
        .all()
    ]
    observed_max = max(per_anchor, default=0)
    return {
        "relations": relations,
        "edges_excluded_total": sum(entry["edges"] for entry in relations.values()),
        "consumed": sorted(CONTROL_RELATIONS),
        "materialization_budget": {
            "limit": FP_MATERIALIZE_LIMIT,
            "distinct_principals_per_anchor_scope_max": observed_max,
            "headroom": FP_MATERIALIZE_LIMIT - observed_max,
            "anchor_scopes_at_the_limit": sum(1 for total in per_anchor if total >= FP_MATERIALIZE_LIMIT),
            "anchor_scopes": len(per_anchor),
            "reading": (
                "PSAT_FP_MATERIALIZE_LIMIT caps the principals materialised per (contract, "
                "deployment) scope. Published so the enumeration above can be read as UN-CLIPPED "
                "rather than trusted to be: anchor_scopes_at_the_limit is the number of scopes "
                "that could have lost a tail, and a zero there is the proven 'nothing was cut'"
            ),
        },
        "basis": (
            "every relation present in this protocol's control_graph_edges, unioned with "
            "every relation db.CONTROL_EDGE_RELATIONS lets the writer emit, minus the "
            "consumed set. Counts are of edges, not of principals: duplicate (principal, "
            "anchor) pairs are distinct witnesses and are counted as the rows they are"
        ),
        "reading": (
            "an excluded relation is reach this scorer is NOT claiming, published so a "
            "consumer can see the size of the bound and re-open the ruling when a "
            "witnessed licence lands. Declining to walk one costs confidence — it never "
            "earns it"
        ),
    }


def discovery_relation_entities(session: Session, protocol_id: int) -> dict[str, set[str]]:
    """Endpoints of every authority relation discovery recorded, per relation.

    The scorer walks three of the seven, but the other four's entities still enter the confidence perimeter.
    Non-authority relations are excluded. Sibling of :func:`unconsumed_reach_relations`.
    """
    from db.models import CONTROL_EDGE_RELATIONS, Contract, ControlGraphEdge

    out: dict[str, set[str]] = {relation: set() for relation in sorted(CONTROL_EDGE_RELATIONS)}
    rows = (
        session.query(
            ControlGraphEdge.relation, ControlGraphEdge.from_node_id, ControlGraphEdge.to_node_id, Contract.chain
        )
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphEdge.relation.in_(sorted(CONTROL_EDGE_RELATIONS)))
        .order_by(ControlGraphEdge.id)
        .all()
    )
    for relation, source, target, chain in rows:
        for raw in (source, target):
            address = str(raw or "").replace("address:", "").lower()
            if address:
                out[str(relation)].add(entity_key(chain, address))
    return out


def load_upgrade_provenance(session: Session, protocol_id: int) -> dict[str, Any]:
    """Upgrade history as provenance only (no severity in v1), counted by transaction (one carried 19 ``Upgraded``
    logs). Zero after exclusions publishes ``None``: no recorded event doesn't prove no upgrade.
    """
    from db.models import Contract
    from services.discovery.upgrade_history import governance_actions_for, upgrade_action_counts

    contract_ids = [
        row[0]
        for row in session.query(Contract.id).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    ]
    if not contract_ids:
        return {"contracts": 0, "governance_actions": 0, "per_contract": {}}
    counts = upgrade_action_counts(session, contract_ids)
    actions = governance_actions_for(session, contract_ids)
    per_contract = {
        str(cid): {
            "upgrade_count": entry.get("count"),
            "executor_kinds": entry.get("basis", {}).get("executor_kinds"),
            "recorded_event_coverage": entry.get("basis", {}).get("recorded_event_coverage"),
            "direct_upgrade_witnessed_at_block": entry.get("basis", {}).get("direct_upgrade_witnessed_at_block"),
        }
        for cid, entry in sorted(counts.items())
    }
    return {
        "contracts": len(per_contract),
        "governance_actions": len(actions),
        "per_contract": per_contract,
        "note": (
            "upper bound; deployments excluded, unproven events kept. Executor kind "
            "annotates and does not modify the upgrade-authority weakness in v1"
        ),
    }


def load_ledgers(session: Session, protocol_id: int) -> dict[str, Any]:
    """Omission ledgers as provenance: nothing was dropped only if both selection ledgers are empty; spawn
    dispositions partition the nodes only when ``walked``. A missing artifact predates the writer.
    """
    from db.models import Artifact, Job

    out: dict[str, Any] = {}
    for name in ("selection_summary", "perimeter_spawn_summary", "fp_materialization_summary"):
        rows = (
            session.query(Artifact.job_id)
            .join(Job, Job.id == Artifact.job_id)
            .filter(Job.protocol_id == protocol_id, Artifact.name == name)
            .order_by(Artifact.job_id)
            .all()
        )
        out[name] = {
            "artifacts": len(rows),
            "job_ids": [str(row[0]) for row in rows][:8],
            "reading": "absent = predates the ledger, never 'omitted nothing'",
        }
    return out


def perimeter_state(session: Session, protocol_id: int) -> tuple[str, dict[str, Any]]:
    """Whether the perimeter was settled when scored; a failed queue read is ``not_determined``, not "unsettled"."""
    from db.models import Job, JobStatus, PendingEffectsWork

    try:
        pending = (
            session.query(sql_func.count(Job.id))
            .filter(
                Job.protocol_id == protocol_id,
                Job.status.in_([JobStatus.queued, JobStatus.processing]),
            )
            .scalar()
        )
        pending_effects = (
            session.query(sql_func.count(PendingEffectsWork.id))
            .filter(
                PendingEffectsWork.protocol_id == protocol_id,
                PendingEffectsWork.state != "complete",
            )
            .scalar()
        )
    except Exception as exc:  # pragma: no cover - a failed read is a real third state
        return PERIMETER_NOT_DETERMINED, {"error": type(exc).__name__}
    if pending is None or pending_effects is None:
        return PERIMETER_NOT_DETERMINED, {"pending_jobs": pending, "pending_balance_effects": pending_effects}
    return (PERIMETER_SETTLED if pending == 0 and pending_effects == 0 else PERIMETER_UNSETTLED), {
        "pending_jobs": int(pending),
        "pending_balance_effects": int(pending_effects),
    }


def load_audit_posture(session: Session, protocol_id: int, value_plane: ValuePlane) -> dict[str, Any]:
    """Audit coverage weighted by contracts and by value (rows are per audit and contract, so counting them answers
    neither). Uses the fold's own value reduction so joins can't double count; undetermined totals contribute
    nothing.
    """
    from db.models import AuditContractCoverage, AuditReport, Contract

    equivalence_classes = {
        "candidate_path_missing": "our_side_data_gap",
        "commit_not_found_in_repo": "our_side_data_gap",
        "hash_mismatch": "deployed_source_provably_differs",
        "etherscan_fetch_failed": "infrastructure",
    }
    rows = (
        session.query(AuditContractCoverage)
        .filter(AuditContractCoverage.protocol_id == protocol_id)
        .order_by(AuditContractCoverage.contract_id, AuditContractCoverage.id)
        .all()
    )
    proven = [r for r in rows if r.equivalence_status == "proven" and r.matched_commit_sha]
    classified: dict[str, int] = defaultdict(int)
    for row in rows:
        bucket = equivalence_classes.get(str(row.equivalence_status))
        if bucket:
            classified[bucket] += 1

    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    covered_ids = {row.contract_id for row in rows}
    proven_ids = {row.contract_id for row in proven}
    covered_value, covered_priced = _audited_value(contracts, covered_ids, value_plane)
    proven_value, proven_priced = _audited_value(contracts, proven_ids, value_plane)

    reports = int(
        session.query(sql_func.count(AuditReport.id)).filter(AuditReport.protocol_id == protocol_id).scalar() or 0
    )
    # Zero audits is only a fact if discovery provably ran; otherwise not determined.
    reports_on_file = reports if reports or _audit_discovery_witnessed(session, protocol_id) else None
    # Zero covered contracts is only licensed when no audit is on file; otherwise the matcher run is unwitnessed.
    coverage_zero_licensed = reports_on_file == 0
    return {
        "rows": len(rows),
        "proven_equivalence": len(proven),
        "reports_on_file": reports_on_file,
        "contracts_total": len(contracts),
        "contracts_covered": len(covered_ids) if rows or coverage_zero_licensed else None,
        "contracts_proven": len(proven_ids) if rows or coverage_zero_licensed else None,
        "value_covered_usd": covered_value,
        "value_proven_usd": proven_value,
        "value_entities_priced": {"covered": covered_priced, "proven": proven_priced},
        "non_coverage_classified": dict(sorted(classified.items())),
        "reading": (
            "equivalence_status='proven' + matched_commit_sha is the admissible core; "
            "proof_kind is banned in every value; a non-proven row is UNKNOWN, not 0. "
            "The value figures are floors over the PRICED covered entities — an unpriced "
            "audited contract contributes nothing and is never read as $0 — and null means "
            "no covered entity was priced at all. A null count is an unwitnessed stage, "
            "never a zero: the discovery witness is the persisted audit_reports artifact, "
            "and a failure INSIDE the row sync after that artifact committed is recorded "
            "only in the stage_errors artifact body, which this DB-only fold does not read"
        ),
    }


def _audit_discovery_witnessed(session: Session, protocol_id: int) -> bool:
    """Whether audit discovery ran and persisted (the ``audit_reports`` artifact row is the witness)."""
    from db.models import Artifact, Job

    return (
        session.query(Artifact.id)
        .join(Job, Job.id == Artifact.job_id)
        .filter(Job.protocol_id == protocol_id, Artifact.name == "audit_reports")
        .order_by(Artifact.id)
        .first()
    ) is not None


def _audited_value(
    contracts: list[Any], audited_contract_ids: set[int], value_plane: ValuePlane
) -> tuple[float | None, int]:
    """Priced value behind audited contracts, and how many are priced.

    An entity counts if its own contract or the implementation it delegates to is audited (proxies hold balances; audits
    review implementations).
    """
    audited_keys = {entity_key(c.chain, c.address) for c in contracts if c.id in audited_contract_ids}
    entities: set[str] = set()
    for contract in contracts:
        own = entity_key(contract.chain, contract.address)
        implementation = entity_key(contract.chain, contract.implementation) if contract.implementation else None
        if own in audited_keys or (implementation is not None and implementation in audited_keys):
            entities.add(value_plane.canonical(own))
    totals = [value_plane.total(key) for key in sorted(entities)]
    priced = [total for total in totals if total is not None]
    if not priced:
        return None, 0
    return round(sum(sorted(priced)), 2), len(priced)


def plane_row_counts(session: Session, protocol_id: int) -> dict[str, Any]:
    from db.models import (
        Contract,
        ContractBalanceLatest,
        EffectiveFunction,
        EffectVerdict,
        FunctionPrincipal,
        FunctionScoreSignal,
        RestakingPositionLatest,
        RoleHolderPlane,
    )

    def _count(query: Any, plane: str) -> int | None:
        """An unreadable plane is ``None``, never 0 (a missing table isn't an empty plane)."""
        try:
            return int(query.scalar() or 0)
        except Exception as exc:
            session.rollback()
            # The exception type says why; usually schema drift.
            logger.warning(
                "plane row count unreadable for %s",
                plane,
                extra={"protocol_id": protocol_id, "plane": plane, "exc_type": type(exc).__name__},
            )
            return None

    contracts = session.query(sql_func.count(Contract.id)).filter(Contract.protocol_id == protocol_id)
    functions = (
        session.query(sql_func.count(EffectiveFunction.id))
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
    )
    principals = (
        session.query(sql_func.count(FunctionPrincipal.id))
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
    )
    verdicts = (
        session.query(sql_func.count(EffectVerdict.id))
        .join(EffectiveFunction, EffectiveFunction.id == EffectVerdict.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
    )
    # Both keying arms, so entity-keyed holders are counted.
    entity_identities = sorted(
        (chain, address)
        for chain, _, address in (key.partition("::") for key in load_proven_eoa_entities(session, protocol_id))
        if chain and address
    )
    balances = session.query(sql_func.count(ContractBalanceLatest.id)).filter(
        sql_or(
            ContractBalanceLatest.contract_id.in_(
                session.query(Contract.id).filter(Contract.protocol_id == protocol_id)
            ),
            (
                tuple_(ContractBalanceLatest.entity_chain, ContractBalanceLatest.entity_address).in_(entity_identities)
                if entity_identities
                else sql_false()
            ),
        )
    )
    signals = session.query(sql_func.count(FunctionScoreSignal.id)).filter(
        FunctionScoreSignal.protocol_id == protocol_id
    )
    try:
        max_verdict_updated = (
            session.query(sql_func.max(EffectVerdict.updated_at))
            .join(EffectiveFunction, EffectiveFunction.id == EffectVerdict.function_id)
            .join(Contract, Contract.id == EffectiveFunction.contract_id)
            .filter(Contract.protocol_id == protocol_id)
            .scalar()
        )
    except Exception as exc:
        session.rollback()
        logger.warning(
            "plane freshness unreadable for %s",
            "max_effect_verdict_updated_at",
            extra={
                "protocol_id": protocol_id,
                "plane": "max_effect_verdict_updated_at",
                "exc_type": type(exc).__name__,
            },
        )
        max_verdict_updated = None
    return {
        "contracts": _count(contracts, "contracts"),
        "effective_functions": _count(functions, "effective_functions"),
        "function_principals": _count(principals, "function_principals"),
        "effect_verdicts": _count(verdicts, "effect_verdicts"),
        "contract_balances_latest": _count(balances, "contract_balances_latest"),
        "function_score_signals": _count(signals, "function_score_signals"),
        "restaking_positions_latest": _count(
            session.query(sql_func.count(RestakingPositionLatest.id)).filter(
                RestakingPositionLatest.protocol_id == protocol_id
            ),
            "restaking_positions_latest",
        ),
        "role_holder_planes": _count(session.query(sql_func.count(RoleHolderPlane.role_hash)), "role_holder_planes"),
        "max_effect_verdict_updated_at": max_verdict_updated.isoformat() if max_verdict_updated else None,
    }


def native_value_state(plane: ValuePlane, key: str) -> Tri[float]:
    """Native holding of an entity with no native row: ``proven_zero`` is 0.0, anything else (including failed
    fetches) is ``not_determined``. The label is the same whichever witness supplied the zero.
    """
    canonical = plane.canonical(key)
    assets = plane.per_asset.get(canonical) or {}
    if NATIVE_ASSET in assets:
        held = assets[NATIVE_ASSET]
        return Tri.proven("proven_zero" if held == 0.0 else "proven", held)
    fact = plane.native_fact.get(canonical)
    if fact and fact.startswith("proven_zero"):
        return Tri.proven("proven_zero", 0.0)
    return Tri[float].not_determined()
