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

# Confined to the I/O-EDGE loaders in this module — the handlers that swallow a
# database error while reading a plane. The resolution work itself publishes
# every refusal into the document (inv. 11/12: the fold must replay from the
# document alone), so nothing on a compute path logs. These WARNINGs carry no
# ``record_degraded`` because no accumulator is bound here today: the fold runs
# on the score loop's monitor thread and under the offline CLI, and the call
# would be a permanent no-op rather than a record of anything.
logger = logging.getLogger("services.scoring.planes")


# Why each relation this scorer knows of is NOT walked as reach. The map is a
# vocabulary of reasons, not the published set: ``unconsumed_reach_relations``
# enumerates from what the DATABASE holds (plus every relation the graph writer
# can emit), so a relation nobody has classified still gets published with its
# count rather than being dropped for want of an entry here.
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
    """Every edge that exists but is NOT walked as reach, and why. Provenance.

    DISCOVERY-FIXED: the enumeration is built from what the database holds —
    ``GROUP BY relation`` over this protocol's edges, with no filter — unioned
    with every relation the graph writer is able to emit
    (``db.CONTROL_EDGE_RELATIONS``). It is deliberately NOT built from what this
    scorer chose to name: a relation nobody classified, and a relation that
    carries no rows today and rows tomorrow, would both be silently unwalked
    under an enumeration keyed on the consumed set. A zero count is a named
    exclusion, not an absence.
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
    # The withdrawn rationale for excluding ``capability_principal`` was that its
    # population is materialization-budget gated. Withdrawing it in prose leaves
    # a reader unable to check the refutation, so the budget and the observed
    # headroom are published beside the exclusion: the perimeter above is a full
    # enumeration only if nothing was clipped, and that is a number, not a claim.
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
    """Every endpoint of every AUTHORITY relation discovery recorded, per relation.

    ``CONTROL_EDGE_RELATIONS`` is the database's own vocabulary for a relation
    that carries authority; this scorer walks three of its seven. The four it
    declines are still work discovery did, and the entities they name are still
    entities this document must answer for — so they enter the confidence
    perimeter whether or not the walk consumes them. Relations outside that set
    (``external_call_target``, ``controller_value_unattributed``) assert no
    authority by their own register entries and are not admitted here.

    Sibling of :func:`unconsumed_reach_relations`, which counts the same excluded
    edges: that one publishes how much reach is not being claimed, this one puts
    the entities behind it into the denominator that has to account for them.
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
    """Upgrade history as PROVENANCE only — it moves no severity in v1.

    Counted through the action folds, never ``COUNT(upgrade_events.id)``: the
    unit is the transaction, one of which carried 19 ``Upgraded`` logs. A
    post-exclusion zero publishes ``None``, because "no event recorded" never
    licenses "no upgrade happened" over a recording surface that is itself
    unwitnessed.
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
    """The omission ledgers, as provenance references.

    Nothing was dropped only if BOTH selection ledgers are empty, and the spawn
    dispositions partition the node list only when ``walked`` is true. An absent
    artifact means the ledger predates the writer, never "omitted nothing".
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
    """Whether the perimeter was settled when this score was computed.

    A failed queue read lands on ``not_determined`` rather than either polarity:
    stamping "unsettled" on an unreadable queue would be a positive claim with no
    witness.
    """
    from db.models import Job, JobStatus

    try:
        pending = (
            session.query(sql_func.count(Job.id))
            .filter(
                Job.protocol_id == protocol_id,
                Job.status.in_([JobStatus.queued, JobStatus.processing]),
            )
            .scalar()
        )
    except Exception as exc:  # pragma: no cover - a failed read is a real third state
        return PERIMETER_NOT_DETERMINED, {"error": type(exc).__name__}
    if pending is None:
        return PERIMETER_NOT_DETERMINED, {"pending_jobs": None}
    return (PERIMETER_SETTLED if pending == 0 else PERIMETER_UNSETTLED), {"pending_jobs": int(pending)}


def load_audit_posture(session: Session, protocol_id: int, value_plane: ValuePlane) -> dict[str, Any]:
    """Audit coverage, classified and weighted by contracts and by value.

    Coverage rows are per (audit, contract), so counting them answers neither
    "how much of the protocol is audited" nor "how much of the money is": one
    contract reviewed by four audits is four rows and one contract, and the
    contracts that hold the value are a handful of the total. Both weightings
    are computed here, over the same reduction the fold's exposure uses — the
    latest observation per (entity, asset, observed account), implementation
    folded onto its proxy — so a consumer joining these counts to a value plane
    of its own would re-introduce the double count that reduction exists to
    remove. An entity whose total is not a number contributes nothing and is
    never read as $0.
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
    # A published zero is a claim that the protocol has no audits, and an empty
    # table is that fact only where discovery is proven to have looked. A stage
    # that never ran, or died before persisting (the billing-failure shape),
    # leaves the same empty table and lands on not_determined instead.
    reports_on_file = reports if reports or _audit_discovery_witnessed(session, protocol_id) else None
    # Zero covered contracts needs its own licence: with no audit on file there
    # was nothing that could match, but audits with no coverage row are a
    # matcher run this fold has no witness for.
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
    """Whether audit discovery is proven to have run and persisted its result.

    ``store_artifact(job, "audit_reports", ...)`` commits on the one path that
    persists discovered reports, so the row is the witness that the stage got
    that far. Existence only — the body lives in the bucket and this fold reads
    the database alone.
    """
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
    """Canonical priced value behind a set of audited contracts, and how many priced.

    An entity counts when its own contract is audited OR when the implementation
    it delegates to is: a proxy holds the balance and an audit reviews the
    implementation's source, so keying on the audited row's contract alone would
    report the money as unaudited.
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
    """Per-plane row counts + max ``updated_at``, for the provenance block."""
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
        """A plane that cannot be read is ``None`` — not_determined, never 0.

        A missing table (a database this build's migration has not reached) and
        a genuinely empty plane are different facts, and a zero here would make
        an unread plane look like a proven-empty one in the provenance block.
        """
        try:
            return int(query.scalar() or 0)
        except Exception as exc:
            session.rollback()
            # The document says "not_determined"; only the exception type says
            # WHY, and schema drift is the usual answer.
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
    # Both keying arms, because both are rows the value plane reads. Counting
    # only the join to ``contracts`` would report a plane smaller than the one
    # the score was computed over the moment an entity-keyed holder is observed.
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
    """The native holding of an entity with no native balance row.

    ``proven_zero`` is a real answer and enters as 0.0; everything else —
    including a failed fetch — is ``not_determined`` and is never read as zero.

    The label a proven zero carries is the same whichever witness supplied it: a
    stored zero-quantity native row and the fetch record's ``proven_zero`` status
    are the same fact read two ways, and calling one of them plain ``proven``
    would make the label depend on which writer got there first.
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
