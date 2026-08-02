"""The resolution planes the Layer-2 fold reads to resolve a signal's references.

Signals carry references — ``function_principals`` ids and ``<chain>::<address>``
entity keys — so the fold is the first place that can turn them into units,
dollars and breadth. Every read here is ordered, read-only, and publishes its
own three-state: an unreadable or absent witness lands on ``not_determined`` and
is counted in the provenance block rather than defaulted to a number.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func as sql_func
from sqlalchemy.orm import Session

from services.scoring.schema import Tri, coalesce_chain, entity_key
from utils.scoring_status import (
    PERIMETER_NOT_DETERMINED,
    PERIMETER_SETTLED,
    PERIMETER_UNSETTLED,
)

NATIVE_ASSET = "native"

# Control relations that carry authority. ``safe_owner`` is excluded (one owner
# does not satisfy k-of-n) and ``controller_value_unattributed`` is excluded
# (real principals whose authority RELATION was never established — a confidence
# item, not an edge).
CONTROL_RELATIONS = ("controller_value", "role_principal", "mapping_member")

# ``capability_principal`` is deliberately NOT a reach relation here. Its own
# register entry licenses it "for REACHABILITY only" on the argument that the
# authority graph already folds the same link — but in THIS closure, which is
# built from control edges alone, it is the sole carrier of those links rather
# than a duplicate of them, so admitting it moves value no other witness moved.
# Its population is also budget-gated (``PSAT_FP_MATERIALIZE_LIMIT``): a reach
# that appears or disappears with a materialization budget is not a witnessed
# fact about the protocol. The register's designated reach licence is
# ``gated_contract_backlink``, which the distiller consumes.
UNCONSUMED_REACH_RELATIONS = ("capability_principal",)


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass
class ValuePlane:
    """Per-entity value, reduced MAX per (entity, asset).

    ``contract_entities`` is every entity the protocol's ``contracts`` rows name,
    priced or not. It is the confidence perimeter's base population: discovery
    fixes it, so it does not move with what has been analysed, and an unpriced
    contract outside the control closure still carries its unanswered weight
    instead of vanishing from its own denominator.
    """

    contract_entities: set[str] = field(default_factory=set)
    per_asset: dict[str, dict[str, float]] = field(default_factory=dict)
    native_fact: dict[str, str] = field(default_factory=dict)
    alias: dict[str, str] = field(default_factory=dict)
    unpriced_positions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def canonical(self, key: str) -> str:
        """An implementation's key folds onto the proxy that deploys it."""
        return self.alias.get(key, key)

    def total(self, key: str) -> float | None:
        """The entity's priced holdings, or ``None`` when nothing is priced.

        ``None`` is not zero: an entity whose every row is unpriced and one
        proven to hold nothing are different facts, and only the second may
        reach a consumer as a number.
        """
        assets = self.per_asset.get(self.canonical(key))
        if not assets:
            return None
        return round(sum(sorted(assets.values())), 6)

    @property
    def tracked_total(self) -> float:
        # Only priced entities enter the denominator. An unpriced one contributes
        # nothing rather than a zero, so the ratio is over what was measured.
        totals = [self.total(k) for k in self.per_asset]
        return round(sum(sorted(t for t in totals if t is not None)), 2)


def load_value_plane(session: Session, protocol_id: int) -> ValuePlane:
    from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest, RestakingPositionLatest
    from services.monitoring.balance_reads import native_balance_fact

    plane = ValuePlane()
    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    chain_of: dict[int, str] = {}
    address_of: dict[int, str] = {}
    impl_to_proxy: dict[str, str] = {}
    shared_impl: list[dict[str, Any]] = []
    for contract in contracts:
        chain = coalesce_chain(contract.chain)
        chain_of[contract.id] = chain
        address_of[contract.id] = _lower(contract.address)
        plane.contract_entities.add(entity_key(chain, contract.address))
        if not contract.implementation:
            continue
        impl_key = entity_key(chain, contract.implementation)
        proxy_key = entity_key(chain, contract.address)
        previous = impl_to_proxy.get(impl_key)
        if previous is not None and previous != proxy_key:
            # Two proxies sharing one implementation. Last-wins would be
            # arbitrary; pin the lowest key and publish the collision.
            shared_impl.append({"implementation": impl_key, "proxies": sorted([previous, proxy_key])})
            impl_to_proxy[impl_key] = min(previous, proxy_key)
        else:
            impl_to_proxy[impl_key] = proxy_key
    plane.alias = impl_to_proxy

    per_asset: dict[str, dict[str, float]] = defaultdict(dict)
    native_seen: set[str] = set()
    fetched: list[Any] = []
    rows = (
        session.query(ContractBalanceLatest)
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceLatest.contract_id, ContractBalanceLatest.token_address, ContractBalanceLatest.id)
        .all()
    )
    for row in rows:
        key = plane.canonical(entity_key(chain_of.get(row.contract_id), address_of.get(row.contract_id)))
        # A NULL token_address IS the native asset by this column's definition,
        # not a missing value standing in for one.
        asset = _lower(row.token_address) if row.token_address else NATIVE_ASSET
        if asset == NATIVE_ASSET:
            native_seen.add(key)
        usd = _float(row.usd_value)
        if row.fetched_at is not None:
            fetched.append(row.fetched_at)
        if usd is None:
            # NULL usd_value is not_determined, never 0: nothing separates a
            # worthless asset from a failed price lookup.
            continue
        previous = per_asset[key].get(asset)
        if previous is None or usd > previous:
            per_asset[key][asset] = usd
    plane.per_asset = {k: dict(sorted(v.items())) for k, v in sorted(per_asset.items())}

    # The proven-zero / fetch-failed discriminator for an ABSENT native row.
    latest_fetch: dict[int, Any] = {}
    for fetch in (
        session.query(ContractBalanceFetch)
        .join(Contract, Contract.id == ContractBalanceFetch.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceFetch.contract_id, ContractBalanceFetch.fetched_at, ContractBalanceFetch.id)
        .all()
    ):
        latest_fetch[fetch.contract_id] = fetch
    for contract_id, fetch in sorted(latest_fetch.items()):
        key = plane.canonical(entity_key(chain_of.get(contract_id), address_of.get(contract_id)))
        if key in native_seen:
            continue
        plane.native_fact[key] = native_balance_fact(fetch.native_status, fetch.block_number)

    # The restaking plane is separate by construction and carries NO USD column,
    # so its positions cannot enter the band arithmetic. They fold under the same
    # MAX-per-entity rule as unpriced quantities and are published as such.
    positions = (
        session.query(RestakingPositionLatest)
        .filter(RestakingPositionLatest.protocol_id == protocol_id)
        .order_by(RestakingPositionLatest.chain_id, RestakingPositionLatest.node_address)
        .all()
    )
    unpriced: dict[str, dict[str, float]] = defaultdict(dict)
    residual_seen = False
    for position in positions:
        chain = _chain_name(position.chain_id)
        if chain is None:
            continue
        key = plane.canonical(entity_key(chain, position.node_address))
        shares = _float(position.eigenlayer_beacon_shares_wei)
        if position.shares_basis not in ("eigenlayer_beacon_shares", "no_eigenpod_proven") or shares is None:
            continue
        if position.cross_read_agreement == "inconsistent":
            continue
        previous = unpriced[key].get("eigenlayer_beacon_shares_wei")
        if previous is None or shares > previous:
            unpriced[key]["eigenlayer_beacon_shares_wei"] = shares
        residual_seen = residual_seen or position.consensus_layer_residual is not None
    plane.unpriced_positions = {
        key: [{"asset": asset, "quantity_wei": qty} for asset, qty in sorted(assets.items())]
        for key, assets in sorted(unpriced.items())
    }
    if positions:
        plane.annotations.append(
            {
                "fact": "restaking positions folded as UNPRICED entity contributions",
                "entities": len(plane.unpriced_positions),
                "note": (
                    "the plane carries no USD column and pricing it would need a "
                    "banned price source, so these quantities raise a confidence gap "
                    "and never a band; node_set_completeness is not_determined, so "
                    "any cross-node aggregate is a floor"
                ),
                "consensus_layer_residual": (
                    "not_determined and BANNED as a number; never read as 0" if residual_seen else "no rows"
                ),
            }
        )

    plane.contract_entities = {plane.canonical(key) for key in plane.contract_entities}
    plane.provenance = {
        "entity_key": "effective_functions.deployment_address -> contracts.address, chain-scoped",
        "contract_entities": len(plane.contract_entities),
        "reduction": "MAX per (entity, asset)",
        "balance_rows": len(rows),
        "restaking_rows": len(positions),
        "shared_implementations": shared_impl,
        "fetched_at_span_seconds": (
            round((max(fetched) - min(fetched)).total_seconds(), 3) if len(fetched) > 1 else None
        ),
        "fetched_at_is_a_write_timestamp": (
            "not an observation height; a cross-contract sum is not a single-block quantity"
        ),
        "absent_native_row": "not_determined unless contract_balance_fetches.native_status proves zero",
    }
    return plane


def _chain_name(chain_id: int | None) -> str | None:
    if chain_id is None:
        return None
    from utils.chains import UnknownChainError, chain_by_id

    try:
        return coalesce_chain(chain_by_id(int(chain_id)).name)
    except (UnknownChainError, ValueError, TypeError):
        return None


@dataclass
class PrincipalFacts:
    function_principal_id: int
    chain: str
    address: str
    resolved_type: str | None
    owners: frozenset[str]
    threshold: int | None
    delay_seconds: float | None
    protection_credit_withheld: bool
    protection_basis: str
    resolver_bases: tuple[str, ...]
    role_bindings: tuple[tuple[str, str], ...]

    @property
    def key(self) -> str:
        return entity_key(self.chain, self.address)


def load_principal_plane(session: Session, refs: list[Any]) -> dict[int, PrincipalFacts]:
    """``function_principals`` rows behind the signals' references."""
    from db.models import FunctionPrincipal

    ids = sorted({int(ref.function_principal_id) for ref in refs})
    if not ids:
        return {}
    chain_by_id: dict[int, str] = {}
    for ref in refs:
        chain_by_id.setdefault(int(ref.function_principal_id), ref.chain)
    rows = session.query(FunctionPrincipal).filter(FunctionPrincipal.id.in_(ids)).order_by(FunctionPrincipal.id).all()
    out: dict[int, PrincipalFacts] = {}
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        withheld, basis = _safe_protection_verdict(details)
        out[row.id] = PrincipalFacts(
            function_principal_id=row.id,
            chain=coalesce_chain(chain_by_id.get(row.id)),
            address=_lower(row.address),
            resolved_type=row.resolved_type,
            owners=frozenset(_lower(o) for o in (details.get("owners") or []) if o),
            threshold=_int(details.get("threshold")),
            delay_seconds=_float(details.get("delay")),
            protection_credit_withheld=withheld,
            protection_basis=basis,
            resolver_bases=_resolver_bases(details),
            role_bindings=_role_bindings(details),
        )
    return out


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_protection_verdict(details: dict[str, Any]) -> tuple[bool, str]:
    """Whether the k/n demotion is WITHHELD, and on what basis.

    k/n is an upper bound on protection, and only a PROVEN bypass denies the
    credit: a witnessed module (``protection_is_upper_bound`` true, or an
    enumerated non-empty module set) or a witnessed guard address. Everything
    else — an absent plane, an unreadable head word, a basis that proves nothing
    — leaves the credit standing, annotated. Withholding on an unreadable witness
    would be a demotion claim minted from an absence, which the ruling for this
    plane forbids in both directions.
    """
    protection = details.get("safe_protection")
    if not isinstance(protection, dict):
        return False, "safe_protection_absent(not_determined);credit_stands"
    if protection.get("protection_is_upper_bound") is True:
        return True, "protection_is_upper_bound(proven module)"
    module_set = protection.get("module_set")
    if isinstance(module_set, list) and module_set:
        return True, "module_set_enumerated_non_empty(proven module)"
    if protection.get("guard") == "proven_address":
        return True, "guard_proven_present"
    basis = protection.get("module_set_basis")
    if isinstance(module_set, list) and not module_set and basis == "storage_linked_list_terminated":
        return False, f"module_set_proven_empty@{protection.get('probe_block')}"
    return False, f"module_set_not_determined({basis or 'not_determined'});credit_stands"


def _resolver_bases(details: dict[str, Any]) -> tuple[str, ...]:
    bases: set[str] = set()
    for step in details.get("trace") or []:
        if not isinstance(step, dict):
            continue
        basis = step.get("basis")
        if isinstance(basis, str):
            bases.add(basis)
        elif isinstance(basis, list):
            bases.update(str(b) for b in basis)
    return tuple(sorted(bases))


def _role_bindings(details: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """(registry, role_hash) pairs this principal's resolution is bound to.

    Only a trace step naming exactly ONE role hash binds: a fold that published
    several role labels says which roles the registry has, not which one gates
    this function, and attributing a holder floor on that basis would import a
    different role's breadth.
    """
    out: set[tuple[str, str]] = set()
    for step in details.get("trace") or []:
        if not isinstance(step, dict):
            continue
        registry = _lower(step.get("authority") or step.get("registry"))
        labels = step.get("role_labels")
        if not registry or not isinstance(labels, dict) or len(labels) != 1:
            continue
        out.add((registry, _lower(next(iter(labels)))))
    return tuple(sorted(out))


def load_role_holder_floors(session: Session) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Proven holder floors per (chain, registry, role hash).

    ``holders`` is a LOWER BOUND and ``len(holders)`` is never a count; the floor
    may raise breadth concern and may never lower it. ``holder_set_exhaustive``
    is always ``not_determined``.
    """
    from db.models import RoleHolderPlane

    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    rows = (
        session.query(RoleHolderPlane)
        .order_by(RoleHolderPlane.chain_id, RoleHolderPlane.registry_address, RoleHolderPlane.role_hash)
        .all()
    )
    for row in rows:
        chain = _chain_name(row.chain_id)
        if chain is None or not isinstance(row.holders, list) or not row.holders:
            continue
        if row.holders_basis != "pinned_has_role_confirmed":
            continue
        out[(chain, _lower(row.registry_address), _lower(row.role_hash))] = {
            "holders_floor": len(row.holders),
            "as_of_block": row.as_of_block,
            "coverage": row.coverage,
            "holder_set_exhaustive": "not_determined",
        }
    return out


def load_control_closure(session: Session, protocol_id: int) -> dict[str, set[str]]:
    """``controls[X] = {Y}``: entities X is a proven controller of.

    Chain-scoped on both ends — an edge is only ever within one chain's graph,
    and keying it unscoped would let one chain's twin inherit the other's reach.
    """
    from db.models import Contract, ControlGraphEdge

    controls: dict[str, set[str]] = defaultdict(set)
    rows = (
        session.query(ControlGraphEdge, Contract.chain)
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphEdge.relation.in_(CONTROL_RELATIONS))
        .order_by(ControlGraphEdge.id)
        .all()
    )
    for edge, chain in rows:
        source = _lower(str(edge.from_node_id or "").replace("address:", ""))
        target = _lower(str(edge.to_node_id or "").replace("address:", ""))
        if not source or not target:
            continue
        # Stored from=anchor, to=principal; the authority direction is the
        # reverse, so the principal is what controls the anchor.
        controls[entity_key(chain, target)].add(entity_key(chain, source))
    for contract in session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all():
        if contract.admin:
            chain = coalesce_chain(contract.chain)
            controls[entity_key(chain, contract.admin)].add(entity_key(chain, contract.address))
    return {key: set(value) for key, value in sorted(controls.items())}


def unconsumed_reach_relations(session: Session, protocol_id: int) -> dict[str, Any]:
    """Edges that exist but are NOT walked as reach, and why. Provenance only.

    A relation this scorer declines to walk is a STATED exclusion rather than a
    silent one, so a consumer can see how much reach is being left unconsumed and
    re-open the ruling when a witnessed licence lands.
    """
    from db.models import Contract, ControlGraphEdge

    counts: dict[str, int] = {}
    for relation in UNCONSUMED_REACH_RELATIONS:
        counts[relation] = int(
            session.query(sql_func.count(ControlGraphEdge.id))
            .join(Contract, Contract.id == ControlGraphEdge.contract_id)
            .filter(Contract.protocol_id == protocol_id, ControlGraphEdge.relation == relation)
            .scalar()
            or 0
        )
    return {
        "edges": counts,
        "reason": (
            "capability_principal is the SOLE carrier of these links in a closure built "
            "from control edges alone, not a duplicate of one, and its population is "
            "materialization-budget gated — a reach that moves with a budget is not a "
            "witnessed fact. The register's designated reach licence is "
            "gated_contract_backlink, which the distiller consumes"
        ),
    }


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


def load_audit_posture(session: Session, protocol_id: int) -> dict[str, Any]:
    """Audit coverage, classified. Non-proven statuses read UNKNOWN, never 0."""
    from db.models import AuditContractCoverage

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
    return {
        "rows": len(rows),
        "proven_equivalence": len(proven),
        "non_coverage_classified": dict(sorted(classified.items())),
        "reading": (
            "equivalence_status='proven' + matched_commit_sha is the admissible core; "
            "proof_kind is banned in every value; a non-proven row is UNKNOWN, not 0"
        ),
    }


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

    def _count(query: Any) -> int | None:
        """A plane that cannot be read is ``None`` — not_determined, never 0.

        A missing table (a database this build's migration has not reached) and
        a genuinely empty plane are different facts, and a zero here would make
        an unread plane look like a proven-empty one in the provenance block.
        """
        try:
            return int(query.scalar() or 0)
        except Exception:
            session.rollback()
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
    balances = (
        session.query(sql_func.count(ContractBalanceLatest.id))
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(Contract.protocol_id == protocol_id)
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
    except Exception:
        session.rollback()
        max_verdict_updated = None
    return {
        "contracts": _count(contracts),
        "effective_functions": _count(functions),
        "function_principals": _count(principals),
        "effect_verdicts": _count(verdicts),
        "contract_balances_latest": _count(balances),
        "function_score_signals": _count(signals),
        "restaking_positions_latest": _count(
            session.query(sql_func.count(RestakingPositionLatest.id)).filter(
                RestakingPositionLatest.protocol_id == protocol_id
            )
        ),
        "role_holder_planes": _count(session.query(sql_func.count(RoleHolderPlane.role_hash))),
        "max_effect_verdict_updated_at": max_verdict_updated.isoformat() if max_verdict_updated else None,
    }


def native_value_state(plane: ValuePlane, key: str) -> Tri[float]:
    """The native holding of an entity with no native balance row.

    ``proven_zero`` is a real answer and enters as 0.0; everything else —
    including a failed fetch — is ``not_determined`` and is never read as zero.
    """
    canonical = plane.canonical(key)
    assets = plane.per_asset.get(canonical) or {}
    if NATIVE_ASSET in assets:
        return Tri.proven("proven", assets[NATIVE_ASSET])
    fact = plane.native_fact.get(canonical)
    if fact and fact.startswith("proven_zero"):
        return Tri.proven("proven_zero", 0.0)
    return Tri[float].not_determined()


__all__ = [
    "CONTROL_RELATIONS",
    "PrincipalFacts",
    "ValuePlane",
    "load_audit_posture",
    "load_control_closure",
    "load_ledgers",
    "load_principal_plane",
    "load_role_holder_floors",
    "load_upgrade_provenance",
    "load_value_plane",
    "native_value_state",
    "perimeter_state",
    "plane_row_counts",
]
