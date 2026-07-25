"""§6 selection cascade + transitive value-at-stake ordering.

Chooses which effective functions the effects-simulation stage should probe,
over data already persisted by the earlier pipeline stages — no RPC, no new
facts. Two independent concerns:

1. **Cascade** — the filter that produces the blank-gated simulation set
   (Appendix A funnel: 756 → gated 406 / facts 691 / blank+facts+gated 265).
   Every row that survives is a distinct behavior we must simulate.
2. **Ordering** — transitive value-at-stake sorts the survivors so the highest
   blast-radius unknowns run first. Value ORDERS, it never GATES (inv. 4): the
   only thing that removes a candidate is a hard resource safety-valve, and if
   that ever fires it logs exactly what it dropped.

Reach is a conservative upper bound (inv. 5): a control edge propagates the
FULL downstream value of whatever it reaches. Over-approximation is safe here
because it only moves a candidate earlier in the queue, never out of it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import (
    Artifact,
    Contract,
    ContractBalance,
    ControlGraphEdge,
    EffectiveFunction,
    EffectsPlanMarker,
    EffectVerdict,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
)
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT
from utils.chains import UnknownChainError, canonical_chain, chain_by_id
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

# Node IDs in ``control_graph_edges`` are stored as ``address:0x…``.
_NODE_PREFIX = "address:"

# §5c gate lift — claim families that re-enroll an already-claimed function for
# fork probing. A ``flow.*`` claim needs the value-reach probe (§5b); a
# ``supply.*`` claim needs the mint-backing probe (§5a). Every other claim family
# (``pause.*``, ``upgrade.*``, …) is already explained and is NOT re-simulated.
_FLOW_CLAIM_PREFIX = "flow."
_SUPPLY_CLAIM_PREFIX = "supply."


def _addr(value: str | None) -> str | None:
    """Normalize a node id / address to a bare lowercase 0x address."""
    if value is None:
        return None
    v = value.strip()
    if v.startswith(_NODE_PREFIX):
        v = v[len(_NODE_PREFIX) :]
    v = v.lower()
    return v or None


@dataclass(frozen=True)
class Candidate:
    """One effective function selected for simulation, with its ordering value."""

    function_id: int
    contract_id: int
    # The CODE-bearing address (``contracts.address``) — for a proxy-backed
    # protocol this is the implementation. Behavioral hashing keys on it.
    contract_address: str
    selector: str | None
    function_name: str
    authority_public: bool
    effect_targets: tuple[str, ...]
    principal_addresses: tuple[str, ...]
    # Transitive USD an exercise of this function can reach through the control
    # graph. Upper bound; orders only (inv. 4/5).
    value_at_stake_usd: float = 0.0
    # ``effective_functions.deployment_address`` — the address that actually holds
    # the state. Empty when the row predates it / is not proxy-backed.
    deployment_address: str = ""
    # §5c gate lift. ``None`` = a BLANK function: synthesize every effect class
    # (the §6 default). A non-empty set = a function already carrying a
    # flow.*/supply.* claim, re-enrolled for exactly those value/supply families
    # (never the whole class set — we don't re-simulate what's already explained).
    restrict_families: frozenset[str] | None = None
    # §5b downstream value-reach inputs. ``value_holders`` is the protocol's
    # WITNESSED value-holder set — ``(address, usd)`` from ``contract_balances``, NOT
    # control_graph_edges (which has no fund-flow edge) — against which the fork
    # value-reach probe measures value that provably LEAVES a holder when the call
    # runs. ``acting_balance_usd`` is this function's own deployment balance, the
    # floor when downstream reach is fork-observed to be nothing. Shared by
    # reference across a protocol's candidates (small, immutable), so carrying it
    # per-candidate is cheap.
    value_holders: tuple[tuple[str, float], ...] = ()
    acting_balance_usd: float = 0.0

    @property
    def probe_target(self) -> str:
        """The address every PROBE must call. An implementation contract has
        empty storage of its own (an uninitialized ``totalSupply``, a virgin
        pause latch, empty role sets), so probing it mints silently-wrong
        witnesses; only the deployment answers for behavior. Hashing deliberately
        stays on ``contract_address`` — the behavior belongs to the code."""
        return self.deployment_address or self.contract_address


@dataclass
class AuthorityGraph:
    """Address-keyed authority closure inputs for value-at-stake.

    ``controls[A]`` is the set of addresses A has authority over (A → B means
    "A controls B"). ``balance[addr]`` is the summed USD held at that address,
    keyed on the CODE-bearing ``contracts.address`` — the same plane the control
    edges are keyed on, which is what makes the closure sum meaningful.

    ``deployment_balance`` is the same money keyed on the address that actually
    HOLDS it. The two differ for every proxy-fronted contract, and only the
    second can be compared against a chain observation: the balances were fetched
    for the proxy (``resolution_worker`` reads ``proxy_address or address``) but
    stored on the implementation's contract row, and a ``Transfer`` log names the
    proxy. Keying §5b value-reach on ``balance`` therefore matched no holder and
    floored every acting balance to zero.
    """

    controls: dict[str, set[str]] = field(default_factory=dict)
    balance: dict[str, float] = field(default_factory=dict)
    deployment_balance: dict[str, float] = field(default_factory=dict)

    def _add_control(self, controller: str | None, controlled: str | None) -> None:
        c, t = _addr(controller), _addr(controlled)
        if not c or not t or c == t:
            return
        self.controls.setdefault(c, set()).add(t)

    def reachable_value(self, seeds: set[str]) -> float:
        """Sum balances over the transitive closure of ``seeds`` (seeds included)."""
        stack = [s for s in (_addr(s) for s in seeds) if s]
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(self.controls.get(node, ()))
        return sum(self.balance.get(a, 0.0) for a in seen)


def build_authority_graph(session: Session, protocol_id: int) -> AuthorityGraph:
    """Assemble the control closure + balances for one protocol.

    Authority edges come from three sources, all reduced to "controller →
    controlled contract":

    * ``control_graph_edges`` — the row stores *contract controlled BY
      controller* (``from_node`` = contract, ``to_node`` = controller), so the
      authority direction is the reverse of the stored edge.
    * proxy-admin — a proxy's ``admin`` controls the proxy.
    * principal → contract — a function's resolved principal controls the
      contract that function lives on.
    """
    graph = AuthorityGraph()

    # Balances: sum USD per contract, keyed by the contract's on-chain address.
    bal_rows = session.execute(
        select(Contract.id, Contract.address, func.coalesce(func.sum(ContractBalance.usd_value), 0))
        .join(ContractBalance, ContractBalance.contract_id == Contract.id)
        .where(Contract.protocol_id == protocol_id)
        .group_by(Contract.id, Contract.address)
    ).all()
    holders = _deployment_by_contract(session, protocol_id)
    for contract_id, address, usd in bal_rows:
        a = _addr(address)
        if a is None:
            continue
        graph.balance[a] = graph.balance.get(a, 0.0) + float(usd or 0.0)
        holder = holders.get(contract_id) or a
        # MAX, not sum: two implementation rows fronted by one proxy each carry a
        # copy of that ONE deployment's holdings, and adding them would report the
        # money twice.
        graph.deployment_balance[holder] = max(graph.deployment_balance.get(holder, 0.0), float(usd or 0.0))

    # control_graph_edges: reverse to controller → contract.
    edge_rows = session.execute(
        select(ControlGraphEdge.from_node_id, ControlGraphEdge.to_node_id)
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .where(Contract.protocol_id == protocol_id)
    ).all()
    for from_node, to_node in edge_rows:
        graph._add_control(to_node, from_node)

    # proxy-admin: admin controls the proxy contract.
    admin_rows = session.execute(
        select(Contract.admin, Contract.address).where(Contract.protocol_id == protocol_id, Contract.admin.isnot(None))
    ).all()
    for admin, address in admin_rows:
        graph._add_control(admin, address)

    # principal → contract the function lives on.
    prin_rows = session.execute(
        select(FunctionPrincipal.address, Contract.address)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(Contract.protocol_id == protocol_id)
    ).all()
    for principal, address in prin_rows:
        graph._add_control(principal, address)

    return graph


def _deployment_by_contract(session: Session, protocol_id: int) -> dict[int, str]:
    """``contract id -> the address that holds its state``.

    ``effective_functions.deployment_address`` is the proxy a contract's code runs
    behind; it is uniform per contract (a code row is planned for one deployment)
    and absent for a contract that fronts nothing."""
    rows = session.execute(
        select(EffectiveFunction.contract_id, EffectiveFunction.deployment_address)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(Contract.protocol_id == protocol_id, EffectiveFunction.deployment_address.isnot(None))
        .distinct()
    ).all()
    out: dict[int, str] = {}
    for contract_id, deployment in rows:
        addr = _addr(deployment)
        if addr is not None:
            out.setdefault(contract_id, addr)
    return out


@dataclass(frozen=True)
class JobScope:
    """The contract one effects job is responsible for planning.

    Without a scope, ``select_candidates`` plans the WHOLE protocol — which means
    every one of a protocol's jobs re-plans (and re-writes) every other contract's
    candidates. With a scope, a job plans its own contract plus the protocol's
    *unowned* contracts (see :func:`_scope_predicate`), which partitions the work
    without losing a single candidate.

    ``address`` is the CODE-bearing ``contracts.address`` the job was created for;
    ownership is matched on that, never on a proxy deployment address.

    ``planned_since`` is the reading job's own ``created_at``. It bounds how long
    an :class:`~db.models.EffectsPlanMarker` counts as ownership — see
    :func:`_scope_predicate` rule 4. ``None`` disables that rule entirely, which
    is the conservative direction (re-sweep rather than skip), so a caller with
    no timestamp loses efficiency and never coverage.
    """

    address: str
    chain_id: int
    planned_since: datetime | None = None


def _chain_name(chain_id: int) -> str:
    try:
        return chain_by_id(chain_id).name.lower()
    except UnknownChainError:
        return "ethereum"


def _contract_chain_matches(chain_id: int):
    """``Contract.chain`` is a name string and NULL means legacy-mainnet — the same
    convention (and coalesce) ``services/discovery/upgrade_history`` uses."""
    name = canonical_chain(_chain_name(chain_id)) or "ethereum"
    return func.lower(func.coalesce(Contract.chain, "ethereum")) == name


# The per-stage timing artifact ``BaseWorker`` writes when a stage finishes.
# Derived rather than hardcoded so it cannot drift from the writer.
_EFFECTS_STAGE_ARTIFACT = f"stage_timing_{JobStage.effects.value}"

# The ``status`` ``BaseWorker._record_stage_timing`` stamps on the success path.
# The failure path writes the SAME artifact with ``"failed"``, and the effects
# stage fail-forwards (``EffectsWorker._finalize_terminal_failure`` advances the
# job to ``coverage`` rather than failing it), so a failed stage is never re-run:
# counting it as ownership strands the contract with nobody planning it. Any
# other or unreadable value reads as "did not succeed", which re-sweeps — the
# direction that costs work rather than coverage.
_STAGE_STATUS_SUCCESS = "success"

# A job in either of these states will never run the effects stage again.
_FINISHED_JOB_STATES = (JobStatus.completed, JobStatus.failed_terminal)

# The stages from which a job can still ARRIVE at the effects stage. Source
# order in :class:`~db.models.JobStage` is the progression, so the slice is the
# prefix through ``effects``. A job past it never runs effects again — which is
# exactly what a fail-forwarded job looks like (the finalizer advances it to
# ``coverage``) and what a flag-off job looks like (policy skips straight to
# ``coverage``) — so "in flight" alone is not a promise to plan anything.
_JOB_STAGE_ORDER = list(JobStage)
_EFFECTS_REACHABLE_STAGES = tuple(_JOB_STAGE_ORDER[: _JOB_STAGE_ORDER.index(JobStage.effects) + 1])

# storage_key -> recorded stage status, for artifacts belonging to jobs that can
# no longer rewrite them. ``store_artifact`` upserts on a deterministic key, so a
# LIVE job's artifact may still change (transient retry: failed → success) and is
# deliberately never cached.
_STAGE_STATUS_CACHE: dict[str, str] = {}
_STAGE_STATUS_CACHE_MAX = 20_000


def _job_owns_contract_address(protocol_id: int, scope: JobScope):
    """Join predicate tying a ``jobs`` row to the ``contracts`` row it is for.

    Protocol- AND chain-qualified: one address can host unrelated contracts on
    different chains, and (schema-permitting) belong to different protocols,
    neither of which may claim ownership of the other's.
    """
    return and_(
        Job.protocol_id == protocol_id,
        Job.chain_id == scope.chain_id,
        Job.address.is_not(None),
        func.lower(Job.address) == func.lower(Contract.address),
    )


def _protocol_contracts_on_chain(protocol_id: int, scope: JobScope):
    return (Contract.protocol_id == protocol_id, _contract_chain_matches(scope.chain_id))


def _contracts_with_an_effects_capable_job(session: Session, protocol_id: int, scope: JobScope) -> set[int]:
    """Rule 1 — a job at this contract's address is in flight AND can still reach
    the effects stage."""
    rows = (
        session.execute(
            select(Contract.id)
            .join(Job, _job_owns_contract_address(protocol_id, scope))
            .where(
                *_protocol_contracts_on_chain(protocol_id, scope),
                Job.status.not_in(_FINISHED_JOB_STATES),
                Job.stage.in_(_EFFECTS_REACHABLE_STAGES),
            )
            .distinct()
        )
        .scalars()
        .all()
    )
    return set(rows)


def _contracts_with_verdicts(session: Session, protocol_id: int, scope: JobScope) -> set[int]:
    """Rule 3 — the residue a sweep leaves behind."""
    rows = (
        session.execute(
            select(Contract.id)
            .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
            .join(EffectVerdict, EffectVerdict.function_id == EffectiveFunction.id)
            .where(*_protocol_contracts_on_chain(protocol_id, scope))
            .distinct()
        )
        .scalars()
        .all()
    )
    return set(rows)


def _contracts_with_a_fresh_marker(session: Session, protocol_id: int, scope: JobScope) -> set[int]:
    """Rule 4 — a sweep planned it and it yielded no plans, within this job's own
    lifetime."""
    if scope.planned_since is None:
        return set()
    rows = (
        session.execute(
            select(Contract.id)
            .join(EffectsPlanMarker, EffectsPlanMarker.contract_id == Contract.id)
            .where(
                *_protocol_contracts_on_chain(protocol_id, scope),
                EffectsPlanMarker.planned_at >= scope.planned_since,
            )
            .distinct()
        )
        .scalars()
        .all()
    )
    return set(rows)


def _recorded_stage_status(data: Any) -> str | None:
    if isinstance(data, dict):
        status = data.get("status")
        if isinstance(status, str):
            return status
    return None


def _resolve_stored_statuses(keys_to_types: dict[str, str | None]) -> dict[str, str | None]:
    """Fetch stage-timing bodies that live in object storage, in ONE round trip.

    With ``ARTIFACT_STORAGE_*`` configured (every deployed environment)
    ``store_artifact`` writes ``artifacts.data`` as JSON ``null`` and puts the body
    in the bucket, so the status is invisible to SQL — measured on the psat-pr-160
    preview: 70/70 ``stage_timing_effects`` rows have a NULL ``data->>'status'``.
    A read failure yields ``None``, which reads as "did not succeed" (re-sweep).
    """
    from db.storage import deserialize_artifact, get_storage_client

    try:
        client = get_storage_client()
        if client is None:
            return {}
        bodies = client.get_many(list(keys_to_types))
    except Exception as exc:
        # Safe direction (every contract re-sweeps), but it silently multiplies the
        # stage's planning work, so it has to surface as a degraded record and not
        # only as a log line someone would have to go looking for.
        record_degraded(phase="effects_selection_stage_status", exc=exc, context={"keys": len(keys_to_types)})
        logger.warning("effects selection: stage-timing bodies unreadable; re-sweeping instead", exc_info=True)
        return {}
    out: dict[str, str | None] = {}
    for key, content_type in keys_to_types.items():
        body = bodies.get(key)
        if body is None:
            continue
        try:
            out[key] = _recorded_stage_status(deserialize_artifact(body, content_type))
        except Exception:
            logger.warning("effects selection: undecodable stage-timing body %s", key, exc_info=True)
    return out


def _contracts_with_a_successful_effects_run(
    session: Session, protocol_id: int, scope: JobScope, *, already_owned: set[int]
) -> set[int]:
    """Rule 2 — a job at this contract's address ran the effects stage AND it
    succeeded.

    Scoped to contracts nothing else already owns so the storage reads below stay
    proportional to the contracts this rule alone can save (8 of 31 candidate
    contracts on the preview shape), not to the protocol.
    """
    where = [
        *_protocol_contracts_on_chain(protocol_id, scope),
        func.lower(Contract.address) != scope.address.lower(),
    ]
    if already_owned:
        where.append(Contract.id.not_in(already_owned))
    rows = session.execute(
        select(Contract.id, Artifact.data, Artifact.storage_key, Artifact.content_type, Job.status)
        .select_from(Contract)
        .join(Job, _job_owns_contract_address(protocol_id, scope))
        .join(Artifact, and_(Artifact.job_id == Job.id, Artifact.name == _EFFECTS_STAGE_ARTIFACT))
        .where(*where)
    ).all()

    owned: set[int] = set()
    pending: dict[str, str | None] = {}
    deferred: list[tuple[int, str, bool]] = []
    for contract_id, data, storage_key, content_type, job_status in rows:
        if contract_id in owned:
            continue
        status = _recorded_stage_status(data)
        if status is not None:
            if status == _STAGE_STATUS_SUCCESS:
                owned.add(contract_id)
            continue
        if not storage_key:
            continue
        cached = _STAGE_STATUS_CACHE.get(storage_key)
        if cached is not None:
            if cached == _STAGE_STATUS_SUCCESS:
                owned.add(contract_id)
            continue
        pending[storage_key] = content_type
        deferred.append((contract_id, storage_key, job_status in _FINISHED_JOB_STATES))

    if pending:
        resolved = _resolve_stored_statuses(pending)
        if len(_STAGE_STATUS_CACHE) > _STAGE_STATUS_CACHE_MAX:
            _STAGE_STATUS_CACHE.clear()
        for contract_id, storage_key, job_is_finished in deferred:
            status = resolved.get(storage_key)
            if status is None:
                continue
            if job_is_finished:
                _STAGE_STATUS_CACHE[storage_key] = status
            if status == _STAGE_STATUS_SUCCESS:
                owned.add(contract_id)
    return owned


def _owned_contract_ids(session: Session, protocol_id: int, scope: JobScope) -> set[int]:
    """The contracts some OTHER job demonstrably owns — see :func:`_scope_predicate`."""
    owned = _contracts_with_an_effects_capable_job(session, protocol_id, scope)
    owned |= _contracts_with_verdicts(session, protocol_id, scope)
    owned |= _contracts_with_a_fresh_marker(session, protocol_id, scope)
    owned |= _contracts_with_a_successful_effects_run(session, protocol_id, scope, already_owned=owned)
    return owned


def _scope_predicate(session: Session, protocol_id: int, scope: JobScope):
    """Which contracts THIS job plans: its own, plus every *unowned* one.

    Ownership must answer "will some job actually plan this contract?", NOT "does
    a job row exist at this address". Those differ exactly where it matters: a
    protocol whose jobs all completed in an earlier run (production's steady
    state) has a job row for every contract and yet nothing scheduled to plan any
    of them, so a row-existence rule would leave every contract unplanned while
    looking like a clean partition. A contract is owned when:

    1. a job at its address is in flight AND can still reach the effects stage,
       so it will plan the contract itself; or
    2. a job at its address ALREADY ran the effects stage AND that stage
       SUCCEEDED — it was planned, even if the plans yielded no verdict
       (measured: 5 of 29 contracts in the live run planned candidates and wrote
       none, so verdict-existence alone would re-sweep them forever); or
    3. its functions already carry verdicts — which is what a *sweep* leaves
       behind, and is what stops a sweep repeating across a run: the first job to
       sweep a contract marks it planned for every job after it; or
    4. a sweep planned it and it yielded NO plans, recorded as an
       ``effects_plan_markers`` row (rule 3's blind spot: an empty planning pass
       writes no verdict, so a contract with no job of its own left no trace at
       all and was re-swept by every later job forever).

    Rules 1 and 2 each carry a qualifier that is the whole point of the rule.
    Rule 2's is that ``BaseWorker`` writes the SAME ``stage_timing_effects``
    artifact on the FAILURE path, and the effects stage fail-forwards instead of
    failing the job, so a stage that blew up never runs again — counting it left
    the contract planned by nobody, permanently and silently. Rule 1's is that
    a job past the effects stage cannot run it again, and a fail-forwarded job is
    exactly that: still in flight (at ``coverage``) with its effects stage already
    lost. Bounding rule 1 to :data:`_EFFECTS_REACHABLE_STAGES` releases such a
    contract back to its siblings the moment the stage fails rather than when the
    whole job finishes.

    Rule 4 is the only one that expires, and deliberately: a marker counts only
    while it is at least as new as the reading job (``scope.planned_since``).
    Planning inputs change out from under a contract — an ``upgrade_events`` row
    lands from the indexer, a re-analysis rewrites ``effective_functions`` — so an
    eternal "yielded nothing" would strand a contract that has since become
    plannable, which is silent recall loss. Bounding it to the reading job's own
    lifetime kills the intra-run re-sweep (every job of a wave was created before
    the marker its siblings wrote) while guaranteeing the next wave re-plans it.
    Rules 1-3 need no such bound: each is re-established by the new run's own job.

    Together these make the union over a protocol's jobs the whole protocol-wide
    set — every contract is owned (planned by its owner) or unowned (planned by
    whichever job reaches this stage next) — while keeping each job's work to its
    own contract in the steady state.

    Rule 1 remains the one PREDICTION in the set, and it has an irreducible
    residual: if the promising job dies before reaching the effects stage AND no
    other job of the protocol reaches the stage afterwards, nothing re-reads the
    now-broken promise. No selection predicate can close that — the falsifying
    event happens strictly after the last reader — so the contract is recovered by
    the next run (its new job owns it under rule 1, and rules 2-4 hold no stale
    evidence for it). Every case where the promise is already broken at read time
    IS closed here, by the stage bound above and by ``failed_terminal`` never
    counting as in flight.

    All job matching is protocol- AND chain-qualified: one address can host
    unrelated contracts on different chains, and (schema-permitting) belong to
    different protocols, neither of which may claim ownership of the other's.
    """
    owned = _owned_contract_ids(session, protocol_id, scope)
    if not owned:
        return literal(True)
    return or_(func.lower(Contract.address) == scope.address.lower(), Contract.id.not_in(owned))


def _cascade_rows(session: Session, protocol_id: int, scope: JobScope | None = None):
    """The §6 filter cascade as one query.

    (a) has a sink   — ``array_length(effect_targets, 1) > 0`` (there is no
        ``sinks`` column; the sink is the state-write target list).
    (c) gated over public — ``authority_public = false``.

    Filter (b) — the blank-claim gate — is applied in PYTHON on the returned
    ``claims`` column (see :func:`_enrolled_families`), because it is no longer a
    binary keep/drop: BLANK rows still get full synthesis (the §6 default), while
    rows already carrying a ``flow.*``/``supply.*`` claim are RE-ENROLLED for just
    those value/supply families (§5c gate lift) so the fork value-reach and
    mint-backing probes can run on the functions that need them. Rows carrying
    only other claims (pause/upgrade/…) are already explained and are dropped by
    :func:`select_candidates`. Widening the SQL to all gated rows keeps the whole
    decision inspectable in one place instead of split across a fragile JSONB
    predicate.

    ``scope`` narrows the cascade to one job's own contracts (:class:`JobScope`);
    ``None`` keeps the historical protocol-wide behavior.
    """
    where = [
        Contract.protocol_id == protocol_id,
        func.array_length(EffectiveFunction.effect_targets, 1) > 0,
        EffectiveFunction.authority_public.is_(False),
    ]
    if scope is not None:
        # Chain-scoping is part of the fix, not incidental: protocol-wide selection
        # handed a chain-1 job the candidates of every other chain's contracts and
        # probed them through chain-1 seams.
        where.append(_contract_chain_matches(scope.chain_id))
        where.append(_scope_predicate(session, protocol_id, scope))
    return session.execute(
        select(
            EffectiveFunction.id,
            EffectiveFunction.contract_id,
            Contract.address,
            EffectiveFunction.selector,
            EffectiveFunction.function_name,
            EffectiveFunction.authority_public,
            EffectiveFunction.effect_targets,
            EffectiveFunction.deployment_address,
            EffectiveFunction.claims,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(*where)
    ).all()


def _enrolled_families(claims: Any) -> frozenset[str] | None:
    """Which effect families a candidate should be probed for, from its claims.

    * ``None`` — the function is BLANK (no claims). It is the §6 default candidate:
      every effect class is synthesized. ``[]``, SQL ``NULL`` and the ORM's
      JSON-``null`` all read as blank here.
    * a **non-empty** frozenset — the function already carries a ``flow.*`` and/or
      ``supply.*`` claim, so it is re-enrolled (§5c) for exactly ``value_out``
      and/or ``supply``. Never the whole class set: re-simulating pause/authority/
      upgrade for an already-explained function is the waste the gate guards.
    * the **empty** frozenset — the function carries only other claims (pause,
      upgrade, …); already explained, so the caller drops it (fail-closed: an
      unrecognized claim shape enrolls nothing).
    """
    if not isinstance(claims, list) or not claims:
        return None
    families: set[str] = set()
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        cid = claim.get("claim_id")
        if not isinstance(cid, str):
            continue
        if cid.startswith(_FLOW_CLAIM_PREFIX):
            families.add(EFFECT_CLASS_VALUE_OUT)
        elif cid.startswith(_SUPPLY_CLAIM_PREFIX):
            families.add(EFFECT_CLASS_SUPPLY)
    return frozenset(families)


def _principals_by_function(session: Session, function_ids: list[int]) -> dict[int, list[str]]:
    if not function_ids:
        return {}
    rows = session.execute(
        select(FunctionPrincipal.function_id, FunctionPrincipal.address).where(
            FunctionPrincipal.function_id.in_(function_ids)
        )
    ).all()
    out: dict[int, list[str]] = {}
    for fid, addr in rows:
        a = _addr(addr)
        if a is not None:
            out.setdefault(fid, []).append(a)
    return out


def select_candidates(
    session: Session,
    protocol_id: int,
    *,
    resource_cap: int | None = None,
    scope: JobScope | None = None,
) -> list[Candidate]:
    """Return the blank-gated simulation set, ordered by transitive value.

    ``resource_cap`` is the ONLY permissible cutoff (inv. 4): a hard
    safety-valve for a pathological protocol. When it fires it drops the
    lowest-value candidates and ``log()``s exactly what it dropped — value
    never silently removes work.

    ``scope`` narrows the CANDIDATE set to the calling job's own contracts. The
    two protocol-wide inputs below are deliberately NOT narrowed: the authority
    closure and the §5b value-holder set are properties of the whole protocol, and
    computing either from one contract's slice would understate every candidate's
    blast radius.
    """
    rows = _cascade_rows(session, protocol_id, scope)
    function_ids = [r[0] for r in rows]
    principals = _principals_by_function(session, function_ids)
    graph = build_authority_graph(session, protocol_id)

    # §5b: the protocol's witnessed value-holder set (on-chain balances), built once
    # and shared by reference across every candidate. Only positive balances — a
    # zero-balance holder can't be a value-reach target and only adds noise. Keyed
    # on the HOLDING address, which is the one a ``Transfer`` log can name.
    value_holders = tuple(sorted((a, u) for a, u in graph.deployment_balance.items() if u > 0.0))

    candidates: list[Candidate] = []
    for fid, contract_id, address, selector, name, public, targets, deployment, claims in rows:
        families = _enrolled_families(claims)
        # Claim-carrying but no flow/supply family to re-probe → already explained.
        if families is not None and not families:
            continue
        addr = _addr(address) or ""
        prins = principals.get(fid, [])
        seeds = {addr, *prins}
        deployment_addr = _addr(deployment) or ""
        acting = deployment_addr or addr
        candidates.append(
            Candidate(
                function_id=fid,
                contract_id=contract_id,
                contract_address=addr,
                selector=selector,
                function_name=name,
                authority_public=bool(public),
                effect_targets=tuple(targets or ()),
                principal_addresses=tuple(prins),
                value_at_stake_usd=graph.reachable_value(seeds),
                deployment_address=deployment_addr,
                restrict_families=families,
                value_holders=value_holders,
                acting_balance_usd=graph.deployment_balance.get(acting, 0.0),
            )
        )

    # Highest value first; stable tiebreak on function_id for determinism.
    candidates.sort(key=lambda c: (-c.value_at_stake_usd, c.function_id))

    if resource_cap is not None and len(candidates) > resource_cap:
        kept, dropped = candidates[:resource_cap], candidates[resource_cap:]
        _log_dropped(protocol_id, resource_cap, dropped)
        return kept

    return candidates


def record_empty_planning(
    session: Session,
    *,
    job_id: Any,
    candidates_by_contract: dict[int, int],
) -> int:
    """Mark contracts whose candidates were fully planned and yielded NO plans.

    ``candidates_by_contract`` maps ``contracts.id`` → how many of its candidates
    the caller planned. The caller must pass ONLY contracts whose every candidate
    was resolved and probed without error: a candidate skipped for a missing
    behavioral hash, or a prober that raised, is a transient failure and marking
    it would suppress the retry. This is rule 4 of :func:`_scope_predicate`; see
    :class:`~db.models.EffectsPlanMarker` for why the row is time-bounded.

    Returns the number of contracts marked.
    """
    if not candidates_by_contract:
        return 0
    now = datetime.now(timezone.utc)
    stmt = pg_insert(EffectsPlanMarker).values(
        [
            {"contract_id": cid, "job_id": job_id, "candidates_planned": n, "planned_at": now}
            for cid, n in sorted(candidates_by_contract.items())
        ]
    )
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[EffectsPlanMarker.contract_id],
            # Refresh unconditionally: the newest empty planning pass is the one
            # whose freshness rule 4 compares against, and an older ``planned_at``
            # would only cause an extra sweep.
            set_={
                "job_id": stmt.excluded.job_id,
                "candidates_planned": stmt.excluded.candidates_planned,
                "planned_at": stmt.excluded.planned_at,
            },
        )
    )
    session.flush()
    return len(candidates_by_contract)


def _log_dropped(protocol_id: int, resource_cap: int, dropped: list[Candidate]) -> None:
    """Name every dropped candidate — no silent truncation (inv. 4)."""
    manifest = ", ".join(
        f"fn={c.function_id}({c.selector or c.function_name}) on {c.contract_address}"
        f" value=${c.value_at_stake_usd:,.0f}"
        for c in dropped
    )
    logger.warning(
        "effects selection resource cap hit for protocol_id=%s: cap=%d dropped %d candidate(s): %s",
        protocol_id,
        resource_cap,
        len(dropped),
        manifest,
    )
