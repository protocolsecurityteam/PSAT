"""Selection cascade and transitive value-at-stake ordering.

Chooses which effective functions the effects stage probes, from already-persisted data (no RPC).

1. Cascade: filters to the set worth simulating (see :func:`_cascade_rows`).
2. Ordering: transitive value-at-stake runs the highest blast-radius unknowns first. Value orders, never gates; only the
resource cap removes candidates, and it logs what it drops.

Reach is a conservative upper bound (a control edge propagates the full downstream value), which only moves candidates
earlier.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, NamedTuple

from sqlalchemy import and_, case, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.jsonb import jsonb_state
from db.models import (
    CONTROL_EDGE_RELATIONS,
    Artifact,
    Contract,
    ContractBalanceFetch,
    ContractBalanceLatest,
    ControlGraphEdge,
    EffectiveFunction,
    EffectsPlanMarker,
    EffectVerdict,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    TvlSnapshot,
)
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT, NATIVE_ASSET_LOG_EMITTER
from services.monitoring.balance_reads import positive_raw_balance
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    USD_CRUMB_THRESHOLD,
)
from utils.chains import UnknownChainError, canonical_chain, chain_by_id, chain_by_name
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

_NODE_PREFIX = "address:"

# Claim families that re-enroll an already-claimed function: ``flow.*`` needs the value-reach probe, ``supply.*`` the
# mint-backing probe. Other families are already explained.
_FLOW_CLAIM_PREFIX = "flow."
_SUPPLY_CLAIM_PREFIX = "supply."

# Claims that don't explain value/supply behaviour (``rate_limit.consume`` is a zero-weight fact,
# ``delegatecall.execute`` names code provenance). Filtered before :func:`_enrolled_families`, so a row carrying only
# these stays blank (full synthesis). A zero-weight fact must never remove a function from evidence gathering.
_ENROLLMENT_TRANSPARENT_CLAIM_IDS = frozenset({"rate_limit.consume", "delegatecall.execute"})

# Claims that admit a public function (see :func:`_cascade_rows`): value leaving or units printed, where "anyone may
# call" is the security question. ``flow.in`` (a wrapper's purpose) and ``value_router`` are excluded.
_PUBLIC_ADMISSION_CLAIM_IDS = ("flow.out", "supply.mint")

_MAX_TOKEN_ARG_CANDIDATES = 2

# Sample size for the cap-drop WARNING; the count is always exact.
_DROPPED_SAMPLE = 8


_ZERO_USD = Decimal(0)


def _usd(value: Any) -> Decimal:
    """Exact USD from ``contract_balances.usd_value`` (``numeric(38,18)``, already a ``Decimal``).

    Floats make a set-ordered sum order-dependent; same bug class as ``predicates._source_sort_key``.
    """
    if value is None:
        return _ZERO_USD
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def _addr(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    if v.startswith(_NODE_PREFIX):
        v = v[len(_NODE_PREFIX) :]
    v = v.lower()
    return v or None


@dataclass(frozen=True)
class Candidate:
    function_id: int
    contract_id: int
    # The code-bearing address (the implementation for proxies); behavioural hashing keys on it.
    contract_address: str
    selector: str | None
    function_name: str
    authority_public: bool
    # No ``effect_targets``: it was write-only here and conflates state writes with call heads, which the cascade no
    # longer selects on (:func:`_has_effect_evidence`).
    principal_addresses: tuple[str, ...]
    # Transitive USD reachable through the control graph; an upper bound used only for ordering. ``Decimal`` so equal
    # values compare equal and the ``function_id`` tiebreak decides.
    value_at_stake_usd: Decimal = _ZERO_USD
    # Where the state lives; empty for legacy or non-proxy rows.
    deployment_address: str = ""
    # ``None``: blank, synthesize every class. Non-empty: re-enrolled for exactly those flow/supply families.
    restrict_families: frozenset[str] | None = None
    # The protocol's witnessed holdings from ``contract_balances`` (not control edges, which carry no fund flow), per
    # asset, for the value-reach probe. ``acting_balance_usd`` is this deployment's balance, the floor when nothing is
    # observed leaving a holder.
    #
    # ``None`` is a third state: the balance join is INNER so a contract with no row yields no floor. A present ``0.0``
    # is a witness.
    #
    # Per asset because per-holder matching let a synthetic ETH move match a 99.99%-eETH holder and publish $3.489B of
    # false reach.
    #
    # ``usd_value`` stays ``float`` because it's published to jsonb (which can't encode Decimal); each is one cell
    # converted, never a set sum.
    value_holders: tuple[AssetHolding, ...] = ()
    acting_balance_usd: float | None = None
    # ``tvl_snapshots.defillama_tvl``, a ceiling for reach (one function can't reach more than the protocol holds).
    # ``None`` skips the check, and the recipe records that.
    protocol_tvl_usd: float | None = None
    # Richest priced holdings, for caller-supplied token parameters.
    input_token_addresses: tuple[str, ...] = ()
    # The resolver claims an exact caller set. If the probe as that member is rejected by a canonical gate error, the
    # enumeration named the wrong holder.
    membership_exact: bool = False

    @property
    def probe_target(self) -> str:
        """The address every probe must call.

        An implementation's own storage is empty (zero supply, virgin latches, empty roles), so only the deployment
        answers for behaviour. Hashing stays on ``contract_address``.
        """
        return self.deployment_address or self.contract_address


@dataclass
class AuthorityGraph:
    """Address-keyed authority closure inputs for value-at-stake.

    ``controls[A]`` is what A controls. ``balance[addr]`` is USD keyed on the code-bearing ``contracts.address``,
    matching the control edges. ``deployment_balance`` is the same money keyed on the holding (proxy) address, the only
    one a Transfer log names; keying reach on ``balance`` matched nothing. Both are ``Decimal`` so set-ordered sums are
    exact.
    """

    controls: dict[str, set[str]] = field(default_factory=dict)
    balance: dict[str, Decimal] = field(default_factory=dict)
    deployment_balance: dict[str, Decimal] = field(default_factory=dict)

    def _add_control(self, controller: str | None, controlled: str | None) -> None:
        c, t = _addr(controller), _addr(controlled)
        if not c or not t or c == t:
            return
        self.controls.setdefault(c, set()).add(t)

    def reachable_value(self, seeds: set[str]) -> Decimal:
        """Sum balances over the transitive closure of ``seeds`` (included), over ``sorted(seen)`` in an exact type,
        so equal values compare equal and the ``function_id`` tiebreak works.
        """
        stack = [s for s in (_addr(s) for s in seeds) if s]
        seen: set[str] = set()
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(self.controls.get(node, ()))
        total = _ZERO_USD
        for a in sorted(seen):
            total += self.balance.get(a, _ZERO_USD)
        return total


def build_authority_graph(session: Session, protocol_id: int) -> AuthorityGraph:
    """Assemble the control closure and balances for one protocol, as controller → controlled edges from:

    * ``control_graph_edges``, reversed (stored as contract → controller). Only ``CONTROL_EDGE_RELATIONS``:
    ``external_call_target`` moves no authority and would leak a callee's balance.
    * proxy admin → proxy.
    * resolved principal → the function's contract.
    """
    graph = AuthorityGraph()

    # Sum USD per contract from the ``latest`` view (the base table is insert-only and would sum every cycle).
    #
    # INNER join on purpose: a contract with no current row gets no ``deployment_balance`` key, so
    # ``acting_balance_usd`` is None and no floor is published. A LEFT JOIN would mint a $0.00 floor from a failed
    # fetch. A contract with only unpriced rows still gets $0.00, so consumers must still treat 0.0 as not_determined.
    bal_rows = session.execute(
        select(Contract.id, Contract.address, func.coalesce(func.sum(ContractBalanceLatest.usd_value), 0))
        .join(ContractBalanceLatest, ContractBalanceLatest.contract_id == Contract.id)
        .where(Contract.protocol_id == protocol_id)
        .group_by(Contract.id, Contract.address)
    ).all()
    holders = _deployment_by_contract(session, protocol_id)
    for contract_id, address, usd in bal_rows:
        a = _addr(address)
        if a is None:
            continue
        exact = _usd(usd)
        graph.balance[a] = graph.balance.get(a, _ZERO_USD) + exact
        holder = holders.get(contract_id) or a
        # MAX, not sum: two impl rows behind one proxy each carry a copy of its holdings.
        graph.deployment_balance[holder] = max(graph.deployment_balance.get(holder, _ZERO_USD), exact)

    edge_rows = session.execute(
        select(ControlGraphEdge.from_node_id, ControlGraphEdge.to_node_id)
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .where(
            Contract.protocol_id == protocol_id,
            ControlGraphEdge.relation.in_(CONTROL_EDGE_RELATIONS),
        )
    ).all()
    for from_node, to_node in edge_rows:
        graph._add_control(to_node, from_node)

    admin_rows = session.execute(
        select(Contract.admin, Contract.address).where(Contract.protocol_id == protocol_id, Contract.admin.isnot(None))
    ).all()
    for admin, address in admin_rows:
        graph._add_control(admin, address)

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
    """``contract id -> the address holding its state``: the proxy from ``effective_functions.deployment_address``
    (uniform per contract), absent for non-proxies.
    """
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


# Whether a holder's holdings list is whole. Deliberately no ``"complete"`` state: that would need the fetch's page
# length, which isn't persisted (``get_token_balances`` drops zero balances first).
HOLDINGS_COMPLETENESS_AT_PAGE_CAP = "at_page_cap"
HOLDINGS_COMPLETENESS_NOT_DETERMINED = "not_determined"
HOLDINGS_COMPLETENESS_STATES = (HOLDINGS_COMPLETENESS_AT_PAGE_CAP, HOLDINGS_COMPLETENESS_NOT_DETERMINED)


class AssetHolding(NamedTuple):
    """One (holder, asset) balance the value-reach probe can match.

    ``asset`` is the Transfer emitter: the token, or :data:`~services.effects.config.NATIVE_ASSET_LOG_EMITTER` for
    native. Per asset to prevent the asset-blind over-claim.

    ``usd_value`` is ``None`` when unpriced (most local rows), never zero: unknown must rank worse than a proven-benign
    value.
    """

    holder: str
    asset: str
    usd_value: float | None
    # One of :data:`HOLDINGS_COMPLETENESS_STATES`, never complete: only the fetch's ``at_page_cap`` status is a witness.
    # Uniform per holder, carried per row for convenience.
    completeness: str = HOLDINGS_COMPLETENESS_NOT_DETERMINED


def _asset_holdings_by_deployment(session: Session, protocol_id: int) -> dict[str, tuple[AssetHolding, ...]]:
    """``deployment address -> its per-asset holdings``, keyed on the holding (proxy) address.

    MAX per (holder, asset), since impl rows behind one proxy carry copies.
    """
    rows = session.execute(
        select(
            Contract.id,
            ContractBalanceLatest.token_address,
            ContractBalanceLatest.usd_value,
            ContractBalanceLatest.raw_balance,
            ContractBalanceFetch.asset_set_status,
        )
        .join(ContractBalanceLatest, ContractBalanceLatest.contract_id == Contract.id)
        # OUTER so legacy rows with no fetch aren't dropped.
        .outerjoin(ContractBalanceFetch, ContractBalanceFetch.id == ContractBalanceLatest.fetch_id)
        .where(Contract.protocol_id == protocol_id)
    ).all()
    holders = _deployment_by_contract(session, protocol_id)
    addresses: dict[int, str] = {
        cid: address
        for cid, address in session.execute(
            select(Contract.id, Contract.address).where(Contract.protocol_id == protocol_id)
        ).all()
    }
    kept: list[tuple[str, str, float | None, str | None]] = []
    for (
        contract_id,
        token_address,
        usd,
        raw_balance,
        asset_set_status,
    ) in rows:
        holder = holders.get(contract_id) or _addr(addresses.get(contract_id))
        if holder is None:
            continue
        if not positive_raw_balance(raw_balance):
            continue
        asset = _addr(token_address) or NATIVE_ASSET_LOG_EMITTER
        value = None if usd is None else float(_usd(usd))
        kept.append((holder, asset, value, asset_set_status))
    # (holder, asset) -> usd. Unpriced never overwrites priced and is never 0 in the max.
    best: dict[tuple[str, str], float | None] = {}
    # Weakest wins: one capped sibling fetch means the list may be missing entries.
    from services.monitoring.balance_reads import latest_partial_asset_fetches

    holder_capped: dict[str, bool] = {}
    for contract_id in latest_partial_asset_fetches(session, protocol_id):
        holder = holders.get(contract_id) or _addr(addresses.get(contract_id))
        if holder is not None:
            holder_capped[holder] = True
    for holder, asset, value, asset_set_status in kept:
        key = (holder, asset)
        if key not in best:
            best[key] = value
        else:
            current = best[key]
            if current is None:
                best[key] = value
            elif value is not None:
                best[key] = max(current, value)
        if _completeness_from_fetch(asset_set_status) == HOLDINGS_COMPLETENESS_AT_PAGE_CAP:
            holder_capped[holder] = True
    out: dict[str, list[AssetHolding]] = {}
    for (holder, asset), usd_value in sorted(best.items()):
        completeness = (
            HOLDINGS_COMPLETENESS_AT_PAGE_CAP if holder_capped.get(holder) else HOLDINGS_COMPLETENESS_NOT_DETERMINED
        )
        out.setdefault(holder, []).append(
            AssetHolding(
                holder=holder,
                asset=asset,
                usd_value=usd_value,
                completeness=completeness,
            )
        )
    return {holder: tuple(items) for holder, items in out.items()}


def _completeness_from_fetch(asset_set_status: str | None) -> str:
    """Map one fetch's ``asset_set_status`` to a completeness state; total, and can never return complete.

    Only ``at_page_cap`` witnesses truncation. The stored entry count isn't a discriminator (a fully paged list often
    exceeds ``TOKEN_BALANCE_PAGE_SIZE``). ``returned_assets``, ``fetch_failed`` and ``None`` are all ``not_determined``.
    """
    if asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP:
        return HOLDINGS_COMPLETENESS_AT_PAGE_CAP
    return HOLDINGS_COMPLETENESS_NOT_DETERMINED


def _protocol_tvl_usd(session: Session, protocol_id: int) -> float | None:
    """The protocol's latest ``defillama_tvl``, or ``None`` (the ceiling check is then skipped, and says so).

    Other TVL columns are NULL locally.
    """
    value = session.execute(
        select(TvlSnapshot.defillama_tvl)
        .where(TvlSnapshot.protocol_id == protocol_id, TvlSnapshot.defillama_tvl.isnot(None))
        .order_by(TvlSnapshot.timestamp.desc(), TvlSnapshot.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    return None if value is None else float(value)


def _token_holdings_by_contract(session: Session, protocol_id: int, limit: int) -> dict[int, tuple[str, ...]]:
    """The deployment's richest priced holdings, within the token cap.

    Partial observations may supply identities; unpriced holdings are ineligible.
    """
    rows = session.execute(
        select(
            Contract.id,
            ContractBalanceLatest.token_address,
            ContractBalanceLatest.usd_value,
            ContractBalanceLatest.id,
        )
        .join(ContractBalanceLatest, ContractBalanceLatest.contract_id == Contract.id)
        .where(
            Contract.protocol_id == protocol_id,
            ContractBalanceLatest.token_address.isnot(None),
            # A cent or more is necessarily held; $0.01 is kept, $0.009 is a crumb.
            ContractBalanceLatest.usd_value >= USD_CRUMB_THRESHOLD,
        )
        # Trailing keys make the order total (ties exist).
        .order_by(
            ContractBalanceLatest.usd_value.desc(),
            ContractBalanceLatest.token_address.asc(),
            ContractBalanceLatest.id.asc(),
        )
    ).all()
    # A newer interrupted prefix may add identities; its value is never added to the accepted total.
    from services.monitoring.balance_reads import partial_asset_rows

    candidate_rows = [
        (cid, token, usd, row_id) for cid, token, usd, row_id in rows if token is not None and usd is not None
    ]
    for contract_id, partials in partial_asset_rows(session, protocol_id).items():
        for row in partials:
            if (
                row.token_address
                and positive_raw_balance(row.raw_balance)
                and row.usd_value is not None
                and row.usd_value >= USD_CRUMB_THRESHOLD
            ):
                candidate_rows.append((contract_id, row.token_address, row.usd_value, row.id))
    out: dict[int, list[str]] = {}
    # Richest-first across both sources before dedup and the cap; values only rank.
    for contract_id, token, _usd_value, _row_id in sorted(candidate_rows, key=lambda row: (-row[2], row[1], row[3])):
        addr = _addr(token)
        if addr is None:
            continue
        holdings = out.setdefault(contract_id, [])
        if addr not in holdings and len(holdings) < limit:
            holdings.append(addr)
    return {cid: tuple(v) for cid, v in out.items()}


@dataclass(frozen=True)
class JobScope:
    """The contract one effects job plans.

    Without a scope every job re-plans the whole protocol. With one, a job plans its own contract plus the protocol's
    unowned contracts (:func:`_scope_predicate`). ``address`` is the code-bearing ``contracts.address``.
    ``planned_since`` is the job's ``created_at`` and bounds marker ownership (rule 4); ``None`` disables that rule,
    which only costs extra sweeps.
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
    """``Contract.chain`` is a name; NULL is legacy mainnet (as in ``services/discovery/upgrade_history``)."""
    name = canonical_chain(_chain_name(chain_id)) or "ethereum"
    return func.lower(func.coalesce(Contract.chain, "ethereum")) == name


# Derived so it can't drift from ``BaseWorker``.
_EFFECTS_STAGE_ARTIFACT = f"stage_timing_{JobStage.effects.value}"

# The failure path writes the same artifact with ``"failed"``, and effects fail-forwards, so only success counts as
# ownership; anything else re-sweeps.
_STAGE_STATUS_SUCCESS = "success"

_FINISHED_JOB_STATES = (JobStatus.completed, JobStatus.failed_terminal)

# Stages from which a job can still reach effects (``JobStage`` order through ``effects``). Fail-forwarded and flag-off
# jobs are past it.
_JOB_STAGE_ORDER = list(JobStage)
_EFFECTS_REACHABLE_STAGES = tuple(_JOB_STAGE_ORDER[: _JOB_STAGE_ORDER.index(JobStage.effects) + 1])

# storage_key -> status, only for jobs that can't rewrite the artifact (a live job's may still change).
_STAGE_STATUS_CACHE: dict[str, str] = {}
_STAGE_STATUS_CACHE_MAX = 20_000


def _job_owns_contract_address(protocol_id: int, scope: JobScope):
    """Ties a job to its contract, protocol- and chain-qualified."""
    return and_(
        Job.protocol_id == protocol_id,
        # Recovery owns a selected function/family, never the whole contract.
        Job.request["effects_resume_work_id"].astext.is_(None),
        Job.chain_id == scope.chain_id,
        Job.address.is_not(None),
        func.lower(Job.address) == func.lower(Contract.address),
    )


def _protocol_contracts_on_chain(protocol_id: int, scope: JobScope):
    return (Contract.protocol_id == protocol_id, _contract_chain_matches(scope.chain_id))


def _contracts_with_an_effects_capable_job(session: Session, protocol_id: int, scope: JobScope) -> set[int]:
    """Rule 1: a job at this address is in flight and can still reach effects."""
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
    """Rule 3: verdicts left by a sweep."""
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
    """Rule 4: a sweep planned it with no plans, within this job's lifetime."""
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
    """Fetch stage-timing bodies from object storage in one round trip.

    With artifact storage configured, ``artifacts.data`` is JSON null, so SQL can't see the status. Read failures give
    ``None`` (re-sweep).
    """
    from db.storage import deserialize_artifact, get_storage_client

    try:
        client = get_storage_client()
        if client is None:
            return {}
        bodies = client.get_many(list(keys_to_types))
    except Exception as exc:
        # Safe but multiplies planning work, so record it as degraded.
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
        except Exception as exc:
            # Same as above.
            record_degraded(phase="effects_selection_stage_status", exc=exc, context={"key": key})
            logger.warning(
                "effects selection: undecodable stage-timing body",
                extra={"key": key, "exc_type": type(exc).__name__},
            )
    return out


def _contracts_with_a_successful_effects_run(
    session: Session, protocol_id: int, scope: JobScope, *, already_owned: set[int]
) -> set[int]:
    """Rule 2: a job at this address ran effects and succeeded.

    Only checked for otherwise-unowned contracts to bound storage reads.
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
    owned = _contracts_with_an_effects_capable_job(session, protocol_id, scope)
    owned |= _contracts_with_verdicts(session, protocol_id, scope)
    owned |= _contracts_with_a_fresh_marker(session, protocol_id, scope)
    owned |= _contracts_with_a_successful_effects_run(session, protocol_id, scope, already_owned=owned)
    return owned


def _scope_predicate(session: Session, protocol_id: int, scope: JobScope):
    """Which contracts this job plans: its own, plus every unowned one.

    Ownership means "some job will actually plan it", not "a job row exists" (in steady state every contract has a
    finished job and nobody scheduled). Owned when:

    1. a job at its address is in flight and can still reach the effects stage (:data:`_EFFECTS_REACHABLE_STAGES`);
    2. a job at its address already ran effects successfully (a failed stage fail-forwards and never reruns, so it
    doesn't count);
    3. its functions already carry verdicts (left by a sweep);
    4. an ``effects_plan_markers`` row says a sweep planned it with no plans, and the marker is no older than this job
    (``scope.planned_since``), so changed inputs get re-planned next wave.

    The union over a protocol's jobs covers every contract. Rule 1 is a prediction: if the promising job dies before
    effects and no sibling reaches effects afterwards, the next run recovers it. All matching is protocol- and
    chain-qualified.
    """
    owned = _owned_contract_ids(session, protocol_id, scope)
    if not owned:
        return literal(True)
    return or_(func.lower(Contract.address) == scope.address.lower(), Contract.id.not_in(owned))


def _carries_public_admission_claim():
    """SQL predicate: ``claims`` holds a :data:`_PUBLIC_ADMISSION_CLAIM_IDS` id.

    In SQL because these rows are outside the ``authority_public = false`` set. Uses containment (``@>``) because
    ``jsonb_array_elements`` raises on the JSON ``null`` this column can hold, which would abort selection for the
    protocol.
    """
    return or_(
        *(
            EffectiveFunction.claims.op("@>")(cast([{"claim_id": claim_id}], JSONB))
            for claim_id in _PUBLIC_ADMISSION_CLAIM_IDS
        )
    )


def _proven_array_len(col: Any):
    """``jsonb_array_length`` that can't raise: non-arrays (jsonb ``null``, malformed) fold to 0.

    Callers must pair it with :func:`_evidence_not_determined`, since the fold isn't proven emptiness.
    """
    return func.jsonb_array_length(case((jsonb_state(col) == "array", col), else_=cast(literal("[]"), JSONB)))


def _evidence_proven_present(col: Any):
    """A non-empty jsonb array: the writer looked and found."""
    return and_(jsonb_state(col) == "array", _proven_array_len(col) > 0)


def _evidence_not_determined(col: Any):
    """The column holds no array (SQL NULL, jsonb ``null``, or malformed), all meaning not determined.

    Never NULL itself (``jsonb_state`` coalesces), so it can't vanish from an ``or_``.
    """
    return jsonb_state(col) != "array"


def _has_effect_evidence():
    """SQL predicate for cascade filter (a): is there anything to simulate, or could we not determine that there isn't?

    Reads the three-state evidence plane (``state_changing`` / ``state_writes`` / ``sinks``), not
    ``effect_targets``, a display field mixing state writes with external-call heads (a third of populated rows had
    only call heads).

    ==================  ================  ==============  =========  ================================
    ``state_changing``  ``state_writes``  ``sinks``       candidacy  why
    ==================  ================  ==============  =========  ================================
    any                 array, len>0      any             ADMIT      proven state write
    any                 any               array, len>0    ADMIT      proven sink of any kind
    ``TRUE``            ``[]``            ``[]``          ADMIT      ABI says mutable, extractor found
                                                                     nothing: unsettled, so probe
    ``NULL``            any               any             ADMIT      not determined
    any                 not an array      any             ADMIT      not determined
    any                 any               not an array    ADMIT      not determined
    ``FALSE``           ``[]``            ``[]``          EXCLUDE    compiler-typed view/pure and the
                                                                     writer found no write or sink
    ==================  ================  ==============  =========  ================================

    * Not-determined admits: unwritten or withheld evidence is probed, not dropped.
    * ``state_changing`` is only a bool. ``TRUE`` covers assembly writes the IR missed; ``FALSE`` only comes from
      named view/pure functions (``fallback``/``receive`` are withheld to NULL, e.g. WETH9's ``fallback()`` writes).
    * ``writer_selectors`` isn't read: it's empty without a ``state_write`` sink, so it adds no recall.

    ``state_changing IS FALSE`` alone isn't the exclusion (despite
    ``test_a_state_write_only_filter_would_suppress_the_positive_control``): view/pure only proves no mutation,
    while this stage also tests the authority plane. Both the compiler and the extractor must agree. Today that
    choice affects one row.

    Origin-agnostic: guard-origin writes count, since probes run modifiers too.
    """
    return or_(
        _evidence_proven_present(EffectiveFunction.state_writes),
        _evidence_proven_present(EffectiveFunction.sinks),
        EffectiveFunction.state_changing.is_(True),
        _evidence_not_determined(EffectiveFunction.state_writes),
        _evidence_not_determined(EffectiveFunction.sinks),
        EffectiveFunction.state_changing.is_(None),
    )


def _cascade_rows(
    session: Session,
    protocol_id: int,
    scope: JobScope | None = None,
    *,
    chain_id: int | None = None,
    function_ids: list[int] | None = None,
):
    """The filter cascade as one query.

    (a) something to simulate: see :func:`_has_effect_evidence`.
    (c) gated, i.e. ``authority_public = false``, except public functions carrying ``flow.out`` or ``supply.mint``. For
    a permissionless payout or mint, "anyone can call" is the finding (770 public functions got no verdict before).
    Probed from :data:`calldata.NEUTRAL_CALLER`. Kept narrow to avoid wrapper noise.

    Filter (b), the blank-claim gate, runs in Python (:func:`_enrolled_families`): blank rows get full synthesis,
    flow/supply-claimed rows are re-enrolled for those families, other claimed rows are dropped in
    :func:`select_candidates`.

    ``scope`` narrows to one job's contracts (:class:`JobScope`); ``None`` is protocol-wide.
    """
    where = [
        Contract.protocol_id == protocol_id,
        _has_effect_evidence(),
        # Keyed on the bool, not ``authority_openness``: undetermined authority must be admitted like a witnessed
        # restriction; ``= 'restricted'`` would drop undetermined rows (fail-open).
        or_(EffectiveFunction.authority_public.is_(False), _carries_public_admission_claim()),
    ]
    if chain_id is not None:
        where.append(_contract_chain_matches(chain_id))
    if function_ids is not None:
        where.append(EffectiveFunction.id.in_(function_ids))
    if scope is not None:
        # Chain scoping matters: protocol-wide selection probed other chains' contracts through chain-1 seams.
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
            EffectiveFunction.deployment_address,
            EffectiveFunction.claims,
            EffectiveFunction.capability_expr,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(*where)
    ).all()


def _membership_exact(capability_expr: Any) -> bool:
    """Whether the resolver claims an exact enumeration of F's callers: ``finite_set`` kind and exact quality
    (``unsupported`` / ``conditional_universal`` also report exact).
    """
    return (
        isinstance(capability_expr, dict)
        and capability_expr.get("kind") == "finite_set"
        and capability_expr.get("membership_quality") == "exact"
    )


def _enrolled_families(claims: Any) -> frozenset[str] | None:
    """Which effect families to probe, from the claims.

    * ``None``: blank (``[]``, SQL NULL and JSON null alike); synthesize everything.
    * non-empty: re-enrolled for ``value_out`` and/or ``supply``.
    * empty: only other claims, already explained; dropped. Unrecognised shapes enroll nothing.

    :data:`_ENROLLMENT_TRANSPARENT_CLAIM_IDS` are removed first so they never turn a blank row into a dropped one.
    """
    if not isinstance(claims, list) or not claims:
        return None
    claims = [c for c in claims if not (isinstance(c, dict) and c.get("claim_id") in _ENROLLMENT_TRANSPARENT_CLAIM_IDS)]
    if not claims:
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
    """``function id -> its resolved principals`` in a total order.

    Element ``[0]`` is the identity every fork probe impersonates, so without ORDER BY the probe's gate, reverts and
    witness depended on the query plan (some functions have 15-33 principals). Ordered on ``address`` to match
    ``calldata._principals_by_selector``; ``id`` breaks duplicate addresses.
    """
    if not function_ids:
        return {}
    rows = session.execute(
        select(FunctionPrincipal.function_id, FunctionPrincipal.address)
        .where(FunctionPrincipal.function_id.in_(function_ids))
        .order_by(FunctionPrincipal.function_id, FunctionPrincipal.address, FunctionPrincipal.id)
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
    chain_id: int | None = None,
    function_ids: list[int] | None = None,
    scope: JobScope | None = None,
    funnel: dict[str, Any] | None = None,
) -> list[Candidate]:
    """The blank-gated simulation set, ordered by transitive value.

    ``funnel`` is filled with ``rows_in``, ``skipped_already_explained``, ``cap_dropped`` and ``selected`` so "found
    nothing" is distinguishable from "dropped everything".

    ``resource_cap`` is the only cutoff; it drops the lowest-value candidates and logs them. ``scope`` narrows
    candidates only; the authority closure and holder set stay protocol-wide so blast radius isn't understated.
    """
    rows = (
        _cascade_rows(session, protocol_id, scope, chain_id=chain_id, function_ids=function_ids)
        if chain_id is not None or function_ids is not None
        else _cascade_rows(session, protocol_id, scope)
    )
    if funnel is not None:
        funnel["rows_in"] = len(rows)
        funnel["skipped_already_explained"] = 0
        funnel["cap_dropped"] = 0
        funnel["selected"] = 0
    function_ids = [r[0] for r in rows]
    principals = _principals_by_function(session, function_ids)
    graph = build_authority_graph(session, protocol_id)

    # Built once and shared, per asset, keyed on the holding address. Unpriced holdings are kept (``usd_value=None``) so
    # a moved unpriced asset makes reach not-determined rather than invisible; a priced 0 is also kept.
    value_holders = tuple(
        holding
        for holdings_for_deployment in _asset_holdings_by_deployment(session, protocol_id).values()
        for holding in holdings_for_deployment
    )
    holdings = _token_holdings_by_contract(session, protocol_id, _MAX_TOKEN_ARG_CANDIDATES)
    from services.effects.balance_dependencies import balance_owners

    holder_chain = chain_id or (scope.chain_id if scope else None)
    if holder_chain:
        owners = balance_owners(session, protocol_id, holder_chain, [r[6] or r[2] for r in rows])
        holder_ids = {r[0]: owners.get((r[6] or r[2]).lower()) for r in rows}
    else:
        code_chains = {}
        for cid, name in session.execute(
            select(Contract.id, Contract.chain).where(Contract.id.in_([r[1] for r in rows]))
        ):
            try:
                code_chains[cid] = chain_by_name(name or "ethereum").chain_id
            except UnknownChainError:
                continue
        holder_ids = {}
        for actual_chain in set(code_chains.values()):
            chain_rows = [r for r in rows if code_chains.get(r[1]) == actual_chain]
            owners = balance_owners(session, protocol_id, actual_chain, [r[6] or r[2] for r in chain_rows])
            holder_ids.update({r[0]: owners.get((r[6] or r[2]).lower()) for r in chain_rows})
    protocol_tvl = _protocol_tvl_usd(session, protocol_id)

    candidates: list[Candidate] = []
    for fid, contract_id, address, selector, name, public, deployment, claims, capability_expr in rows:
        families = _enrolled_families(claims)
        if families is not None and not families:
            if funnel is not None:
                funnel["skipped_already_explained"] += 1
            continue
        addr = _addr(address) or ""
        prins = principals.get(fid, [])
        seeds = {addr, *prins}
        deployment_addr = _addr(deployment) or ""
        acting = deployment_addr or addr
        acting_balance = graph.deployment_balance.get(acting)
        candidates.append(
            Candidate(
                function_id=fid,
                contract_id=contract_id,
                contract_address=addr,
                selector=selector,
                function_name=name,
                authority_public=bool(public),
                principal_addresses=tuple(prins),
                value_at_stake_usd=graph.reachable_value(seeds),
                deployment_address=deployment_addr,
                restrict_families=families,
                value_holders=value_holders,
                acting_balance_usd=None if acting_balance is None else float(acting_balance),
                protocol_tvl_usd=protocol_tvl,
                input_token_addresses=holdings.get(holder_ids.get(fid) or -1, ()),
                membership_exact=_membership_exact(capability_expr),
            )
        )

    # Highest value first, ``function_id`` tiebreak. Ties are common (an 84-member cluster), hence exact values.
    candidates.sort(key=lambda c: (-c.value_at_stake_usd, c.function_id))

    if resource_cap is not None and len(candidates) > resource_cap:
        kept, dropped = candidates[:resource_cap], candidates[resource_cap:]
        _log_dropped(protocol_id, resource_cap, dropped)
        if funnel is not None:
            funnel["cap_dropped"] = len(dropped)
            funnel["selected"] = len(kept)
        return kept

    if funnel is not None:
        funnel["selected"] = len(candidates)
    return candidates


def record_empty_planning(
    session: Session,
    *,
    job_id: Any,
    candidates_by_contract: dict[int, int],
) -> int:
    """Mark contracts whose candidates were fully planned with no plans (rule 4 of :func:`_scope_predicate`; see
    :class:`~db.models.EffectsPlanMarker`).

    Pass only contracts whose every candidate was probed without error; marking a transient failure suppresses the
    retry. Returns the number marked.
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
            # Refresh: rule 4 compares against the newest pass.
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
    """Log every dropped candidate: the count is exact, the manifest a bounded sample."""
    manifest = [
        {
            "function_id": c.function_id,
            "selector": c.selector or c.function_name,
            "contract_address": c.contract_address,
            "value_at_stake_usd": round(c.value_at_stake_usd, 2),
        }
        for c in dropped[:_DROPPED_SAMPLE]
    ]
    logger.warning(
        "effects selection resource cap hit: dropped %d candidate(s) below the cap",
        len(dropped),
        extra={
            "protocol_id": protocol_id,
            "resource_cap": resource_cap,
            "dropped": len(dropped),
            "dropped_sample": manifest,
            "dropped_sample_truncated": len(dropped) > _DROPPED_SAMPLE,
        },
    )
