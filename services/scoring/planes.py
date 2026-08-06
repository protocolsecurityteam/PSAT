"""The resolution planes the Layer-2 fold reads to resolve a signal's references.

Signals carry references — ``function_principals`` ids and ``<chain>::<address>``
entity keys — so the fold is the first place that can turn them into units,
dollars and breadth. Every read here is ordered, read-only, and publishes its
own three-state: an unreadable or absent witness lands on ``not_determined`` and
is counted in the provenance block rather than defaulted to a number.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
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

ZERO_ADDRESS = "0x" + "0" * 40

# Control relations that carry authority. ``safe_owner`` is excluded (one owner
# does not satisfy k-of-n) and ``controller_value_unattributed`` is excluded
# (real principals whose authority RELATION was never established — a confidence
# item, not an edge).
CONTROL_RELATIONS = ("controller_value", "role_principal", "mapping_member")

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

# --- what one (entity, asset) reading proves ---------------------------------
# ``usd_value`` is numeric(20,2), so 0.00 is the STORAGE FLOOR and not a number:
# a $0.0035 holding stores as 0.00 indistinguishably from a $0.00 one. The
# quantity is what separates them — a proven-zero raw balance is worth zero at
# any price — so a 0.00 reading is only ever a determined zero when the quantity
# proves it, and is otherwise below the column's resolution.
ASSET_PRICED = "priced"
ASSET_BELOW_RESOLUTION = "priced_below_resolution"
ASSET_PROVEN_ZERO = "proven_zero"
ASSET_UNPRICED = "unpriced"

# --- what a whole balance sheet proves ---------------------------------------
SHEET_PRICED = "priced"
SHEET_BELOW_RESOLUTION = "priced_below_resolution"
SHEET_UNPRICED = "unpriced"
SHEET_PROVEN_EMPTY = "proven_empty"
SHEET_NO_ROWS = "no_rows"

# The states in which a sheet total is NOT a number. Kept apart from each other
# all the way to the consumer: "every price lookup answered below the column's
# resolution" and "no price lookup answered" are different facts, and neither is
# "proven to hold nothing".
SHEET_NOT_DETERMINED = (SHEET_BELOW_RESOLUTION, SHEET_UNPRICED, SHEET_NO_ROWS)


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass
class ValuePlane:
    """Per-entity value, reduced to the LATEST observation per (entity, asset).

    ``contract_entities`` is every entity the protocol's ``contracts`` rows name,
    priced or not. It is the confidence perimeter's base population: discovery
    fixes it, so it does not move with what has been analysed, and an unpriced
    contract outside the control closure still carries its unanswered weight
    instead of vanishing from its own denominator.

    ``per_asset`` carries only DETERMINED dollar readings — an asset whose price
    lookup never answered, or answered below the storage column's resolution, is
    absent from it and named in ``per_asset_state`` instead. The two together are
    the three-state: a number, a stated reason there is no number, or no row at
    all. A key present in ``per_asset`` with no ``per_asset_state`` entry (a
    hand-built plane) is read as determined, which is what that map means.
    """

    contract_entities: set[str] = field(default_factory=set)
    per_asset: dict[str, dict[str, float]] = field(default_factory=dict)
    per_asset_state: dict[str, dict[str, str]] = field(default_factory=dict)
    native_fact: dict[str, str] = field(default_factory=dict)
    alias: dict[str, str] = field(default_factory=dict)
    unpriced_positions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def canonical(self, key: str) -> str:
        """An implementation's key folds onto the proxy that deploys it."""
        return self.alias.get(key, key)

    def sheet_state(self, key: str) -> str:
        """What the entity's balance sheet PROVES, in one of five states.

        ``priced`` — at least one determined non-zero reading, so ``total`` is a
        floor over what was priced. ``priced_below_resolution`` — every price
        lookup that answered landed on the ``numeric(20,2)`` floor, which is a
        holding of *at most* half a cent per row and never a proven zero.
        ``unpriced`` — rows exist and no lookup answered. ``proven_empty`` — every
        asset's QUANTITY is proven zero, the only witness under which 0.00 is a
        number rather than a rounding artefact. ``no_rows`` — nothing observed.
        """
        canonical = self.canonical(key)
        values = self.per_asset.get(canonical) or {}
        states = self.per_asset_state.get(canonical) or {}
        if any(value != 0.0 for value in values.values()):
            return SHEET_PRICED
        if any(state == ASSET_BELOW_RESOLUTION for state in states.values()):
            return SHEET_BELOW_RESOLUTION
        if any(state == ASSET_UNPRICED for state in states.values()):
            return SHEET_UNPRICED
        if values or any(state == ASSET_PROVEN_ZERO for state in states.values()):
            return SHEET_PROVEN_EMPTY
        return SHEET_NO_ROWS

    def total(self, key: str) -> float | None:
        """The entity's priced holdings, or ``None`` when they are not a number.

        ``None`` is not zero, and the three ways of not being a number are kept
        apart in ``sheet_state``: an entity whose every row is unpriced, one whose
        every price rounded to the storage floor, and one proven to hold nothing
        are different facts, and only the last may reach a consumer as ``0.0``.
        """
        state = self.sheet_state(key)
        if state == SHEET_PROVEN_EMPTY:
            return 0.0
        if state in SHEET_NOT_DETERMINED:
            return None
        assets = self.per_asset.get(self.canonical(key)) or {}
        return round(sum(sorted(assets.values())), 6)

    @property
    def tracked_total(self) -> float:
        # Only entities with a determined total enter the denominator. One whose
        # total is not a number contributes nothing rather than a zero, so the
        # ratio is over what was measured.
        totals = [self.total(k) for k in set(self.per_asset) | set(self.per_asset_state)]
        return round(sum(sorted(t for t in totals if t is not None)), 2)


_EPOCH = datetime.min


def _write_order(row: Any) -> tuple[bool, Any, int]:
    """Insert order, for observations whose READ height was never recorded."""
    return (row.fetched_at is not None, row.fetched_at or _EPOCH, int(row.id or 0))


def _latest_observation(rows: list[Any]) -> tuple[Any, bool]:
    """The current reading of one account, and whether a HEIGHT witnessed it.

    Ordering by ``block_number`` is the only ordering that proves which reading
    is current, and it is available only where every competing row carries one:
    ``contract_balance_fetches.block_number`` pins the native quantity and is
    deliberately never projected onto ERC-20 rows, so most competing readings
    have no height at all. There the fallback is write order, which is a fact
    about this database rather than about the chain — hence the flag, counted in
    the provenance so the fiat is stated rather than silent.
    """
    if len(rows) == 1:
        return rows[0], rows[0].block_number is not None
    if all(row.block_number is not None for row in rows):
        return max(rows, key=lambda row: (row.block_number, _write_order(row))), True
    return max(rows, key=_write_order), False


def _is_proven_zero_quantity(row: Any) -> bool:
    """Whether the QUANTITY held is proven zero — worth 0 at any price.

    The only witness under which a ``0.00`` dollar reading is a number rather
    than the storage column's floor. An unparseable raw balance proves nothing
    and lands on False, which keeps the reading below-resolution rather than
    minting a proven zero out of a value nobody could read.
    """
    try:
        return float(str(row.raw_balance)) == 0.0
    except (TypeError, ValueError):
        return False


def _asset_reading(row: Any) -> tuple[float | None, str]:
    """One row's dollar reading and the state that reading is in."""
    usd = _float(row.usd_value)
    if usd is None:
        # NULL usd_value is not_determined, never 0: nothing separates a
        # worthless asset from a failed price lookup.
        return None, ASSET_UNPRICED
    if usd != 0.0:
        return usd, ASSET_PRICED
    if _is_proven_zero_quantity(row):
        return 0.0, ASSET_PROVEN_ZERO
    return None, ASSET_BELOW_RESOLUTION


def _reduce_observations(
    observations: dict[tuple[str, str], dict[str, list[Any]]],
) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, str]], dict[str, Any]]:
    """Latest observation per account; SUM across DISTINCT observed accounts.

    Two readings of one account are one holding read twice — the later one is
    the answer and the earlier one is stale, so MAX over them publishes a
    high-water mark that was already false when it was written. Two readings of
    two accounts are two holdings of the same entity, and the entity holds their
    SUM. The discriminator is ``observed_address``, the address the read was
    actually issued against.

    Where the account identity itself is missing on any competing reading the
    sum is not licensed — summing over an unwitnessed identity is how the double
    count this reduction exists to remove gets back in — so those buckets fall
    back to MAX and are counted separately.
    """
    per_asset: dict[str, dict[str, float]] = defaultdict(dict)
    per_asset_state: dict[str, dict[str, str]] = defaultdict(dict)
    counters: dict[str, int] = defaultdict(int)
    stale_usd = 0.0

    for (key, asset), accounts in sorted(observations.items()):
        counters["buckets"] += 1
        readings: list[tuple[float | None, str]] = []
        for account in sorted(accounts):
            rows = accounts[account]
            if len(rows) > 1:
                counters["multi_observation_accounts"] += 1
            row, height_witnessed = _latest_observation(rows)
            counters["height_witnessed_accounts" if height_witnessed else "write_order_accounts"] += 1
            readings.append(_asset_reading(row))
            priced = [_float(candidate.usd_value) for candidate in rows]
            highest = max((value for value in priced if value is not None), default=None)
            current = _float(row.usd_value)
            if highest is not None and current is not None and highest > current:
                counters["stale_high_water_marks_dropped"] += 1
                stale_usd += highest - current

        if len(accounts) > 1:
            counters["multi_account_buckets"] += 1
            if "" in accounts:
                counters["unwitnessed_account_buckets"] += 1

        determined = [value for value, state in readings if value is not None]
        if any(state == ASSET_PRICED for _, state in readings):
            state = ASSET_PRICED
            # The MAX fallback where an account identity is missing: never a sum
            # over readings that may be the same account twice.
            value = max(determined) if "" in accounts and len(accounts) > 1 else sum(determined)
        elif any(pair[1] == ASSET_BELOW_RESOLUTION for pair in readings):
            state, value = ASSET_BELOW_RESOLUTION, None
        elif any(pair[1] == ASSET_UNPRICED for pair in readings):
            state, value = ASSET_UNPRICED, None
        else:
            state, value = ASSET_PROVEN_ZERO, 0.0
        counters[f"assets_{state}"] += 1
        per_asset_state[key][asset] = state
        if value is not None:
            per_asset[key][asset] = round(value, 6)

    reduction: dict[str, Any] = dict(sorted(counters.items()))
    reduction["stale_high_water_usd_dropped"] = round(stale_usd, 2)
    return (
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset.items())},
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset_state.items())},
        reduction,
    )


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

    native_seen: set[str] = set()
    fetched: list[Any] = []
    rows = (
        session.query(ContractBalanceLatest)
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceLatest.contract_id, ContractBalanceLatest.token_address, ContractBalanceLatest.id)
        .all()
    )
    # One bucket per (entity, asset, observed account). The alias fold puts a
    # proxy's rows and its implementation's rows under one entity key, and those
    # are the SAME on-chain account read twice at two heights by two writers —
    # not two holdings — so the account is what a reading has to be reduced over.
    observations: dict[tuple[str, str], dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        key = plane.canonical(entity_key(chain_of.get(row.contract_id), address_of.get(row.contract_id)))
        # A NULL token_address IS the native asset by this column's definition,
        # not a missing value standing in for one.
        asset = _lower(row.token_address) if row.token_address else NATIVE_ASSET
        if asset == NATIVE_ASSET:
            native_seen.add(key)
        if row.fetched_at is not None:
            fetched.append(row.fetched_at)
        observations[(key, asset)][_lower(row.observed_address)].append(row)

    per_asset, per_asset_state, reduction = _reduce_observations(observations)
    plane.per_asset = per_asset
    plane.per_asset_state = per_asset_state

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

    sheet_states: dict[str, int] = defaultdict(int)
    for key in sorted(set(plane.per_asset) | set(plane.per_asset_state)):
        sheet_states[plane.sheet_state(key)] += 1
    if reduction.get(f"assets_{ASSET_BELOW_RESOLUTION}"):
        plane.annotations.append(
            {
                "fact": "priced readings at the storage column's resolution floor are NOT proven zeros",
                "assets": reduction[f"assets_{ASSET_BELOW_RESOLUTION}"],
                "entities": sheet_states[SHEET_BELOW_RESOLUTION],
                "note": (
                    "usd_value is numeric(20,2), so a $0.0035 holding stores as 0.00. Such a "
                    "reading answers 'below half a cent', never 'holds nothing', and an entity "
                    "whose every priced reading is one has NO determined total. Only a "
                    "proven-zero QUANTITY witnesses an empty sheet"
                ),
                "proven_zero_quantity_assets": reduction.get(f"assets_{ASSET_PROVEN_ZERO}", 0),
                "proven_zero_arm_exercised": bool(reduction.get(f"assets_{ASSET_PROVEN_ZERO}")),
            }
        )

    plane.contract_entities = {plane.canonical(key) for key in plane.contract_entities}
    plane.provenance = {
        "entity_key": "effective_functions.deployment_address -> contracts.address, chain-scoped",
        "contract_entities": len(plane.contract_entities),
        "reduction": (
            "latest observation per (entity, asset, observed account); SUM across DISTINCT observed accounts"
        ),
        "observation_reduction": reduction,
        "observation_reduction_reading": (
            "two readings of ONE account are one holding read twice, so the later one is the "
            "answer and MAX would publish a stale high-water mark; two readings of TWO accounts "
            "are two holdings and the entity holds their sum. height_witnessed_accounts were "
            "ordered by block_number; write_order_accounts had no recorded read height (ERC-20 "
            "rows are never height-pinned by construction) and fell back to insert order, which "
            "is a fact about this database and not about the chain"
        ),
        "sheet_states": dict(sorted(sheet_states.items())),
        "sheet_states_reading": (
            "priced = a determined non-zero reading, so the total is a floor; "
            "priced_below_resolution = every price that answered landed on the numeric(20,2) "
            "floor and the total is NOT a number; unpriced = no price answered; proven_empty = "
            "every quantity proven zero, the only state in which 0.00 is a number; no_rows = "
            "nothing observed"
        ),
        # The fold's own exposure denominator, published rather than left to be
        # back-solved from grade_exposure — which is undefined whenever the grade
        # is withheld. An empty priced sheet is not_determined, never a zero.
        "tracked_total_usd": plane.tracked_total if plane.per_asset else None,
        "tracked_total_usd_reading": (
            "latest observation per (entity, asset, observed account), implementation folded "
            "onto its proxy; entities with no determined total contribute nothing and are not "
            "read as 0, so this is a floor. null = no priced entity in the perimeter"
        ),
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


def load_role_holder_floors(session: Session, protocol_id: int) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Proven holder floors per (chain, registry, role hash), protocol-scoped.

    ``holders`` is a LOWER BOUND and ``len(holders)`` is never a count; the floor
    may raise breadth concern and may never lower it. ``holder_set_exhaustive``
    is always ``not_determined``.

    Scoped to the registries THIS protocol's own resolution names — the
    ``authority``/``registry`` of a ``function_principals`` trace step, which is
    the only key the consumer ever looks a floor up by. ``role_holder_planes`` is
    keyed by ``(chain_id, registry_address, role_hash)`` with no protocol column,
    so an unscoped read makes this plane's population a function of which OTHER
    protocols have been analysed: the same protocol scored twice would carry
    different floors, which is a purity break (inv. 11) before it is anything
    else. Scoping loses no floor the fold could have consumed, because a registry
    no trace names has no binding to join to.
    """
    from db.models import Contract, EffectiveFunction, FunctionPrincipal, RoleHolderPlane

    named: set[tuple[str, str]] = set()
    for details, chain in (
        session.query(FunctionPrincipal.details, Contract.chain)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        for step in (details or {}).get("trace") or []:
            if not isinstance(step, dict):
                continue
            registry = _lower(step.get("authority") or step.get("registry"))
            if registry:
                named.add((coalesce_chain(chain), registry))
    if not named:
        return {}

    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    rows = (
        session.query(RoleHolderPlane)
        .filter(sql_func.lower(RoleHolderPlane.registry_address).in_(sorted({address for _, address in named})))
        .order_by(RoleHolderPlane.chain_id, RoleHolderPlane.registry_address, RoleHolderPlane.role_hash)
        .all()
    )
    for row in rows:
        chain = _chain_name(row.chain_id)
        if chain is None or (chain, _lower(row.registry_address)) not in named:
            continue
        if not isinstance(row.holders, list) or not row.holders:
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


# What an edge's label is allowed to say. A ``role_principal`` label carries the
# role numbers the principal holds ("roles 12", "roles 14,16") or, on 55 of 285,
# the bare relation restatement "role principal" and no role at all. Most other
# labels name a state variable ("owner", "hook", "_roles"), but not all of them
# do: ``controller_value_unattributed`` carries dotted access paths
# ("accountantState.payoutAddress", "fee.treasury"), ``safe_owner`` carries the
# constant "safe owner", and ``capability_principal`` carries no label. Anything
# that is not a role set and not a single identifier is ``not_determined`` — the
# parser earns the state-variable reading rather than assuming it. No label in
# any corpus carries a selector, so an edge never names the function it licenses
# — that join lives in function_principals, not here.
SCOPE_ROLES = "roles"
SCOPE_STATE_VAR = "state_var"
SCOPE_NOT_DETERMINED = "not_determined"

# What produced an edge. ``contracts.admin`` is a column, not a graph row: it
# carries no relation, no label and no id, so it is named by its origin rather
# than given an invented relation.
EDGE_WITNESS_CONTROL_GRAPH = "control_graph_edges"
EDGE_WITNESS_ADMIN_COLUMN = "contracts.admin"

_ROLES_LABEL = re.compile(r"^roles\s+(\d+(?:\s*,\s*\d+)*)$")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass(frozen=True)
class EdgeScope:
    """What an edge's label says its authority is scoped TO.

    Three-valued by construction. A label that names neither a role set nor a
    state variable — the 55 ``role principal`` edges that restate their own
    relation and name no role — is ``not_determined``, never an empty scope: an
    empty scope reads as "licenses nothing", and these edges license something
    nobody wrote down.
    """

    kind: str
    roles: tuple[int, ...] = ()
    state_var: str | None = None
    label: str | None = None

    @property
    def is_determined(self) -> bool:
        return self.kind != SCOPE_NOT_DETERMINED


def parse_edge_scope(label: str | None, relation: str | None = None) -> EdgeScope:
    """The scope an edge label proves, or ``not_determined``."""
    text = str(label or "").strip()
    if not text:
        return EdgeScope(SCOPE_NOT_DETERMINED)
    match = _ROLES_LABEL.match(text)
    if match:
        return EdgeScope(SCOPE_ROLES, roles=tuple(sorted({int(n) for n in match.group(1).split(",")})), label=text)
    # A label that only restates its own relation names nothing the relation did
    # not already say. The multi-word restatements measured today ("role
    # principal", "safe owner") would reach not_determined through the
    # identifier check below anyway; this branch is what decides the SINGLE-TOKEN
    # case, where "controller_value" on a controller_value edge would otherwise
    # be read as a state variable of that name — a variable no source declares.
    if relation and text.replace(" ", "_").lower() == relation.lower():
        return EdgeScope(SCOPE_NOT_DETERMINED, label=text)
    if _IDENTIFIER.match(text):
        return EdgeScope(SCOPE_STATE_VAR, state_var=text, label=text)
    return EdgeScope(SCOPE_NOT_DETERMINED, label=text)


@dataclass(frozen=True)
class ControlEdge:
    """One proven control edge: ``principal`` has authority over ``anchor``.

    Both ends are chain-scoped entity keys. ``relation`` and ``edge_id`` are
    ``None`` for the ``contracts.admin`` column, which is a witness that exists
    in no edge table.
    """

    principal: str
    anchor: str
    relation: str | None
    scope: EdgeScope
    witness: str
    edge_id: int | None = None


REFUSAL_ZERO_PRINCIPAL = "zero_address_principal"
REFUSAL_ZERO_ANCHOR = "zero_address_anchor"


@dataclass(frozen=True)
class RefusedEdge:
    """An edge the closure declined to admit, and the rule that declined it."""

    rule: str
    principal: str
    anchor: str
    relation: str | None
    witness: str
    edge_id: int | None = None


@dataclass(frozen=True)
class RenouncedAuthority:
    """An authority slot proven EMPTY: the anchor's ``label`` holds ``0x0``.

    An earned negative, not a missing edge and not a refused one. For an
    ownership slot this is renunciation; for a configuration pointer it is a
    reference nobody set. Either way the slot names no principal at the observed
    height, which is a resolved constraint — the mirror of the whole defect class
    where a proven fact is discarded because the loader had no shape for it.

    Counted apart from the refusals it coincides with: "we refused to walk an
    edge to the burn address" and "this authority is proven to be held by nobody"
    are different facts and only the second is evidence about the protocol.
    """

    anchor: str
    relation: str | None
    scope: EdgeScope
    witness: str
    edge_id: int | None = None


@dataclass
class ControlClosure:
    """The protocol's control edges, indexed by principal.

    Every edge carries the relation and scope it was proven under, so a walk can
    ask what an edge licenses rather than only whether it exists.
    ``controlled_by`` is the adjacency view — the whole answer this plane used to
    return, now derived from the edges rather than standing in for them.

    ``refusals`` and ``renounced`` are what the loader declined to admit and what
    it read as a proven-absent authority; both are published counts rather than
    silent drops, on the ``5b5db0c4`` template where every admission rule states
    where it fired.
    """

    edges: tuple[ControlEdge, ...] = ()
    refusals: tuple[RefusedEdge, ...] = ()
    renounced: tuple[RenouncedAuthority, ...] = ()
    _out: dict[str, tuple[ControlEdge, ...]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        grouped: dict[str, list[ControlEdge]] = defaultdict(list)
        for edge in self.edges:
            grouped[edge.principal].append(edge)
        self._out = {principal: tuple(rows) for principal, rows in sorted(grouped.items())}

    def principals(self) -> tuple[str, ...]:
        """Every entity with at least one outbound control edge, ordered."""
        return tuple(self._out)

    def edges_from(self, principal: str) -> tuple[ControlEdge, ...]:
        return self._out.get(principal, ())

    def controlled_by(self, principal: str) -> tuple[str, ...]:
        """The distinct entities ``principal`` is a proven controller of."""
        return tuple(sorted({edge.anchor for edge in self.edges_from(principal)}))

    def refusal_counts(self) -> dict[str, int]:
        """Edges refused, per admission rule. A rule that never fired reports 0."""
        counts = {REFUSAL_ZERO_PRINCIPAL: 0, REFUSAL_ZERO_ANCHOR: 0}
        for refusal in self.refusals:
            counts[refusal.rule] = counts.get(refusal.rule, 0) + 1
        return dict(sorted(counts.items()))

    def renounced_counts(self) -> dict[str, int]:
        """The earned negative, counted by edge and by the anchor it frees."""
        return {
            "authority_slots": len(self.renounced),
            "anchors": len({row.anchor for row in self.renounced}),
        }


def _is_zero_key(key: str) -> bool:
    return key.endswith("::" + ZERO_ADDRESS)


def load_control_closure(session: Session, protocol_id: int) -> ControlClosure:
    """The proven control edges: ``edges_from(X)`` is what X controls.

    Chain-scoped on both ends — an edge is only ever within one chain's graph,
    and keying it unscoped would let one chain's twin inherit the other's reach.

    Two admission rules run here, each publishing its own count. The zero address
    is refused at BOTH ends: it is a burn sentinel, not an assessable entity
    (``msg.sender != 0x0``), and admitting it as a principal makes it the single
    largest control hub in the graph — every anchor that ever renounced an
    authority, folded into one closure that no witness seeds. And a
    ``controller_value`` edge pointing AT it is read as a renounced authority,
    an earned negative, rather than thrown away with the refusal.
    """
    from db.models import Contract, ControlGraphEdge

    edges: list[ControlEdge] = []
    refusals: list[RefusedEdge] = []
    renounced: list[RenouncedAuthority] = []

    def admit(candidate: ControlEdge) -> None:
        zero_principal = _is_zero_key(candidate.principal)
        if zero_principal and candidate.relation == "controller_value":
            renounced.append(
                RenouncedAuthority(
                    anchor=candidate.anchor,
                    relation=candidate.relation,
                    scope=candidate.scope,
                    witness=candidate.witness,
                    edge_id=candidate.edge_id,
                )
            )
        if zero_principal or _is_zero_key(candidate.anchor):
            refusals.append(
                RefusedEdge(
                    rule=REFUSAL_ZERO_PRINCIPAL if zero_principal else REFUSAL_ZERO_ANCHOR,
                    principal=candidate.principal,
                    anchor=candidate.anchor,
                    relation=candidate.relation,
                    witness=candidate.witness,
                    edge_id=candidate.edge_id,
                )
            )
            return
        edges.append(candidate)

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
        admit(
            ControlEdge(
                principal=entity_key(chain, target),
                anchor=entity_key(chain, source),
                relation=edge.relation,
                scope=parse_edge_scope(edge.label, edge.relation),
                witness=EDGE_WITNESS_CONTROL_GRAPH,
                edge_id=edge.id,
            )
        )
    for contract in session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all():
        if contract.admin:
            chain = coalesce_chain(contract.chain)
            admit(
                ControlEdge(
                    principal=entity_key(chain, contract.admin),
                    anchor=entity_key(chain, contract.address),
                    relation=None,
                    scope=EdgeScope(SCOPE_NOT_DETERMINED),
                    witness=EDGE_WITNESS_ADMIN_COLUMN,
                )
            )
    return ControlClosure(edges=tuple(edges), refusals=tuple(refusals), renounced=tuple(renounced))


def load_proven_eoa_entities(session: Session, protocol_id: int) -> set[str]:
    """Entity keys proven codeless: ``resolved_type == 'eoa'`` is only ever
    written after an empty ``eth_getCode`` (an RPC failure classifies as
    ``contract`` and is not cached), so membership here is an earned witness,
    never an inference from a name or a missing row.
    """
    from db.models import Contract, ControlGraphNode

    rows = (
        session.query(ControlGraphNode.address, Contract.chain)
        .join(Contract, Contract.id == ControlGraphNode.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphNode.resolved_type == "eoa")
        .order_by(ControlGraphNode.id)
        .all()
    )
    return {entity_key(chain, address) for address, chain in rows}


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
    from db.models import Contract, ControlGraphEdge

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
    return {
        "relations": relations,
        "edges_excluded_total": sum(entry["edges"] for entry in relations.values()),
        "consumed": sorted(CONTROL_RELATIONS),
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
    are computed here, over the same MAX-per-(entity, asset) reduction with the
    implementation folded onto its proxy that the fold's exposure uses — a
    consumer joining these counts to a value plane of its own would re-introduce
    the double count that reduction exists to remove.
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
    "ASSET_BELOW_RESOLUTION",
    "ASSET_PRICED",
    "ASSET_PROVEN_ZERO",
    "ASSET_UNPRICED",
    "CONTROL_RELATIONS",
    "EDGE_WITNESS_ADMIN_COLUMN",
    "EDGE_WITNESS_CONTROL_GRAPH",
    "REFUSAL_ZERO_ANCHOR",
    "REFUSAL_ZERO_PRINCIPAL",
    "SCOPE_NOT_DETERMINED",
    "SCOPE_ROLES",
    "SCOPE_STATE_VAR",
    "SHEET_BELOW_RESOLUTION",
    "SHEET_NOT_DETERMINED",
    "SHEET_NO_ROWS",
    "SHEET_PRICED",
    "SHEET_PROVEN_EMPTY",
    "SHEET_UNPRICED",
    "UNCONSUMED_REACH_REASONS",
    "ZERO_ADDRESS",
    "ControlClosure",
    "ControlEdge",
    "EdgeScope",
    "PrincipalFacts",
    "RefusedEdge",
    "RenouncedAuthority",
    "ValuePlane",
    "load_audit_posture",
    "load_control_closure",
    "load_ledgers",
    "load_principal_plane",
    "load_proven_eoa_entities",
    "load_role_holder_floors",
    "load_upgrade_provenance",
    "load_value_plane",
    "native_value_state",
    "parse_edge_scope",
    "perimeter_state",
    "plane_row_counts",
]
