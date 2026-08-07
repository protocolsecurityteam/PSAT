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
    # Implementation keys TWO proxies share. There is no proxy to fold them onto
    # — pinning one is a coin toss that charges the loser's sheet — so they are
    # named here and aliased nowhere.
    alias_ambiguous: set[str] = field(default_factory=set)
    unpriced_positions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def canonical(self, key: str) -> str:
        """An implementation's key folds onto the proxy that deploys it.

        Resolved to a FIXED POINT at load: ``J -> I`` beside ``I -> P`` answers
        ``P`` here and not ``I``, so a two-step alias chain cannot orphan J's
        balances at a key nothing else folds onto while P is counted twice.
        A key in ``alias_ambiguous`` folds onto nothing — two proxies share that
        implementation and neither owns it.
        """
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

# Every counter the reduction publishes, so a rule that never fired reports a
# named zero instead of an absence a consumer would have to read as either.
_REDUCTION_COUNTERS = (
    "buckets",
    "single_reading_accounts",
    "multi_observation_accounts",
    "height_witnessed_accounts",
    "write_order_accounts",
    "write_order_decided_accounts",
    "write_order_disagreeing_accounts",
    "multi_account_buckets",
    "unwitnessed_account_buckets",
    "unpriced_supersession_accounts",
    "stale_high_water_marks_dropped",
)


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

    Every counter this returns is published whether or not it fired: a rule that
    reports nothing where it never applied cannot be told apart from one that was
    never wired up.
    """
    per_asset: dict[str, dict[str, float]] = defaultdict(dict)
    per_asset_state: dict[str, dict[str, str]] = defaultdict(dict)
    counters: dict[str, int] = dict.fromkeys(_REDUCTION_COUNTERS, 0)
    for state in (ASSET_PRICED, ASSET_BELOW_RESOLUTION, ASSET_PROVEN_ZERO, ASSET_UNPRICED):
        counters[f"assets_{state}"] = 0
    stale_usd = 0.0
    write_order_selected_usd = 0.0
    write_order_spread_usd = 0.0

    for (key, asset), accounts in sorted(observations.items()):
        counters["buckets"] += 1
        readings: list[tuple[float | None, str]] = []
        for account in sorted(accounts):
            rows = accounts[account]
            competing = len(rows) > 1
            counters["multi_observation_accounts" if competing else "single_reading_accounts"] += 1
            row, height_witnessed = _latest_observation(rows)
            counters["height_witnessed_accounts" if height_witnessed else "write_order_accounts"] += 1
            readings.append(_asset_reading(row))
            priced = [value for value in (_float(candidate.usd_value) for candidate in rows) if value is not None]
            current = _float(row.usd_value)
            if competing and not height_witnessed:
                # The fiat, sized: how many readings write order actually DECIDED,
                # how many of those it decided between figures that differ, and
                # how many dollars it selected. An account whose competing
                # readings agree is not evidence of anything the ordering did.
                counters["write_order_decided_accounts"] += 1
                if len(set(priced)) > 1:
                    counters["write_order_disagreeing_accounts"] += 1
                    write_order_spread_usd += max(priced) - min(priced)
                    if current is not None:
                        write_order_selected_usd += current
            if priced and current is None:
                # The current reading answers no price while an earlier one did:
                # a determined value disappears, and the sheet is not_determined
                # by the same rule that would have published it.
                counters["unpriced_supersession_accounts"] += 1
            highest = max(priced, default=None)
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
    reduction["write_order_selected_usd"] = round(write_order_selected_usd, 2)
    reduction["write_order_spread_usd"] = round(write_order_spread_usd, 2)
    return (
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset.items())},
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset_state.items())},
        reduction,
    )


class AliasCycleError(ValueError):
    """The implementation alias map contains a cycle. Loud, never resolved."""


def _alias_fixed_point(alias: dict[str, str]) -> dict[str, str]:
    """Follow ``J -> I -> P`` to ``J -> P``, and refuse a cycle out loud.

    A single-level lookup answers ``I`` for J, so J's balances fold onto a key
    that itself folds elsewhere: J is orphaned from the entity that ends up
    holding it and P is counted once for itself and once for I. A cycle is not a
    fold at all — it says two contracts each implement the other — so it raises
    rather than picking a member, which would publish a canonical entity chosen
    by iteration order.
    """
    out: dict[str, str] = {}
    for key in sorted(alias):
        seen = [key]
        current = alias[key]
        while current in alias and alias[current] != current:
            if current in seen:
                raise AliasCycleError("implementation alias cycle: " + " -> ".join([*seen, current]))
            seen.append(current)
            current = alias[current]
        out[key] = current
    return out


def load_value_plane(session: Session, protocol_id: int) -> ValuePlane:
    from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest, RestakingPositionLatest
    from services.monitoring.balance_reads import native_balance_fact

    plane = ValuePlane()
    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    chain_of: dict[int, str] = {}
    address_of: dict[int, str] = {}
    impl_to_proxy: dict[str, str] = {}
    impl_proxies: dict[str, set[str]] = defaultdict(set)
    for contract in contracts:
        chain = coalesce_chain(contract.chain)
        chain_of[contract.id] = chain
        address_of[contract.id] = _lower(contract.address)
        plane.contract_entities.add(entity_key(chain, contract.address))
        if not contract.implementation:
            continue
        impl_key = entity_key(chain, contract.implementation)
        proxy_key = entity_key(chain, contract.address)
        impl_proxies[impl_key].add(proxy_key)
        impl_to_proxy[impl_key] = proxy_key
    # Two proxies sharing one implementation. Pinning either of them — by
    # ``min``, by ``contracts.id`` order, by anything — charges a finding that
    # reaches only proxy B's implementation with proxy A's whole balance sheet,
    # publishes A as an entity nothing reached, and spends A's exposure budget.
    # The implementation is not a fold of either proxy, so it folds onto
    # NEITHER: it keeps its own key and the collision is published.
    ambiguous = {impl for impl, proxies in impl_proxies.items() if len(proxies) > 1}
    shared_impl = [{"implementation": impl, "proxies": sorted(impl_proxies[impl])} for impl in sorted(ambiguous)]
    for impl in ambiguous:
        impl_to_proxy.pop(impl, None)
    plane.alias = _alias_fixed_point(impl_to_proxy)
    plane.alias_ambiguous = ambiguous

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
    # so its positions cannot enter the band arithmetic. They keep a MAX-per-node
    # fold of their own — this plane records no observation height to order by —
    # and are published as unpriced quantities.
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

    # Every state, including the ones no entity is in: an omitted state and a
    # state with no entities read the same way to a consumer, and only one of
    # them is a fact about the protocol.
    sheet_states: dict[str, int] = dict.fromkeys(
        (SHEET_PRICED, SHEET_BELOW_RESOLUTION, SHEET_UNPRICED, SHEET_PROVEN_EMPTY, SHEET_NO_ROWS), 0
    )
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
            "is a fact about this database and not about the chain. write_order_accounts counts "
            "the ordering BASIS and includes single_reading_accounts, where nothing was ordered; "
            "write_order_decided_accounts is the subset the fallback actually decided, of which "
            "write_order_disagreeing_accounts decided between figures that DIFFER. "
            "write_order_selected_usd is the dollars those decisions selected and "
            "write_order_spread_usd the max-minus-min they were selected from — together the "
            "size of the fiat, not a claim that the selected figure is wrong"
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
        "shared_implementation_aliases_refused": len(shared_impl),
        "shared_implementation_reading": (
            "an implementation two proxies share folds onto NEITHER: it keeps its own entity "
            "key, so a reach that lands on it is charged that key's own sheet and never the "
            "sheet of whichever proxy an arbitrary pin happened to select. A zero here is the "
            "proven 'no implementation is shared', not an unasked question"
        ),
        "implementation_alias_fixed_point": (
            "resolved transitively, so J->I beside I->P answers P for J; a cycle raises rather than selecting a member"
        ),
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
# ``contracts.beacon`` is the same kind of witness as ``contracts.admin`` — a
# column populated by the same slot read, present in no edge table — and it
# carries its own name rather than borrowing admin's, because a consumer that
# wants to know which witness produced a hop must be able to tell them apart.
# Consumers branch on THIS value; ``relation is None`` is a property both share
# and is not a witness.
EDGE_WITNESS_BEACON_COLUMN = "contracts.beacon"

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


ROLE_SCOPED_RELATIONS = ("role_principal",)


def parse_edge_scope(label: str | None, relation: str | None = None) -> EdgeScope:
    """The scope an edge label proves, or ``not_determined``.

    The relation decides which readings are AVAILABLE, not which one wins. On a
    ``role_principal`` edge the only positive answer is a role set: the relation
    is the assertion "this principal holds a role", so a label that names no role
    has not named a state variable either, and reading a bare identifier there as
    one fabricated a variable (``state_var="roles"`` on the literal label
    ``roles``) that no source declares and no consumer could check.

    There is deliberately NO relation-restatement branch. One existed to stop a
    single-token label equal to its own relation ("controller_value" on a
    ``controller_value`` edge) from being read as a variable of that name. It
    decided nothing: DB-wide the only labels equal to their relation are the
    multi-word "role principal" and "safe owner", which fail the identifier check
    on their own, and no single-token case exists. What it did carry was an
    inversion hazard — a relation named after a real getter (``authority``) would
    have suppressed the 100 genuine ``authority`` state-var labels the same day
    it was introduced, silently, with no count anywhere. A rule that decides
    nothing and can invert is deleted rather than documented; the role case it
    was covering is now decided by the relation gate above, structurally.
    """
    text = str(label or "").strip()
    if not text:
        return EdgeScope(SCOPE_NOT_DETERMINED)
    match = _ROLES_LABEL.match(text)
    if match:
        return EdgeScope(SCOPE_ROLES, roles=tuple(sorted({int(n) for n in match.group(1).split(",")})), label=text)
    if relation in ROLE_SCOPED_RELATIONS:
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
# A beacon or admin column that names the contract itself. The edge would say
# the entity controls itself, which adds no reach and asserts no authority over
# anyone — refused with a count rather than admitted as a self-loop the walk
# silently absorbs.
REFUSAL_SELF_EDGE = "self_referential_column"


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
        counts = {REFUSAL_ZERO_PRINCIPAL: 0, REFUSAL_ZERO_ANCHOR: 0, REFUSAL_SELF_EDGE: 0}
        for refusal in self.refusals:
            counts[refusal.rule] = counts.get(refusal.rule, 0) + 1
        return dict(sorted(counts.items()))

    def renounced_counts(self) -> dict[str, Any]:
        """The earned negative, counted three ways because they differ.

        ``control_graph_edges`` carries one row per witnessed read, so the same
        ``owner`` slot on the same anchor appears many times; publishing the row
        count as a slot count multiplies the earned negative by however often the
        resolver looked. The slot is ``(anchor, label)`` — the anchor's named
        authority — and the edge count is kept beside it rather than replaced,
        since it is the citable population.
        """
        slots = {(row.anchor, row.scope.label) for row in self.renounced}
        by_label: dict[str, int] = {}
        for _, label in slots:
            by_label[str(label)] = by_label.get(str(label), 0) + 1
        return {
            "edges": len(self.renounced),
            "authority_slots": len(slots),
            "anchors": len({row.anchor for row in self.renounced}),
            # An ``owner`` slot holding 0x0 is a renunciation; a ``_pendingOwner``
            # or an ``accessController`` holding it is a pointer nobody ever set.
            # Both are proven-absent authority, and the earned negative is the
            # same shape — but they are different facts about the protocol, and
            # the day one of them moves a number the distinction has to already
            # be in the document rather than be reconstructed from it.
            "authority_slots_by_label": dict(sorted(by_label.items())),
        }


def is_zero_key(key: str) -> bool:
    """The burn sentinel, at either end of an edge or as a reach key.

    One helper for every refusal of it — the closure loader here, the reach keys
    and the walk in ``fold`` — so the rule cannot drift between the plane that
    builds the graph and the fold that walks it.
    """
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

    Two column witnesses join the graph rows. ``contracts.admin`` is the proxy
    admin; ``contracts.beacon`` is the beacon whose implementation slot every
    proxy pointing at it follows — the broadest code-control link there is, and
    one the closure carried no representation of at all. Both are populated by
    the same slot read, exist in no edge table, and carry their own witness
    string so a consumer can tell which produced a hop.
    """
    from db.models import Contract, ControlGraphEdge

    edges: list[ControlEdge] = []
    refusals: list[RefusedEdge] = []
    renounced: list[RenouncedAuthority] = []

    def admit(candidate: ControlEdge) -> None:
        zero_principal = is_zero_key(candidate.principal)
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
        # The self-edge rule is scoped to the COLUMN witnesses: a
        # ``contracts.beacon`` naming the proxy itself is a degenerate column
        # read, while a witnessed graph row saying an entity holds authority
        # over itself is a fact this loader has no licence to discard.
        self_column = candidate.principal == candidate.anchor and candidate.relation is None
        if zero_principal or is_zero_key(candidate.anchor) or self_column:
            refusals.append(
                RefusedEdge(
                    rule=(
                        REFUSAL_ZERO_PRINCIPAL
                        if zero_principal
                        else REFUSAL_ZERO_ANCHOR
                        if is_zero_key(candidate.anchor)
                        else REFUSAL_SELF_EDGE
                    ),
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
        chain = coalesce_chain(contract.chain)
        for column, witness in (
            (contract.admin, EDGE_WITNESS_ADMIN_COLUMN),
            (contract.beacon, EDGE_WITNESS_BEACON_COLUMN),
        ):
            if not column:
                continue
            admit(
                ControlEdge(
                    principal=entity_key(chain, column),
                    anchor=entity_key(chain, contract.address),
                    relation=None,
                    scope=EdgeScope(SCOPE_NOT_DETERMINED),
                    witness=witness,
                )
            )
    return ControlClosure(edges=tuple(edges), refusals=tuple(refusals), renounced=tuple(renounced))


# --- what a destination's own conditions say about who may call it -----------
#
# A control edge proves AUTHORITY over an entity. It does not prove that the
# entity's own code will accept the controlled node as caller: a destination may
# pin its caller to itself, and no authority relation makes one address another.
# ``effective_functions.conditions`` carries those guards verbatim; the fold read
# none of them, so every hop walked as if the destination had no opinion.
#
# Only ONE shape is recognised as a proven disproof, and it is recognised from
# the verbatim text: a caller-or-initiator identity compared against
# ``address(this)``. Everything else — a balance check, a business predicate, an
# authorization call whose passing is exactly what the control edge witnesses —
# bears on the caller not at all and is not read as one. A recogniser that
# guessed more would turn every unparsed predicate into a refusal and delete a
# proven authority relation on the strength of a string nobody analysed.
HOP_WALKED = "walked"
HOP_NOT_DETERMINED = "not_determined"

# Whose identity the guard pins. ``msg.sender`` is the caller itself; the named
# parameters are the caller as the destination's own callee convention passes it
# on (``initiator`` in a solver callback), which is the same question one frame
# out.
#
# The recogniser is deliberately BROAD on two axes, and both are safe in exactly
# one direction:
#
#   comparator  ``!=`` and ``==`` are both read as a pin. The stored
#               ``description`` is a verbatim predicate with no polarity: the
#               same text is a require-condition in one function and a
#               revert-condition in another, so which comparator means "the
#               caller must be the destination" is not recoverable from it.
#   term        ``sender``/``caller``/``initiator`` (with or without a leading
#               underscore) are read as the caller. A parameter so named is the
#               caller under every callee convention this corpus uses, but the
#               name is the whole evidence — a parameter named ``initiator`` that
#               carried something else would be read as a caller pin here.
#
# Both over-reads land on the same side: a recognised pin only ever moves a hop
# from walked to ``not_determined``. Nothing in this module can turn a pin into a
# proven-clear, so breadth costs withheld reach and never mints reach. The
# reverse error — a pin this regex misses — is the one that would over-claim, and
# it is why the shape is not narrowed further. ``(?<![\w$])`` keeps the terms
# whole, so ``spender``/``resender`` are not caller terms.
_CALLER_TERM = r"(?:msg\.sender|_?sender|_?caller|_?initiator)"
_SELF_PIN = re.compile(
    rf"(?<![\w$])(?:{_CALLER_TERM}\s*[!=]=\s*address\(this\)|address\(this\)\s*[!=]=\s*{_CALLER_TERM}(?![\w$]))"
)

SURFACE_FUNCTION_PRINCIPAL = "function_principal_witness"
SURFACE_DESTINATION_FUNCTIONS = "destination_functions"
SURFACE_NONE = "destination_functions_not_analysed"

# On what a walked hop was walked. "No condition disproved the caller" is three
# different facts, and only the first of them is a read of any condition:
#
#   FULLY          every function consulted at the destination had its
#                  conditions extracted, so the read is complete: a guard was
#                  there to find on all of them and was found on none.
#   PARTLY         at least one permitting function had its conditions
#                  extracted and at least one consulted function did not. A
#                  guard was found on none, but the surface the answer rests on
#                  is not the surface that was consulted.
#   UNANALYSED     every function that permits the caller has ``conditions``
#                  NULL — the extraction never ran there, so "no guard" is a
#                  coverage gap wearing the shape of a clean read.
#   NO_FUNCTION    the destination has no analysed function at all; nothing was
#                  consulted, and the hop stands on the edge alone.
#
# The hop is walked in all three (refusing on an absence would let a coverage
# gap overturn a proven authority relation), so the distinction is a DISCLOSURE
# and not a bound — but a consumer cannot tell a checked hop from an unchecked
# one unless the counts are published apart.
WALKED_ON_ANALYSED_FULLY = "walked_on_fully_analysed_conditions"
WALKED_ON_ANALYSED_PARTLY = "walked_on_partly_analysed_conditions"
WALKED_ON_UNANALYSED = "walked_on_unanalysed_conditions"
WALKED_NO_FUNCTION = "walked_with_no_analysed_function"
WALKED_COVERAGE = (
    WALKED_ON_ANALYSED_FULLY,
    WALKED_ON_ANALYSED_PARTLY,
    WALKED_ON_UNANALYSED,
    WALKED_NO_FUNCTION,
)


@dataclass(frozen=True)
class DestinationFunction:
    """One function of a destination entity, and the caller guards it carries.

    ``analysed`` separates "conditions were extracted and none pins the caller"
    from "the column holds no array and nothing was extracted". Both reach
    ``caller_pinned_to_self == ()``, and reading the second as the first is the
    absence-as-a-witness move at the coverage level. The discriminator is
    ``isinstance(conditions, list)``, which is what puts a SQL null and the
    jsonb scalar null on the same side as each other and the opposite side from
    an empty array — the three-state this column's own read has to make.
    """

    function_id: int
    name: str
    caller_pinned_to_self: tuple[str, ...] = ()
    analysed: bool = False


@dataclass(frozen=True)
class HopConditions:
    """What the destination's conditions say about one caller reaching it."""

    state: str
    basis: str
    surface: str
    functions_consulted: int
    disproving: tuple[dict[str, Any], ...] = ()
    # For a walked hop, which of the three readings above licensed it. ``None``
    # on a hop that was not walked.
    coverage: str | None = None


@dataclass
class ConditionPlane:
    """``effective_functions.conditions``, indexed for the closure walk.

    ``by_entity`` is every analysed function of an entity. ``licensed`` is the
    narrower and better-evidenced surface: the functions of that entity on which
    a given address is a RESOLVED principal, which is the only positive witness
    this plane has of what one caller may do at one destination.
    """

    by_entity: dict[str, tuple[DestinationFunction, ...]] = field(default_factory=dict)
    licensed: dict[tuple[str, str], tuple[DestinationFunction, ...]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def hop(self, caller: str, destination: str) -> HopConditions:
        """Whether ``destination``'s own guards permit ``caller`` to act there.

        The consulted surface is the function-level witness where one exists and
        the destination's whole analysed function set otherwise. A hop is walked
        when at least one consulted function carries no guard pinning its caller
        to the destination itself; it is ``not_determined`` when every consulted
        function does. It is never published as a proven negative: the principal
        enumeration behind the licensed surface is a documented LOWER bound, so
        "no function we witnessed is callable" is not "no function is".

        A destination with no analysed function at all consults nothing, and
        nothing is not a disproof — the edge remains the witness and the
        shortfall is counted rather than converted into a refusal.

        A walked hop carries WHICH of the three coverage readings licensed it,
        because "no condition disproved this caller" over a function whose
        conditions were never extracted is not the same fact as over one whose
        were.
        """
        if caller == destination:
            return HopConditions(HOP_WALKED, "caller_is_the_destination", SURFACE_NONE, 0, coverage=WALKED_NO_FUNCTION)
        surface = self.licensed.get((destination, caller))
        surface_kind = SURFACE_FUNCTION_PRINCIPAL
        if not surface:
            surface = self.by_entity.get(destination) or ()
            surface_kind = SURFACE_DESTINATION_FUNCTIONS if surface else SURFACE_NONE
        if not surface:
            return HopConditions(
                HOP_WALKED,
                "destination_functions_not_analysed(no caller condition witnessed)",
                SURFACE_NONE,
                0,
                coverage=WALKED_NO_FUNCTION,
            )
        permitted = [fn for fn in surface if not fn.caller_pinned_to_self]
        if permitted:
            analysed = [fn for fn in permitted if fn.analysed]
            consulted_analysed = sum(1 for fn in surface if fn.analysed)
            coverage = WALKED_ON_UNANALYSED
            if analysed:
                coverage = WALKED_ON_ANALYSED_FULLY if consulted_analysed == len(surface) else WALKED_ON_ANALYSED_PARTLY
            return HopConditions(
                HOP_WALKED,
                (
                    f"caller_condition_permits({len(permitted)} of {len(surface)} consulted "
                    f"functions, {len(analysed)} of them with conditions extracted; "
                    f"{consulted_analysed} of {len(surface)} consulted functions analysed)"
                ),
                surface_kind,
                len(surface),
                coverage=coverage,
            )
        return HopConditions(
            HOP_NOT_DETERMINED,
            "caller_pinned_to_the_destination_itself_on_every_consulted_function",
            surface_kind,
            len(surface),
            tuple(
                {"function": fn.name, "function_id": fn.function_id, "conditions": list(fn.caller_pinned_to_self)}
                for fn in surface
            ),
        )


def _caller_self_pins(conditions: Any) -> tuple[str, ...]:
    """The verbatim conditions that pin this function's caller to itself."""
    if not isinstance(conditions, list):
        return ()
    out: list[str] = []
    for entry in conditions:
        text = entry.get("description") if isinstance(entry, dict) else None
        if isinstance(text, str) and _SELF_PIN.search(text):
            out.append(text)
    return tuple(out)


def load_condition_plane(session: Session, protocol_id: int) -> ConditionPlane:
    """The destination-side caller guards the closure walk is bounded by."""
    from db.models import Contract, EffectiveFunction, FunctionPrincipal

    plane = ConditionPlane()
    by_entity: dict[str, list[DestinationFunction]] = defaultdict(list)
    entity_of: dict[int, tuple[str, str]] = {}
    functions = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.function_name,
            EffectiveFunction.conditions,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    pinned_functions = 0
    analysed_functions = 0
    for function_id, name, conditions, deployment, address, chain in functions:
        chain_name = coalesce_chain(chain)
        key = entity_key(chain_name, deployment or address)
        pins = _caller_self_pins(conditions)
        # An ARRAY is an extraction that ran, empty or not. Anything else — a SQL
        # null, the jsonb scalar null a Python ``None`` write stores — is one
        # that never did, and the two are indistinguishable downstream unless
        # they are separated here.
        analysed = isinstance(conditions, list)
        pinned_functions += 1 if pins else 0
        analysed_functions += 1 if analysed else 0
        by_entity[key].append(DestinationFunction(int(function_id), str(name), pins, analysed))
        entity_of[int(function_id)] = (key, chain_name)
    plane.by_entity = {key: tuple(rows) for key, rows in sorted(by_entity.items())}

    licensed: dict[tuple[str, str], list[DestinationFunction]] = defaultdict(list)
    rows = (
        session.query(FunctionPrincipal.function_id, FunctionPrincipal.address)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    by_id = {fn.function_id: fn for rows_ in plane.by_entity.values() for fn in rows_}
    for function_id, address in rows:
        located = entity_of.get(int(function_id))
        if located is None:
            continue
        destination, chain_name = located
        function = by_id.get(int(function_id))
        if function is None:
            continue
        licensed[(destination, entity_key(chain_name, address))].append(function)
    plane.licensed = {key: tuple(rows_) for key, rows_ in sorted(licensed.items())}
    plane.provenance = {
        "functions": len(functions),
        "entities_with_analysed_functions": len(plane.by_entity),
        # The coverage this recogniser actually had. A function whose
        # ``conditions`` column is NULL carries no guard to find, so it can only
        # ever report "nothing disproves this caller" — which is the answer a
        # clean read gives too. Published apart, because a hop walked over
        # nothing but unextracted functions is not a checked hop.
        "functions_with_conditions_extracted": analysed_functions,
        "functions_with_no_conditions_recorded": len(functions) - analysed_functions,
        "functions_pinning_caller_to_self": pinned_functions,
        "caller_licensed_pairs": len(plane.licensed),
        "recognised_shape": (
            "a caller-or-initiator identity compared against address(this), read verbatim from "
            "effective_functions.conditions[].description. No other predicate is read as a "
            "statement about the caller: an authorization call is the gate the control edge "
            "already witnesses, and an unparsed business predicate is not evidence against a "
            "proven authority relation"
        ),
        "recogniser_breadth": (
            "BOTH comparators (!= and ==) count as a pin, because the stored description is a "
            "verbatim predicate carrying no polarity — the same text is a require-condition in "
            "one function and a revert-condition in another. msg.sender and whole-word "
            "sender/caller/initiator (with or without a leading underscore) all count as the "
            "caller, on the name alone. Both over-reads move a hop from walked to "
            "not_determined and NOTHING here can mint a proven-clear, so the breadth costs "
            "withheld reach and never reach"
        ),
        "surface_rule": (
            "the functions of the destination on which the caller is a RESOLVED principal where "
            "such a witness exists, else the destination's whole analysed function set. A "
            "destination with no analysed function consults nothing and the hop stands on the "
            "edge rather than being converted into a refusal. The shortfall that produces is "
            "counted in provenance.reach_bounds.hop_census, which splits every walked hop into "
            "walked_on_fully_analysed_conditions, walked_on_partly_analysed_conditions, "
            "walked_on_unanalysed_conditions and walked_with_no_analysed_function. Only the "
            "first rests on a surface that was read in full; the second found a guard on none "
            "of the functions it could read and could not read all of them; the last two are "
            "hops no condition was ever read for, and they are walked on the edge alone"
        ),
    }
    return plane


# --- what a gate CONFERS -----------------------------------------------------
#
# A control edge proves that an authority relation EXISTS. It does not prove
# that the gate a finding seizes is the authority that relation runs on, and
# until this plane there was nothing to ask: gate control walked every edge whose
# label named a scope at all, which is a label-PRESENCE test wearing a conferral
# test's name. Two witnesses answer it, one per scope kind.
#
#   roles N      The role -> selector join. ``function_principals.details.trace[]``
#                records, per resolved principal, the step that admitted it —
#                ``(step, authority, target, selector, roles)`` — so "role N at
#                target T" resolves to the SELECTORS role N licenses at T. A
#                selector is credited only where ``effective_functions.selector``
#                names a function of T under it: four bytes nobody can name is
#                not a licensed function, and the named function is what a
#                magnitude can later be attributed to. A role that licenses no
#                named function at the destination confers nothing anyone can
#                point at, and the hop is not_determined.
#
#   state_var L  A SAME-KIND BOUND, not a conferral witness. Read exactly:
#                the gate's own ``effective_functions.state_writes`` names the
#                variable IT rewrites, on ITS contract; the edge's label names
#                the authority slot on the DESTINATION's contract. Requiring the
#                two names to match is a name match across two different
#                contracts' storage, and it witnesses no composition step — no
#                row anywhere says that seizing A's ``owner`` lets its holder
#                exercise A's ownership of B. What the match does is REFUSE
#                every hop whose authority is of a different kind from the one
#                the gate is witnessed to seize, which is a bound, and a bound
#                is all it is published as. ownership.transfer is witnessed
#                writing owner/_owner; authority.replace writing authority;
#                roles.grant writing _roles. None is witnessed writing hook,
#                vault, roleRegistry or endpoint, so hops running on those are
#                refused. A same-kind hop is walked as the label-presence test
#                already walked it — this bound removes hops, it adds no
#                evidence to the ones that survive.
#
#                Where the kinds differ the hop is NOT disproved and the row is
#                not the only thing missing: whether the seized gate reaches the
#                other authority turns on the intermediate node's own function
#                surface, and THIS PLANE DOES NOT CONSULT IT. The surface often
#                exists — 0x4df6b733's setUserRole, setRoleCapability and
#                transferOwnership are analysed ``effective_functions`` rows on
#                the reference corpus — so this is a join not performed, not a
#                witness that is missing. The join that would decide it is the
#                intermediate node's own functions (``effective_functions``
#                at A, gated by the authority the capability seizes) against its
#                outbound targets (``effective_functions.sinks`` /
#                ``effect_targets``, and the ``external_call_target`` edges
#                CONTROL_RELATIONS excludes): does a function of A that the
#                seized gate lets its holder call exercise A's authority over B.
#                Until that runs, the hop is not_determined — withheld and
#                published, never walked and never counted as a proven negative.
#
# One residual, named rather than assumed away: the ROLE branch asks only what
# the role licenses at the destination. It does not additionally require the
# seizing capability to be one that governs role assignment, so an
# ``authority.replace`` gate walks a ``roles N`` hop on the join's answer alone.
# That is the same homogeneity question the state-variable branch answers with
# state_writes, and there is no equivalent witness for it — the role edge names a
# role, not the authority slot that grants it. The bound stated here is therefore
# what the role LICENSES, which is the bound a compositional magnitude needs, and
# it is an upper bound on what this gate can exercise.
CONFERRAL_CONFERRED = "conferred"
CONFERRAL_SCOPE_NOT_DETERMINED = "scope_not_determined"
CONFERRAL_ROLE_NOT_LICENSED = "role_licenses_no_named_function_at_the_destination"
CONFERRAL_VARIABLE_NOT_REWRITTEN = "capability_not_witnessed_rewriting_this_variable"
CONFERRAL_WRITES_NOT_EXTRACTED = "capability_state_writes_not_extracted"
CONFERRAL_OUTCOMES = (
    CONFERRAL_CONFERRED,
    CONFERRAL_SCOPE_NOT_DETERMINED,
    CONFERRAL_ROLE_NOT_LICENSED,
    CONFERRAL_VARIABLE_NOT_REWRITTEN,
    CONFERRAL_WRITES_NOT_EXTRACTED,
)

# ``state_writes[].origin``: a write in the function BODY is the function doing
# it. A write attributed to a guard is the modifier's bookkeeping (a reentrancy
# latch, a namespaced-storage pointer read) and is not what the capability
# rewrites, so it is not evidence of the authority the gate seizes.
_WRITE_ORIGIN_BODY = "body"


@dataclass(frozen=True, order=True)
class LicensedFunction:
    """One named function a role licenses at a destination.

    Structured, not a formatted string: the selector is the join key back into
    ``effective_functions`` and the name is for the reader. Publishing
    ``"0x39d6ba32 enter"`` made every consumer re-parse a string this plane had
    already taken apart, and a function name containing a space would have
    broken the parse silently.
    """

    selector: str
    name: str

    def as_json(self) -> dict[str, str]:
        return {"selector": self.selector, "name": self.name}


@dataclass(frozen=True)
class ConferralVerdict:
    """Whether one gate confers one hop, and what it confers there."""

    outcome: str
    licensed: tuple[LicensedFunction, ...] = ()
    basis: str = ""

    @property
    def conferred(self) -> bool:
        return self.outcome == CONFERRAL_CONFERRED


@dataclass(frozen=True)
class GateGrant:
    """One gate-control capability instance, and what its witness says it seizes.

    ``rewrites`` is read from the SPECIFIC function the signal was witnessed on,
    not from the capability's class-wide behaviour: the claim being tested is
    what THIS gate rewrites. ``writes_extracted`` keeps the coverage gap distinct
    from an empty answer — a function whose ``state_writes`` never ran rewrites
    nothing anyone read, which is not the same fact as a function proven to
    rewrite nothing, and both are withheld rather than either being walked.
    """

    capability: str
    rewrites: frozenset[str]
    writes_extracted: bool
    basis: str
    plane: ConferralPlane = field(repr=False, compare=False)

    def confers(self, scope: EdgeScope, destination: str) -> ConferralVerdict:
        if not scope.is_determined:
            return ConferralVerdict(
                CONFERRAL_SCOPE_NOT_DETERMINED,
                basis=(
                    "the edge's label names no role and no state variable, so what this gate "
                    "would confer here is not_determined"
                ),
            )
        if scope.kind == SCOPE_ROLES:
            licensed = self.plane.licensed_functions(destination, scope.roles)
            if not licensed:
                return ConferralVerdict(
                    CONFERRAL_ROLE_NOT_LICENSED,
                    basis=(
                        f"no witnessed trace step licenses role(s) {list(scope.roles)} to a named "
                        f"function of {destination}, so the hop confers nothing that can be named"
                    ),
                )
            return ConferralVerdict(
                CONFERRAL_CONFERRED,
                licensed,
                basis=(
                    f"role(s) {list(scope.roles)} license {len(licensed)} named function(s) at "
                    f"{destination} (function_principals.details.trace[].selector joined to "
                    "effective_functions.selector)"
                ),
            )
        if not self.writes_extracted:
            return ConferralVerdict(CONFERRAL_WRITES_NOT_EXTRACTED, basis=self.basis)
        if scope.state_var not in self.rewrites:
            return ConferralVerdict(
                CONFERRAL_VARIABLE_NOT_REWRITTEN,
                basis=(
                    f"{self.capability} is witnessed rewriting {sorted(self.rewrites)} on its own "
                    f"contract and not '{scope.state_var}', so this hop runs on an authority of a "
                    "different kind from the one the gate seizes. Refused as a same-kind bound; "
                    "whether it composes anyway turns on the intermediate node's function surface, "
                    "which this plane does not consult"
                ),
            )
        return ConferralVerdict(
            CONFERRAL_CONFERRED,
            basis=(
                f"same-kind: {self.capability} is witnessed rewriting a variable named "
                f"'{scope.state_var}' on its own contract, which is the name the hop's authority "
                f"slot carries on the destination's ({self.basis}). A NAME MATCH ACROSS TWO "
                "CONTRACTS' STORAGE, not a witness that seizing one exercises the other — the "
                "composition step is unwitnessed and this bound only removes hops of a different "
                "kind"
            ),
        )


@dataclass
class ConferralPlane:
    """The two conferral witnesses, indexed for the walk.

    ``role_functions`` is the role -> selector join, already narrowed to
    selectors that name a function. ``writes_by_function`` is per-function and is
    what the walk consults; ``writes_by_capability`` is the same evidence rolled
    up to the class and is used ONLY by the census, which has no instance to ask.
    The two are published side by side because the class-wide union is an upper
    bound on the per-function answer, and a reader comparing a census count to a
    finding's walk has to be able to see which one they are looking at.
    """

    role_functions: dict[tuple[str, int], tuple[LicensedFunction, ...]] = field(default_factory=dict)
    writes_by_function: dict[int, frozenset[str]] = field(default_factory=dict)
    writes_by_capability: dict[str, frozenset[str]] = field(default_factory=dict)
    # The recovery key for a signal whose ``function_id`` no longer resolves.
    # Populated only where every function under the key agrees on what it
    # rewrites; a key two functions disagree under is left out, because a
    # recovered answer nobody can attribute to one row is a guess.
    writes_by_deployment_selector: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def licensed_functions(self, destination: str, roles: tuple[int, ...]) -> tuple[LicensedFunction, ...]:
        """The named functions the union of ``roles`` licenses at ``destination``.

        The union is the honest read of a multi-role label: "roles 5,9" is one
        principal holding both, and each licenses what it licenses.
        """
        out: set[LicensedFunction] = set()
        for role in roles:
            out.update(self.role_functions.get((destination, int(role)), ()))
        return tuple(sorted(out))

    def grant_for(
        self, capability: str, function_id: int | None, *, entity: str | None = None, selector: str | None = None
    ) -> GateGrant:
        """What one gate seizes, by its own function where that still resolves.

        ``function_score_signals.function_id`` is ``ON DELETE SET NULL`` against
        ``effective_functions``, and a re-analysis DELETES and reinserts a
        contract's rows — so a persisted signal that outlives one re-analysis
        points at nothing, and this lookup would report every gate as
        "state_writes not extracted" and quietly stop walking hops it walked
        yesterday. The withhold would be counted and its CAUSE would be a stale
        foreign key, indistinguishable from an extraction that never ran.

        So a dangling reference falls back to the signal's own
        ``(deployment entity, selector)`` — the identity the signal carries in
        its own columns and the re-analysis preserves. The fallback is admitted
        only where every function under that key agrees on what it rewrites; a
        key two functions disagree under resolves to nothing, and the grant
        stays unextracted rather than picking one.
        """
        writes = self.writes_by_function.get(function_id) if function_id is not None else None
        if writes is not None:
            return GateGrant(
                capability, writes, True, f"effective_functions.state_writes(function {function_id})", self
            )
        key = (str(entity), _lower(str(selector))) if entity and selector else None
        recovered = self.writes_by_deployment_selector.get(key) if key else None
        if recovered is not None:
            return GateGrant(
                capability,
                recovered,
                True,
                (
                    f"effective_functions.state_writes recovered on (deployment, selector) {key} — "
                    f"function_id {function_id} does not resolve"
                ),
                self,
            )
        return GateGrant(
            capability,
            frozenset(),
            False,
            (
                "effective_functions.state_writes carries no extracted array for this gate: "
                f"function_id {function_id} does not resolve and (deployment, selector) {key} "
                "recovers no single agreed answer, so what this gate rewrites was never read"
            ),
            self,
        )

    def capability_grant(self, capability: str) -> GateGrant:
        """The class-wide grant: the UNION of what every witness of ``capability``
        rewrites anywhere in this protocol. Strictly wider than any one instance's
        grant, so it is a census instrument and never a walk input.
        """
        writes = self.writes_by_capability.get(capability)
        if writes is None:
            return GateGrant(
                capability,
                frozenset(),
                False,
                f"no function carrying {capability} has extracted state_writes in this protocol",
                self,
            )
        return GateGrant(
            capability,
            writes,
            True,
            f"union of effective_functions.state_writes over every {capability} witness in this protocol",
            self,
        )


def load_conferral_plane(session: Session, protocol_id: int) -> ConferralPlane:
    """The role -> selector join and the capability -> rewritten-variable witness."""
    from db.models import Contract, EffectiveFunction, FunctionPrincipal

    named: dict[tuple[str, str], LicensedFunction] = {}
    writes_by_function: dict[int, frozenset[str]] = {}
    writes_by_key: dict[tuple[str, str], set[frozenset[str]]] = defaultdict(set)
    claims_by_function: dict[int, tuple[str, ...]] = {}
    functions = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.function_name,
            EffectiveFunction.selector,
            EffectiveFunction.state_writes,
            EffectiveFunction.claims,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    for function_id, name, selector, state_writes, claims, deployment, address, chain in functions:
        key = entity_key(coalesce_chain(chain), deployment or address)
        token = _lower(str(selector)) if selector else None
        if token:
            named.setdefault((key, token), LicensedFunction(token, str(name)))
        # An ARRAY is an extraction that ran; anything else never did, and the
        # two must not reach the walk as the same empty answer.
        if isinstance(state_writes, list):
            written = frozenset(
                str(entry.get("var"))
                for entry in state_writes
                if isinstance(entry, dict) and entry.get("var") and entry.get("origin") == _WRITE_ORIGIN_BODY
            )
            writes_by_function[int(function_id)] = written
            if token:
                writes_by_key[(key, token)].add(written)
        if isinstance(claims, list):
            claims_by_function[int(function_id)] = tuple(
                str(entry.get("claim_id")) for entry in claims if isinstance(entry, dict) and entry.get("claim_id")
            )

    writes_by_capability: dict[str, set[str]] = defaultdict(set)
    capability_functions: dict[str, int] = defaultdict(int)
    capability_functions_extracted: dict[str, int] = defaultdict(int)
    for function_id, claim_ids in claims_by_function.items():
        for claim_id in set(claim_ids):
            capability_functions[claim_id] += 1
            writes = writes_by_function.get(function_id)
            if writes is None:
                continue
            capability_functions_extracted[claim_id] += 1
            writes_by_capability[claim_id].update(writes)

    role_functions: dict[tuple[str, int], set[LicensedFunction]] = defaultdict(set)
    role_authorities: dict[tuple[str, int], set[str]] = defaultdict(set)
    steps = unnamed_selectors = 0
    principals = (
        session.query(FunctionPrincipal.details, Contract.chain)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    for details, chain in principals:
        trace = (details or {}).get("trace") if isinstance(details, dict) else None
        for step in trace or []:
            if not isinstance(step, dict):
                continue
            selector, target, roles = step.get("selector"), step.get("target"), step.get("roles")
            if not selector or not target or not isinstance(roles, list):
                continue
            steps += 1
            key = entity_key(coalesce_chain(chain), str(target))
            function = named.get((key, _lower(str(selector))))
            if function is None:
                # The step names a selector no analysed function of the target
                # carries. It licenses something, but not something this document
                # can name or later attribute a magnitude to, so it is counted
                # and not credited.
                unnamed_selectors += 1
                continue
            for role in roles:
                try:
                    number = int(role)
                except (TypeError, ValueError):
                    continue
                role_functions[(key, number)].add(function)
                if step.get("authority"):
                    role_authorities[(key, number)].add(_lower(str(step["authority"])))

    recovery = {key: next(iter(rows)) for key, rows in sorted(writes_by_key.items()) if len(rows) == 1}
    plane = ConferralPlane(
        role_functions={key: tuple(sorted(rows)) for key, rows in sorted(role_functions.items())},
        writes_by_function=writes_by_function,
        writes_by_capability={key: frozenset(rows) for key, rows in sorted(writes_by_capability.items())},
        writes_by_deployment_selector=recovery,
    )
    plane.provenance = {
        "role_selector_join": {
            "trace_steps_carrying_a_selector": steps,
            "steps_whose_selector_names_no_analysed_function": unnamed_selectors,
            "role_scopes_resolved": len(plane.role_functions),
            "destinations": len({key[0] for key in plane.role_functions}),
            "role_scopes_resolved_by_more_than_one_authority": sum(
                1 for holders in role_authorities.values() if len(holders) > 1
            ),
            "reading": (
                "a (destination, role) pair resolves to the NAMED functions that role licenses "
                "there: function_principals.details.trace[].selector joined to "
                "effective_functions.selector at the same destination. A step whose selector "
                "names no analysed function of the destination is counted above and credited "
                "nowhere — it licenses something this document cannot name. Role numbers are "
                "per-authority; the join is keyed on (destination, role) because the "
                "destination pins which authority governs it, and the count of pairs resolved "
                "through more than one authority is published so a reader can see whether that "
                "pinning was ambiguous anywhere"
            ),
        },
        "capability_rewrites": {
            "functions_with_state_writes_extracted": len(writes_by_function),
            "functions": len(functions),
            "by_capability": {
                capability: {
                    "rewrites": sorted(writes_by_capability.get(capability, ())),
                    "functions": capability_functions[capability],
                    "functions_with_state_writes_extracted": capability_functions_extracted.get(capability, 0),
                }
                for capability in sorted(capability_functions)
            },
            "reading": (
                "what each capability's own witnesses are observed to REWRITE, from "
                "effective_functions.state_writes with origin=body — a guard-origin write is the "
                "modifier's bookkeeping and not what the capability does. The walk consults the "
                "witnessed function's OWN set, never this union; the union is published because "
                "it is the upper bound the hop census is computed against. This is a SAME-KIND "
                "BOUND and not a conferral witness: the gate's variable is named on its own "
                "contract and the hop's authority slot on the destination's, so requiring the "
                "names to match refuses hops of a different kind and witnesses no composition "
                "step for the ones that survive"
            ),
        },
        "stale_function_reference_recovery": {
            "keys": len(recovery),
            "keys_two_functions_disagree_under": sum(1 for rows in writes_by_key.values() if len(rows) > 1),
            "reading": (
                "function_score_signals.function_id is ON DELETE SET NULL against "
                "effective_functions, and a re-analysis deletes and reinserts a contract's rows, "
                "so a persisted signal that outlives one re-analysis points at nothing. Left "
                "alone that reports every gate as state_writes-not-extracted and silently stops "
                "walking hops it walked yesterday — a withhold that is counted and whose cause is "
                "a stale foreign key. A dangling reference falls back to the signal's own "
                "(deployment entity, selector), which the re-analysis preserves, and only where "
                "every function under that key agrees on what it rewrites"
            ),
        },
    }
    return plane


ACT_AS_WITNESSED = "witnessed"
ACT_AS_NO_CALL_SITE = "no_function_of_the_caller_calls_this_selector"
ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE = "call_site_receiver_is_not_a_state_variable"
ACT_AS_RECEIVER_NOT_READ = "caller_state_variable_never_read_on_chain"
ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS = "caller_state_variable_holds_a_different_address"
ACT_AS_CALL_SITE_IS_PUBLIC = "the_call_site_needs_no_gate"
ACT_AS_CALL_SITE_GATE_NOT_DELEGATED = "call_site_caller_gate_is_not_witnessed_delegated_to_an_authority"
ACT_AS_NO_DESTINATION_ACL = "destination_does_not_accept_this_caller_for_this_selector"
ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE = "destination_access_control_row_names_no_admitting_role"
ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE = "destination_access_control_membership_is_not_enumerable"

# Which of the two witness shapes admitted a step. Published on every step so a
# reader is never left to infer from the basis sentence which evidence was read.
ACT_AS_WITNESS_CALLER_STATE_VARIABLE = "caller_state_variable"
ACT_AS_WITNESS_DESTINATION_ACL = "destination_access_control_list"

# The membership quality a destination-side ACL row must carry to witness
# acceptance: the resolver enumerated the accepted set. A ``lower_bound`` row
# names SOME accepted callers and does not bound the set, so it cannot witness
# that this caller's presence is the whole answer.
_ENUMERATED_MEMBERSHIP = "exact"

# The only principal kind whose acceptance of a caller is an ACL fact: a
# ``controller`` row is the resolver's answer to "who may invoke this function".
# The other kinds answer a different question and are not read here.
_ACCEPTING_PRINCIPAL_TYPE = "controller"

# The method a guard calls when a function's caller set is decided by an
# external authority contract rather than by the function's own code. 748 guard
# sinks on the reference corpus carry it; it is the witness that seizing that
# authority is what opens the function.
_DELEGATED_GUARD_METHOD = "cancall"


@dataclass(frozen=True)
class DestinationAcceptance:
    """One ``function_principals`` row: D's own ACL naming a caller of a selector.

    ``roles`` are the role numbers the resolver walked to reach the caller, and
    is EMPTY when the row reached the caller by some route it did not express as
    a role. Such a row is still indexed: it is the difference between "the
    destination's list does not name this caller" and "it names it, and names no
    role that admits it", and a reader is owed which of the two was found.
    ``membership_quality`` is whether the resolver enumerated the accepted set or
    only bounded it below. ``function_principal_id`` names the row so the
    published basis points at the evidence rather than restating it.
    """

    roles: tuple[int, ...]
    membership_quality: str
    destination_function: str
    function_principal_id: int

    @property
    def enumerated(self) -> bool:
        return self.membership_quality == _ENUMERATED_MEMBERSHIP

    @property
    def strength(self) -> tuple[bool, bool]:
        """How much of the acceptance this row witnesses, for picking between
        two rows that name the same caller at the same selector."""
        return (bool(self.roles), self.enumerated)

    def as_json(self) -> dict[str, Any]:
        return {
            "source": "function_principals",
            "function_principal_id": self.function_principal_id,
            "destination_function": self.destination_function,
            "accepting_roles": list(self.roles),
            "membership_quality": self.membership_quality,
        }


@dataclass(frozen=True)
class ActAsStep:
    """One witnessed "N can be made to call ``selector`` at D" step.

    Every field names a witness, not an inference. ``calling_function`` is the
    function of N whose compiled body carries the call site. ``witness_kind``
    says which of the two admissible shapes proved the step lands at D, and the
    fields of the other shape are ``None``: for
    ``ACT_AS_WITNESS_CALLER_STATE_VARIABLE`` the ``receiver_*`` fields are the
    state variable the receiver binds to and the on-chain read that proved it
    holds D; for ``ACT_AS_WITNESS_DESTINATION_ACL`` the receiver is
    parameter-bound — nothing in N's storage names D, and ``acceptance`` is D's
    own access-control row naming N.
    """

    caller: str
    destination: str
    selector: str
    calling_function: str
    calling_function_openness: str
    witness_kind: str = ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    receiver_variable: str | None = None
    receiver_observed_via: str | None = None
    receiver_block: int | None = None
    acceptance: DestinationAcceptance | None = None

    def _basis(self) -> str:
        if self.witness_kind == ACT_AS_WITNESS_DESTINATION_ACL and self.acceptance is not None:
            return (
                f"{self.calling_function} is a restricted function of {self.caller} whose caller "
                f"gate is witnessed delegated to an authority, and whose body calls "
                f"{self.selector} at an address the CALLER of that function supplies — the "
                f"receiver is parameter-bound, so no state variable of {self.caller} names it. "
                f"{self.destination}'s own access-control list is what names the address from the "
                f"other end: function_principals row {self.acceptance.function_principal_id} on "
                f"{self.acceptance.destination_function} accepts {self.caller} as a caller of "
                f"{self.selector} by role(s) {list(self.acceptance.roles)}, with "
                f"membership_quality '{self.acceptance.membership_quality}'"
            )
        return (
            f"{self.calling_function} is a restricted function of {self.caller} whose body "
            f"calls {self.selector} on its own state variable '{self.receiver_variable}', and "
            f"'{self.receiver_variable}' was read {self.receiver_observed_via} at block "
            f"{self.receiver_block} holding {self.destination}"
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "caller": self.caller,
            "destination": self.destination,
            "selector": self.selector,
            "calling_function": self.calling_function,
            "calling_function_openness": self.calling_function_openness,
            "witness_kind": self.witness_kind,
            "receiver_variable": self.receiver_variable,
            "receiver_observed_via": self.receiver_observed_via,
            "receiver_block": self.receiver_block,
            "destination_acceptance": (self.acceptance.as_json() if self.acceptance is not None else None),
            "basis": self._basis(),
        }


@dataclass(frozen=True)
class ActAsVerdict:
    outcome: str
    step: ActAsStep | None = None

    @property
    def witnessed(self) -> bool:
        return self.outcome == ACT_AS_WITNESSED


# An on-chain read of the caller's own storage. ``eth_call_error`` is excluded:
# it is the record of a read that FAILED, and its resolved_type is 'unknown'.
_READ_OBSERVATIONS = frozenset({"eth_call", "eth_call_impl_fallback", "beacon_owner", "event_log"})


@dataclass
class ActAsPlane:
    """Whether seizing a node's gate witnesses making that node ACT somewhere.

    Membership in a gate's licensed set answers "may N call ``s`` at D". It does
    not answer "can the principal make N do it" — the question a composed
    magnitude turns on. Seizing an authority POINTER on N buys the ability to
    call N's own restricted functions; it buys a call at D only if one of those
    functions is witnessed calling D. Pricing the hop on the licence alone is
    the membership-as-capability error one level up from the sheet-as-reach one.

    The CALL SITE is always required — ``effective_functions.sinks``, an
    ``external_call`` entry carrying the called ``selector`` and the receiver it
    is bound to, compiled from N's own verified source. What names the ADDRESS
    that call site lands on has two admissible shapes, and a step is witnessed
    under either:

    * the CALLER'S RECEIVER — ``controller_values``, the on-chain read
      (``eth_call`` at a recorded block) of the state variable that receiver is
      bound to. The row says N's ``vault`` IS D.
    * the DESTINATION'S ACL — ``function_principals``, D's own resolved
      access-control list naming N as an accepted caller of that selector by an
      enumerated role. This is the only shape available when the receiver is a
      PARAMETER: the callee is chosen at call time, so the binding cannot live
      in N's storage, and D's own list of accepted callers is what bounds which
      choices D honours. It is admitted only when the row names a role AND the
      membership is ``exact`` — a row naming no role reached N by a route it did
      not state, and a ``lower_bound`` membership names some accepted callers
      without bounding the set. Each is refused under its own reason, because
      "the list does not name N", "it names N and no role that admits it" and
      "it names a role and does not bound the set" are three different findings
      and collapsing them publishes one of them as the others.

    A parameter-bound call site with NEITHER witness is REFUSED, not credited:
    whoever calls N chooses that address and no evidence at either end names it,
    so the code witnesses a call at an address nobody named. It is a plausible
    path and it is not a witnessed one, and the difference is the whole
    discipline.

    The destination-ACL shape is a MAGNITUDE admission only. It says D accepts a
    call from N; it says nothing about which entities the principal reaches, and
    it is never consulted by the closure walk. It also does not witness that the
    call SUCCEEDS: the same ``function_principals`` row carries D's own business
    preconditions and this plane consults none of them.

    The calling function must itself be ``restricted`` AND its caller gate must
    be witnessed DELEGATED — a guard-origin sink calling ``canCall`` on an
    authority contract. Restricted alone is not enough and the corpus proves it:
    ``ManagerWithMerkleVerification.receiveFlashLoan`` is restricted, calls
    ``vault.manage``, and is gated by ``msg.sender == balancerVault`` — its
    ``authority_roles`` is the proven-empty ``[]`` and it carries no ``canCall``
    guard. Seizing the manager's authority pointer opens
    ``manageVaultWithMerkleVerification`` and does not open that one, and without
    the guard witness the two are indistinguishable. A public call site is
    refused for the opposite reason: it needs no gate at all, so the dollars it
    moves belong to its own finding and not to a gate that conferred nothing.

    What this plane still does NOT witness is that the authority the guard
    consults is the same one the finding's gate seizes: the ``canCall`` receiver
    is a local, and no read pins it. The same-kind bound (``GateGrant``) is what
    stands in for it, and it is a bound, not a witness — recorded here so the
    residual is visible where the composition is built rather than only in a
    review note.
    """

    # (caller entity, selector) -> ((calling function, openness, receiver variable,
    # whether that function's caller gate is delegated to an authority), ...)
    call_sites: dict[tuple[str, str], tuple[tuple[str, str, str, bool], ...]] = field(default_factory=dict)
    # (caller entity, state variable) -> (address it was read holding, observed_via, block)
    reads: dict[tuple[str, str], tuple[str, str, int | None]] = field(default_factory=dict)
    # (destination entity, selector) -> {caller entity: the ACL row accepting it}
    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def acts_as(self, caller: str, destination: str, selector: str) -> ActAsVerdict:
        token = _lower(selector)
        sites = self.call_sites.get((caller, token))
        if not sites:
            return ActAsVerdict(ACT_AS_NO_CALL_SITE)
        outcome = ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE
        for name, openness, variable, delegated in sites:
            if not variable:
                continue
            read = self.reads.get((caller, variable))
            if read is None:
                outcome = _rank_outcome(outcome, ACT_AS_RECEIVER_NOT_READ)
                continue
            held, observed_via, block = read
            if held != destination:
                outcome = _rank_outcome(outcome, ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS)
                continue
            if openness != "restricted":
                outcome = _rank_outcome(outcome, ACT_AS_CALL_SITE_IS_PUBLIC)
                continue
            if not delegated:
                outcome = _rank_outcome(outcome, ACT_AS_CALL_SITE_GATE_NOT_DELEGATED)
                continue
            return ActAsVerdict(
                ACT_AS_WITNESSED,
                ActAsStep(
                    caller=caller,
                    destination=destination,
                    selector=token,
                    calling_function=name,
                    calling_function_openness=openness,
                    witness_kind=ACT_AS_WITNESS_CALLER_STATE_VARIABLE,
                    receiver_variable=variable,
                    receiver_observed_via=observed_via,
                    receiver_block=block,
                ),
            )
        # No state variable of the caller names the destination. The second
        # shape: a call site whose callee the caller's own caller supplies, with
        # the destination's ACL naming this caller from the other end. Sorted so
        # a caller with several such sites names one function deterministically.
        parameter_bound = sorted(site for site in sites if not site[2] and site[1] == "restricted" and site[3])
        if not parameter_bound:
            return ActAsVerdict(outcome)
        accepted = self.destination_acl.get((destination, token), {}).get(caller)
        if accepted is None:
            return ActAsVerdict(_rank_outcome(outcome, ACT_AS_NO_DESTINATION_ACL))
        if not accepted.roles:
            return ActAsVerdict(_rank_outcome(outcome, ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE))
        if not accepted.enumerated:
            return ActAsVerdict(_rank_outcome(outcome, ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE))
        name, openness, _variable, _delegated = parameter_bound[0]
        return ActAsVerdict(
            ACT_AS_WITNESSED,
            ActAsStep(
                caller=caller,
                destination=destination,
                selector=token,
                calling_function=name,
                calling_function_openness=openness,
                witness_kind=ACT_AS_WITNESS_DESTINATION_ACL,
                acceptance=accepted,
            ),
        )


# How far a call site GOT before it was refused, so a caller with several call
# sites for one selector reports the sharpest shortfall rather than whichever it
# happened to look at last. Lower is further. The three destination-ACL refusals
# rank ahead of "the receiver is not a state variable": that reason is what a
# parameter-bound site reports when there is nothing left to consult, and a site
# whose destination ACL WAS consulted got past it. Among the three, a row that
# names a role but bounds its membership only below got further than one that
# names no role at all, which got further than no row at all.
_ACT_AS_RANK = {
    ACT_AS_CALL_SITE_GATE_NOT_DELEGATED: 0,
    ACT_AS_CALL_SITE_IS_PUBLIC: 1,
    ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS: 2,
    ACT_AS_RECEIVER_NOT_READ: 3,
    ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE: 4,
    ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE: 5,
    ACT_AS_NO_DESTINATION_ACL: 6,
    ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE: 7,
    ACT_AS_NO_CALL_SITE: 8,
}


def _rank_outcome(current: str, candidate: str) -> str:
    return candidate if _ACT_AS_RANK[candidate] < _ACT_AS_RANK[current] else current


def load_act_as_plane(session: Session, protocol_id: int) -> ActAsPlane:
    """The call-site, receiver and destination-acceptance witnesses, indexed for
    the composition walk."""
    from db.models import Contract, ControllerValue, EffectiveFunction, FunctionPrincipal

    call_sites: dict[tuple[str, str], list[tuple[str, str, str, bool]]] = defaultdict(list)
    sinks_read = external_calls = selector_bearing = state_variable_bound = delegated_gates = 0
    functions = (
        session.query(
            EffectiveFunction.function_name,
            EffectiveFunction.authority_openness,
            EffectiveFunction.sinks,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    for name, openness, sinks, deployment, address, chain in functions:
        if not isinstance(sinks, list):
            # SQL NULL is "the effects stage did not run here", which is a
            # different fact from a function proven to call nothing. Neither
            # produces a call site, and only the second is an answer.
            continue
        sinks_read += 1
        key = entity_key(coalesce_chain(chain), deployment or address)
        delegated = any(
            isinstance(sink, dict)
            and sink.get("origin") == "guard"
            and _lower(str(sink.get("target") or "")).rsplit(".", 1)[-1] == _DELEGATED_GUARD_METHOD
            for sink in sinks
        )
        delegated_gates += 1 if delegated else 0
        for sink in sinks:
            if not isinstance(sink, dict) or sink.get("kind") != "external_call":
                continue
            external_calls += 1
            selector = _lower(str(sink.get("selector") or ""))
            if not selector.startswith("0x"):
                continue
            selector_bearing += 1
            receiver = sink.get("receiver") if isinstance(sink.get("receiver"), dict) else {}
            variable = ""
            if (receiver or {}).get("binding") == "state_variable":
                variable = str((receiver or {}).get("variable") or "")
                if variable:
                    state_variable_bound += 1
            call_sites[(key, selector)].append((str(name), str(openness or "not_determined"), variable, delegated))

    reads: dict[tuple[str, str], tuple[str, str, int | None]] = {}
    ambiguous: set[tuple[str, str]] = set()
    rows = (
        session.query(
            ControllerValue.source,
            ControllerValue.value,
            ControllerValue.resolved_type,
            ControllerValue.observed_via,
            ControllerValue.block_number,
            ControllerValue.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == ControllerValue.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ControllerValue.id)
        .all()
    )
    for source, value, resolved_type, observed_via, block, deployment, address, chain in rows:
        if not source or resolved_type != "contract" or observed_via not in _READ_OBSERVATIONS:
            continue
        held = _lower(str(value or ""))
        if not held.startswith("0x"):
            continue
        key = (entity_key(coalesce_chain(chain), deployment or address), str(source))
        held_key = entity_key(coalesce_chain(chain), held)
        previous = reads.get(key)
        if previous is not None and previous[0] != held_key:
            # Two reads of one variable disagreeing on which address it holds.
            # Picking one publishes a call destination out of row order, so the
            # variable resolves to nothing and the hop stays unwitnessed.
            ambiguous.add(key)
            continue
        reads.setdefault(key, (held_key, str(observed_via), int(block) if block is not None else None))
    for key in ambiguous:
        reads.pop(key, None)

    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = defaultdict(dict)
    acl_rows_keyed = acl_rows_naming_a_role = 0
    quality_histogram: dict[str, int] = defaultdict(int)
    acl_rows = (
        session.query(
            FunctionPrincipal.id,
            FunctionPrincipal.address,
            FunctionPrincipal.details,
            EffectiveFunction.selector,
            EffectiveFunction.function_name,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .filter(FunctionPrincipal.principal_type == _ACCEPTING_PRINCIPAL_TYPE)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    for row_id, principal, details, selector, function_name, deployment, address, chain in acl_rows:
        token = _lower(str(selector or ""))
        holder = _lower(str(principal or ""))
        if not token.startswith("0x") or not holder.startswith("0x") or not isinstance(details, dict):
            continue
        acl_rows_keyed += 1
        roles: set[int] = set()
        trace = details.get("trace")
        if isinstance(trace, list):
            for step in trace:
                if not isinstance(step, dict):
                    continue
                named = step.get("roles")
                if isinstance(named, list):
                    roles.update(role for role in named if isinstance(role, int) and not isinstance(role, bool))
        if roles:
            acl_rows_naming_a_role += 1
        quality = str(details.get("membership_quality") or "not_determined")
        quality_histogram[quality] += 1
        chain_key = coalesce_chain(chain)
        accepting = DestinationAcceptance(
            roles=tuple(sorted(roles)),
            membership_quality=quality,
            destination_function=str(function_name),
            function_principal_id=int(row_id),
        )
        # Both ends keyed on the destination's own chain: an ACL is a fact about
        # one deployment, and a same-address caller on another chain is a
        # different contract.
        bucket = destination_acl[(entity_key(chain_key, deployment or address), token)]
        previous = bucket.get(entity_key(chain_key, holder))
        # Several rows can name one caller at one selector. Keep the one that
        # witnesses the most, so a row bounded below or naming no role never
        # displaces one that names an enumerated role for the same pair.
        if previous is None or accepting.strength > previous.strength:
            bucket[entity_key(chain_key, holder)] = accepting

    plane = ActAsPlane(
        call_sites={key: tuple(sorted(set(rows))) for key, rows in sorted(call_sites.items())},
        reads=reads,
        destination_acl={key: dict(sorted(callers.items())) for key, callers in sorted(destination_acl.items())},
    )
    plane.provenance = {
        "call_sites": {
            "functions_with_sinks_extracted": sinks_read,
            "functions": len(functions),
            "external_call_sinks": external_calls,
            "sinks_naming_a_selector": selector_bearing,
            "sinks_whose_receiver_is_a_state_variable": state_variable_bound,
            "functions_whose_caller_gate_is_delegated_to_an_authority": delegated_gates,
        },
        "receiver_reads": {
            "state_variables_read_on_chain_holding_a_contract": len(reads),
            "variables_two_reads_disagree_under": len(ambiguous),
            "observations_admitted": sorted(_READ_OBSERVATIONS),
        },
        "destination_acceptance": {
            "function_principal_rows_returned": len(acl_rows),
            "rows_naming_a_selector_and_a_caller_address": acl_rows_keyed,
            "rows_naming_an_admitting_role": acl_rows_naming_a_role,
            "destination_selectors_with_an_indexed_caller": len(destination_acl),
            "indexed_callers": sum(len(callers) for callers in destination_acl.values()),
            "membership_quality": dict(sorted(quality_histogram.items())),
            "principal_type_read": _ACCEPTING_PRINCIPAL_TYPE,
            "membership_quality_admitted": _ENUMERATED_MEMBERSHIP,
        },
        "reading": (
            "the witnesses a composed magnitude needs on top of a licence. The CALL SITE is "
            "always required (effective_functions.sinks, an external_call carrying the called "
            "selector and the receiver it binds to, compiled from the caller's own source). "
            "What names the ADDRESS it lands on has two shapes and either witnesses the step: "
            "the RECEIVER (controller_values, an on-chain read at a recorded block proving that "
            "state variable holds the destination), or — when the receiver is bound to a "
            "parameter, a local or an unresolved head, where no storage of the caller CAN name "
            "it because the callee is chosen at call time — the DESTINATION'S OWN ACL "
            "(function_principals, a principal_type='controller' row naming this caller as an "
            "accepted caller of that selector by an enumerated role). The second shape is "
            "admitted only for a restricted call site whose gate is delegated, only on a row "
            "whose trace names at least one role, only where membership_quality is 'exact', and "
            "only for MAGNITUDE: it is never read into reach, and it does not witness that the "
            "call succeeds — the same row carries the destination's own preconditions and none "
            "of them are consulted. Each shortfall is published as its own reason rather than "
            "collapsed into one: no row naming this caller at all is "
            "destination_does_not_accept_this_caller_for_this_selector; a row that names the "
            "caller but expresses no role that admits it is "
            "destination_access_control_row_names_no_admitting_role — the destination's list "
            "reached this caller by a route it did not state as a role, which is not the same "
            "fact as the list not naming it; and a row that names a role without bounding the "
            "accepted set is destination_access_control_membership_is_not_enumerable, because "
            "naming some accepted callers is not the same fact as bounding which they are. "
            "THE RESIDUAL THIS PLANE DOES NOT CLOSE: the calling function's guard is witnessed "
            "consulting AN authority (a canCall call), never that it is the same authority the "
            "finding's gate seizes — the guard's receiver is a local and no read pins it. The "
            "same-kind GateGrant bound stands in for it, and a bound is not a witness. It is "
            "measured safe on the reference corpus rather than assumed: every one of the 87 "
            "contracts carrying a canCall guard carries exactly one authority-kind state "
            "variable — 'authority' — so there is no second candidate the guard "
            "could be reading; and every one of the 13 callers that actually composed carries "
            "exactly the variable 'authority', which on those contracts is written (state_writes "
            "origin=body) by setAuthority and by nothing else — the gate the finding seizes. On "
            "a corpus where a contract carries two authority-kind variables that measurement "
            "fails and the bound would be doing work a witness should"
        ),
    }
    return plane


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
    "ACT_AS_CALL_SITE_GATE_NOT_DELEGATED",
    "ACT_AS_CALL_SITE_IS_PUBLIC",
    "ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE",
    "ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE",
    "ACT_AS_NO_CALL_SITE",
    "ACT_AS_NO_DESTINATION_ACL",
    "ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS",
    "ACT_AS_RECEIVER_NOT_A_STATE_VARIABLE",
    "ACT_AS_RECEIVER_NOT_READ",
    "ACT_AS_WITNESSED",
    "ACT_AS_WITNESS_CALLER_STATE_VARIABLE",
    "ACT_AS_WITNESS_DESTINATION_ACL",
    "ASSET_BELOW_RESOLUTION",
    "ASSET_PRICED",
    "ASSET_PROVEN_ZERO",
    "ASSET_UNPRICED",
    "CONFERRAL_CONFERRED",
    "CONFERRAL_OUTCOMES",
    "CONFERRAL_ROLE_NOT_LICENSED",
    "CONFERRAL_SCOPE_NOT_DETERMINED",
    "CONFERRAL_VARIABLE_NOT_REWRITTEN",
    "CONFERRAL_WRITES_NOT_EXTRACTED",
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
    "is_zero_key",
    "ActAsPlane",
    "ActAsStep",
    "ActAsVerdict",
    "ConferralPlane",
    "ConferralVerdict",
    "ControlClosure",
    "ControlEdge",
    "DestinationAcceptance",
    "EdgeScope",
    "GateGrant",
    "LicensedFunction",
    "PrincipalFacts",
    "RefusedEdge",
    "RenouncedAuthority",
    "ValuePlane",
    "load_act_as_plane",
    "load_audit_posture",
    "discovery_relation_entities",
    "load_conferral_plane",
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
