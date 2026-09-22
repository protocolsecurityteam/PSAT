"""Selection cascade + transitive value-at-stake ordering.

Chooses which effective functions the effects-simulation stage should probe,
over data already persisted by the earlier pipeline stages — no RPC, no new
facts. Two independent concerns:

1. **Cascade** — the filter that produces the blank-gated simulation set
   (measured funnel: 756 → gated 406 / facts 691 / blank+facts+gated 265).
   Every row that survives is a distinct behavior we must simulate. The "facts"
   leg of that funnel now reads
   the state-write evidence plane (:func:`_has_effect_evidence`), so the number moves —
   on the local protocol-1 slice the cascade admits 49 more rows once that plane
   is written, and 0 fewer.
2. **Ordering** — transitive value-at-stake sorts the survivors so the highest
   blast-radius unknowns run first. Value ORDERS, it never GATES: the
   only thing that removes a candidate is a hard resource safety-valve, and if
   that ever fires it logs exactly what it dropped.

Reach is a conservative upper bound: a control edge propagates the
FULL downstream value of whatever it reaches. Over-approximation is safe here
because it only moves a candidate earlier in the queue, never out of it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
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
    TokenProtocolReference,
    TvlSnapshot,
)
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT, NATIVE_ASSET_LOG_EMITTER
from services.monitoring.balance_reads import positive_raw_balance
from services.monitoring.delivery_evidence import load_delivery_evidence
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
    USD_CRUMB_THRESHOLD,
)
from utils.chains import UnknownChainError, canonical_chain, chain_by_id, chain_by_name
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

# Node IDs in ``control_graph_edges`` are stored as ``address:0x…``.
_NODE_PREFIX = "address:"

# Gate lift — claim families that re-enroll an already-claimed function for
# fork probing. A ``flow.*`` claim needs the downstream value-reach probe; a
# ``supply.*`` claim needs the mint-backing probe. Every other claim family
# (``pause.*``, ``upgrade.*``, …) is already explained and is NOT re-simulated.
_FLOW_CLAIM_PREFIX = "flow."
_SUPPLY_CLAIM_PREFIX = "supply."

# Claim classes TRANSPARENT to enrollment: they record facts that do not EXPLAIN
# the function's value/supply behaviour — ``rate_limit.consume`` is a fact at
# zero severity weight (the call passes through a throughput limiter), and
# ``delegatecall.execute`` names where foreign code comes from, not what the
# function does to value. INVARIANT: a zero-weight FACT must never remove a
# function from evidence-gathering. These ids are filtered out BEFORE
# :func:`_enrolled_families` buckets, so a row whose only claims are transparent
# stays the blank default (``families=None`` → full synthesis) exactly as if
# it carried no claims at all.
_ENROLLMENT_TRANSPARENT_CLAIM_IDS = frozenset({"rate_limit.consume", "delegatecall.execute"})

# The claims that admit a PUBLIC function to the candidate set (see
# :func:`_cascade_rows`). Deliberately these two and no others: they are the
# claims that say value LEAVES the unit or that units are PRINTED, which is
# exactly when "anyone may call this" is the security question rather than a
# footnote.
#
# ``flow.in`` is excluded — a permissionless deposit is a wrapper's whole purpose
# and probing it corroborates nothing — as is ``value_router``, whose entry is
# neither source nor sink (routed labels are static-only by design).
_PUBLIC_ADMISSION_CLAIM_IDS = ("flow.out", "supply.mint")

# How many of a deployment's own holdings may stand in for a caller-supplied token
# parameter. Each one the seeder resolves costs a storage-layout discovery block,
# and ``SeedBudget`` allows 8 per job across ALL tokens — so this stays small
# enough to leave room for the getter-named assets, which are stronger evidence.
_MAX_TOKEN_ARG_CANDIDATES = 2

# How many cap-dropped candidates the drop WARNING names individually. The count
# is always exact; this only bounds the sample (mirrors seeding's ``_SKIP_SAMPLE``).
_DROPPED_SAMPLE = 8


_ZERO_USD = Decimal(0)


def _usd(value: Any) -> Decimal:
    """Exact USD from a ``contract_balances.usd_value`` cell.

    The column is ``numeric(38,18)`` and the driver already hands it back as an
    exact ``Decimal``; money stays in that type all the way through the closure
    sum. Binary floats cannot represent a cent, so a float sum's low bits depend
    on the ORDER the terms are added — and the terms arrive from a ``set``. See
    ``predicates._source_sort_key`` for the same bug class fixed on the string
    plane; this is its numeric twin, and the lesson had never crossed over.
    """
    if value is None:
        return _ZERO_USD
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


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
    # no test ever read it — and what it carries is the display list that conflates a
    # proven state write with a dotted external-call head, which is exactly what the
    # cascade stopped selecting on (:func:`_has_effect_evidence`). A field the next
    # reader would take for the selection evidence, sitting on the object the effects
    # worker passes around, is the trap; the persisted column is still there for the
    # display consumers that own it (``analysis_detail``, ``governance.principals``).
    principal_addresses: tuple[str, ...]
    # Transitive USD an exercise of this function can reach through the control
    # graph. Upper bound; orders only. ``Decimal`` because it is a SORT
    # KEY over a set-derived sum: two candidates that reach the same money must
    # compare EQUAL so the ``function_id`` tiebreak decides them. It is never
    # published — nothing serializes a Candidate — so the exact type costs nothing
    # downstream.
    value_at_stake_usd: Decimal = _ZERO_USD
    # ``effective_functions.deployment_address`` — the address that actually holds
    # the state. Empty when the row predates it / is not proxy-backed.
    deployment_address: str = ""
    # Gate lift. ``None`` = a BLANK function: synthesize every effect class
    # (the default). A non-empty set = a function already carrying a
    # flow.*/supply.* claim, re-enrolled for exactly those value/supply families
    # (never the whole class set — we don't re-simulate what's already explained).
    restrict_families: frozenset[str] | None = None
    # Downstream value-reach inputs. ``value_holders`` is the protocol's
    # WITNESSED value-holder set from ``contract_balances`` — NOT control_graph_edges
    # (which has no fund-flow edge) — against which the fork value-reach probe
    # measures value that provably LEAVES a holder when the call runs.
    # ``acting_balance_usd`` is this function's own deployment balance, the floor
    # when downstream reach is fork-observed to be nothing. Shared by reference
    # across a protocol's candidates (small, immutable), so carrying it
    # per-candidate is cheap.
    #
    # ``None`` is a THIRD state and must stay one all the way to the verdict: the
    # balance join below is INNER precisely so a contract with no current row
    # produces no ``deployment_balance`` key, and defaulting that absence to
    # ``0.0`` here would hand ``_add_reach`` a floor it never witnessed. A PRESENT
    # ``0.0`` is a witness and keeps publishing a floor.
    #
    # PER ASSET, not per holder. This was ``(address, usd)`` — one summed
    # figure per holder — and the reach probe matched ANY ``Transfer`` out of that
    # holder against the whole sum. The weETH proxy's $3.489B is 99.99% eETH, the
    # probe's synthetic native-ETH move matched it, and the row published $3.489B of
    # reach for a call that moved $0 of ETH: 64.96% of ALL published reach USD in the
    # DB came from two such rows, both truly $0. Matching now pins the asset (the
    # ``Transfer`` log's EMITTER), so an asset that moved contributes only its own
    # holding and a moved asset we hold no priced record for contributes NOTHING but
    # marks the total not-determined.
    #
    # ``usd_value`` stays ``float`` (and nullable) where ``value_at_stake_usd`` is
    # ``Decimal``: unlike the sort key it is PUBLISHED — it reaches
    # ``observed_reach_value_usd`` in the verdict's jsonb, which ``json.dumps``
    # cannot encode from a Decimal. Each is a single exact-to-float conversion of one
    # stored cell, never a sum over a set, so the conversion is the last step rather
    # than the first and no order-dependence survives it. Whoever changes them to
    # Decimal must give the jsonb path an encoder first.
    value_holders: tuple[AssetHolding, ...] = ()
    acting_balance_usd: float | None = None
    # The protocol's independently-measured TVL (``tvl_snapshots.defillama_tvl``), or
    # ``None`` when there is no snapshot. A corroborating CEILING for the reach figure:
    # no exercise of one function can reach more value than the protocol holds, and the
    # worst published row asserted $3.489B against a protocol TVL of $3.297B. ``None``
    # means the check is skipped, and the recipe records that it was.
    protocol_tvl_usd: float | None = None
    # Assets the acting deployment PROVABLY holds, richest first — the only honest
    # identity for a caller-supplied token PARAMETER, which has no getter behind it
    # to resolve. Priced entries only (see :func:`_token_holdings_by_contract`).
    input_token_addresses: tuple[str, ...] = ()
    # The resolver marked this function's caller set an EXACT ``finite_set`` —
    # it claims to have enumerated exactly who may call F. If the probe, run as that
    # sole/named member, is then rejected by a canonical gate error, the
    # enumeration named the wrong holder (an authority-plane discrepancy).
    membership_exact: bool = False

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
    proxy. Keying value-reach on ``balance`` therefore matched no holder and
    floored every acting balance to zero.

    Both balance maps carry ``Decimal``, not ``float``: the closure sum below is
    taken over a ``set``, and only an exact type makes that sum independent of
    the order the addends arrive in.
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
        """Sum balances over the transitive closure of ``seeds`` (seeds included).

        The traversal walks ``set``s, so ``seen`` is populated in an order that
        varies across processes; the sum is taken over ``sorted(seen)`` in an
        exact type so the RESULT does not. Order-invariance is what makes the
        ``function_id`` tiebreak at :func:`select_candidates` reachable: values
        that are equal must compare equal, and a one-ulp float difference is
        enough to route two equal-value candidates around it and reorder the
        probe queue.
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
    """Assemble the control closure + balances for one protocol.

    Authority edges come from three sources, all reduced to "controller →
    controlled contract":

    * ``control_graph_edges`` — the row stores *contract controlled BY
      controller* (``from_node`` = contract, ``to_node`` = controller), so the
      authority direction is the reverse of the stored edge. Only relations in
      ``CONTROL_EDGE_RELATIONS`` are read: an ``external_call_target`` row says
      the contract CALLS that address, which moves no authority and would
      otherwise let a callee's balance flow into the caller's value-at-stake.
    * proxy-admin — a proxy's ``admin`` controls the proxy.
    * principal → contract — a function's resolved principal controls the
      contract that function lives on.
    """
    graph = AuthorityGraph()

    # Balances: sum USD per contract, keyed by the contract's on-chain address.
    #
    # Reads the ``latest`` view, not the base table: the writers are insert-only,
    # so the base table carries every past cycle and this SUM would add the same
    # holding once per hour.
    #
    # The join stays INNER, deliberately. A contract with no current row produces
    # NO ``deployment_balance`` key, and that absence is carried to the verdict as
    # ``Candidate.acting_balance_usd = None`` → ``reach_indeterminate: True`` with
    # NO ``observed_reach_floor_usd`` key; a LEFT JOIN would give it a 0 entry, and
    # ``recipes._add_reach`` publishes the acting deployment's balance as
    # ``observed_reach_floor_usd`` — so a $0.00 floor indistinguishable from
    # "holds nothing" would be minted out of a failed fetch.
    #
    # ``coalesce(sum(usd_value), 0)`` below is the remaining collapse this does NOT
    # defend against: a contract whose current rows exist but are ALL unpriced still
    # yields a $0.00 key, and that key is a witnessed-looking zero. A published
    # $0.00 floor therefore still has two causes, not three — an empty priced sheet
    # and an all-unpriced one — so the consumer-side "0.0 is not_determined" gate
    # stays load-bearing.
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
        # MAX, not sum: two implementation rows fronted by one proxy each carry a
        # copy of that ONE deployment's holdings, and adding them would report the
        # money twice.
        graph.deployment_balance[holder] = max(graph.deployment_balance.get(holder, _ZERO_USD), exact)

    # control_graph_edges: reverse to controller → contract.
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


# What is known about a holder's holdings list being WHOLE. TWO states, and the
# missing third one is deliberate: there is no ``"complete"``. Completeness would have
# to be proven from the fetch's PAGE LENGTH, and nothing persists it — ``get_token
# _balances`` drops every zero-balance entry before the rows are stored, so a stored
# count below the cap is consistent with a full page. A boolean here read "below the
# cap" as PROVEN COMPLETE, i.e. a proven-absence claim derived from a count whose input
# had already discarded rows.
HOLDINGS_COMPLETENESS_AT_PAGE_CAP = "at_page_cap"
HOLDINGS_COMPLETENESS_NOT_DETERMINED = "not_determined"
HOLDINGS_COMPLETENESS_STATES = (HOLDINGS_COMPLETENESS_AT_PAGE_CAP, HOLDINGS_COMPLETENESS_NOT_DETERMINED)


class AssetHolding(NamedTuple):
    """One (holder, asset) balance the value-reach probe can match a moved asset to.

    ``asset`` is the address that EMITS a ``Transfer`` log for it: the token
    contract, or :data:`~services.effects.config.NATIVE_ASSET_LOG_EMITTER` for the
    native balance (``contract_balances.token_address IS NULL``). Matching is per
    asset because the over-claim it replaces was asset-blindness: a synthetic native
    move out of the weETH proxy matched a holder whose USD is 99.99% eETH, and the
    row published $3.489B of "reach" for a call that moved $0 of ETH.

    ``usd_value`` is ``None`` when the holding is UNPRICED — 1001 of 1376 local rows
    carry ``price_usd = 0``, which the producer writes for "no price known", and
    ``usd_value`` is the column that encodes that correctly as SQL NULL. It must
    never be read as zero: that is a confident low value where the honest answer is
    "unknown", and "unknown" must rank worse than a proven-benign value.
    """

    holder: str
    asset: str
    usd_value: float | None
    # What is known about whether this holder's holdings list is WHOLE, as one
    # of :data:`HOLDINGS_COMPLETENESS_STATES`. Never ``"complete"``, and that is the
    # point: the ONLY witness is the fetch's own recorded ``asset_set_status``, whose
    # ``at_page_cap`` member is a positive statement that the endpoint cut the list
    # off. Every other status — including a list paged to exhaustion — is
    # ``not_determined``, because no stored field says "and there was nothing more".
    # Uniform across every holding of one holder; carried per row so the reach probe
    # needs no second input to thread.
    completeness: str = HOLDINGS_COMPLETENESS_NOT_DETERMINED
    # How every recorded delivery of this asset into this holder ARRIVED, as one of
    # :data:`~utils.balance_status.DELIVERY_SHAPES`. A DELIVERY claim and never a worth
    # claim: two demonstrably real tokens on this corpus are airdrop-delivered (uniETH
    # at fan-out 101, HEX at 199/399/399), so ``fan_out_all`` states how the balance
    # got here and states nothing about what it is worth.
    #
    # The record is KEPT under every shape — a vanished row is an unwitnessed deletion,
    # and this record's EXISTENCE is what downstream reads as "this deployment holds
    # this asset". Delivery shape alone withholds nothing; a row leaves the holdings
    # claim only under the full conjunction in :func:`disposed_from_holdings`, and it
    # is excluded at the consumption points rather than dropped here, so the exclusion
    # is visible in a labelled record rather than silent in a missing one.
    delivery_shape: str = DELIVERY_SHAPE_NOT_DETERMINED
    # Whether this asset's address was found in the protocol's own discovered
    # universe, as one of :data:`~utils.balance_status.TOKEN_REFERENCE_SHAPES`, read off the
    # last ``token_protocol_reference`` row the producer measured. The second required
    # conjunct — see :func:`disposed_from_holdings` for why this plane reads a stored
    # verdict rather than assembling the universe itself, and what that costs.
    reference_shape: str = TOKEN_REFERENCE_NOT_DETERMINED


def disposed_from_holdings(*, delivery_shape: str, reference_shape: str, usd_value: float | None) -> bool:
    """Does this holding leave the holdings CLAIM? The one definition, three conjuncts.

    The predicate the scorer applies (``services.scoring.planes``
    ``_resolve_asset_disposition``), landed here so the two planes cannot drift: a
    row the score spares must not be pulled out of the page under it. Applying the
    delivery conjunct alone was measured pulling 39 rows of HEX, WETH and base USDC
    — real assets, airdrop-DELIVERED and in the protocol's own universe — out of the
    presented holdings while the score kept every one of them.

    1. ``usd_value is None``. A PRICED reading is never disposed: a dollar figure was
       determined for it, and withdrawing it on evidence about how the token ARRIVED
       would delete a measured number from the page. Deliberately weaker than the
       scorer's arm, which also disposes a priced-below-resolution reading — this
       plane keeps that row presented, which is the direction that shows a real
       holding rather than hides one.
    2. ``delivery_shape == fan_out_all``: every delivery on record was a mass
       distribution. An earned negative and an unmeasured pair both keep the row.
    3. ``reference_shape == absent_from_universe``: the address is not in the
       protocol's discovered universe. A MISSING protocol-reference row is
       ``not_determined`` and keeps the row presented — the producer not having
       measured a pair is never read as the pair having been measured absent.

    **THE DECLARED DIVERGENCE, so a diff of the two surfaces is not read as a
    defect.** This plane's conjunct 1 tests ``usd_value is None``; the scorer's
    (``services.scoring.planes._resolve_asset_disposition``, conjunct 3, over
    ``_DISPOSABLE_ASSET_STATES``) also disposes ``priced_below_resolution`` — a
    reading whose every price landed on the storage column's last digit, the
    eighteenth decimal. So PRESENTATION IS DELIBERATELY WEAKER: it spares every
    below-resolution row the scorer disposes, and never the reverse. That is the
    safe direction — the page shows a holding the score has already stopped
    counting, rather than hiding one the score still counts.

    Two consequences of reading a stored verdict, stated because they are real and
    not because they are harmless:

    * **The verdict is up to one producer cycle STALE relative to the score.** The
      scorer re-reads the live universe on every fold; this plane reads the last row
      the producer's disposition phase wrote, because assembling the universe is a
      measured 26.5 s object-storage read and cannot sit on an API path.
    * **The reference conjunct is ANTI-MONOTONE** — discovery growing un-condemns.
      So when the universe grows, this plane goes on excluding a token the score has
      already spared until the next producer cycle refreshes the row: for at most one
      cycle a REAL holding the protocol owns is not shown on the page. That is the
      safe direction for the acceptance test, and it is still a real holding hidden.

    The row itself is stored, labelled and published under every combination of these
    states, so nothing vanishes from the record while the claim is withheld.
    """
    return (
        usd_value is None
        and delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL
        and reference_shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE
    )


def load_protocol_reference_shapes(session: Session, protocol_ids: Iterable[int]) -> dict[tuple[int, int, str], str]:
    """``(protocol id, chain id, token address) -> reference shape``, as stored.

    One batched read of the producer's own verdicts. The protocol stays IN the key
    rather than being merged out: "is this address in the universe" is a question
    about one protocol's discovery, and two protocols on one page answer it
    independently.

    Every key absent from the result is ``not_determined`` at the call sites, never
    ``absent_from_universe``: this table says what the producer MEASURED, and a pair
    it never measured is a pair nobody answered for.
    """
    ids = sorted({int(pid) for pid in protocol_ids if pid is not None})
    if not ids:
        return {}
    rows = session.execute(
        select(
            TokenProtocolReference.protocol_id,
            TokenProtocolReference.chain_id,
            TokenProtocolReference.token_address,
            TokenProtocolReference.reference_shape,
        ).where(TokenProtocolReference.protocol_id.in_(ids))
    ).all()
    return {
        (int(protocol_id), int(chain_id), str(token or "").lower()): str(shape)
        for protocol_id, chain_id, token, shape in rows
    }


def _merged_reference_shape(shapes: Iterable[str]) -> str:
    """One reference shape for a (holder, asset) several accounts' rows contributed to.

    Mirrors :func:`_merged_delivery_shape` and fails closed the same way. Any account
    whose chain's reference row says ``in_universe`` SPARES the holding outright —
    the scorer tests universe membership chain-blind, and an address discovered on
    one chain is an address the protocol references. ``absent_from_universe`` needs
    unanimity, and an empty contribution set is never vacuously unanimous.
    """
    seen = list(shapes)
    if any(shape == TOKEN_REFERENCE_IN_UNIVERSE for shape in seen):
        return TOKEN_REFERENCE_IN_UNIVERSE
    if seen and all(shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE for shape in seen):
        return TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE
    return TOKEN_REFERENCE_NOT_DETERMINED


def _asset_holdings_by_deployment(session: Session, protocol_id: int) -> dict[str, tuple[AssetHolding, ...]]:
    """``deployment address -> its per-ASSET holdings``.

    Keyed on the address that HOLDS the money (the proxy), because that is the only
    address a ``Transfer`` log can name — the same reason ``deployment_balance``
    exists beside ``balance``.

    MAX per (holder, asset), not SUM, for the reason ``build_authority_graph``
    documents: two implementation rows fronted by one proxy each carry a COPY of that
    one deployment's holdings, and adding them reports the money twice.
    """
    rows = session.execute(
        select(
            Contract.id,
            Contract.chain,
            ContractBalanceLatest.token_address,
            ContractBalanceLatest.usd_value,
            ContractBalanceLatest.raw_balance,
            # The account the read was ISSUED against, which is the key delivery
            # evidence is stored under. It differs from ``contracts.address`` on 162
            # of this protocol's token rows (18 distinct ethereum accounts), so keying
            # the lookup on the contract address would answer ``not_determined`` for
            # every one of them.
            ContractBalanceLatest.observed_address,
            ContractBalanceFetch.chain_id,
            ContractBalanceFetch.asset_set_status,
        )
        .join(ContractBalanceLatest, ContractBalanceLatest.contract_id == Contract.id)
        # OUTER: a legacy row (``fetch_id IS NULL``) has no fetch to join to, and
        # dropping it would silently withdraw every pre-migration holding.
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
    kept: list[tuple[str, str, float | None, tuple[int, str, str] | None, str | None]] = []
    accounts: set[tuple[int, str]] = set()
    for (
        contract_id,
        chain,
        token_address,
        usd,
        raw_balance,
        observed_address,
        fetch_chain_id,
        asset_set_status,
    ) in rows:
        holder = holders.get(contract_id) or _addr(addresses.get(contract_id))
        if holder is None:
            continue
        # A row is a holdings witness only if a strictly positive quantity was
        # witnessed. Row EXISTENCE alone must never mean "holds this asset":
        # that reading is what makes this function the delivery trap for the
        # balance three-state, and it is only accidentally sound today (measured:
        # 0 of 1617 stored rows are non-positive). Unparseable is EXCLUDED, never
        # admitted, and never raised.
        if not positive_raw_balance(raw_balance):
            continue
        asset = _addr(token_address) or NATIVE_ASSET_LOG_EMITTER
        value = None if usd is None else float(_usd(usd))
        account = _delivery_account(fetch_chain_id, chain, observed_address)
        evidence_key = None if account is None or token_address is None else (*account, _addr(token_address) or "")
        if account is not None:
            accounts.add(account)
        kept.append((holder, asset, value, evidence_key, asset_set_status))
    # ONE batched read for the whole protocol's accounts, keyed by the account the
    # balance was read against rather than by any folded entity: two accounts of one
    # deployment are two holders here, and merging them would let one account's
    # evidence answer for the other's holding.
    facts = load_delivery_evidence(session, accounts)
    references = load_protocol_reference_shapes(session, (protocol_id,))
    # (holder, asset) -> usd. ``None`` (unpriced) NEVER overwrites a priced value and
    # is never treated as 0 in the max: a copy of the same holding that happened to be
    # priced is strictly more informative.
    best: dict[tuple[str, str], float | None] = {}
    # Per holder, whether ANY contributing fetch proves its page was capped.
    # WEAKEST WINS: one capped sibling means this holder's asset list may be
    # missing entries, whatever the other siblings said. Taking the last-seen or
    # the strongest value would let a complete-looking fetch mask a capped one.
    holder_capped: dict[str, bool] = {}
    # (holder, asset) -> the shapes every contributing account's evidence answered.
    shapes: dict[tuple[str, str], list[str]] = {}
    # (holder, asset) -> the reference verdict stored for every contributing account's
    # CHAIN. Collected per row rather than per asset because one holding can be read on
    # two chains, and the producer measures the universe question per chain.
    reference_shapes: dict[tuple[str, str], list[str]] = {}
    for holder, asset, value, evidence_key, asset_set_status in kept:
        key = (holder, asset)
        if key not in best:
            best[key] = value
        else:
            current = best[key]
            if current is None:
                best[key] = value
            elif value is not None:
                best[key] = max(current, value)
        fact = None if evidence_key is None else facts.get(evidence_key)
        shapes.setdefault(key, []).append(fact.shape if fact is not None else DELIVERY_SHAPE_NOT_DETERMINED)
        reference_shapes.setdefault(key, []).append(
            TOKEN_REFERENCE_NOT_DETERMINED
            if evidence_key is None
            else references.get((protocol_id, evidence_key[0], evidence_key[2]), TOKEN_REFERENCE_NOT_DETERMINED)
        )
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
                delivery_shape=_merged_delivery_shape(shapes.get((holder, asset), ())),
                reference_shape=_merged_reference_shape(reference_shapes.get((holder, asset), ())),
            )
        )
    return {holder: tuple(items) for holder, items in out.items()}


def _delivery_account(
    fetch_chain_id: int | None, chain_name: str | None, observed_address: str | None
) -> tuple[int, str] | None:
    """The ``(chain_id, account)`` delivery evidence for one balance row is keyed by.

    ``None`` where either half is missing, which is the state that admits no lookup
    and therefore leaves the row ``not_determined`` — the shape that keeps the row
    presented. The fetch's own ``chain_id`` is preferred over the contract's chain
    NAME because it is the value the producer measured against; the name is the
    fallback that still covers a legacy row with no fetch.
    """
    if not observed_address:
        return None
    chain_id = fetch_chain_id
    if chain_id is None and chain_name:
        try:
            chain_id = chain_by_name(chain_name).chain_id
        except UnknownChainError:
            return None
    if chain_id is None:
        return None
    return int(chain_id), str(observed_address).lower()


def _merged_delivery_shape(shapes: Iterable[str]) -> str:
    """One delivery shape for a (holder, asset) several accounts' rows contributed to.

    ``fan_out_all`` only under UNANIMITY, because it is the shape that stops a row
    being presented as a holding and the all-quantifier it comes from is per account:
    one contributing account that saw a direct delivery, or that nobody measured, is
    enough that "every delivery on record was a mass distribution" is not proven for
    this holding. ``has_direct_delivery`` outranks ``not_determined`` — an earned
    negative is not weakened by a sibling gap — and an empty contribution set is
    ``not_determined`` rather than vacuously unanimous.
    """
    seen = list(shapes)
    if seen and all(shape == DELIVERY_SHAPE_FAN_OUT_ALL for shape in seen):
        return DELIVERY_SHAPE_FAN_OUT_ALL
    if any(shape == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY for shape in seen):
        return DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
    return DELIVERY_SHAPE_NOT_DETERMINED


def _completeness_from_fetch(asset_set_status: str | None) -> str:
    """A TOTAL mapping from one fetch's recorded status to a completeness state.

    Total over the whole ``ASSET_SET_STATUSES`` vocabulary plus ``None``, and it
    provably cannot return a whole/complete state — there is no such member of
    :data:`HOLDINGS_COMPLETENESS_STATES` to return. That is the point of routing the
    merged ``asset_set_status`` through one function: the status vocabulary carries
    the one value that names the at-cap case, and a naive reading of its three
    siblings as "not capped, therefore whole" would turn a page fact into a
    proven-absence claim about the holder's assets.

    ``asset_set_status`` is the WHOLE input, and a LENGTH is not part of it. The
    fetch pages the endpoint to exhaustion and records the deduplicated whole-list
    entry count, which routinely exceeds ``TOKEN_BALANCE_PAGE_SIZE`` on a list that
    was never cut off; comparing it to the cap read a complete list as a truncated
    one. ``at_page_cap`` on the status is the producer's own witness that the list it
    stored is a prefix, and it is the only truncation discriminator there is.

    ``returned_assets`` is ``not_determined``, not complete: nothing stored says the
    exhausted list is everything the holder holds, and the one-directional contract
    is what keeps this from minting that sentence.

    ``fetch_failed`` and ``None`` (a legacy row, no fetch recorded) are
    ``not_determined`` for the plainest reason: nothing was learned.
    """
    if asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP:
        return HOLDINGS_COMPLETENESS_AT_PAGE_CAP
    return HOLDINGS_COMPLETENESS_NOT_DETERMINED


def _protocol_tvl_usd(session: Session, protocol_id: int) -> float | None:
    """The protocol's most recent independently-measured TVL, or ``None``.

    Reads ``defillama_tvl`` and NOTHING else. ``total_usd`` and ``contract_breakdown``
    are NULL on EVERY row of this table locally, so a gate written against them cannot
    fire and would be a mitigation that never runs. ``None`` here means the gate is
    SKIPPED, and the caller says so
    out loud rather than passing a comparison that silently always succeeds.
    """
    value = session.execute(
        select(TvlSnapshot.defillama_tvl)
        .where(TvlSnapshot.protocol_id == protocol_id, TvlSnapshot.defillama_tvl.isnot(None))
        .order_by(TvlSnapshot.timestamp.desc(), TvlSnapshot.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    return None if value is None else float(value)


def _token_holdings_by_contract(session: Session, protocol_id: int, limit: int) -> dict[int, tuple[str, ...]]:
    """``contract id -> its richest PRICED ERC-20 holdings``, most valuable first.

    Priced at or above :data:`~utils.balance_status.USD_CRUMB_THRESHOLD`, and that
    filter is load-bearing rather than cosmetic: an unpriced holding is typically an
    airdropped spam token, and a mint witnessed against one would carry a
    ``backing.inflow_observed: true`` indistinguishable from a real deposit. Native
    balance (``token_address IS NULL``) is excluded — it is not an argument any token
    parameter can take.

    The crumb half of that filter is a RULE and not a consequence of storage. It read
    ``usd_value > 0`` while the column was ``numeric(20,2)``, and a crumb was excluded
    because the column had rounded it to 0.00 — so widening the column to
    ``numeric(38,18)`` would have re-admitted every crumb into the probe's input
    without anyone deciding to. The threshold now says which figures are positions,
    and :data:`~utils.balance_status.USD_CRUMB_THRESHOLD` states which readings that
    moves relative to the rounding it replaces.

    Delivery shape does NOT filter this list, and the reason is the disposition
    predicate's own first conjunct (:func:`disposed_from_holdings`): a PRICED reading
    is never disposed. Every row here carries a dollar figure of at least a cent by
    the query itself, so a holding on this list is a real position however it arrived
    — withdrawing one because the token reached the account in a batch would delete a
    measured position from the probe's input on evidence about delivery, which answers
    a different question."""
    rows = session.execute(
        select(
            Contract.id,
            ContractBalanceLatest.token_address,
        )
        .join(ContractBalanceLatest, ContractBalanceLatest.contract_id == Contract.id)
        .where(
            Contract.protocol_id == protocol_id,
            ContractBalanceLatest.token_address.isnot(None),
            # Strictly stronger than the positive-quantity witness
            # ``_asset_holdings_by_deployment`` requires: a holding priced at a
            # cent or more is necessarily a held one. The boundary is on the KEEP
            # side: $0.01 is a position, which is the side the cent-scaled column
            # put it on, and $0.009 is a crumb, which is the side it did not.
            ContractBalanceLatest.usd_value >= USD_CRUMB_THRESHOLD,
        )
        # `usd_value DESC` alone is a PARTIAL order and the tie population is not
        # empty (two contracts here hold 2 and 3 tokens at an identical value), so
        # which holdings survive the `limit` below would be left to the query
        # plan. The trailing keys make the order total.
        .order_by(
            ContractBalanceLatest.usd_value.desc(),
            ContractBalanceLatest.token_address.asc(),
            ContractBalanceLatest.id.asc(),
        )
    ).all()
    out: dict[int, list[str]] = {}
    for contract_id, token in rows:
        addr = _addr(token)
        if addr is None:
            continue
        holdings = out.setdefault(contract_id, [])
        if addr not in holdings and len(holdings) < limit:
            holdings.append(addr)
    return {cid: tuple(v) for cid, v in out.items()}


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
        except Exception as exc:
            # Same safe direction and same accounting as the read failure above:
            # the contract re-sweeps, and the extra planning work has to be
            # attributable to a recorded degradation.
            record_degraded(phase="effects_selection_stage_status", exc=exc, context={"key": key})
            logger.warning(
                "effects selection: undecodable stage-timing body",
                extra={"key": key, "exc_type": type(exc).__name__},
            )
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


def _carries_public_admission_claim():
    """SQL predicate: the row's ``claims`` JSONB holds a ``claim_id`` in
    :data:`_PUBLIC_ADMISSION_CLAIM_IDS`.

    In SQL rather than in Python beside the other claim logic because it is a
    KEEP predicate, not a refinement of an already-selected row: these functions
    are outside the ``authority_public = false`` set the query returns at all, so
    Python never sees them to reconsider.

    Containment (``@>``) rather than ``jsonb_array_elements``, and the difference
    is not stylistic: the set-returning form RAISES ``cannot extract elements
    from a scalar`` on a JSON-``null`` ``claims`` — a value this column really
    holds (see :func:`_enrolled_families`, which treats SQL ``NULL``, ``[]`` and
    JSON-``null`` alike as blank) — and one such row would abort candidate
    selection for the entire protocol. ``@>`` is total: every non-matching shape,
    scalar included, is simply ``false``. It also matches on a SUBSET of each
    object, so the ``tier`` a claim carries alongside its id is irrelevant here.
    """
    return or_(
        *(
            EffectiveFunction.claims.op("@>")(cast([{"claim_id": claim_id}], JSONB))
            for claim_id in _PUBLIC_ADMISSION_CLAIM_IDS
        )
    )


def _proven_array_len(col: Any):
    """``jsonb_array_length`` that cannot raise, for a column whose payload is a
    jsonb array or nothing.

    The bare function ERRORS on any non-array: ``cannot get array length of a
    scalar``. SQL NULL is safe, but the jsonb scalar ``null`` and every malformed
    payload would abort candidate selection for the whole protocol — the same
    total-vs-partial trap ``_carries_public_admission_claim`` documents for
    ``jsonb_array_elements``. The guard folds a non-array to ``[]`` so the
    expression is total; callers must NOT read that fold as a proven emptiness,
    which is why :func:`_evidence_not_determined` tests the shape separately and
    every caller here pairs the two.
    """
    return func.jsonb_array_length(case((jsonb_state(col) == "array", col), else_=cast(literal("[]"), JSONB)))


def _evidence_proven_present(col: Any):
    """The column holds a non-empty jsonb array — the writer looked and FOUND."""
    return and_(jsonb_state(col) == "array", _proven_array_len(col) > 0)


def _evidence_not_determined(col: Any):
    """The column holds no array — SQL NULL (never written / withheld), the jsonb
    scalar ``null``, or a malformed shape. All three mean NOT DETERMINED: a value
    that is not the writer's array shape is not evidence of emptiness, exactly as
    ``policy.permission_index._mutability_fields`` treats a wrongly-typed
    field on the producing side. Total by construction — ``jsonb_state``
    coalesces SQL NULL to a non-type name, so this never evaluates to NULL and
    can never be silently dropped from an ``or_``."""
    return jsonb_state(col) != "array"


def _has_effect_evidence():
    """SQL predicate for cascade filter (a): is there anything here to simulate,
    or could we not determine that there is not?

    Reads the state-write evidence plane — ``state_changing`` /
    ``state_writes`` / ``sinks``, each three-state,
    which is a display field that concatenates state-write variable names with
    dotted external-call heads. Selecting on it
    made a populated value assert a state write nothing had proven: **501 of its
    1,642 populated rows carry only call heads**, and on the local protocol-1
    slice **156 gated functions** entered this cascade on external-call targets
    alone while the docstring here claimed the list *was* the state-write target
    list. What is removed is that inference, not those rows: no reader of this
    filter can infer a proven write from membership any more.

    Which disjunct actually admits those 156, measured on the projected plane
    (never assumed — the shape below is not the obvious one):
    ``state_changing IS TRUE`` for **147**, not-determined for **8**
    (``state_changing`` NULL), and the sink evidence for exactly **1**
    (``shouldSubmitReport(address)``, function_id 2344). So for 147 of them the
    admitting ground is the ABI's mutability flag and the sink list is redundant.
    The population the sink ground is actually load-bearing for is a DIFFERENT one:
    116 filter-(a) rows that are compiler-typed views (``state_changing`` FALSE)
    with ``state_writes = []`` and a proven non-empty ``external_call`` sink list.
    115 of those are public and filter (c) drops them; the 116th is 2344, and it is
    the only candidate this predicate would lose if the two
    :func:`_evidence_proven_present` disjuncts were deleted (``pp_sinks`` sole-admits
    116 rows / 1 candidate; ``pp_state_writes`` sole-admits 0 rows today — see the
    two dedicated arms in ``test_filter_a_keeps_the_three_evidence_states_apart``,
    which exist because every other arm survives that deletion).

    Input shape → candidacy. Every ADMIT is either proven-active or
    not-determined; the single EXCLUDE needs three independent proven absences:

    ==================  ==============  ==============  =========  ==================================
    ``state_changing``  ``state_writes``  ``sinks``     candidacy  why
    ==================  ==============  ==============  =========  ==================================
    any                 array, len>0    any             ADMIT      proven state write
    any                 any             array, len>0    ADMIT      proven sink of ANY kind
    ``TRUE``            ``[]``          ``[]``          ADMIT      the ABI proves mutability and the
                                                                   extractor found no sink — two
                                                                   witnesses disagree, so nothing is
                                                                   settled and evidence is what a
                                                                   probe is for
    ``NULL``            any             any             ADMIT      not determined
    any                 not an array    any             ADMIT      not determined
    any                 any             not an array    ADMIT      not determined
    ``FALSE``           ``[]``          ``[]``          EXCLUDE    the only proven-inert shape:
                                                                   compiler-typed view/pure (the
                                                                   compiler forbids ``SSTORE``,
                                                                   low-level calls and value sends
                                                                   there) AND a writer that looked
                                                                   and found no write and no sink
    ==================  ==============  ==============  =========  ==================================

    Three consequences worth naming, because they are the point:

    * **Not-determined admits.** A row whose evidence was never written (every
      row written before those columns existed), or withheld — the view-contradiction
      rule nulls 89 legitimate ``external_call`` sinks on 14 rows — is probed, not
      dropped. Dropping it would publish "nothing to see here" from an absence of
      measurement. Where
      the plane is entirely unwritten (1,773/1,773 rows locally) this filter is
      vacuous by design and the cascade is bounded by (b), (c) and the
      ``resource_cap``, which names everything it drops.
    * **``state_changing`` is read as a bool, not as evidence of writes.** It is
      ``TRUE`` for a selector-bearing external/public non-view function whose
      writes may sit in inline assembly the IR never saw — the exact row this
      plane exists to stop losing. ``FALSE`` reaches this filter only from a named
      function the compiler typed ``view``/``pure``: ``_mutability_fields``
      withholds it to NULL for ``fallback``/``receive`` (no selector is not a
      proof of purity — WETH9's ``fallback()`` writes ``balanceOf``).
    * **``writer_selectors`` is deliberately not read.** It answers "which
      selector replays this write", not "is there a write": ``_writer_selectors_for``
      returns ``[]`` unless a ``state_write`` sink exists, so it can admit nothing
      the two columns above do not (verified: 0 rows over the 1,179 projected
      protocol-1 rows carry a non-empty ``writer_selectors`` without a proven
      write or sink). Reading it would also drag the fabricated
      ``keccak("fallback()")[:4]`` values (15 fallback/receive rows) into a
      selection decision for no recall at all.

    **Why ``state_changing IS FALSE`` alone is not the exclusion.**
    ``tests/test_effective_function_mutability_columns.py``'s
    ``test_a_state_write_only_filter_would_suppress_the_positive_control`` — the
    pin for whoever retargets this filter — ends "a sink-only filter is not
    sufficient on its own, ``state_changing`` is", and a stricter reading of it
    would drop every compiler-typed view outright. It is not taken, because
    ``view``/``pure`` is a proof about STATE MUTATION and this filter's question is
    broader than that. The effects stage
    also contradicts the AUTHORITY plane (it is the only stage
    that calls as a resolved principal), and a gated view can carry a caller-set
    claim a probe would falsify. Using a mutation proof to assert "there is
    nothing here to observe" is the same over-reach in miniature. So the
    exclusion requires the compiler AND the extractor to agree: ``state_changing``
    is the discriminator that keeps ``sweepDust`` (proven actor, ``state_writes =
    []``) in, via the ``TRUE`` arm, and it can only help drop a row when both
    evidence lists are proven empty beside it. Measured cost of the choice on the
    local slice: exactly ONE row differs — ``shouldSubmitReport(address)``
    (function_id 2344, a gated view with one ``external_call`` sink), which stays
    a candidate and plans 0 probes, so the fork budget is untouched either way.
    That is the same single row the sink ground sole-admits, which is the honest
    size of this choice today: one candidate, and 115 more public rows of the same
    shape that filter (c) drops anyway.

    Origin-agnostic on purpose: ``sinks``/``state_writes`` carry a modifier's
    ``origin='guard'`` facts as well as body ones.
    those out. A probe executes the modifiers too, so a guard-origin write is
    state the simulation really does change; and the difference only ever ADMITS
    (10 of the projected new rows, measured from the raw effects artifacts), which
    is the direction that cannot publish a false absence.
    """
    return or_(
        _evidence_proven_present(EffectiveFunction.state_writes),
        _evidence_proven_present(EffectiveFunction.sinks),
        EffectiveFunction.state_changing.is_(True),
        _evidence_not_determined(EffectiveFunction.state_writes),
        _evidence_not_determined(EffectiveFunction.sinks),
        EffectiveFunction.state_changing.is_(None),
    )


def _cascade_rows(session: Session, protocol_id: int, scope: JobScope | None = None):
    """The filter cascade as one query.

    (a) has something to simulate — the state-write evidence plane, three
        states kept apart; see :func:`_has_effect_evidence` for the input-shape
        table.
        call head.
    (c) gated over public — ``authority_public = false``, EXCEPT a public
        function carrying ``flow.out`` or ``supply.mint``.

    That exception is the gate lift applied to the permissionless case, and
    it exists because the original rule read "public means no authority to
    resolve, so there is nothing to probe as". True of the principal; false of
    the effect. A permissionless payout or a permissionless mint is the shape
    where "anyone can call this" is the finding — ``EtherFiRedemptionManager
    .redeem*`` and the public mints sat outside the candidate set entirely, so
    the stage produced no verdict for 770 public functions and the gap was
    invisible. Such a function is probed from :data:`calldata.NEUTRAL_CALLER`,
    an arbitrary non-zero identity, which is a valid probe precisely BECAUSE no
    gate has to be satisfied.

    Kept narrow on purpose: admitting every public function would spend fork
    budget on wrapper in/out and routed-deposit noise that corroborates nothing.

    Filter (b) — the blank-claim gate — is applied in PYTHON on the returned
    ``claims`` column (see :func:`_enrolled_families`), because it is no longer a
    binary keep/drop: BLANK rows still get full synthesis (the default), while
    rows already carrying a ``flow.*``/``supply.*`` claim are RE-ENROLLED for just
    those value/supply families (the gate lift) so the fork value-reach and
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
        _has_effect_evidence(),
        # Deliberately still keyed on the BOOL, not the new three-state
        # ``authority_openness``: this predicate selects the *candidate* set, so
        # a not-determined authority must be admitted exactly as a witnessed
        # restriction is (both are "not proven open"), which is precisely what
        # ``authority_public IS FALSE`` already does. Switching to
        # ``authority_openness = 'restricted'`` would DROP every
        # not-determined row from probing — the fail-open direction. The three
        # states matter to a consumer *reporting* the authority, not to this
        # filter; see ``capability_surface_openness``.
        or_(EffectiveFunction.authority_public.is_(False), _carries_public_admission_claim()),
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
            EffectiveFunction.deployment_address,
            EffectiveFunction.claims,
            EffectiveFunction.capability_expr,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(*where)
    ).all()


def _membership_exact(capability_expr: Any) -> bool:
    """Whether the resolver claims an EXACT enumeration of F's caller set. An
    ``unsupported`` / ``conditional_universal`` capability also carries
    ``membership_quality: exact``, so both the ``finite_set`` kind AND the exact
    quality are required — this is "the resolver named a finite, complete set of
    holders", the only shape a canonical gate rejection can contradict."""
    return (
        isinstance(capability_expr, dict)
        and capability_expr.get("kind") == "finite_set"
        and capability_expr.get("membership_quality") == "exact"
    )


def _enrolled_families(claims: Any) -> frozenset[str] | None:
    """Which effect families a candidate should be probed for, from its claims.

    * ``None`` — the function is BLANK (no claims). It is the default candidate:
      every effect class is synthesized. ``[]``, SQL ``NULL`` and the ORM's
      JSON-``null`` all read as blank here.
    * a **non-empty** frozenset — the function already carries a ``flow.*`` and/or
      ``supply.*`` claim, so it is re-enrolled for exactly ``value_out``
      and/or ``supply``. Never the whole class set: re-simulating pause/authority/
      upgrade for an already-explained function is the waste the gate guards.
    * the **empty** frozenset — the function carries only other claims (pause,
      upgrade, …); already explained, so the caller drops it (fail-closed: an
      unrecognized claim shape enrolls nothing).

    Claims in :data:`_ENROLLMENT_TRANSPARENT_CLAIM_IDS` are removed BEFORE the
    bucketing above — they are facts, not explanations, and must never flip a
    blank row from ``None`` (probe everything) to the empty set (probe nothing).
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
    """``function id -> its resolved principals``, in a TOTAL order.

    The ORDER BY is load-bearing, not cosmetic: element ``[0]`` of
    this list becomes the identity every fork probe impersonates
    (``candidate.principal_addresses[0]`` at ``calldata.py`` :1395, :1437, :1720,
    :2312, and the first resolved principal of the code-upgrade plan in
    ``orchestrator.py``). Without it, WHO the probe runs as — and therefore which
    gate it passes, which revert it records, and what the witness says — was left
    to the query plan / heap order rather than being a function of the data. The
    multi-principal population is not hypothetical: fid 2527 carries 33 principals
    locally, 801 and 811 carry 27, 2908/2909 carry 15.

    Ordered on ``address`` for the same reason ``calldata._principals_by_selector``
    is: the two must agree, because the pause plan reads the per-selector map while
    the value probes read this one, and a job that impersonates two different
    holders of the same function is unreproducible by construction. ``id`` makes
    the order total when one function records the same address twice.

    A third determinism class alongside PYTHONHASHSEED and allocation order,
    invisible to both of those gates because they fix the PROCESS, not the query
    plan.
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
    scope: JobScope | None = None,
    funnel: dict[str, Any] | None = None,
) -> list[Candidate]:
    """Return the blank-gated simulation set, ordered by transitive value.

    ``funnel``, when passed, is filled with the counts this function alone can
    reconcile — ``rows_in`` from the cascade query, ``skipped_already_explained``
    (a claim-carrying row with no family left to re-probe), ``cap_dropped``, and
    the ``selected`` total. The caller publishes them; without it the difference
    between "the cascade found nothing" and "everything it found was dropped
    here" is invisible downstream.

    ``resource_cap`` is the ONLY permissible cutoff: a hard
    safety-valve for a pathological protocol. When it fires it drops the
    lowest-value candidates and ``log()``s exactly what it dropped — value
    never silently removes work.

    ``scope`` narrows the CANDIDATE set to the calling job's own contracts. The
    two protocol-wide inputs below are deliberately NOT narrowed: the authority
    closure and the value-holder set are properties of the whole protocol, and
    computing either from one contract's slice would understate every candidate's
    blast radius.
    """
    rows = _cascade_rows(session, protocol_id, scope)
    if funnel is not None:
        funnel["rows_in"] = len(rows)
        funnel["skipped_already_explained"] = 0
        funnel["cap_dropped"] = 0
        funnel["selected"] = 0
    function_ids = [r[0] for r in rows]
    principals = _principals_by_function(session, function_ids)
    graph = build_authority_graph(session, protocol_id)

    # The protocol's witnessed value-holder set (on-chain balances), built once
    # and shared by reference across every candidate, PER ASSET. Keyed on the HOLDING
    # address, which is the one a ``Transfer`` log can name.
    #
    # An UNPRICED holding is kept (``usd_value=None``) where the old per-holder set
    # dropped anything summing to zero: "we hold this and cannot value it" is the
    # input that makes a reach total not-determined, and dropping it made a moved
    # unpriced asset silently equivalent to no movement at all. A holding priced at
    # exactly 0 is likewise kept — a measured zero is evidence.
    #
    # A DISPOSED holding is not presented here — unpriced, every delivery on record a
    # mass distribution, AND the address absent from the protocol's own universe. All
    # three, because membership of this tuple is read downstream as "this deployment
    # holds this asset" and that reading has to be wrong before the row comes out. The
    # record itself is kept and labelled by ``_asset_holdings_by_deployment``, so the
    # exclusion is readable off the labelled row rather than inferred from a row that
    # vanished. See :func:`disposed_from_holdings` for the conjuncts and for what
    # reading a stored universe verdict costs.
    value_holders = tuple(
        holding
        for holdings_for_deployment in _asset_holdings_by_deployment(session, protocol_id).values()
        for holding in holdings_for_deployment
        if not disposed_from_holdings(
            delivery_shape=holding.delivery_shape,
            reference_shape=holding.reference_shape,
            usd_value=holding.usd_value,
        )
    )
    holdings = _token_holdings_by_contract(session, protocol_id, _MAX_TOKEN_ARG_CANDIDATES)
    protocol_tvl = _protocol_tvl_usd(session, protocol_id)

    candidates: list[Candidate] = []
    for fid, contract_id, address, selector, name, public, deployment, claims, capability_expr in rows:
        families = _enrolled_families(claims)
        # Claim-carrying but no flow/supply family to re-probe → already explained.
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
                input_token_addresses=holdings.get(contract_id, ()),
                membership_exact=_membership_exact(capability_expr),
            )
        )

    # Highest value first; stable tiebreak on function_id for determinism. The
    # tiebreak fires only on EXACT equality, which is why the value it breaks has
    # to be exact: ties are the common case here (one 84-member cluster in the
    # local corpus alone) and a float sum put a one-ulp gap between members that
    # hold the same money, ordering them by rounding noise instead.
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
    """Account for every dropped candidate — no silent truncation.

    The COUNT is the fact (nothing is dropped without it being logged); the
    manifest is a bounded sample, because a pathological protocol is exactly the
    case that trips the cap and a full manifest there is a single log line
    thousands of entries long."""
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
