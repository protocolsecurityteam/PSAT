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
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractBalance,
    ControlGraphEdge,
    EffectiveFunction,
    FunctionPrincipal,
)
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT

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
    "A controls B"). ``balance[addr]`` is the summed USD held at that address.
    """

    controls: dict[str, set[str]] = field(default_factory=dict)
    balance: dict[str, float] = field(default_factory=dict)

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
        select(Contract.address, func.coalesce(func.sum(ContractBalance.usd_value), 0))
        .join(ContractBalance, ContractBalance.contract_id == Contract.id)
        .where(Contract.protocol_id == protocol_id)
        .group_by(Contract.address)
    ).all()
    for address, usd in bal_rows:
        a = _addr(address)
        if a is not None:
            graph.balance[a] = graph.balance.get(a, 0.0) + float(usd or 0.0)

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


def _cascade_rows(session: Session, protocol_id: int):
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
    """
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
        .where(
            Contract.protocol_id == protocol_id,
            func.array_length(EffectiveFunction.effect_targets, 1) > 0,
            EffectiveFunction.authority_public.is_(False),
        )
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
) -> list[Candidate]:
    """Return the blank-gated simulation set, ordered by transitive value.

    ``resource_cap`` is the ONLY permissible cutoff (inv. 4): a hard
    safety-valve for a pathological protocol. When it fires it drops the
    lowest-value candidates and ``log()``s exactly what it dropped — value
    never silently removes work.
    """
    rows = _cascade_rows(session, protocol_id)
    function_ids = [r[0] for r in rows]
    principals = _principals_by_function(session, function_ids)
    graph = build_authority_graph(session, protocol_id)

    # §5b: the protocol's witnessed value-holder set (on-chain balances), built once
    # and shared by reference across every candidate. Only positive balances — a
    # zero-balance holder can't be a value-reach target and only adds noise.
    value_holders = tuple(sorted((a, u) for a, u in graph.balance.items() if u > 0.0))

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
                acting_balance_usd=graph.balance.get(acting, 0.0),
            )
        )

    # Highest value first; stable tiebreak on function_id for determinism.
    candidates.sort(key=lambda c: (-c.value_at_stake_usd, c.function_id))

    if resource_cap is not None and len(candidates) > resource_cap:
        kept, dropped = candidates[:resource_cap], candidates[resource_cap:]
        _log_dropped(protocol_id, resource_cap, dropped)
        return kept

    return candidates


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
