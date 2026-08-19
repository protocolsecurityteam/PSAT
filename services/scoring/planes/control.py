"""The control plane: proven authority edges and their closure."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.planes._shared import (
    CONTROL_RELATIONS,
    EDGE_WITNESS_ADMIN_COLUMN,
    EDGE_WITNESS_BEACON_COLUMN,
    EDGE_WITNESS_CONTROL_GRAPH,
    SCOPE_NOT_DETERMINED,
    EdgeScope,
    _lower,
    is_zero_key,
    parse_edge_scope,
)
from services.scoring.schema import NOT_DETERMINED, coalesce_chain, entity_key


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
# A stored edge whose endpoint node id carries no address. It is a row this
# loader cannot key, and dropping it uncounted would make a graph writer that
# started emitting unusable ids read as a protocol with less control in it.
REFUSAL_MALFORMED_NODE_ID = "malformed_node_id"


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
        counts = {
            REFUSAL_ZERO_PRINCIPAL: 0,
            REFUSAL_ZERO_ANCHOR: 0,
            REFUSAL_SELF_EDGE: 0,
            REFUSAL_MALFORMED_NODE_ID: 0,
        }
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
            refusals.append(
                RefusedEdge(
                    rule=REFUSAL_MALFORMED_NODE_ID,
                    # Chain-scoped like every sibling refusal; the endpoint that
                    # carried no address has no key to be scoped.
                    principal=entity_key(chain, target) if target else NOT_DETERMINED,
                    anchor=entity_key(chain, source) if source else NOT_DETERMINED,
                    relation=edge.relation,
                    witness=EDGE_WITNESS_CONTROL_GRAPH,
                    edge_id=edge.id,
                )
            )
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
