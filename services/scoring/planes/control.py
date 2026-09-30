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
    """One proven control edge: ``principal`` has authority over ``anchor`` (chain-scoped keys).

    ``relation``/``edge_id`` are ``None`` for the ``contracts.admin`` column.
    """

    principal: str
    anchor: str
    relation: str | None
    scope: EdgeScope
    witness: str
    edge_id: int | None = None


REFUSAL_ZERO_PRINCIPAL = "zero_address_principal"
REFUSAL_ZERO_ANCHOR = "zero_address_anchor"
# A beacon or admin column naming the contract itself: refused and counted, not absorbed as a self-loop.
REFUSAL_SELF_EDGE = "self_referential_column"
# An endpoint with no address: counted, so a writer emitting unusable ids isn't silent.
REFUSAL_MALFORMED_NODE_ID = "malformed_node_id"


@dataclass(frozen=True)
class RefusedEdge:
    rule: str
    principal: str
    anchor: str
    relation: str | None
    witness: str
    edge_id: int | None = None


@dataclass(frozen=True)
class RenouncedAuthority:
    """An authority slot proven empty (the anchor's ``label`` holds ``0x0``): renunciation for ownership, an unset
    pointer otherwise. An earned negative, counted apart from the refusals it coincides with.
    """

    anchor: str
    relation: str | None
    scope: EdgeScope
    witness: str
    edge_id: int | None = None


@dataclass
class ControlClosure:
    """The protocol's control edges indexed by principal, each with its relation and scope.

    ``controlled_by`` is derived adjacency. ``refusals`` and ``renounced`` are published counts, not silent drops.
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
        return tuple(self._out)

    def edges_from(self, principal: str) -> tuple[ControlEdge, ...]:
        return self._out.get(principal, ())

    def controlled_by(self, principal: str) -> tuple[str, ...]:
        return tuple(sorted({edge.anchor for edge in self.edges_from(principal)}))

    def refusal_counts(self) -> dict[str, int]:
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
        """The earned negative counted by slot (``(anchor, label)``) as well as by edge rows (one per witnessed
        read), which would otherwise multiply it.
        """
        slots = {(row.anchor, row.scope.label) for row in self.renounced}
        by_label: dict[str, int] = {}
        for _, label in slots:
            by_label[str(label)] = by_label.get(str(label), 0) + 1
        return {
            "edges": len(self.renounced),
            "authority_slots": len(slots),
            "anchors": len({row.anchor for row in self.renounced}),
            # An empty ``owner`` is renunciation, an empty ``_pendingOwner`` a pointer never set: same shape, different
            # facts.
            "authority_slots_by_label": dict(sorted(by_label.items())),
        }


def load_control_closure(session: Session, protocol_id: int) -> ControlClosure:
    """The proven control edges; ``edges_from(X)`` is what X controls. Chain-scoped on both ends.

    The zero address is refused at both ends (a burn sentinel would otherwise become the biggest control hub), and a
    ``controller_value`` edge pointing at it is read as a renounced authority. ``contracts.admin`` and
    ``contracts.beacon`` join as column witnesses (the beacon being the broadest code-control link), each tagged with
    its own witness string.
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
        # Self-edges are only refused for column witnesses; a graph row saying an entity controls itself is kept.
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
                    principal=entity_key(chain, target) if target else NOT_DETERMINED,
                    anchor=entity_key(chain, source) if source else NOT_DETERMINED,
                    relation=edge.relation,
                    witness=EDGE_WITNESS_CONTROL_GRAPH,
                    edge_id=edge.id,
                )
            )
            continue
        # Stored anchor -> principal; authority runs the other way.
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
