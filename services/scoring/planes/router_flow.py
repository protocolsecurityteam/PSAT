"""The router-flow plane: how an intermediate's body treats its destination call."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.schema import coalesce_chain, is_entity_key

# How an intermediate's body treats the destination call it makes. Each positive token is earned from one field of the
# intermediate's stored value-flow witness, never names or shapes; anything else is ``not_determined``.
ROUTE_AMOUNT_AUTHORED = "destination_amount_is_authored_by_the_intermediate"
# Earned from ``target_constraint``, which pins the destination call's counterparty argument. Not a callee restriction:
# no witness says the intermediate restricts the object called.
ROUTE_TARGET_CONSTRAINED = "destination_target_is_constrained_by_the_intermediate"
ROUTE_NOT_DETERMINED = "not_determined"
ROUTE_CLASSIFICATIONS = (ROUTE_AMOUNT_AUTHORED, ROUTE_TARGET_CONSTRAINED, ROUTE_NOT_DETERMINED)

# No flow witness names this destination call, or one does and both conjuncts are unproven.
ROUTE_NO_FLOW_WITNESS = "the_intermediate_body_names_no_value_flow_into_this_destination_selector"
ROUTE_NEITHER_CONJUNCT = "the_intermediate_flow_witness_proves_neither_an_authored_amount_nor_a_constrained_target"

# From ``effective_functions.claims[].witness.flows[]``: ``amount_kind == "param_derived"`` means the intermediate
# computes the amount itself (``param`` is pass-through); ``target_constraint.state == "constrained"`` means it pins the
# counterparty. ``unconstrained_proven`` and ``not_determined`` earn nothing and differ.
_FLOW_AMOUNT_PARAM_DERIVED = "param_derived"
_FLOW_TARGET_CONSTRAINED = "constrained"


@dataclass(frozen=True)
class RouterFlow:
    sink_id: str | None
    destination_selector: str
    amount_kind: str | None
    target_constraint_state: str | None
    target_constraint_guard: str | None

    def as_json(self) -> dict[str, Any]:
        return {
            "sink_id": self.sink_id,
            "destination_selector": self.destination_selector,
            "amount_kind": self.amount_kind,
            "target_constraint_state": self.target_constraint_state,
            "target_constraint_guard": self.target_constraint_guard,
        }


@dataclass(frozen=True)
class RouteClassification:
    state: str
    reason: str | None
    flows: tuple[RouterFlow, ...]
    amount_authored: bool | None
    target_constrained: bool | None

    def __post_init__(self) -> None:
        if self.state in (ROUTE_AMOUNT_AUTHORED, ROUTE_TARGET_CONSTRAINED):
            if self.reason is not None or not self.flows:
                raise ValueError("a classified route names no reason and rests on at least one flow witness")
        elif self.state == ROUTE_NOT_DETERMINED:
            if self.reason not in (ROUTE_NO_FLOW_WITNESS, ROUTE_NEITHER_CONJUNCT):
                raise ValueError(f"an unclassified route must name a registered reason, got {self.reason!r}")
        else:
            raise ValueError(f"unknown route classification {self.state!r}")

    def as_json(self) -> dict[str, Any]:
        return {
            "source": "effective_functions.claims[].witness.flows[]",
            "state": self.state,
            "reason": self.reason,
            # Both conjuncts published in every state; ``null`` where no flow witness answered.
            "amount_is_authored_by_the_intermediate": self.amount_authored,
            "destination_target_is_constrained_by_the_intermediate": self.target_constrained,
            "flows": [flow.as_json() for flow in self.flows],
            "reading": (
                "read from the INTERMEDIATE function's own compiled body — the function the "
                "act-as chain's last step enters the destination through — and only from the "
                "flows whose router op names THIS entry's destination selector. Two conjuncts, "
                "each its own field above and each earned separately: amount_kind == "
                "'param_derived' proves the intermediate computes the quantity the destination "
                "moves rather than forwarding one its caller supplied, and target_constraint "
                "== 'constrained' proves it pins the destination call's counterparty under a "
                "guard it enforces. Both are statements about the INTERMEDIATE's body and "
                "neither is read from the destination's own witness, from a function name, "
                "from a selector or from how many hops the chain has. Where no flow of the "
                "intermediate names this destination selector, or where both conjuncts are "
                "unproven, the state is not_determined — which withholds the magnitude just as "
                "a classified route does and claims nothing about why"
            ),
        }


@dataclass
class RouterFlowPlane:
    """Every intermediate function's stored value-flows, keyed by ``(chain, intermediate, that function's own
    selector)``, the pair the act-as step publishes.
    """

    flows: dict[tuple[str, str, str], tuple[RouterFlow, ...]] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        return {
            "router_flow_functions": len(self.flows),
            "router_flow_witnesses": sum(len(rows) for rows in self.flows.values()),
        }

    def classify(self, caller_key: str, calling_selector: str | None, destination_selector: str) -> RouteClassification:
        rows: tuple[RouterFlow, ...] = ()
        if is_entity_key(caller_key) and calling_selector:
            chain, _, address = caller_key.partition("::")
            key = (coalesce_chain(chain), address.lower(), calling_selector.lower())
            rows = tuple(
                flow for flow in self.flows.get(key, ()) if flow.destination_selector == destination_selector.lower()
            )
        if not rows:
            return RouteClassification(ROUTE_NOT_DETERMINED, ROUTE_NO_FLOW_WITNESS, (), None, None)
        # Every matching flow must agree; disagreeing flows haven't proved it.
        amount_authored = all(flow.amount_kind == _FLOW_AMOUNT_PARAM_DERIVED for flow in rows)
        target_constrained = all(flow.target_constraint_state == _FLOW_TARGET_CONSTRAINED for flow in rows)
        if amount_authored:
            # Both may hold; the amount conjunct is the one about the figure. The other is published too.
            return RouteClassification(ROUTE_AMOUNT_AUTHORED, None, rows, True, target_constrained)
        if target_constrained:
            return RouteClassification(ROUTE_TARGET_CONSTRAINED, None, rows, False, True)
        return RouteClassification(ROUTE_NOT_DETERMINED, ROUTE_NEITHER_CONJUNCT, rows, False, False)


def load_router_flow_plane(session: Session, protocol_id: int) -> RouterFlowPlane:
    """Every value-flow an analysed function routes into a named callee op, from ``effective_functions.claims``
    (asked what the function decides about its call). Protocol-scoped: a missing row can only make a route less
    classified.
    """
    from db.models import Contract, EffectiveFunction

    plane = RouterFlowPlane()
    rows = (
        session.query(
            EffectiveFunction.selector,
            EffectiveFunction.claims,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id, EffectiveFunction.selector.is_not(None))
        .order_by(EffectiveFunction.id)
        .all()
    )
    flows: dict[tuple[str, str, str], list[RouterFlow]] = defaultdict(list)
    for selector, claims, address, chain in rows:
        key = (coalesce_chain(chain), str(address).lower(), str(selector).lower())
        for claim in claims if isinstance(claims, list) else ():
            witness = (claim or {}).get("witness") if isinstance(claim, dict) else None
            if not isinstance(witness, dict):
                continue
            for flow in witness.get("flows") or ():
                if not isinstance(flow, dict):
                    continue
                amount = flow.get("amount_kind")
                constraint = flow.get("target_constraint")
                for op in flow.get("router_ops") or ():
                    op_selector = (op or {}).get("selector") if isinstance(op, dict) else None
                    if not isinstance(op_selector, str) or not op_selector.startswith("0x"):
                        continue
                    flows[key].append(
                        RouterFlow(
                            sink_id=_first_str(witness.get("sink_ids")),
                            destination_selector=op_selector.lower(),
                            amount_kind=(amount or {}).get("kind") if isinstance(amount, dict) else None,
                            target_constraint_state=(
                                (constraint or {}).get("state") if isinstance(constraint, dict) else None
                            ),
                            target_constraint_guard=(
                                (constraint or {}).get("guard") if isinstance(constraint, dict) else None
                            ),
                        )
                    )
    plane.flows = {key: tuple(rows_here) for key, rows_here in sorted(flows.items())}
    return plane


def _first_str(values: Any) -> str | None:
    return next((v for v in values if isinstance(v, str)), None) if isinstance(values, list) else None
