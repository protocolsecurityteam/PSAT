"""Scorer-authoritative reach, computed once and shipped to the surface.

Replaces the surface's ungated client BFS, which published reach on paths the score holds as ``not_determined``. The
per-hop verdict is :func:`hop_bound`, which the fold imports so they can't drift; un-established hops are published as
frontier entries.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.population import current_signals_with_faults
from services.scoring.schema import FunctionSignal, entity_key
from utils.scoring_status import VALUE_STATE_PROVEN_REACH

REACH_MODEL = "scorer_closure_v1"

BASIS_CLOSURE_EDGE = "closure_edge"
BASIS_SIGNAL_SEED = "signal_seed"
BASIS_WALKED_HOP = "walked_hop"

HOP_REFUSED_SCOPE = "gate_scope_not_determined"
HOP_REFUSED_CONFERRAL = "gate_does_not_confer_this_scope"
HOP_REFUSED_CONDITION = "caller_condition_not_satisfiable"

# A stored-authority anchor's edges aren't expanded without a distilled gate signal witnessing what exercising it
# reaches.
AUTHORITY_EXERCISE_NOT_WITNESSED = "authority_exercise_not_witnessed"
_AUTHORITY_EXERCISE_BASIS = "no witness of what exercising this stored authority reaches"


def hop_bound(edge: P.ControlEdge, conditions: P.ConditionPlane, *, grant: P.GateGrant | None) -> dict[str, Any] | None:
    """Why this hop is NOT walked as proven, or ``None`` when it is.

    Scope bound (gate control only; ``grant=None`` is code control, which exercises everything): a ``roles N`` edge
    walks where the role -> selector join licenses functions at the destination, a ``state_var`` edge where the gate's
    witness rewrites that variable. Labels naming unseized scopes, or nothing, don't suffice.

    Condition bound (shared): the destination's guards may pin the caller to the destination itself.

    Refused hops are published ``not_determined``.
    """
    if grant is not None:
        verdict = grant.confers(edge.scope, edge.anchor)
        if not verdict.conferred:
            return {
                "caller": edge.principal,
                "destination": edge.anchor,
                # "Named nothing" is a pipeline gap; "named something unseized" isn't, so they keep separate reasons.
                "reason": (
                    HOP_REFUSED_SCOPE if verdict.outcome == P.CONFERRAL_SCOPE_NOT_DETERMINED else HOP_REFUSED_CONFERRAL
                ),
                "conferral": verdict.outcome,
                "capability": grant.capability,
                "relation": edge.relation,
                "witness": edge.witness,
                "edge_label": edge.scope.label,
                "basis": verdict.basis,
            }
    hop = conditions.hop(edge.principal, edge.anchor)
    if hop.state == P.HOP_WALKED:
        return None
    return {
        "caller": edge.principal,
        "destination": edge.anchor,
        "reason": HOP_REFUSED_CONDITION,
        "relation": edge.relation,
        "witness": edge.witness,
        "edge_label": edge.scope.label,
        "basis": hop.basis,
        "surface": hop.surface,
        "functions_consulted": hop.functions_consulted,
        "disproving_conditions": list(hop.disproving),
    }


def _bfs(
    seeds: Iterable[str], closure: P.ControlClosure, conditions: P.ConditionPlane, grant: P.GateGrant | None
) -> tuple[dict[str, int], dict[str, str], list[dict[str, Any]]]:
    """One walk: min hop per reached key, the parent that proved it, and the refusals.

    Seeds are hop 1; further hops need :func:`hop_bound` to return ``None``. The zero address is refused at every hop,
    as in ``fold._closure``. Refusals are deduped by pair and dropped if reached another way.
    """
    dist = {key: 1 for key in sorted(seeds) if not P.is_zero_key(key)}
    parent: dict[str, str] = {}
    refused: dict[tuple[str, str], dict[str, Any]] = {}
    queue = deque(dist)
    while queue:
        key = queue.popleft()
        for edge in closure.edges_from(key):
            if P.is_zero_key(edge.anchor):
                continue
            bound = hop_bound(edge, conditions, grant=grant)
            if bound is None:
                if edge.anchor not in dist:
                    dist[edge.anchor] = dist[key] + 1
                    parent[edge.anchor] = key
                    queue.append(edge.anchor)
                continue
            refused.setdefault((edge.principal, edge.anchor), bound)
    gaps = [bound for pair, bound in sorted(refused.items()) if pair[1] not in dist]
    return dist, parent, gaps


def _relax(reached: dict[str, dict[str, Any]], parents: dict[str, str], self_keys: set[str]) -> None:
    """Shorten each published hop to the ``parents`` route the overlay draws.

    Merging walks can leave a child's count longer than its lit route; every ``parents`` edge was walked, so this claims
    no new reach.
    """
    changed = True
    while changed:
        changed = False
        for child, parent in parents.items():
            entry = reached.get(child)
            if entry is None:
                continue
            parent_hop = 0 if parent in self_keys else (reached.get(parent) or {}).get("hop")
            if parent_hop is not None and parent_hop + 1 < entry["hop"]:
                entry["hop"] = parent_hop + 1
                changed = True


def entity_reach(
    entity: str,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    signals_by_principal: Mapping[str, Sequence[FunctionSignal]],
    canonical: Callable[[str], str] | None = None,
    signals_by_seed: Mapping[str, Sequence[FunctionSignal]] | None = None,
) -> dict[str, Any]:
    """What ``entity`` provably reaches, and every path that is not_determined.

    1. ``entity``'s own closure edges: the anchor is hop 1. Column witnesses (``contracts.admin``/``beacon``) are code
    control and walk on with ``grant=None``; other relations publish the anchor's outgoing edges as frontier.
    2. ``entity``'s proven-reach signals: seeds at hop 1; transitive capabilities walk on under their own grant;
    non-transitive ones stop with no frontier.
    3. Transitive signals seeded at ``entity`` (``signals_by_seed``), so the standpoint shows the same path the finding
    row does.
    4. Merge: min hop wins, ``parents`` records the proving hop, reached beats frontier, and hop-verdict entries
    displace authority-exercise ones.

    Everything is published at ``canonical`` keys, matching the fold's ``reached`` set.
    """
    fold_key = canonical or (lambda key: key)
    self_keys = {entity, fold_key(entity)}
    reached: dict[str, dict[str, Any]] = {}
    parents: dict[str, str] = {}
    frontier: dict[tuple[str, str], dict[str, Any]] = {}

    def admit(key: str, hop: int, basis: str, parent: str) -> None:
        key = fold_key(key)
        parent = fold_key(parent)
        if key in self_keys or key == parent:
            return
        current = reached.get(key)
        if current is None or hop < current["hop"]:
            reached[key] = {"hop": hop, "basis": basis}
            parents[key] = parent

    def refuse(entry: dict[str, Any]) -> None:
        pair = (fold_key(str(entry["from"])), fold_key(str(entry["to"])))
        # Refusal onto the caller's own alias withheld nothing.
        if pair[0] == pair[1]:
            return
        standing = frontier.get(pair)
        if standing is None or standing["reason"] == AUTHORITY_EXERCISE_NOT_WITNESSED:
            frontier[pair] = {**entry, "from": pair[0], "to": pair[1]}

    def merge_walk(seeds: set[str], grant: P.GateGrant | None, hop_offset: int = 0) -> None:
        dist, parent, gaps = _bfs(seeds, closure, conditions, grant)
        for key, hop in sorted(dist.items()):
            if hop >= 2:
                admit(key, hop + hop_offset, BASIS_WALKED_HOP, parent[key])
        for bound in gaps:
            refuse(
                {
                    "from": str(bound["caller"]),
                    "to": str(bound["destination"]),
                    "reason": str(bound["reason"]),
                    "basis": str(bound["basis"]),
                }
            )

    def signal_grant(signal: FunctionSignal) -> P.GateGrant | None:
        if signal.claim_id in K.CODE_CONTROL_CAPABILITIES:
            return None
        return conferral.grant_for(
            signal.claim_id,
            signal.function_id,
            entity=entity_key(signal.chain, signal.deployment_address),
            selector=signal.selector,
        )

    code_seeds: set[str] = set()
    for edge in closure.edges_from(entity):
        if P.is_zero_key(edge.anchor):
            continue
        admit(edge.anchor, 1, BASIS_CLOSURE_EDGE, entity)
        if edge.relation is None:
            code_seeds.add(edge.anchor)
        else:
            for onward in closure.edges_from(edge.anchor):
                if P.is_zero_key(onward.anchor):
                    continue
                refuse(
                    {
                        "from": edge.anchor,
                        "to": onward.anchor,
                        "reason": AUTHORITY_EXERCISE_NOT_WITNESSED,
                        "basis": _AUTHORITY_EXERCISE_BASIS,
                    }
                )
    if code_seeds:
        merge_walk(code_seeds, None)

    for signal in signals_by_principal.get(entity, ()):
        if signal.value_state != VALUE_STATE_PROVEN_REACH:
            continue
        seeds = {key for key in signal.value_entity_keys if not P.is_zero_key(key)}
        for key in sorted(seeds):
            admit(key, 1, BASIS_SIGNAL_SEED, entity)
        if signal.claim_id not in K.TRANSITIVE_CAPABILITIES:
            continue
        merge_walk(seeds, signal_grant(signal))

    # Hops are numbered from this standpoint (hence -1). Only transitive rows are in the map; value seeds aren't
    # standpoints.
    for signal in (signals_by_seed or {}).get(entity, ()):
        merge_walk({entity}, signal_grant(signal), hop_offset=-1)

    _relax(reached, parents, self_keys)
    return {
        "reached": {key: reached[key] for key in sorted(reached)},
        "parents": {key: parents[key] for key in sorted(parents)},
        # Reached another way, or a cycle back to ``entity``, isn't a frontier.
        "frontier": [
            frontier[pair] for pair in sorted(frontier) if pair[1] not in reached and pair[1] not in self_keys
        ],
    }


def merge_reach(records: Iterable[dict[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """Per-protocol reach maps folded into one entity map, using the walk's merge rules (one principal can hold
    authority in two protocols).
    """
    out: dict[str, dict[str, Any]] = {}
    for entities in records:
        for entity, record in sorted(entities.items()):
            standing = out.get(entity)
            if standing is None:
                out[entity] = {
                    "reached": {key: dict(entry) for key, entry in record["reached"].items()},
                    "parents": dict(record["parents"]),
                    "frontier": [dict(entry) for entry in record["frontier"]],
                }
                continue
            for key, entry in record["reached"].items():
                current = standing["reached"].get(key)
                if current is None or entry["hop"] < current["hop"]:
                    standing["reached"][key] = dict(entry)
                    standing["parents"][key] = record["parents"][key]
            merged: dict[tuple[str, str], dict[str, Any]] = {(e["from"], e["to"]): e for e in standing["frontier"]}
            for entry in record["frontier"]:
                pair = (entry["from"], entry["to"])
                held = merged.get(pair)
                if held is None or held["reason"] == AUTHORITY_EXERCISE_NOT_WITNESSED:
                    merged[pair] = dict(entry)
            _relax(standing["reached"], standing["parents"], {entity})
            standing["reached"] = {key: standing["reached"][key] for key in sorted(standing["reached"])}
            standing["parents"] = {key: standing["parents"][key] for key in sorted(standing["parents"])}
            standing["frontier"] = [
                merged[pair] for pair in sorted(merged) if pair[1] not in standing["reached"] and pair[1] != entity
            ]
    return out


def load_protocol_reach(session: Session, protocol_id: int) -> dict[str, dict[str, Any]]:
    """entity_key -> reach record for every entity with an outbound closure edge or a current proven-reach signal.

    Uses the fold's loaders. Untypeable signal rows contribute nothing. Published at canonical keys throughout so it
    joins with the score document and surface nodes.
    """
    closure = P.load_control_closure(session, protocol_id)
    conditions = P.load_condition_plane(session, protocol_id)
    conferral = P.load_conferral_plane(session, protocol_id)
    signals, _faults = current_signals_with_faults(session, protocol_id)
    alias, _ambiguous = P.load_entity_alias(session, protocol_id)

    def canonical(key: str) -> str:
        return alias.get(key, key)

    signals_by_principal: dict[str, list[FunctionSignal]] = {}
    signals_by_seed: dict[str, list[FunctionSignal]] = {}
    for signal in signals:
        if signal.value_state != VALUE_STATE_PROVEN_REACH:
            continue
        for key in sorted({ref.key for ref in signal.principal_refs}):
            signals_by_principal.setdefault(key, []).append(signal)
        if signal.claim_id not in K.TRANSITIVE_CAPABILITIES:
            continue
        for key in sorted(set(signal.value_entity_keys)):
            if not P.is_zero_key(key):
                signals_by_seed.setdefault(key, []).append(signal)

    entities = sorted(set(closure.principals()) | set(signals_by_principal) | set(signals_by_seed))
    return merge_reach(
        {
            canonical(entity): entity_reach(
                entity, closure, conditions, conferral, signals_by_principal, canonical, signals_by_seed
            )
        }
        for entity in entities
        if not P.is_zero_key(entity)
    )
