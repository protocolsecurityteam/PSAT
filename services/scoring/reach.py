"""Scorer-authoritative reach, computed once and shipped to the surface.

The surface used to run its own ungated client BFS over display edges and so
published reach on paths the score document holds as ``not_determined``. This
module is the single server-side computation both consumers share: the per-hop
verdict is :func:`hop_bound` — the fold imports it back, so the two cannot
drift — and every hop the walk could not establish is published as a frontier
entry, a distinct third state, never dropped and never walked.
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

# A stored-authority anchor's outgoing edges are not blindly expanded: being
# the slot's value is only witnessed to matter via a distilled gate signal,
# which walks under its own grant. Without one, what exercising the authority
# reaches is a question nothing answered.
AUTHORITY_EXERCISE_NOT_WITNESSED = "authority_exercise_not_witnessed"
_AUTHORITY_EXERCISE_BASIS = "no witness of what exercising this stored authority reaches"


def hop_bound(edge: P.ControlEdge, conditions: P.ConditionPlane, *, grant: P.GateGrant | None) -> dict[str, Any] | None:
    """Why this hop is NOT walked as proven, or ``None`` when it is.

    Two bounds, in the order that costs least to decide. The SCOPE bound is
    gate-control's alone — ``grant`` is the gate asking, and ``None`` is code
    control, which does not ask: controlling the code exercises everything the
    code is authorized to exercise, whatever the label happened to record.

    For a gate the question is CONFERRAL, not label presence: a ``roles N`` edge
    is walked where the role -> selector join names functions role N licenses at
    the destination, and a ``state_var`` edge where the gate's own witness is
    observed to rewrite a variable of that name. A label naming a scope the gate
    is not witnessed to seize (`hook`, `vault`, `roleRegistry`) is no longer
    enough, and neither is a label naming nothing at all — 55 of the role edges
    restate their own relation and name no role.

    The CONDITION bound is shared: the destination's own guards may pin their
    caller to the destination itself, and no authority relation makes one
    address another.

    A refused hop is a published ``not_determined``, never a silent drop and
    never a proven negative.
    """
    if grant is not None:
        verdict = grant.confers(edge.scope, edge.anchor)
        if not verdict.conferred:
            return {
                "caller": edge.principal,
                "destination": edge.anchor,
                # The unlabelled edges keep their own reason: "the label named
                # nothing" and "the label named something this gate does not
                # seize" are different shortfalls and only the first is a
                # pipeline gap.
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
    """One walk: min hop per reached key, the parent that proved it, the refusals.

    Seeds start at hop 1 (they are already reached by their own witness); every
    further hop is admitted only where :func:`hop_bound` returns ``None`` —
    the fold's verdict, computed by the fold's code. The burn sentinel is
    refused at every hop, same second line of defence as ``fold._closure``.
    Refusals are deduped on the ``(caller, destination)`` pair and, as in the
    fold, a hop another path reached anyway withheld nothing.
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

    Min-hop merging across walks can leave a child's count from one walk while
    its parent was later re-admitted shorter by another. Every ``parents`` edge
    was individually walked, so relaxing along them never claims new reach —
    it only stops a chip's number exceeding the length of its own lit route.
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
) -> dict[str, Any]:
    """What ``entity`` provably reaches, and every path that is not_determined.

    Three evidence sources, merged with ``reached`` winning over the frontier:

    1. ``entity``'s own closure edges. The anchor is reached at hop 1. A column
       witness (``relation is None``: ``contracts.admin`` / ``contracts.beacon``)
       is code control — holding the slot is upgrade power — so the walk
       continues from the anchor with ``grant=None``. Any other relation is a
       stored authority whose exercise no gate signal witnesses: no blind
       expansion, and each of the anchor's own outgoing edges is published as a
       frontier entry instead.
    2. ``entity``'s current proven-reach signals. Seeds are reached at hop 1;
       a transitive capability walks on from them under its own grant
       (``None`` for code control, ``grant_for`` for a gate — the fold's exact
       inputs). Non-transitive capabilities stop at their seeds with NO
       frontier: non-transitivity is a proven boundary, not a gap.
    3. Merge: min hop wins and ``parents`` records the hop that proved it; a
       frontier entry whose destination is reached anyway is dropped, and a
       hop-verdict entry displaces the less specific authority-exercise one.

    ``canonical`` is the value plane's proxy/impl fold. The walk speaks in raw
    edge anchors and an implementation folded onto its proxy is one entity
    under two of them, so everything is PUBLISHED at the canonical key — the
    same rule the fold applies to its ``reached`` set — or a consumer keying
    nodes by the proxy would silently miss every destination that folds.
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
        # A refusal folding onto its own caller withheld nothing: the
        # destination is the caller's alias, reached the moment the caller was.
        if pair[0] == pair[1]:
            return
        standing = frontier.get(pair)
        if standing is None or standing["reason"] == AUTHORITY_EXERCISE_NOT_WITNESSED:
            frontier[pair] = {**entry, "from": pair[0], "to": pair[1]}

    def merge_walk(seeds: set[str], grant: P.GateGrant | None) -> None:
        dist, parent, gaps = _bfs(seeds, closure, conditions, grant)
        for key, hop in sorted(dist.items()):
            if hop >= 2:
                admit(key, hop, BASIS_WALKED_HOP, parent[key])
        for bound in gaps:
            refuse(
                {
                    "from": str(bound["caller"]),
                    "to": str(bound["destination"]),
                    "reason": str(bound["reason"]),
                    "basis": str(bound["basis"]),
                }
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
        grant = (
            None
            if signal.claim_id in K.CODE_CONTROL_CAPABILITIES
            else conferral.grant_for(
                signal.claim_id,
                signal.function_id,
                entity=entity_key(signal.chain, signal.deployment_address),
                selector=signal.selector,
            )
        )
        merge_walk(seeds, grant)

    _relax(reached, parents, self_keys)
    return {
        "reached": {key: reached[key] for key in sorted(reached)},
        "parents": {key: parents[key] for key in sorted(parents)},
        # Same rule as the fold: a hop another path reached anyway withheld
        # nothing. ``entity`` itself is trivially reached, so a cycle back to
        # it is not an unconfirmed path either.
        "frontier": [
            frontier[pair] for pair in sorted(frontier) if pair[1] not in reached and pair[1] not in self_keys
        ],
    }


def merge_reach(records: Iterable[dict[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """Per-protocol reach maps folded into one entity map.

    Closure edges never cross protocols, but one principal can hold authority
    in two protocols of the same company, so a key collision merges on the same
    rules the walk uses: min hop wins, reached beats frontier, and a
    hop-verdict frontier entry displaces the authority-exercise one.
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
    """entity_key -> reach record, for every entity with any outbound closure
    edge or any current proven-reach signal held.

    Same loaders the fold uses, one pass over shared planes. A signal row that
    could not be typed withholds itself (the score document already publishes
    the fault) and contributes no reach here.

    Published entirely at CANONICAL keys — the value plane's proxy/impl fold,
    on both the outer entity keys and everything inside a record — so the
    block joins against the same keys the score document's ``reached`` set and
    the surface's nodes use. Two raw holders folding onto one canonical entity
    merge on the walk's own rules.
    """
    closure = P.load_control_closure(session, protocol_id)
    conditions = P.load_condition_plane(session, protocol_id)
    conferral = P.load_conferral_plane(session, protocol_id)
    signals, _faults = current_signals_with_faults(session, protocol_id)
    alias, _ambiguous = P.load_entity_alias(session, protocol_id)

    def canonical(key: str) -> str:
        return alias.get(key, key)

    signals_by_principal: dict[str, list[FunctionSignal]] = {}
    for signal in signals:
        if signal.value_state != VALUE_STATE_PROVEN_REACH:
            continue
        for key in sorted({ref.key for ref in signal.principal_refs}):
            signals_by_principal.setdefault(key, []).append(signal)

    entities = sorted(set(closure.principals()) | set(signals_by_principal))
    return merge_reach(
        {canonical(entity): entity_reach(entity, closure, conditions, conferral, signals_by_principal, canonical)}
        for entity in entities
        if not P.is_zero_key(entity)
    )
