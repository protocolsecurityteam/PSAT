"""The hop census, the frontier behind it, and closure over the act-as walk."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.fold.types import _WalkedHop
from services.scoring.reach import HOP_REFUSED_CONDITION, HOP_REFUSED_CONFERRAL, HOP_REFUSED_SCOPE
from services.scoring.reach import hop_bound as _hop_bound

# Never asked at this hop (an earlier hop broke the path), so distinct from an act-as refusal.
ACT_AS_CALLER_UNREACHED = "caller_not_reachable_from_the_seized_node"


# The census has no instance, so it asks the class-wide union: an upper bound, labelled as one.
_CENSUS_GATE_CAPABILITIES = tuple(sorted(K.GATE_CONTROL_CAPABILITIES))


# Edge rows duplicate pairs (2,937 over 565), and a pair walks if any edge does, so report each pair's furthest-reaching
# answer.
_CONFERRAL_RANK = {
    P.CONFERRAL_CONFERRED: 0,
    P.CONFERRAL_ROLE_NOT_LICENSED: 1,
    P.CONFERRAL_VARIABLE_NOT_REWRITTEN: 2,
    P.CONFERRAL_WRITES_NOT_EXTRACTED: 3,
    P.CONFERRAL_SCOPE_NOT_DETERMINED: 4,
}


# A fully bound pair reports its sharpest bound: condition, then conferral, then scope.
_REFUSAL_RANK = {HOP_REFUSED_CONDITION: 0, HOP_REFUSED_CONFERRAL: 1, HOP_REFUSED_SCOPE: 2}


_SCOPE_KIND_RANK = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 1, P.SCOPE_NOT_DETERMINED: 2}


def _hop_census(closure: P.ControlClosure, conditions: P.ConditionPlane, conferral: P.ConferralPlane) -> dict[str, Any]:
    """Every hop in the graph, by what each class of capability can prove of it.

    Counted over distinct ``(principal, anchor)`` pairs, since edges repeat per read. Published even when no bound
    fired, so "never fired" differs from "never wired". Gate control is the union over the five gate capabilities, with
    ``by_capability`` per capability; the union over-counts across both capabilities and instances.
    """
    pairs: dict[tuple[str, str], list[P.ControlEdge]] = defaultdict(list)
    for edge in closure.edges:
        pairs[(edge.principal, edge.anchor)].append(edge)
    census: dict[str, Any] = {"distinct_hops": len(pairs), "edges": len(closure.edges)}

    def count(grant: P.GateGrant | None) -> dict[str, Any]:
        counts: dict[str, int] = {"walked": 0, HOP_REFUSED_SCOPE: 0, HOP_REFUSED_CONFERRAL: 0, HOP_REFUSED_CONDITION: 0}
        counts.update(dict.fromkeys(P.WALKED_COVERAGE, 0))
        by_scope_kind = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 0, P.SCOPE_NOT_DETERMINED: 0}
        conferral_outcomes: dict[str, int] = dict.fromkeys(P.CONFERRAL_OUTCOMES, 0)
        for (principal, anchor), edges in pairs.items():
            if grant is not None:
                outcomes = [grant.confers(edge.scope, edge.anchor).outcome for edge in edges]
                conferral_outcomes[min(outcomes, key=lambda o: _CONFERRAL_RANK[o])] += 1
            bounds = [(_hop_bound(edge, conditions, grant=grant), edge) for edge in edges]
            walked = [edge for bound, edge in bounds if bound is None]
            if not walked:
                refusals = [str(bound["reason"]) for bound, _ in bounds if bound is not None]
                counts[min(refusals, key=lambda r: _REFUSAL_RANK[r])] += 1
                continue
            counts["walked"] += 1
            by_scope_kind[min((edge.scope.kind for edge in walked), key=lambda k: _SCOPE_KIND_RANK[k])] += 1
            counts[conditions.hop(principal, anchor).coverage or P.WALKED_NO_FUNCTION] += 1
        out: dict[str, Any] = dict(counts)
        out["walked_by_scope_kind"] = dict(sorted(by_scope_kind.items()))
        if grant is not None:
            out["conferral"] = dict(sorted(conferral_outcomes.items()))
        return out

    census["code_control"] = count(None)
    by_capability: dict[str, Any] = {}
    walked_by_any: set[tuple[str, str]] = set()
    conferred_by_any: set[tuple[str, str]] = set()
    for capability in _CENSUS_GATE_CAPABILITIES:
        grant = conferral.capability_grant(capability)
        by_capability[capability] = count(grant)
        for pair, edges in pairs.items():
            for edge in edges:
                if grant.confers(edge.scope, edge.anchor).conferred:
                    conferred_by_any.add(pair)
                    if _hop_bound(edge, conditions, grant=grant) is None:
                        walked_by_any.add(pair)
    census["gate_control"] = {
        "walked_by_at_least_one_gate_capability": len(walked_by_any),
        "conferred_by_at_least_one_gate_capability": len(conferred_by_any),
        "conferred_by_none": len(pairs) - len(conferred_by_any),
        "reading": (
            # Only states what this function establishes; it runs before any finding exists.
            "the union over the five gate capabilities, each asked with the class-wide union of "
            "what its witnesses rewrite. It is an upper bound on every real walk twice over — "
            "over capabilities, because a pair walked by any one of the five is counted here, "
            "and over instances, because each capability is asked with the union of what its "
            "witnesses rewrite anywhere rather than with one instance's own set. Nothing here "
            "counts findings, and no row is claimed to walk this width. by_capability is "
            "the per-capability answer at the same class-wide width"
        ),
    }
    census["gate_control_by_capability"] = by_capability
    # Counted three ways: only pairs with no labelled edge can lose a hop to this rule, and deduping alone would show 55
    # role edges as 9.
    unlabelled_edges = [edge for edge in closure.edges if not edge.scope.is_determined]
    unlabelled_pairs = {(edge.principal, edge.anchor) for edge in unlabelled_edges}
    by_relation: dict[str, int] = defaultdict(int)
    for edge in unlabelled_edges:
        by_relation[str(edge.relation) if edge.relation else edge.witness] += 1
    census["scope_not_determined"] = {
        "edges": len(unlabelled_edges),
        "pairs_carrying_one": len(unlabelled_pairs),
        "pairs_with_no_labelled_edge": sum(
            1 for pair in unlabelled_pairs if all(not edge.scope.is_determined for edge in pairs[pair])
        ),
        "edges_by_relation": dict(sorted(by_relation.items())),
        "reading": (
            "edges whose label names neither a role nor a state variable — the role_principal "
            "rows that restate their own relation, and the column witnesses that carry no label "
            "at all. Every one is published as not_determined for gate control and none is "
            "dropped; code control does not ask the question"
        ),
    }
    census["reading"] = (
        "what each class could establish about every hop the closure holds, before any "
        "signal seeds it. A hop counted not_determined here is withheld from a finding "
        "only when that finding's walk actually needs it and no other path reaches the "
        "destination; the per-finding lists carry that narrower population. The four "
        "walked_* counts partition `walked` by what was READ to walk it: only "
        "walked_on_fully_analysed_conditions rests on a surface read in full, "
        "walked_on_partly_analysed_conditions found no guard on the functions it could read "
        "and could not read all of them, and the last two are hops where no condition "
        "existed to read at all, walked on the edge alone. walked_by_scope_kind partitions "
        "the same total by what the edge label named. `conferral` partitions every hop by "
        "the CONFERRAL test — whether the gate is witnessed to seize the authority the hop "
        "runs on — which replaced the label-presence test that walked any labelled edge"
    )
    return census


def _behind_the_frontier(
    gaps: list[dict[str, Any]],
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    value_plane: P.ValuePlane,
    reached: set[str],
) -> dict[str, Any]:
    """The entities a row's withheld hops hide.

    Walks the closure from withheld destinations with no scope bound (code control's walk) and subtracts what the row
    reached. An upper bound on what's hidden, not a claim of reach.
    """
    if not gaps:
        return {"hops": 0, "entities": 0, "entity_keys": [], "reading": "no hop was withheld"}
    frontier = {str(gap["destination"]) for gap in gaps}
    seen, _, _, _ = _closure(frontier, closure, conditions, grant=None)
    behind = sorted({value_plane.canonical(key) for key in seen} - reached)
    return {
        "hops": len(gaps),
        "entities": len(behind),
        "entity_keys": behind,
        "reading": (
            "entities the closure places behind the hops this row could not establish, and which "
            "the row therefore does NOT reach. Sized by walking from the withheld destinations "
            "with no scope bound — the widest walk this fold performs — so it is an upper bound "
            "on the withheld subtree, published because a withheld frontier hop otherwise hides "
            "everything behind it with no trace in the document"
        ),
    }


def _closure(
    seeds: set[str], closure: P.ControlClosure, conditions: P.ConditionPlane, *, grant: P.GateGrant | None
) -> tuple[set[str], list[dict[str, Any]], dict[str, set[P.LicensedFunction]], list[_WalkedHop]]:
    """The reach the walk proves, the hops it couldn't establish, and what walked hops license at each destination.

    ``grant`` is the walking gate; ``None`` is code control. Returns:

    1. the reach set;
    2. un-walked hops, deduped on ``(caller, destination)``;
    3. licensed functions per raw anchor (callers re-key to canonical), absent for state-variable-only destinations;
    4. walked hops as (caller, destination, licensed), since composition needs the caller.

    The zero address is refused at every hop even though ``load_control_closure`` already drops it, so the guarantee
    doesn't depend on how the closure was built.
    """
    seen: set[str] = set()
    withheld: dict[tuple[str, str], dict[str, Any]] = {}
    licensed: dict[str, set[P.LicensedFunction]] = defaultdict(set)
    walked: dict[tuple[str, str], set[P.LicensedFunction]] = {}
    stack = [key for key in sorted(seeds) if not P.is_zero_key(key)]
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for edge in closure.edges_from(key):
            if P.is_zero_key(edge.anchor):
                continue
            bound = _hop_bound(edge, conditions, grant=grant)
            if bound is None:
                here: set[P.LicensedFunction] = set()
                if grant is not None:
                    here = set(grant.confers(edge.scope, edge.anchor).licensed)
                    licensed[edge.anchor].update(here)
                walked.setdefault((edge.principal, edge.anchor), set()).update(here)
                if edge.anchor not in seen:
                    stack.append(edge.anchor)
                continue
            withheld.setdefault((edge.principal, edge.anchor), bound)
    # Reached by another path, so nothing was withheld.
    gaps = [bound for pair, bound in sorted(withheld.items()) if pair[1] not in seen]
    hops = [
        _WalkedHop(caller=pair[0], destination=pair[1], licensed=frozenset(rows))
        for pair, rows in sorted(walked.items())
    ]
    return seen, gaps, {key: set(rows) for key, rows in sorted(licensed.items()) if rows}, hops
