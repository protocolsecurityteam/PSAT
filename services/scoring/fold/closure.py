"""The hop census, the frontier behind it, and closure over the act-as walk."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.fold.types import _WalkedHop
from services.scoring.reach import HOP_REFUSED_CONDITION, HOP_REFUSED_CONFERRAL, HOP_REFUSED_SCOPE
from services.scoring.reach import hop_bound as _hop_bound

# A licensed hop the composition walk never offered, because it never reached
# the hop's CALLER: every path from the seized node to it broke at an earlier
# hop that carried no act-as witness. Not an act-as refusal at this hop — the
# question was never asked here — and named separately for exactly that reason.
ACT_AS_CALLER_UNREACHED = "caller_not_reachable_from_the_seized_node"


# Every gate-control capability, each asking the conferral question with its own
# witness. The census has no signal instance to ask, so it asks the class-wide
# union — an upper bound on what any one instance's walk can confer, and labelled
# as one wherever it is published.
_CENSUS_GATE_CAPABILITIES = tuple(sorted(K.GATE_CONTROL_CAPABILITIES))


# Duplicate edge rows are real — 2,937 rows over 565 distinct pairs — and a pair
# is walked when ANY of its edges licenses it, so the census counts pairs and has
# to pick which of a pair's answers to report. Each ranking reports the answer
# that got FURTHEST, so a pair is never filed under a shortfall one of its own
# edges did not have. Ordering is by rank, ties impossible (the keys are total).
_CONFERRAL_RANK = {
    P.CONFERRAL_CONFERRED: 0,
    # The gate was asked and the label was readable; these two are the real
    # negative answers and rank alike.
    P.CONFERRAL_ROLE_NOT_LICENSED: 1,
    P.CONFERRAL_VARIABLE_NOT_REWRITTEN: 2,
    # Coverage shortfalls: nothing about this gate or this label was read.
    P.CONFERRAL_WRITES_NOT_EXTRACTED: 3,
    P.CONFERRAL_SCOPE_NOT_DETERMINED: 4,
}


# A pair every edge of which was bound reports the SHARPEST bound it hit: being
# disproved at the destination is a fact about the destination's own code, and
# outranks "this gate does not confer it", which outranks "the label said
# nothing".
_REFUSAL_RANK = {HOP_REFUSED_CONDITION: 0, HOP_REFUSED_CONFERRAL: 1, HOP_REFUSED_SCOPE: 2}


# Among the edges that DID walk a pair, the most specific scope reported it.
_SCOPE_KIND_RANK = {P.SCOPE_ROLES: 0, P.SCOPE_STATE_VAR: 1, P.SCOPE_NOT_DETERMINED: 2}


def _hop_census(closure: P.ControlClosure, conditions: P.ConditionPlane, conferral: P.ConferralPlane) -> dict[str, Any]:
    """Every hop in the graph, by what each class of capability can prove of it.

    Counted over DISTINCT ``(principal, anchor)`` pairs. ``control_graph_edges``
    holds one row per witnessed read — several times the pair count — so an
    edge-keyed census would report the same hop as many findings as the resolver
    happened to look.

    Published whether or not a bound ever bit: a rule with no fired count and a
    rule that was never wired read identically from the outside.

    Gate control is now capability-dependent — ownership.transfer and
    authority.replace confer different hops — so the class-level block is the
    UNION over the five gate capabilities (a hop is counted walked there if ANY
    of them confers it) and ``by_capability`` carries each one's own answer. The
    union is an upper bound twice over: over the capabilities, and over the
    instances, because each capability is asked with the union of what its
    witnesses rewrite anywhere rather than with one function's own set.
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
            # "and no finding walks it" was here: a universal over the findings
            # population, authored in a census that runs over the control
            # closure BEFORE any finding exists and therefore never asked it.
            # What is stated instead is the property this function does
            # establish — why the union over-counts — which holds at every value
            # of the counters.
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
    # The label-names-nothing population, counted three ways because a pair is
    # not an edge and a pair carrying one unlabelled edge is not a pair a gate
    # can be withheld on: the walk reaches a destination if ANY of the pair's
    # edges confers it, so only pairs with no labelled edge at all can lose their
    # hop to this rule. Publishing only the deduped number would report the 55
    # unlabelled role edges as 9.
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
    """The entities a row's withheld hops hide, counted rather than left implicit.

    A hop published as ``not_determined`` names one destination. The closure
    places a whole subtree behind that destination, and none of it appears on the
    row: two published hops can withhold twenty-two entities, twenty of which are
    named nowhere in the document. The withheld population is therefore SIZED
    here, by walking the closure from the withheld destinations with no scope
    bound at all — the widest walk this fold performs, which is code control's —
    and subtracting what the row reached anyway.

    This is the size of what was withheld and NOT a claim of reach: the row does
    not reach these entities, that is the whole point. The number is an upper
    bound on the subtree for the same reason the code-control walk is an upper
    bound on any gate's, and it is published as one.
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
    """The reach the walk proves, every hop it could not establish, and what the
    hops it did walk LICENSE at each destination.

    ``grant`` is the gate doing the walking; ``None`` is code control, which asks
    no conferral question. The third return value is the role -> selector join's
    output, keyed by the RAW anchor: the named functions a walked ``roles`` hop
    licenses there. Callers that publish it re-key onto the canonical entity,
    which is what the reach set is keyed on and what a consumer joins against.
    It is the reach's own answer to "to do *what*", and it is
    what a compositional magnitude is later attributed to — a destination reached
    only through state-variable hops has no entry, because nothing named which of
    its functions the gate reaches.

    The burn sentinel is refused at every hop. ``load_control_closure`` already
    refuses ``0x0`` at both ends of an edge, so on the production path that guard
    never fires. It is here because the fold's guarantee must not be a property
    of how the closure was BUILT: the sentinel is the single largest fan-out in
    the graph, and one edge into it — from a repoint witness, a hand-built
    closure, or a future loader — would otherwise hand a row everything behind
    ``msg.sender != 0x0``. Refusing reach is always monotone, so the second line
    of defence costs nothing.

    The second return value is the hops this walk did not walk AS PROVEN, keyed
    on the distinct ``(caller, destination)`` pair. The edge table carries one
    row per witnessed read — 2,937 rows over 565 pairs on the reference corpus —
    so counting refusals per EDGE would report the same withheld hop five times
    and read as five findings.

    The fourth return value is the walked hops themselves — (caller, destination,
    what that hop licensed there). The licensed map above collapses every caller
    that reached a destination into one entry, which is the right shape for "what
    does this row reach it to do" and the wrong one for composing a magnitude:
    the question a composition asks is whether THAT caller can be made to act,
    and a map keyed on the destination alone cannot say which caller a licence
    came from.
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
    # A hop another path reached anyway withheld nothing: the destination is in
    # reach either way, and reporting it as a gap would publish a shortfall the
    # walk does not have.
    gaps = [bound for pair, bound in sorted(withheld.items()) if pair[1] not in seen]
    hops = [
        _WalkedHop(caller=pair[0], destination=pair[1], licensed=frozenset(rows))
        for pair, rows in sorted(walked.items())
    ]
    return seen, gaps, {key: set(rows) for key, rows in sorted(licensed.items()) if rows}, hops
