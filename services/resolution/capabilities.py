"""CapabilityExpr — resolver-side authority-set algebra.

The static stage produces a ``PredicateTree`` per guarded function;
the resolver evaluates the tree against on-chain state and emits a
``CapabilityExpr``. This module defines that type plus the closed,
total combinators (intersect/union/negate) called by the evaluator.

Per v4 plan + v6 round-3 fix #4 (closed combinators with confidence-
aware quality), the capability vocabulary is:

  finite_set            — exact / lower_bound / upper_bound members
  threshold_group       — Safe-style M-of-N
  cofinite_blacklist    — "anyone except these"
  signature_witness     — anyone with a valid signature from <signer>
  external_check_only   — query-only (EIP-1271, oracle policy)
  conditional_universal — anyone, given side conditions (time/business/etc.)
  unsupported           — typed reason; propagates fail-closed under AND
  AND, OR               — structural composition when no closed-form result

Combinators are TOTAL functions: every combination either resolves to
a typed capability or returns ``unsupported(reason)``. Never raises.
"""

from __future__ import annotations

from schemas.resolution_schemas import (
    CapabilityConfidence as Confidence,
)
from schemas.resolution_schemas import (
    CapabilityExpr,
    CapKind,
    Condition,
    ExternalCheck,
    MembershipQuality,
    _canon_addresses,
)
from schemas.resolution_schemas import (
    CapabilitySubject as Subject,
)

__all__ = [
    "CapKind",
    "CapabilityExpr",
    "Condition",
    "Confidence",
    "ExternalCheck",
    "MembershipQuality",
    "Subject",
    "intersect",
    "negate",
    "union",
]

# ---------------------------------------------------------------------------
# Combinators
# ---------------------------------------------------------------------------


def intersect(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    """``a AND b`` — every caller in both. Total over all kinds."""
    # unsupported absorbs.
    if a.kind == "unsupported":
        return CapabilityExpr.unsupported(f"intersect_with_unsupported_{a.unsupported_reason}")
    if b.kind == "unsupported":
        return CapabilityExpr.unsupported(f"intersect_with_unsupported_{b.unsupported_reason}")

    # X ∩ conditional_universal(c) — preserve X with c appended. conditional_universal
    # is pure side-conditions (anyone, given C); it never constrains the caller set,
    # so this holds for either subject. Handled BEFORE the cross-subject divert so a
    # bound check AND-ed with a root side-condition stays the bound check rather than
    # collapsing to a public path. (Preserves test_intersect_finite_with_conditional_universal_keeps_set.)
    if a.kind == "conditional_universal":
        return _attach_conditions(b, a.conditions)
    if b.kind == "conditional_universal":
        return _attach_conditions(a, b.conditions)

    # Cross-dimension AND (root caller ∩ bound intermediate). The bound side is a
    # runtime side-condition on a downstream call, NOT a narrowing of the end-user
    # caller set — attaching it as a condition preserves the real callers, whereas
    # set-intersection would compute {users} ∩ {intermediate} = ∅. Covers every
    # remaining shape (finite_set, external_check_only, cofinite_blacklist, …);
    # same-subject pairs fall through to the set algebra unchanged. See ``Subject``.
    if a.subject != b.subject:
        return _intersect_cross_subject(a, b)

    # finite_set ∩ finite_set
    if a.kind == "finite_set" and b.kind == "finite_set":
        return _intersect_finite(a, b)

    # finite_set ∩ cofinite_blacklist (and reverse)
    if a.kind == "finite_set" and b.kind == "cofinite_blacklist":
        return _intersect_finite_blacklist(a, b)
    if a.kind == "cofinite_blacklist" and b.kind == "finite_set":
        return _intersect_finite_blacklist(b, a)

    # cofinite_blacklist ∩ cofinite_blacklist
    if a.kind == "cofinite_blacklist" and b.kind == "cofinite_blacklist":
        # Anyone not in (a.blacklist ∪ b.blacklist).
        return CapabilityExpr.cofinite_blacklist(_canon_addresses((a.blacklist or []) + (b.blacklist or [])))

    # threshold_group ∩ X — defer to structural AND.
    if a.kind == "threshold_group" or b.kind == "threshold_group":
        return CapabilityExpr.structural_and([a, b])

    # signature_witness / external_check_only — structural AND.
    return CapabilityExpr.structural_and([a, b])


def union(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    """``a OR b`` — caller in either. Total."""
    if a.kind == "unsupported":
        return CapabilityExpr.structural_or([a, b])
    if b.kind == "unsupported":
        return CapabilityExpr.structural_or([a, b])

    # Cross-dimension OR: a bound-subject alternative (e.g. an inlined downstream
    # call's authorization) is a distinct route, not an additional end-user caller.
    # Keep both as a structural OR rather than merging an intermediate address into
    # the root member list (which would mint a phantom end-user principal). See
    # ``Subject``.
    if a.subject != b.subject:
        return CapabilityExpr.structural_or([a, b])

    if a.kind == "finite_set" and b.kind == "finite_set":
        return _union_finite(a, b)

    if a.kind == "cofinite_blacklist" and b.kind == "cofinite_blacklist":
        # Anyone not in (a.blacklist ∩ b.blacklist).
        ab = set((a.blacklist or []))
        bb = set((b.blacklist or []))
        return CapabilityExpr.cofinite_blacklist(_canon_addresses(list(ab & bb)))

    # finite_set ∪ cofinite_blacklist: cofinite minus members already in
    # finite_set (those are still in finite_set, so allowed).
    if a.kind == "finite_set" and b.kind == "cofinite_blacklist":
        return _union_finite_blacklist(a, b)
    if a.kind == "cofinite_blacklist" and b.kind == "finite_set":
        return _union_finite_blacklist(b, a)

    if a.kind == "conditional_universal" and b.kind == "conditional_universal" and a.conditions == b.conditions:
        return a

    # X ∪ conditional_universal — structural OR (anyone, with c) is
    # not the same as X.
    return CapabilityExpr.structural_or([a, b])


def negate(a: CapabilityExpr) -> CapabilityExpr:
    """``NOT a`` — used when a leaf has operator=falsy / op=ne and the
    underlying capability needs inversion. Total."""
    if a.kind == "finite_set":
        if a.membership_quality != "exact":
            return CapabilityExpr.unsupported("negate_partial_set")
        return CapabilityExpr.cofinite_blacklist(
            list(a.members or []),
            confidence=a.confidence,
            conditions=a.conditions,
            subject=a.subject,
        )
    if a.kind == "cofinite_blacklist":
        return CapabilityExpr.finite_set(
            list(a.blacklist or []),
            quality="exact",
            confidence=a.confidence,
            conditions=a.conditions,
            subject=a.subject,
        )
    if a.kind == "conditional_universal":
        # Negation of "anyone if C" is "no one if C" — empty set with
        # the condition negated. Concretely: empty set if C, full
        # set if NOT C. We emit unsupported because the negation of
        # a condition isn't always representable as a typed
        # condition (e.g., negation of a business invariant).
        return CapabilityExpr.unsupported("negate_conditional_universal")
    if a.kind in ("threshold_group", "signature_witness", "external_check_only"):
        return CapabilityExpr.unsupported(f"negate_unsupported_capability_{a.kind}")
    if a.kind == "unsupported":
        return CapabilityExpr.unsupported(f"negate_of_{a.unsupported_reason}")
    if a.kind in ("AND", "OR"):
        # De Morgan: NOT(AND) = OR(NOT each); NOT(OR) = AND(NOT each).
        # But each child's negate may produce unsupported; that's
        # propagated.
        flipped = [negate(c) for c in a.children]
        if a.kind == "AND":
            return CapabilityExpr.structural_or(flipped)
        return CapabilityExpr.structural_and(flipped)
    return CapabilityExpr.unsupported(f"negate_unknown_kind_{a.kind}")


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _intersect_finite(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    am = set(a.members or [])
    bm = set(b.members or [])
    common = _canon_addresses(list(am & bm))
    quality = _intersect_quality(a.membership_quality, b.membership_quality)
    if quality is None:
        return CapabilityExpr.structural_and([a, b])
    confidence = _meet_confidence(a.confidence, b.confidence)
    conditions = list(a.conditions) + list(b.conditions)
    # Reached only for same-subject pairs (cross-subject diverts before the kind
    # dispatch), so a.subject == b.subject — carry it onto the result.
    cap = CapabilityExpr.finite_set(
        common,
        quality=quality,
        confidence=confidence,
        conditions=conditions,
        subject=a.subject,
    )
    cap.trace = list(a.trace) + list(b.trace)
    return cap


def _union_finite(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    am = list(a.members or [])
    bm = list(b.members or [])
    merged = _canon_addresses(am + bm)
    quality = _union_quality(a.membership_quality, b.membership_quality)
    if quality is None:
        return CapabilityExpr.structural_or([a, b])
    confidence = _meet_confidence(a.confidence, b.confidence)
    conditions = list(a.conditions) + list(b.conditions)
    cap = CapabilityExpr.finite_set(
        merged,
        quality=quality,
        confidence=confidence,
        conditions=conditions,
        subject=a.subject,
    )
    cap.trace = list(a.trace) + list(b.trace)
    return cap


def _intersect_finite_blacklist(finite: CapabilityExpr, blacklist: CapabilityExpr) -> CapabilityExpr:
    """``finite ∩ cofinite_blacklist`` = ``finite − blacklist``."""
    members_set = set(finite.members or [])
    bl = set(blacklist.blacklist or [])
    out = _canon_addresses(list(members_set - bl))
    cap = CapabilityExpr.finite_set(
        out,
        quality=finite.membership_quality,
        confidence=_meet_confidence(finite.confidence, blacklist.confidence),
        conditions=list(finite.conditions) + list(blacklist.conditions),
    )
    cap.trace = list(finite.trace) + list(blacklist.trace)
    return cap


def _union_finite_blacklist(finite: CapabilityExpr, blacklist: CapabilityExpr) -> CapabilityExpr:
    """``finite ∪ cofinite_blacklist`` = ``cofinite_blacklist − finite``."""
    bl = set(blacklist.blacklist or [])
    fin = set(finite.members or [])
    out = _canon_addresses(list(bl - fin))
    return CapabilityExpr.cofinite_blacklist(
        out,
        confidence=_meet_confidence(finite.confidence, blacklist.confidence),
        conditions=list(finite.conditions) + list(blacklist.conditions),
    )


def _intersect_quality(qa: MembershipQuality, qb: MembershipQuality) -> MembershipQuality | None:
    """Quality lattice for intersect:
    exact ∩ exact   = exact
    exact ∩ lower   = lower_bound (members must be in both;
                       the partial side may have more)
    lower ∩ lower   = lower_bound
    upper ∩ upper   = structural (lose the upper bound)
    mixed lower/upper → structural
    """
    if qa == qb == "exact":
        return "exact"
    if {qa, qb} <= {"exact", "lower_bound"}:
        return "lower_bound"
    if qa == qb == "upper_bound":
        return None  # signal: defer to structural
    return None


def _union_quality(qa: MembershipQuality, qb: MembershipQuality) -> MembershipQuality | None:
    """Quality lattice for union:
    exact ∪ exact     = exact (members from either are in result)
    exact ∪ lower     = lower_bound (known-in-either, may have more)
    lower ∪ lower     = lower_bound
    upper ∪ upper     = upper_bound (possible-in-either)
    mixed lower/upper → structural
    """
    if qa == qb == "exact":
        return "exact"
    if {qa, qb} <= {"exact", "lower_bound"}:
        return "lower_bound"
    if qa == qb == "upper_bound":
        return "upper_bound"
    return None


def _meet_confidence(a: Confidence, b: Confidence) -> Confidence:
    """Confidence lattice meet (least-confident wins)."""
    order = {"enumerable": 2, "partial": 1, "check_only": 0}
    if order[a] <= order[b]:
        return a
    return b


def _attach_conditions(cap: CapabilityExpr, conditions: list[Condition]) -> CapabilityExpr:
    """Returns a copy of ``cap`` with ``conditions`` appended.
    conditional_universal stays conditional_universal but with the
    extra conditions in the list (no special compress)."""
    if not conditions:
        return cap
    return CapabilityExpr(
        kind=cap.kind,
        members=list(cap.members) if cap.members is not None else None,
        threshold=cap.threshold,
        blacklist=list(cap.blacklist) if cap.blacklist is not None else None,
        signer=cap.signer,
        check=cap.check,
        conditions=list(cap.conditions) + list(conditions),
        unsupported_reason=cap.unsupported_reason,
        children=list(cap.children),
        membership_quality=cap.membership_quality,
        confidence=cap.confidence,
        last_indexed_block=cap.last_indexed_block,
        trace=list(cap.trace),
        subject=cap.subject,
    )


def _intersect_cross_subject(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    """AND of two capabilities on different caller dimensions (one ``root``, one
    ``bound``).

    The bound side constrains an intermediate-contract caller (an inlined
    downstream call's ``requiresAuth``), not the function's end-user caller — it is
    a runtime side-condition. Fold it onto the root side as condition(s) so the
    real caller set survives, rather than set-intersecting (``{users} ∩ {teller}``
    = ∅). The root side keeps its kind: an empty root set stays exact-empty (→
    ``resolved_empty``), a populated one keeps its members. Because the bound side
    becomes a condition (not a finite_set child), an empty bound set can never make
    the AND look ``resolved_empty``.
    """
    root, bound = (a, b) if b.subject == "bound" else (b, a)
    return _attach_conditions(root, _bound_as_conditions(bound))


def _bound_as_conditions(bound: CapabilityExpr) -> list[Condition]:
    """Render a bound-subject capability as side-condition(s): carry forward any
    conditions it already accumulated, plus one describing the delegated check."""
    return list(bound.conditions) + [Condition(kind="business", description=_bound_condition_description(bound))]


def _bound_condition_description(bound: CapabilityExpr) -> str:
    target = bound.check.target_address if bound.check is not None else None
    selector = bound.check.target_call_selector if bound.check is not None else None
    if target is None:
        for step in bound.trace or []:
            if isinstance(step, dict) and step.get("target"):
                target = step.get("target")
                selector = selector or step.get("selector")
                break
    if target is not None:
        sel = f".{selector}" if selector else ""
        return f"delegated authorization: intermediate contract must be authorized for {target}{sel}"
    return "delegated cross-contract authorization (intermediate-contract caller)"
