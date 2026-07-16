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

from dataclasses import dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------


CapKind = Literal[
    "finite_set",
    "threshold_group",
    "cofinite_blacklist",
    "signature_witness",
    "external_check_only",
    "conditional_universal",
    "unsupported",
    "AND",
    "OR",
]

MembershipQuality = Literal["exact", "lower_bound", "upper_bound"]
Confidence = Literal["enumerable", "partial", "check_only"]

# Why a finite_set is empty, when it is. Lets the policy layer tell an
# empty-by-design ceiling (a 2-step accept gate with no pending transfer) apart
# from a silent read gap, and distinguishes the gap's flavor (revert vs empty
# return vs nothing-attempted) so each is classified instead of funneling to one
# ``lower_bound`` sink. ``None`` on a populated set, or on an empty set whose
# emptiness predates this field. See ``predicate_evaluator`` for who sets each.
EmptyReason = Literal[
    "empty_by_design",
    "unreadable_revert",
    "unreadable_empty",
    "needs_enumeration",
    "bad_input",
    "not_read",
]

# Which caller dimension a capability constrains. ``root`` = the function's
# end-user caller (msg.sender / tx.origin at the protected entrypoint). ``bound``
# = an already-resolved intermediate subject — the caller of an *inlined*
# downstream cross-contract call (e.g. a Teller calling ``vault.exit``, where the
# inner ``requiresAuth`` is keyed on the Teller's address, not the end user).
# A bound-subject guard is a runtime side-condition, never a narrowing of the
# end-user principal set: combining it via set-intersection (``{users} ∩ {teller}``)
# wrongly zeroes the real callers. Default ``root`` — everything is an end-user
# gate unless the leaf evaluator proves the subject was already bound.
Subject = Literal["root", "bound"]


# ---------------------------------------------------------------------------
# Helper records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Condition:
    """A side condition that doesn't restrict the principal set but
    must hold at runtime for the function to succeed (time, pause,
    reentrancy, business invariants).

    ``one_shot`` — an initializer-family latch: anyone may call until the
    global latch is consumed, then nobody. Whether it IS consumed is
    on-chain state the resolver annotates onto the serialized condition
    dict (``latch_state``), not a field here. ``permit_sig`` — the open
    path verifies a signature from the affected party (EIP-2612/3009 /
    ecrecover-equality folds that stay open). ``denylist`` — open except a
    finite exclusion (the cofinite projection's typed badge)."""

    kind: Literal[
        "time",
        "pause",
        "reentrancy",
        "business",
        "self_service",
        "one_shot",
        "permit_sig",
        "denylist",
    ]
    description: str = ""
    parameter_index: int | None = None
    parameter_name: str | None = None


@dataclass(frozen=True)
class ExternalCheck:
    """Descriptor for an external_check_only capability — a probe
    interface the UI / API can call to ask 'is this address
    authorized'. The resolver populates the address + selector from
    the predicate's set_descriptor."""

    target_address: str | None
    target_call_selector: str | None
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CapabilityExpr
# ---------------------------------------------------------------------------


def _canon_addresses(values: list[str]) -> list[str]:
    """Lowercase + sort + dedup the address list for stable equality.
    Members are the universal canonical form for set ops."""
    seen: set[str] = set()
    out: list[str] = []
    for v in sorted(values, key=lambda x: x.lower() if isinstance(x, str) else str(x)):
        key = v.lower() if isinstance(v, str) else str(v)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


@dataclass
class CapabilityExpr:
    kind: CapKind
    members: list[str] | None = None
    threshold: tuple[int, list[str]] | None = None
    blacklist: list[str] | None = None
    signer: "CapabilityExpr | None" = None
    check: ExternalCheck | None = None
    conditions: list[Condition] = field(default_factory=list)
    unsupported_reason: str | None = None
    children: list["CapabilityExpr"] = field(default_factory=list)
    membership_quality: MembershipQuality = "exact"
    # Quality of a cofinite_blacklist's ``blacklist`` (the EXCLUDED set), independent of
    # ``membership_quality`` (which describes a finite_set's allow-list). ``exact`` = the
    # exclusion is fully enumerated, so the complement is exactly "anyone else";
    # ``lower_bound`` = at least these are excluded (an un-enumerated denylist), so the
    # complement is an upper bound on who may call. Inert today — every cofinite produced
    # now is exact — and carried for surfacing only; the projection never branches on it.
    blacklist_quality: MembershipQuality = "exact"
    confidence: Confidence = "enumerable"
    # Why this set is empty (see ``EmptyReason``); only meaningful for an empty
    # finite_set. Default-None keeps the wire shape of every populated set and of
    # the pre-existing empty sets byte-identical.
    empty_reason: EmptyReason | None = None
    last_indexed_block: int | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)
    # Caller dimension this capability constrains; see ``Subject``. Set at leaf
    # resolution and propagated by the combinators below.
    subject: Subject = "root"

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def finite_set(
        cls,
        members: list[str],
        *,
        quality: MembershipQuality = "exact",
        confidence: Confidence = "enumerable",
        conditions: list[Condition] | None = None,
        last_indexed_block: int | None = None,
        trace: list[dict[str, Any]] | None = None,
        subject: Subject = "root",
        empty_reason: EmptyReason | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind="finite_set",
            members=_canon_addresses(members),
            membership_quality=quality,
            confidence=confidence,
            conditions=list(conditions or []),
            last_indexed_block=last_indexed_block,
            trace=list(trace or []),
            subject=subject,
            empty_reason=empty_reason,
        )

    @classmethod
    def threshold_group(
        cls,
        m: int,
        signers: list[str],
        *,
        confidence: Confidence = "enumerable",
        conditions: list[Condition] | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind="threshold_group",
            threshold=(m, _canon_addresses(signers)),
            confidence=confidence,
            conditions=list(conditions or []),
        )

    @classmethod
    def cofinite_blacklist(
        cls,
        blacklist: list[str],
        *,
        confidence: Confidence = "enumerable",
        conditions: list[Condition] | None = None,
        subject: Subject = "root",
        blacklist_quality: MembershipQuality = "exact",
    ) -> "CapabilityExpr":
        return cls(
            kind="cofinite_blacklist",
            blacklist=_canon_addresses(blacklist),
            confidence=confidence,
            conditions=list(conditions or []),
            subject=subject,
            blacklist_quality=blacklist_quality,
        )

    @classmethod
    def signature_witness(
        cls,
        signer: "CapabilityExpr",
        *,
        conditions: list[Condition] | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind="signature_witness",
            signer=signer,
            conditions=list(conditions or []),
            confidence="check_only",
        )

    @classmethod
    def external_check_only(
        cls,
        check: ExternalCheck,
        *,
        conditions: list[Condition] | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind="external_check_only",
            check=check,
            confidence="check_only",
            conditions=list(conditions or []),
        )

    @classmethod
    def conditional_universal(cls, condition: Condition) -> "CapabilityExpr":
        """Universal set with side conditions (time gates, pause,
        reentrancy, business invariants). Anyone may call, but the
        condition must hold."""
        return cls(
            kind="conditional_universal",
            conditions=[condition],
            confidence="enumerable",
        )

    @classmethod
    def unsupported(cls, reason: str) -> "CapabilityExpr":
        return cls(kind="unsupported", unsupported_reason=reason, confidence="check_only")

    @classmethod
    def structural_and(cls, children: list["CapabilityExpr"]) -> "CapabilityExpr":
        if len(children) == 1:
            return children[0]
        return cls(kind="AND", children=list(children))

    @classmethod
    def structural_or(cls, children: list["CapabilityExpr"]) -> "CapabilityExpr":
        if len(children) == 1:
            return children[0]
        return cls(kind="OR", children=list(children))


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
        return CapabilityExpr.cofinite_blacklist(
            _canon_addresses((a.blacklist or []) + (b.blacklist or [])),
            blacklist_quality=_combine_blacklist_quality(a.blacklist_quality, b.blacklist_quality),
        )

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
        return CapabilityExpr.cofinite_blacklist(
            _canon_addresses(list(ab & bb)),
            blacklist_quality=_combine_blacklist_quality(a.blacklist_quality, b.blacklist_quality),
        )

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
    underlying capability needs inversion. Total.

    ``falsy``/``ne`` is the static lowering of an ``if (predicate) revert``
    exclusion: the predicate names the *denied* set, so the function proceeds for
    everyone else. ``negate`` maps a constraint on that excluded set to its
    complement — an open (cofinite) caller set — wherever the complement is
    faithfully representable. The polarity is the safety boundary: a positive gate
    (``require(...)`` → ``truthy``/``eq``) is never negated, so an authority never
    reaches these arms.
    """
    if a.kind == "finite_set":
        if a.membership_quality != "exact":
            # A non-exact (lower_bound) exclusion is "at least these are denied";
            # its complement is "anyone except an un-enumerated exclusion" — a
            # lower_bound cofinite, not an unknown. (Was unsupported("negate_partial_set"),
            # which discarded the denylist.)
            return CapabilityExpr.cofinite_blacklist(
                list(a.members or []),
                blacklist_quality="lower_bound",
                confidence=a.confidence,
                conditions=a.conditions,
                subject=a.subject,
            )
        return CapabilityExpr.cofinite_blacklist(
            list(a.members or []),
            confidence=a.confidence,
            conditions=a.conditions,
            subject=a.subject,
        )
    if a.kind == "cofinite_blacklist":
        # The complement of a cofinite denylist is exactly its members. A
        # lower_bound denylist ("at least these are denied") complements to a
        # lower_bound finite set, not a provably-complete one — calling it "exact"
        # would claim we enumerated everyone the gate admits.
        quality = "exact" if a.blacklist_quality == "exact" else "lower_bound"
        return CapabilityExpr.finite_set(
            list(a.blacklist or []),
            quality=quality,
            confidence=a.confidence,
            conditions=a.conditions,
            subject=a.subject,
        )
    if a.kind == "external_check_only":
        # An external membership probe under ``falsy`` is an un-enumerated denylist
        # (``if (check(caller)) revert``): anyone the probe does NOT flag may call. Its
        # complement is an empty-known, lower_bound cofinite. Surface the probe as a
        # side-condition so the filter stays visible, and preserve ``subject`` so a
        # bound (inlined-hook) denylist folds as a condition under cross-subject AND
        # rather than opening an authority'd function. (Was
        # unsupported("negate_unsupported_capability_external_check_only").)
        conditions = list(a.conditions)
        probe = _external_check_as_condition(a.check)
        if probe is not None:
            conditions.append(probe)
        return CapabilityExpr.cofinite_blacklist(
            [],
            blacklist_quality="lower_bound",
            confidence=a.confidence,
            conditions=conditions,
            subject=a.subject,
        )
    if a.kind == "conditional_universal":
        # Negation of "anyone if C" is "no one if C" — empty set with
        # the condition negated. Concretely: empty set if C, full
        # set if NOT C. We emit unsupported because the negation of
        # a condition isn't always representable as a typed
        # condition (e.g., negation of a business invariant).
        return CapabilityExpr.unsupported("negate_conditional_universal")
    if a.kind in ("threshold_group", "signature_witness"):
        # An M-of-N or signature gate has no faithful open complement — keep gated.
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
        blacklist_quality=blacklist.blacklist_quality,
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


def _combine_blacklist_quality(qa: MembershipQuality, qb: MembershipQuality) -> MembershipQuality:
    """Quality of a blacklist combined from two cofinite blacklists (the union under
    cofinite ∩ cofinite, the intersection under cofinite ∪ cofinite). Inert in Part 1:
    every cofinite is ``exact`` today, so this returns ``exact`` and changes nothing. It
    exists so the field is carried, never silently dropped, once Part 2 introduces
    ``lower_bound`` denylists. Matching qualities survive; a mismatch degrades to the
    conservative ``lower_bound`` (a combination involving an under-known exclusion can
    only be a lower bound on the true excluded set)."""
    if qa == qb:
        return qa
    return "lower_bound"


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
        blacklist_quality=cap.blacklist_quality,
        confidence=cap.confidence,
        # Preserved so an empty-by-design ceiling that gains a side condition
        # (e.g. an OZ accept-admin gate AND-ed with its schedule check) keeps its
        # reason — otherwise the policy layer would re-read it as a silent gap.
        empty_reason=cap.empty_reason,
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


def _external_check_as_condition(check: ExternalCheck | None) -> Condition | None:
    """Render an ``external_check_only``'s probe as a side-condition describing the
    denylist filter, for the ``negate(external_check_only) → cofinite`` arm. Returns
    None when there's no probe to describe (the cofinite still carries the generic
    ``denylist exclusion`` from the projector)."""
    if check is None:
        return None
    target = check.target_address
    selector = check.target_call_selector
    if target is not None:
        sel = f".{selector}" if selector else ""
        return Condition(kind="denylist", description=f"denylist exclusion via external check {target}{sel}")
    return Condition(kind="denylist", description="denylist exclusion via external check")


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
