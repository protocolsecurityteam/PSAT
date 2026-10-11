"""CapabilityExpr: resolver-side authority-set algebra.

The resolver evaluates each function's ``PredicateTree`` into a ``CapabilityExpr``:

  finite_set            members, exact / lower_bound / upper_bound
  threshold_group       Safe-style M-of-N
  cofinite_blacklist    anyone except these
  signature_witness     anyone with a valid signature from <signer>
  external_check_only   query-only (EIP-1271, oracle policy)
  conditional_universal anyone, given side conditions
  unsupported           typed reason; propagates fail-closed under AND
  AND, OR               structural composition when no closed form exists

The combinators are total: they return a typed capability or ``unsupported(reason)``, never raise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

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
CapabilityConfidence = Literal["enumerable", "partial", "check_only"]

# Why a finite_set is empty: separates empty-by-design ceilings from read gaps, and classifies gap flavors. ``None`` on
# populated sets and legacy empties; see ``predicate_evaluator``.
EmptyReason = Literal[
    "empty_by_design",
    "unreadable_revert",
    "unreadable_empty",
    "needs_enumeration",
    "bad_input",
    "not_read",
    # What was read (a zero word at a stated block), unlike ``empty_by_design`` which classifies why.
    "owner_read_zero",
    "slot_read_zero",
    # 0x…dEaD is a convention, not proof of unspendability, so it never licenses an earned negative.
    "owner_read_burn_address",
]

# Which caller a capability constrains. ``root`` is the function's end-user caller; ``bound`` is the caller of an
# inlined downstream call (e.g. a Teller calling ``vault.exit``). A bound guard is a runtime side condition;
# intersecting it with root callers would wrongly zero them.
Subject = Literal["root", "bound"]


@dataclass(frozen=True)
class Condition:
    """A side condition that must hold at runtime but doesn't restrict the principal set (time, pause, reentrancy,
    business invariants).

    ``one_shot``: an initializer latch (the resolver annotates ``latch_state``). ``permit_sig``: the open path verifies
    the affected party's signature. ``denylist``: open except a finite exclusion.
    """

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
    """Probe descriptor for an external_check_only capability (address + selector), for asking "is this address
    authorized".
    """

    target_address: str | None
    target_call_selector: str | None
    extra: dict[str, Any] = field(default_factory=dict)


def _canon_addresses(values: list[str]) -> list[str]:
    """Lowercase, sort and dedup for stable equality."""
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
    # Quality of the excluded set, separate from ``membership_quality``: ``exact`` means the complement is exactly
    # everyone else, ``lower_bound`` makes it an upper bound on callers. Currently every cofinite is exact; carried for
    # surfacing only.
    blacklist_quality: MembershipQuality = "exact"
    confidence: CapabilityConfidence = "enumerable"
    # Only meaningful for an empty finite_set. The combinators propagate it and the fold heights, so outputs built from
    # height-bearing operands differ from the old shape; registered in SCORING_INVARIANTS B16.
    empty_reason: EmptyReason | None = None
    last_indexed_block: int | None = None
    # The height at which this set is exact: an ``int`` when all operands had equal heights, ``"not_determined"`` when
    # heights differed (an earned refusal), ``None`` when never computed.
    #
    # ``last_indexed_block`` (the MIN) is a staleness floor, not an as-of: folds publish state at their own height with
    # revocations applied, and subtractive paths publish subsets, so the set at MIN can differ.
    exact_as_of: int | Literal["not_determined"] | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)
    # Set at leaf resolution and propagated by the combinators.
    subject: Subject = "root"

    @classmethod
    def finite_set(
        cls,
        members: list[str],
        *,
        quality: MembershipQuality = "exact",
        confidence: CapabilityConfidence = "enumerable",
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
        confidence: CapabilityConfidence = "enumerable",
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
        confidence: CapabilityConfidence = "enumerable",
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
        """Anyone may call, given the side conditions."""
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


def intersect(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    """``a AND b``: callers in both. Total over all kinds."""
    if a.kind == "unsupported":
        return CapabilityExpr.unsupported(f"intersect_with_unsupported_{a.unsupported_reason}")
    if b.kind == "unsupported":
        return CapabilityExpr.unsupported(f"intersect_with_unsupported_{b.unsupported_reason}")

    # conditional_universal never constrains callers, so keep X with the conditions added. Handled before the
    # cross-subject divert so a bound check stays a bound check.
    if a.kind == "conditional_universal":
        return _attach_conditions(b, a.conditions)
    if b.kind == "conditional_universal":
        return _attach_conditions(a, b.conditions)

    # Cross-subject: attach the bound side as a condition instead of intersecting it away. See ``Subject``.
    if a.subject != b.subject:
        return _intersect_cross_subject(a, b)

    if a.kind == "finite_set" and b.kind == "finite_set":
        return _intersect_finite(a, b)

    if a.kind == "finite_set" and b.kind == "cofinite_blacklist":
        return _intersect_finite_blacklist(a, b)
    if a.kind == "cofinite_blacklist" and b.kind == "finite_set":
        return _intersect_finite_blacklist(b, a)

    if a.kind == "cofinite_blacklist" and b.kind == "cofinite_blacklist":
        # Anyone not in (a.blacklist ∪ b.blacklist).
        return _carry_fold_provenance(
            _with_operand_traces(
                CapabilityExpr.cofinite_blacklist(
                    _canon_addresses((a.blacklist or []) + (b.blacklist or [])),
                    blacklist_quality=_combine_blacklist_quality(a.blacklist_quality, b.blacklist_quality),
                ),
                a,
                b,
            ),
            a,
            b,
        )

    if a.kind == "threshold_group" or b.kind == "threshold_group":
        return CapabilityExpr.structural_and([a, b])

    return CapabilityExpr.structural_and([a, b])


def union(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    """``a OR b``: callers in either. Total."""
    if a.kind == "unsupported":
        return CapabilityExpr.structural_or([a, b])
    if b.kind == "unsupported":
        return CapabilityExpr.structural_or([a, b])

    # Cross-subject: keep a structural OR so an intermediate address isn't merged in as an end-user principal.
    if a.subject != b.subject:
        return CapabilityExpr.structural_or([a, b])

    if a.kind == "finite_set" and b.kind == "finite_set":
        return _union_finite(a, b)

    if a.kind == "cofinite_blacklist" and b.kind == "cofinite_blacklist":
        # Anyone not in (a.blacklist ∩ b.blacklist).
        ab = set((a.blacklist or []))
        bb = set((b.blacklist or []))
        return _carry_fold_provenance(
            _with_operand_traces(
                CapabilityExpr.cofinite_blacklist(
                    _canon_addresses(list(ab & bb)),
                    blacklist_quality=_combine_blacklist_quality(a.blacklist_quality, b.blacklist_quality),
                ),
                a,
                b,
            ),
            a,
            b,
        )

    # Cofinite minus members already allowed by the finite set.
    if a.kind == "finite_set" and b.kind == "cofinite_blacklist":
        return _union_finite_blacklist(a, b)
    if a.kind == "cofinite_blacklist" and b.kind == "finite_set":
        return _union_finite_blacklist(b, a)

    if a.kind == "conditional_universal" and b.kind == "conditional_universal" and a.conditions == b.conditions:
        return a

    # Anyone-with-condition isn't the same as X.
    return CapabilityExpr.structural_or([a, b])


def negate(a: CapabilityExpr) -> CapabilityExpr:
    """``NOT a``, for ``falsy``/``ne`` leaves. Total.

    Those are the static lowering of ``if (predicate) revert``: the predicate names the denied set, so the result is its
    complement where representable. Positive gates are never negated, so authorities never reach these arms.
    """
    if a.kind == "finite_set":
        if a.membership_quality != "exact":
            # A lower_bound exclusion complements to a lower_bound cofinite, not an unknown.
            return _carry_fold_provenance(
                CapabilityExpr.cofinite_blacklist(
                    list(a.members or []),
                    blacklist_quality="lower_bound",
                    confidence=a.confidence,
                    conditions=a.conditions,
                    subject=a.subject,
                ),
                a,
            )
        return _carry_fold_provenance(
            CapabilityExpr.cofinite_blacklist(
                list(a.members or []),
                confidence=a.confidence,
                conditions=a.conditions,
                subject=a.subject,
            ),
            a,
        )
    if a.kind == "cofinite_blacklist":
        # A lower_bound denylist complements to a lower_bound finite set, not an exact one.
        quality = "exact" if a.blacklist_quality == "exact" else "lower_bound"
        # Height carries through complementation; ``empty_reason`` doesn't.
        return _carry_fold_provenance(
            CapabilityExpr.finite_set(
                list(a.blacklist or []),
                quality=quality,
                confidence=a.confidence,
                conditions=a.conditions,
                subject=a.subject,
            ),
            a,
        )
    if a.kind == "external_check_only":
        # A falsy external probe is an un-enumerated denylist: complement to a lower_bound empty cofinite, with the
        # probe kept as a condition and ``subject`` preserved so bound denylists fold as conditions.
        conditions = list(a.conditions)
        probe = _external_check_as_condition(a.check)
        if probe is not None:
            conditions.append(probe)
        # Deliberately no fold provenance: a probe isn't an enumeration and has no height (a test asserts this).
        complement = CapabilityExpr.cofinite_blacklist(
            [],
            blacklist_quality="lower_bound",
            confidence=a.confidence,
            conditions=conditions,
            subject=a.subject,
        )
        complement.trace = _deferral_steps(a.check)
        return complement
    if a.kind == "conditional_universal":
        # The negation of a condition isn't always representable (e.g. business invariants).
        return CapabilityExpr.unsupported("negate_conditional_universal")
    if a.kind in ("threshold_group", "signature_witness"):
        # M-of-N and signature gates have no faithful open complement.
        return CapabilityExpr.unsupported(f"negate_unsupported_capability_{a.kind}")
    if a.kind == "unsupported":
        return CapabilityExpr.unsupported(f"negate_of_{a.unsupported_reason}")
    if a.kind in ("AND", "OR"):
        # De Morgan; unsupported children propagate.
        flipped = [negate(c) for c in a.children]
        if a.kind == "AND":
            return CapabilityExpr.structural_or(flipped)
        return CapabilityExpr.structural_and(flipped)
    return CapabilityExpr.unsupported(f"negate_unknown_kind_{a.kind}")


def _propagated_height(*operands: CapabilityExpr) -> int | None:
    """MIN of the operands' fold heights, or ``None`` when any operand lacks one.

    Fail closed: stamping a height onto a composition that includes an unpinned live read would claim time-bounded
    knowledge. A staleness floor, never an as-of. Operands are same-chain by construction (chain-scoped resolution,
    #158).
    """
    heights = [op.last_indexed_block for op in operands]
    if any(height is None for height in heights):
        return None
    return min(height for height in heights if height is not None)


def _carry_fold_provenance(
    cap: CapabilityExpr,
    *operands: CapabilityExpr,
    exact_as_of_licensed: bool = True,
) -> CapabilityExpr:
    """Carry the operands' fold provenance onto a rebuilt capability.

    Factories can't see operands, so combinators used to drop the leaf heights. ``last_indexed_block`` propagates via
    :func:`_propagated_height`. ``exact_as_of`` is published only when all operands have equal heights, the result is
    ``exact``, and any emptiness was inherited.

    The refusal is recorded before anything else: otherwise a result with one MIN height and no ``exact_as_of`` looks
    like a leaf, and a later combinator would mint an as-of the first refused (three such launderings existed). The
    refusal is the weakest state, so publishing it can't over-claim.
    """
    cap.last_indexed_block = _propagated_height(*operands)
    cap.exact_as_of = None
    heights = [op.last_indexed_block for op in operands]
    # A prior refusal poisons every composition; disagreeing heights can never license an as-of.
    if any(op.exact_as_of == "not_determined" for op in operands) or (
        all(height is not None for height in heights) and len(set(heights)) > 1
    ):
        cap.exact_as_of = "not_determined"
        return cap
    if not exact_as_of_licensed:
        return cap
    quality = cap.blacklist_quality if cap.kind == "cofinite_blacklist" else cap.membership_quality
    if quality != "exact":
        return cap
    if any(height is None for height in heights):
        return cap
    cap.exact_as_of = heights[0]
    return cap


def _inherited_empty_reason(*operands: CapabilityExpr) -> EmptyReason | None:
    """The reason carried by already-empty operands, or ``None``.

    Emptiness created by this operation has no witness (see :func:`_intersect_finite`); disagreeing reasons give
    ``None``.
    """
    reasons: set[EmptyReason] = {
        op.empty_reason for op in operands if op.kind == "finite_set" and not op.members and op.empty_reason is not None
    }
    if len(reasons) == 1:
        return next(iter(reasons))
    return None


def _intersect_finite(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    am = set(a.members or [])
    bm = set(b.members or [])
    common = _canon_addresses(list(am & bm))
    quality = _intersect_quality(a.membership_quality, b.membership_quality)
    if quality is None:
        return CapabilityExpr.structural_and([a, b])
    if not common and am and bm:
        # Emptiness created by intersecting two non-empty sets means a conjunct is wrong, not that nobody can call.
        # Publishing exact-empty minted false ``resolved_empty`` on live withdrawal paths, so keep the AND. Inherited
        # emptiness still resolves below.
        return CapabilityExpr.structural_and([a, b])
    confidence = _meet_confidence(a.confidence, b.confidence)
    conditions = list(a.conditions) + list(b.conditions)
    # Only same-subject pairs reach here.
    cap = CapabilityExpr.finite_set(
        common,
        quality=quality,
        confidence=confidence,
        conditions=conditions,
        subject=a.subject,
        empty_reason=_inherited_empty_reason(a, b) if not common else None,
    )
    cap.trace = list(a.trace) + list(b.trace)
    # Any emptiness here is inherited; created-empty diverted above.
    return _carry_fold_provenance(cap, a, b)


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
        empty_reason=_inherited_empty_reason(a, b) if not merged else None,
    )
    cap.trace = list(a.trace) + list(b.trace)
    # A union is empty only when both operands were.
    return _carry_fold_provenance(cap, a, b)


def _intersect_finite_blacklist(finite: CapabilityExpr, blacklist: CapabilityExpr) -> CapabilityExpr:
    members_set = set(finite.members or [])
    bl = set(blacklist.blacklist or [])
    out = _canon_addresses(list(members_set - bl))
    # No structural-AND diversion here, so a subtraction that removes every member creates emptiness with no reason or
    # as-of; only an already-empty allow-list keeps its own.
    inherited_empty = not members_set
    cap = CapabilityExpr.finite_set(
        out,
        quality=finite.membership_quality,
        confidence=_meet_confidence(finite.confidence, blacklist.confidence),
        conditions=list(finite.conditions) + list(blacklist.conditions),
        empty_reason=_inherited_empty_reason(finite) if not out and inherited_empty else None,
    )
    cap.trace = list(finite.trace) + list(blacklist.trace)
    return _carry_fold_provenance(cap, finite, blacklist, exact_as_of_licensed=bool(out) or inherited_empty)


def _union_finite_blacklist(finite: CapabilityExpr, blacklist: CapabilityExpr) -> CapabilityExpr:
    bl = set(blacklist.blacklist or [])
    fin = set(finite.members or [])
    out = _canon_addresses(list(bl - fin))
    return _carry_fold_provenance(
        _with_operand_traces(
            CapabilityExpr.cofinite_blacklist(
                out,
                confidence=_meet_confidence(finite.confidence, blacklist.confidence),
                conditions=list(finite.conditions) + list(blacklist.conditions),
                blacklist_quality=blacklist.blacklist_quality,
            ),
            finite,
            blacklist,
        ),
        finite,
        blacklist,
    )


def _intersect_quality(qa: MembershipQuality, qb: MembershipQuality) -> MembershipQuality | None:
    """Quality lattice for intersect:
    exact ∩ exact   = exact
    exact ∩ lower   = lower_bound
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
    exact ∪ exact     = exact
    exact ∪ lower     = lower_bound
    lower ∪ lower     = lower_bound
    upper ∪ upper     = upper_bound
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
    """Quality of a blacklist combined from two cofinites.

    Matching qualities survive; a mismatch degrades to ``lower_bound``. Inert while every cofinite is exact.
    """
    if qa == qb:
        return qa
    return "lower_bound"


def _meet_confidence(a: CapabilityConfidence, b: CapabilityConfidence) -> CapabilityConfidence:
    order = {"enumerable": 2, "partial": 1, "check_only": 0}
    if order[a] <= order[b]:
        return a
    return b


def _attach_conditions(cap: CapabilityExpr, conditions: list[Condition]) -> CapabilityExpr:
    """A copy of ``cap`` with ``conditions`` appended."""
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
        # Keep the reason so an empty-by-design ceiling with a side condition isn't re-read as a gap.
        empty_reason=cap.empty_reason,
        last_indexed_block=cap.last_indexed_block,
        # Conditions narrow when, not who, so height and as-of survive.
        exact_as_of=cap.exact_as_of,
        trace=list(cap.trace),
        subject=cap.subject,
    )


def _intersect_cross_subject(a: CapabilityExpr, b: CapabilityExpr) -> CapabilityExpr:
    """AND of a ``root`` and a ``bound`` capability.

    The bound side becomes a condition on the root side, so real callers survive (intersecting would give ∅), an empty
    root stays exact-empty, and an empty bound side can't make the AND look ``resolved_empty``.
    """
    root, bound = (a, b) if b.subject == "bound" else (b, a)
    out = _attach_conditions(root, _bound_as_conditions(bound))
    # The bound side's deferrals outlive its folding into a condition.
    out.trace = (
        list(out.trace)
        + _carried_deferrals(bound)
        + _deferral_steps(bound.check if bound.kind == "external_check_only" else None)
    )
    return out


def _bound_as_conditions(bound: CapabilityExpr) -> list[Condition]:
    """A bound-subject capability as side conditions: its existing conditions plus one for the delegated check."""
    return list(bound.conditions) + [Condition(kind="business", description=_bound_condition_description(bound))]


# Same value as ``deferred_reconciler.DEFERRED_MARKER``, shared by value to avoid an import dependency.
DEFERRED_MARKER = "deferred_pending_index"
DEFERRED_STEP = "deferred_external_check"


def _deferral_steps(check: ExternalCheck | None) -> list[dict[str, Any]]:
    """A cold-index deferral, as a trace step, for a probe a combinator folds away.

    Without it the reconciler, which finds deferrals by their marker, never re-resolves the result once the index is
    warm. Only a deferral naming the topic cursors it waits on is carried: the reconciler re-enqueues it once those
    complete, while an address-level one (a role check, which also defers behind a failing tail) would re-enqueue on
    every pass.
    """
    if check is None or not check.extra.get(DEFERRED_MARKER):
        return []
    topic0s = check.extra.get("deferred_topic0s")
    if not topic0s:
        return []
    return [
        {
            "step": DEFERRED_STEP,
            DEFERRED_MARKER: True,
            "target_address": check.target_address,
            "deferred_topic0s": list(topic0s),
        }
    ]


def _carried_deferrals(*operands: CapabilityExpr) -> list[dict[str, Any]]:
    return [step for operand in operands for step in operand.trace if step.get(DEFERRED_MARKER)]


def _with_operand_traces(cap: CapabilityExpr, *operands: CapabilityExpr) -> CapabilityExpr:
    """Carry the operands' deferrals onto a rebuilt cofinite, which otherwise keeps no trace."""
    cap.trace = _carried_deferrals(*operands)
    return cap


def _external_check_as_condition(check: ExternalCheck | None) -> Condition | None:
    """An ``external_check_only`` probe as a denylist side condition, or None when there's no probe."""
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
