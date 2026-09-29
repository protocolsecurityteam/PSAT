"""Tests for ``CapabilityExpr`` + total combinators: factory well-formedness,
intersect/union/negate totality over the kind cross-product, quality and confidence
lattice propagation, address canonicalization, and identities
(intersect(A, A) ≡ A; intersect(A, universe) ≡ A)."""

from __future__ import annotations

import pytest

from services.resolution.capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
    intersect,
    negate,
    union,
)

# Test fixtures.
ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADDR_C = "0xcccccccccccccccccccccccccccccccccccccccc"


# ---------------------------------------------------------------------------
# Factories + canonicalization
# ---------------------------------------------------------------------------


def test_finite_set_and_threshold_group_canonicalize():
    cap = CapabilityExpr.finite_set([ADDR_B.upper(), ADDR_A, ADDR_A])
    assert cap.members == [ADDR_A.lower(), ADDR_B.lower()]
    assert cap.membership_quality == "exact"
    assert cap.confidence == "enumerable"

    tg = CapabilityExpr.threshold_group(2, [ADDR_B, ADDR_A])
    assert tg.threshold == (2, [ADDR_A.lower(), ADDR_B.lower()])


# ---------------------------------------------------------------------------
# Intersect — finite × finite
# ---------------------------------------------------------------------------


def test_intersect_finite_exact_exact():
    a = CapabilityExpr.finite_set([ADDR_A, ADDR_B])
    b = CapabilityExpr.finite_set([ADDR_B, ADDR_C])
    out = intersect(a, b)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_B.lower()]
    assert out.membership_quality == "exact"


def test_intersect_finite_disjoint_yields_structural_and_not_empty():
    """INVERTED (was ``..._yields_empty``, pinning the G2 HIT 3 defect): two independently
    resolved NON-empty, non-overlapping caller sets are self-refuting evidence on a
    deployed function ({liquidityPool} ∩ {upgradeTimelock} = ∅ on requestWithdraw), never
    a witnessed exact-empty "provably nobody". The AND keeps both conjuncts visible; the
    policy layer reads it as not-determined."""
    a = CapabilityExpr.finite_set([ADDR_A])
    b = CapabilityExpr.finite_set([ADDR_B])
    out = intersect(a, b)
    assert out.kind == "AND"
    assert [c.members for c in out.children] == [[ADDR_A], [ADDR_B]]
    assert out.members is None


def test_intersect_inherited_empty_stays_exact_empty():
    """Emptiness INHERITED from an already-witnessed-empty input (all-revoked role store,
    empty-by-design ceiling) keeps resolving: the witness lives in the input."""
    empty = CapabilityExpr.finite_set([], quality="exact")
    other = CapabilityExpr.finite_set([ADDR_A])
    for a, b in ((empty, other), (other, empty), (empty, empty)):
        out = intersect(a, b)
        assert out.kind == "finite_set"
        assert out.members == []
        assert out.membership_quality == "exact"


# ---------------------------------------------------------------------------
# Intersect — finite × cofinite_blacklist
# ---------------------------------------------------------------------------


def test_intersect_finite_with_blacklist():
    """``finite ∩ cofinite_blacklist`` = ``finite - blacklist``."""
    fin = CapabilityExpr.finite_set([ADDR_A, ADDR_B, ADDR_C])
    bl = CapabilityExpr.cofinite_blacklist([ADDR_B])
    out = intersect(fin, bl)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_A.lower(), ADDR_C.lower()]
    # Commutes: argument order does not change the result.
    assert intersect(bl, fin).members == out.members


# ---------------------------------------------------------------------------
# Intersect — cofinite_blacklist × cofinite_blacklist
# ---------------------------------------------------------------------------


def test_intersect_blacklists_unions_them():
    """Excluding A AND excluding B = excluding (A ∪ B)."""
    a = CapabilityExpr.cofinite_blacklist([ADDR_A])
    b = CapabilityExpr.cofinite_blacklist([ADDR_B])
    out = intersect(a, b)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist is not None
    assert set(out.blacklist) == {ADDR_A.lower(), ADDR_B.lower()}


# ---------------------------------------------------------------------------
# Intersect — conditional_universal preserves
# ---------------------------------------------------------------------------


def test_intersect_finite_with_conditional_universal_keeps_set():
    fin = CapabilityExpr.finite_set([ADDR_A])
    cond = Condition(kind="time", description="after T")
    cu = CapabilityExpr.conditional_universal(cond)
    out = intersect(fin, cu)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_A.lower()]
    assert any(c.kind == "time" for c in out.conditions)


# ---------------------------------------------------------------------------
# Intersect — unsupported absorbs
# ---------------------------------------------------------------------------


def test_intersect_unsupported_absorbs():
    fin = CapabilityExpr.finite_set([ADDR_A])
    u = CapabilityExpr.unsupported("opaque_control_flow")
    out = intersect(fin, u)
    assert out.kind == "unsupported"
    assert out.unsupported_reason is not None
    assert "opaque_control_flow" in out.unsupported_reason
    out2 = intersect(u, fin)
    assert out2.kind == "unsupported"


# ---------------------------------------------------------------------------
# Union — finite × finite
# ---------------------------------------------------------------------------


def test_union_finite_exact_exact():
    a = CapabilityExpr.finite_set([ADDR_A])
    b = CapabilityExpr.finite_set([ADDR_B])
    out = union(a, b)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_A.lower(), ADDR_B.lower()]
    assert out.membership_quality == "exact"


@pytest.mark.parametrize(
    "op, a_members, b_members",
    [
        pytest.param(intersect, [ADDR_A, ADDR_B], [ADDR_B, ADDR_C], id="intersect"),
        pytest.param(union, [ADDR_A], [ADDR_B], id="union"),
    ],
)
def test_finite_exact_with_lower_bound_yields_lower_bound(op, a_members, b_members):
    a = CapabilityExpr.finite_set(a_members)
    b = CapabilityExpr.finite_set(b_members, quality="lower_bound")
    assert op(a, b).membership_quality == "lower_bound"


@pytest.mark.parametrize("op", [intersect, union])
def test_idempotent(op):
    """``intersect(A, A) ≡ A`` and ``union(A, A) ≡ A`` for canonical finite sets."""
    a = CapabilityExpr.finite_set([ADDR_A, ADDR_B])
    out = op(a, a)
    assert out.kind == "finite_set"
    assert out.members == a.members


def test_union_identical_conditionals_collapses():
    cond = Condition(kind="business", description="same guard")
    a = CapabilityExpr.conditional_universal(cond)
    b = CapabilityExpr.conditional_universal(cond)
    out = union(a, b)
    assert out.kind == "conditional_universal"
    assert out.conditions == [cond]


# ---------------------------------------------------------------------------
# Union — cofinite_blacklist intersects
# ---------------------------------------------------------------------------


def test_union_blacklists_intersects():
    """Excluding A OR excluding B = excluding (A ∩ B)."""
    a = CapabilityExpr.cofinite_blacklist([ADDR_A, ADDR_B])
    b = CapabilityExpr.cofinite_blacklist([ADDR_B, ADDR_C])
    out = union(a, b)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == [ADDR_B.lower()]


# ---------------------------------------------------------------------------
# Union — finite ∪ cofinite_blacklist
# ---------------------------------------------------------------------------


def test_union_finite_with_blacklist_yields_blacklist_minus_finite():
    fin = CapabilityExpr.finite_set([ADDR_A])
    bl = CapabilityExpr.cofinite_blacklist([ADDR_A, ADDR_B])
    out = union(fin, bl)
    # ADDR_A is in finite (allowed), so it's removed from the
    # remaining blacklist. Result: anyone except ADDR_B.
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == [ADDR_B.lower()]


# ---------------------------------------------------------------------------
# Intersect/Union — threshold × finite stays structural
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "op, tg_members, fin_members, expected_kind",
    [
        pytest.param(intersect, [ADDR_A, ADDR_B, ADDR_C], [ADDR_A], "AND", id="intersect"),
        pytest.param(union, [ADDR_A, ADDR_B], [ADDR_C], "OR", id="union"),
    ],
)
def test_threshold_with_finite_stays_structural(op, tg_members, fin_members, expected_kind):
    tg = CapabilityExpr.threshold_group(2, tg_members)
    fin = CapabilityExpr.finite_set(fin_members)
    out = op(tg, fin)
    assert out.kind == expected_kind
    assert len(out.children) == 2


# ---------------------------------------------------------------------------
# Negate
# ---------------------------------------------------------------------------


def test_negate_finite_exact_yields_blacklist():
    fin = CapabilityExpr.finite_set([ADDR_A, ADDR_B])
    out = negate(fin)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == [ADDR_A.lower(), ADDR_B.lower()]
    # Double negation: negate(negate(finite_exact)) == finite_exact (canonical).
    twice = negate(out)
    assert twice.kind == "finite_set"
    assert twice.members == fin.members


def test_negate_finite_lower_bound_yields_lower_bound_blacklist():
    # Part 2: a non-exact exclusion negates to a lower_bound cofinite ("anyone except an
    # un-enumerated denylist"), not unsupported — so a partially-known denylist opens.
    fin = CapabilityExpr.finite_set([ADDR_A], quality="lower_bound")
    out = negate(fin)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == [ADDR_A.lower()]
    assert out.blacklist_quality == "lower_bound"


def test_negate_blacklist_yields_finite():
    bl = CapabilityExpr.cofinite_blacklist([ADDR_A, ADDR_B])
    out = negate(bl)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_A.lower(), ADDR_B.lower()]


def test_negate_lower_bound_blacklist_yields_lower_bound_finite():
    # A lower_bound cofinite complements to a lower_bound finite set, not an "exact" one,
    # which would falsely claim we enumerated everyone the gate admits.
    bl = CapabilityExpr.cofinite_blacklist([ADDR_A], blacklist_quality="lower_bound")
    out = negate(bl)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_A.lower()]
    assert out.membership_quality == "lower_bound"


def test_negate_de_morgan_and():
    a = CapabilityExpr.finite_set([ADDR_A])
    b = CapabilityExpr.finite_set([ADDR_B])
    and_node = CapabilityExpr.structural_and([a, b])
    out = negate(and_node)
    # NOT(A AND B) = NOT A OR NOT B (each becomes a blacklist).
    assert out.kind == "OR"
    assert len(out.children) == 2
    assert all(c.kind == "cofinite_blacklist" for c in out.children)


# blacklist_quality — Part 1 representation. Describes the EXCLUDED set (vs
# membership_quality for an allow-list); carried through every cofinite-producing
# combinator and inert today (every cofinite is exact).


@pytest.mark.parametrize(
    "op, a_members, b_members, c_members",
    [
        pytest.param(intersect, [ADDR_A], [ADDR_B], [ADDR_B], id="intersect"),
        pytest.param(union, [ADDR_A, ADDR_B], [ADDR_B, ADDR_C], [ADDR_B, ADDR_C], id="union"),
    ],
)
def test_blacklists_thread_quality(op, a_members, b_members, c_members):
    a = CapabilityExpr.cofinite_blacklist(a_members)
    b = CapabilityExpr.cofinite_blacklist(b_members)
    assert op(a, b).blacklist_quality == "exact"  # exact op exact stays exact (no-op today)
    c = CapabilityExpr.cofinite_blacklist(c_members, blacklist_quality="lower_bound")
    assert op(a, c).blacklist_quality == "lower_bound"  # carried, not dropped


def test_attach_conditions_preserves_blacklist_quality():
    # A cofinite flows through _attach_conditions (cofinite ∩ conditional_universal); the
    # quality must survive that field-by-field rebuild.
    bl = CapabilityExpr.cofinite_blacklist([ADDR_A], blacklist_quality="lower_bound")
    cu = CapabilityExpr.conditional_universal(Condition(kind="pause", description="whenNotPaused"))
    out = intersect(bl, cu)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist_quality == "lower_bound"
    assert any(c.description == "whenNotPaused" for c in out.conditions)


def test_every_cofinite_states_its_denylist_quality():
    # INVERTED (was ``test_default_cofinite_serializes_identically_to_pre_field``). The
    # emit-when-non-default rule made ABSENCE mean ``exact``, so a consumer unaware of the
    # key read every denylist as a COMPLETE exclusion — a default making the STRONG claim.
    # Stating the quality beats byte-identity with the pre-field wire shape.
    from services.resolution.capability_resolver import capability_to_dict

    exact = capability_to_dict(CapabilityExpr.cofinite_blacklist([ADDR_A, ADDR_B]))
    assert exact["blacklist_quality"] == "exact"
    assert set(exact.keys()) == {"kind", "blacklist", "membership_quality", "confidence", "blacklist_quality"}

    lower = capability_to_dict(CapabilityExpr.cofinite_blacklist([ADDR_A], blacklist_quality="lower_bound"))
    assert lower["blacklist_quality"] == "lower_bound"

    # And it is emitted ONLY on a denylist, so absence means "not a denylist"
    # rather than "a complete denylist".
    assert "blacklist_quality" not in capability_to_dict(CapabilityExpr.finite_set([ADDR_A]))


# Part 2: negate totality — un-enumerable exclusions open through the algebra. The
# ``falsy``/``ne`` operator is the only path to negate (the static lowering of
# ``if (predicate) revert``, naming the EXCLUDED set), so opening its un-resolved
# forms to a cofinite is faithful, not a guess.


def test_negate_external_check_yields_lower_bound_blacklist_carrying_probe():
    # A denylist hook resolving to an external probe (``if (check(caller)) revert``)
    # negates to a lower_bound cofinite, keeping the probe as a side-condition.
    check = ExternalCheck(target_address=ADDR_A, target_call_selector="0xdeadbeef")
    out = negate(CapabilityExpr.external_check_only(check))
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == []
    assert out.blacklist_quality == "lower_bound"
    assert any(ADDR_A.lower() in c.description and "0xdeadbeef" in c.description for c in out.conditions), (
        "the external probe must survive as a surfaced condition"
    )


def test_negate_unsupported_no_adapter_stays_unsupported():
    # THE SEAM: the no_adapter → cofinite conversion lives in the membership branch of
    # ``_evaluate_leaf`` (narrow, falsy-only), NOT in ``negate``, which keeps every
    # ``unsupported`` reason ``unsupported`` so a genuinely-unknown predicate can never be
    # "helpfully" opened. Pinned so nobody widens negate into a blanket opener.
    out = negate(CapabilityExpr.unsupported("no_adapter"))
    assert out.kind == "unsupported"
    assert out.unsupported_reason == "negate_of_no_adapter"


def test_negate_threshold_and_signature_stay_gated():
    # Only external_check_only joined finite_set/cofinite as a negate-opens arm; an M-of-N or
    # signature gate has no faithful open complement.
    assert negate(CapabilityExpr.threshold_group(2, [ADDR_A, ADDR_B])).kind == "unsupported"
    assert negate(CapabilityExpr.signature_witness(CapabilityExpr.finite_set([ADDR_A]))).kind == "unsupported"


# Part 2 security invariants: a denylist must NEVER open a function whose authorization
# is a positive gate.


def test_mixed_role_gate_and_denylist_stays_gated():
    # role gate AND denylist → the role finite_set folds the denylist as a set-subtraction
    # and stays gated; a denylist must never erase a positive gate.
    role = CapabilityExpr.finite_set([ADDR_A, ADDR_B])
    denylist = CapabilityExpr.cofinite_blacklist([], blacklist_quality="lower_bound")
    out = intersect(role, denylist)
    assert out.kind == "finite_set"
    assert set(out.members or []) == {ADDR_A.lower(), ADDR_B.lower()}


def test_cross_subject_root_authority_and_bound_denylist_stays_gated():
    # A real ROOT authority AND a BOUND denylist (via an inlined hook) keeps its root
    # callers; only a function whose SOLE gate is a denylist opens. Dropping the ``bound``
    # tag would open an authority'd function.
    root_authority = CapabilityExpr.finite_set([ADDR_A, ADDR_B])
    bound_denylist = CapabilityExpr.cofinite_blacklist([], blacklist_quality="lower_bound", subject="bound")
    out = intersect(root_authority, bound_denylist)
    assert out.kind == "finite_set"
    assert set(out.members or []) == {ADDR_A.lower(), ADDR_B.lower()}
    assert out.subject == "root"
    assert out.conditions, "the bound denylist must survive as a side-condition, not be set-intersected away"


# ---------------------------------------------------------------------------
# Total-function discipline: nothing raises across the kind cross-product.
# ---------------------------------------------------------------------------


def _all_kinds() -> list[CapabilityExpr]:
    return [
        CapabilityExpr.finite_set([ADDR_A]),
        CapabilityExpr.finite_set([ADDR_A], quality="lower_bound"),
        CapabilityExpr.finite_set([ADDR_A], quality="upper_bound"),
        CapabilityExpr.threshold_group(2, [ADDR_A, ADDR_B]),
        CapabilityExpr.cofinite_blacklist([ADDR_A]),
        CapabilityExpr.signature_witness(CapabilityExpr.finite_set([ADDR_A])),
        CapabilityExpr.external_check_only(ExternalCheck(target_address=ADDR_A, target_call_selector="0xabcdef00")),
        CapabilityExpr.conditional_universal(Condition(kind="time")),
        CapabilityExpr.unsupported("test"),
    ]


_ALL_RESULT_KINDS = (
    "finite_set",
    "threshold_group",
    "cofinite_blacklist",
    "signature_witness",
    "external_check_only",
    "conditional_universal",
    "unsupported",
    "AND",
    "OR",
)


def test_combinators_total_over_all_kinds():
    """No intersect/union/negate combination raises; every result is a typed CapabilityExpr."""
    for a in _all_kinds():
        for b in _all_kinds():
            assert intersect(a, b).kind in _ALL_RESULT_KINDS
            assert union(a, b).kind in _ALL_RESULT_KINDS
        # negate's only constraint: never raises, returns a CapabilityExpr.
        assert isinstance(negate(a), CapabilityExpr)


# ---------------------------------------------------------------------------
# Subject dimension (root caller vs bound intermediate)
# ---------------------------------------------------------------------------


def test_intersect_cross_subject_preserves_root_set_as_condition():
    # The bug: a bound intermediate ({}) intersected with the real root set zeroed it;
    # cross-subject intersect must keep the root set and attach the bound side as a side-condition.
    root = CapabilityExpr.finite_set([ADDR_A, ADDR_B])  # real end-user callers
    bound_empty = CapabilityExpr.finite_set([], subject="bound")  # inlined downstream auth, empty
    out = intersect(root, bound_empty)
    assert out.kind == "finite_set"
    assert set(out.members or []) == {ADDR_A, ADDR_B}  # NOT zeroed
    assert out.subject == "root"
    assert out.conditions, "the bound check must be attached as a side-condition"


def test_intersect_cross_subject_is_commutative():
    root = CapabilityExpr.finite_set([ADDR_A])
    bound = CapabilityExpr.finite_set([ADDR_C], subject="bound")
    left = intersect(root, bound)
    right = intersect(bound, root)
    assert set(left.members or []) == set(right.members or []) == {ADDR_A}
    assert left.subject == right.subject == "root"


def test_intersect_cross_subject_empty_root_stays_resolved_empty():
    # Guardrail: a genuinely-empty ROOT gate AND a bound side-condition stay exact-empty
    # (the bound side never resurrects callers).
    root_empty = CapabilityExpr.finite_set([], quality="exact")
    bound = CapabilityExpr.finite_set([ADDR_C], subject="bound")
    out = intersect(root_empty, bound)
    assert out.kind == "finite_set" and out.members == [] and out.membership_quality == "exact"


def test_intersect_same_subject_bound_uses_set_algebra():
    # Two bound sides share a dimension → ordinary set algebra (not attach).
    a = CapabilityExpr.finite_set([ADDR_A, ADDR_B], subject="bound")
    b = CapabilityExpr.finite_set([ADDR_B], subject="bound")
    out = intersect(a, b)
    assert set(out.members or []) == {ADDR_B}
    assert out.subject == "bound"


def test_intersect_conditional_universal_runs_before_cross_subject():
    # conditional_universal is pure side-conditions: X ∩ cond_universal keeps X across
    # subjects (the bound check stays bound, not a public path).
    bound = CapabilityExpr.finite_set([], subject="bound")
    cu = CapabilityExpr.conditional_universal(Condition(kind="business", description="c"))
    out = intersect(cu, bound)
    assert out.kind == "finite_set" and out.subject == "bound"
    assert any(c.description == "c" for c in out.conditions)


def test_union_cross_subject_yields_structural_or():
    root = CapabilityExpr.finite_set([ADDR_A])
    bound = CapabilityExpr.finite_set([ADDR_C], subject="bound")
    out = union(root, bound)
    assert out.kind == "OR"  # not merged — an intermediate address never joins the root set
    assert {c.subject for c in out.children} == {"root", "bound"}


def test_negate_preserves_subject():
    bound = CapabilityExpr.finite_set([ADDR_A], quality="exact", subject="bound")
    out = negate(bound)
    assert out.kind == "cofinite_blacklist" and out.subject == "bound"
    # round-trip back to finite keeps it bound too
    assert negate(out).subject == "bound"


@pytest.mark.parametrize(
    "build, apply",
    [
        # A bound (inlined-hook) denylist must stay ``bound`` through the negate external_check arm so the
        # cross-subject intersect keeps it a side-condition (see the security invariants above).
        pytest.param(
            lambda: CapabilityExpr.external_check_only(
                ExternalCheck(target_address=ADDR_A, target_call_selector="0x01")
            ),
            negate,
            id="negate-external-check",
        ),
        pytest.param(
            lambda: CapabilityExpr.finite_set([ADDR_A]),
            lambda e: intersect(e, CapabilityExpr.conditional_universal(Condition(kind="time", description="t"))),
            id="attach-conditions",
        ),
    ],
)
def test_bound_subject_is_preserved(build, apply):
    bound = build()
    bound.subject = "bound"
    assert apply(bound).subject == "bound"


def test_bound_condition_description_variants():
    from services.resolution.capabilities import _bound_condition_description

    via_check = CapabilityExpr.external_check_only(
        ExternalCheck(target_address="0x" + "11" * 20, target_call_selector="0xdeadbeef")
    )
    via_check.subject = "bound"
    desc = _bound_condition_description(via_check)
    assert "0x" + "11" * 20 in desc and "0xdeadbeef" in desc

    via_trace = CapabilityExpr.finite_set([], subject="bound", trace=[{"target": "0x" + "22" * 20}])
    assert "0x" + "22" * 20 in _bound_condition_description(via_trace)

    generic = CapabilityExpr.finite_set([], subject="bound")
    assert "delegated cross-contract authorization" in _bound_condition_description(generic)
