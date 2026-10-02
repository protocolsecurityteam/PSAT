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

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADDR_C = "0xcccccccccccccccccccccccccccccccccccccccc"


def test_finite_set_and_threshold_group_canonicalize():
    cap = CapabilityExpr.finite_set([ADDR_B.upper(), ADDR_A, ADDR_A])
    assert cap.members == [ADDR_A.lower(), ADDR_B.lower()]
    assert cap.membership_quality == "exact"
    assert cap.confidence == "enumerable"

    tg = CapabilityExpr.threshold_group(2, [ADDR_B, ADDR_A])
    assert tg.threshold == (2, [ADDR_A.lower(), ADDR_B.lower()])


def test_intersect_finite_with_blacklist():
    fin = CapabilityExpr.finite_set([ADDR_A, ADDR_B, ADDR_C])
    bl = CapabilityExpr.cofinite_blacklist([ADDR_B])
    out = intersect(fin, bl)
    assert out.kind == "finite_set"
    assert out.members == [ADDR_A.lower(), ADDR_C.lower()]
    assert intersect(bl, fin).members == out.members


def test_intersect_blacklists_unions_them():
    a = CapabilityExpr.cofinite_blacklist([ADDR_A])
    b = CapabilityExpr.cofinite_blacklist([ADDR_B])
    out = intersect(a, b)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist is not None
    assert set(out.blacklist) == {ADDR_A.lower(), ADDR_B.lower()}


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


def test_union_identical_conditionals_collapses():
    cond = Condition(kind="business", description="same guard")
    a = CapabilityExpr.conditional_universal(cond)
    b = CapabilityExpr.conditional_universal(cond)
    out = union(a, b)
    assert out.kind == "conditional_universal"
    assert out.conditions == [cond]


def test_union_blacklists_intersects():
    a = CapabilityExpr.cofinite_blacklist([ADDR_A, ADDR_B])
    b = CapabilityExpr.cofinite_blacklist([ADDR_B, ADDR_C])
    out = union(a, b)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == [ADDR_B.lower()]


def test_negate_finite_lower_bound_yields_lower_bound_blacklist():
    # A partially-known denylist opens.
    fin = CapabilityExpr.finite_set([ADDR_A], quality="lower_bound")
    out = negate(fin)
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == [ADDR_A.lower()]
    assert out.blacklist_quality == "lower_bound"


def test_negate_lower_bound_blacklist_yields_lower_bound_finite():
    # ``exact`` would falsely claim everyone the gate admits was enumerated.
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
    assert out.kind == "OR"
    assert len(out.children) == 2
    assert all(c.kind == "cofinite_blacklist" for c in out.children)


# Describes the excluded set and is carried through every cofinite-producing combinator.


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


# ``falsy``/``ne`` is the only path to negate and names the excluded set, so opening it is faithful.


def test_negate_external_check_yields_lower_bound_blacklist_carrying_probe():
    check = ExternalCheck(target_address=ADDR_A, target_call_selector="0xdeadbeef")
    out = negate(CapabilityExpr.external_check_only(check))
    assert out.kind == "cofinite_blacklist"
    assert out.blacklist == []
    assert out.blacklist_quality == "lower_bound"
    assert any(ADDR_A.lower() in c.description and "0xdeadbeef" in c.description for c in out.conditions), (
        "the external probe must survive as a surfaced condition"
    )


# A denylist must never open a positive gate.


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
    for a in _all_kinds():
        for b in _all_kinds():
            assert intersect(a, b).kind in _ALL_RESULT_KINDS
            assert union(a, b).kind in _ALL_RESULT_KINDS
        assert isinstance(negate(a), CapabilityExpr)


def test_intersect_cross_subject_preserves_root_set_as_condition():
    # A bound intermediate used to zero the root set.
    root = CapabilityExpr.finite_set([ADDR_A, ADDR_B])  # real end-user callers
    bound_empty = CapabilityExpr.finite_set([], subject="bound")  # inlined downstream auth, empty
    out = intersect(root, bound_empty)
    assert out.kind == "finite_set"
    assert set(out.members or []) == {ADDR_A, ADDR_B}  # NOT zeroed
    assert out.subject == "root"
    assert out.conditions, "the bound check must be attached as a side-condition"


def test_union_cross_subject_yields_structural_or():
    root = CapabilityExpr.finite_set([ADDR_A])
    bound = CapabilityExpr.finite_set([ADDR_C], subject="bound")
    out = union(root, bound)
    assert out.kind == "OR"  # not merged — an intermediate address never joins the root set
    assert {c.subject for c in out.children} == {"root", "bound"}


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
