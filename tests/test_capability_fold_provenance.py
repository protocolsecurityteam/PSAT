"""A2 — fold provenance survives the combinators, fail-closed.

Every combinator rebuilds its result through a factory that cannot see the
operands, so each rebuild silently dropped the height the adapter leaf had
already computed — on every solmate fold in the corpus. These tests drive the
REAL ``intersect`` / ``union`` / ``negate`` plus ``capability_to_dict`` and pin
byte-exact output dicts, including the arms that must publish NOTHING.

The three rules under test, each with its own failure mode:

* a height propagates only when EVERY operand carries one (``min``-of-present
  would stamp a fold height onto a composition whose other operand is an
  unpinned live read);
* ``exact_as_of`` is licensed only by EQUAL operand heights and only for
  inherited emptiness (the MIN is a staleness floor — promoting it to an as-of
  is false across heterogeneous heights and inverts outright on the subtractive
  paths);
* ``empty_reason`` propagates only on emptiness a combinator INHERITED, never on
  emptiness it created.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution.capabilities import (  # noqa: E402
    CapabilityExpr,
    Condition,
    ExternalCheck,
    intersect,
    negate,
    union,
)
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# The two heights the investigation measured inside ONE resolution job — 203
# blocks apart while both were presented as equally current.
B1 = 25619032
B2 = 25619235


def _fold(members: list[str], *, block: int | None, reason=None) -> CapabilityExpr:
    """An adapter-shaped leaf: an exact enumeration folded to a cursor height."""
    return CapabilityExpr.finite_set(
        members,
        quality="exact",
        confidence="enumerable",
        last_indexed_block=block,
        trace=[{"step": "enumerable_role_store"}],
        empty_reason=reason,
    )


def _blockless_live_getter(members: list[str]) -> CapabilityExpr:
    """The live ``owner()`` read: exact, enumerable — and blockless by
    construction, because the eth_call falls back to ``"latest"`` when the
    resolution frame carries no pinned height."""
    return CapabilityExpr.finite_set(
        members,
        quality="exact",
        confidence="enumerable",
        trace=[{"step": "live_getter_resolution"}],
    )


# ---------------------------------------------------------------------------
# Leaf — the value that used to be thrown away
# ---------------------------------------------------------------------------


def test_leaf_height_is_preserved_on_the_wire():
    out = capability_to_dict(_fold([ADDR_A], block=B1))
    assert out["last_indexed_block"] == B1
    # A leaf never computed an as-of: absent, not "not_determined".
    assert "exact_as_of" not in out


# ---------------------------------------------------------------------------
# intersect / union of two finite sets
# ---------------------------------------------------------------------------


def test_intersect_two_folds_takes_the_min_and_refuses_an_as_of():
    out = capability_to_dict(intersect(_fold([ADDR_A, ADDR_B], block=B1), _fold([ADDR_A], block=B2)))
    assert out["members"] == [ADDR_A]
    assert out["last_indexed_block"] == B1
    # Heights present but heterogeneous: an EARNED refusal, not an omission.
    assert out["exact_as_of"] == "not_determined"


def test_union_two_folds_takes_the_min_and_refuses_an_as_of():
    out = capability_to_dict(union(_fold([ADDR_A], block=B1), _fold([ADDR_B], block=B2)))
    assert out["members"] == [ADDR_A, ADDR_B]
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == "not_determined"


def test_equal_heights_license_an_exact_as_of():
    for combine in (intersect, union):
        out = capability_to_dict(combine(_fold([ADDR_A], block=B1), _fold([ADDR_A], block=B1)))
        assert out["last_indexed_block"] == B1
        assert out["exact_as_of"] == B1


def test_intersect_with_blockless_operand_publishes_no_height():
    """THE fail-closed arm. This is the shape of all 261 solmate rows:
    ``OR(fold, live owner() read)`` — and it must stay blockless."""
    out = capability_to_dict(intersect(_fold([ADDR_A], block=B1), _blockless_live_getter([ADDR_A])))
    assert "last_indexed_block" not in out
    assert "exact_as_of" not in out


def test_union_with_blockless_operand_publishes_no_height():
    out = capability_to_dict(union(_fold([ADDR_A], block=B1), _blockless_live_getter([ADDR_B])))
    assert "last_indexed_block" not in out
    assert "exact_as_of" not in out


def test_min_of_present_is_not_implemented():
    """Explicit statement of the banned behaviour: the height that IS present
    must not leak out just because the other operand had none."""
    result = intersect(_fold([ADDR_A], block=B1), _blockless_live_getter([ADDR_A]))
    assert result.last_indexed_block is None


# ---------------------------------------------------------------------------
# finite ∩ cofinite (the subtractive path — no structural-AND diversion)
# ---------------------------------------------------------------------------


def _blacklist(members: list[str], *, block: int | None) -> CapabilityExpr:
    cap = CapabilityExpr.cofinite_blacklist(members, confidence="enumerable")
    cap.last_indexed_block = block
    return cap


def test_intersect_finite_blacklist_propagates_min():
    out = capability_to_dict(intersect(_fold([ADDR_A, ADDR_B], block=B1), _blacklist([ADDR_B], block=B2)))
    assert out["members"] == [ADDR_A]
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == "not_determined"


def test_intersect_finite_blacklist_fails_closed_on_blockless():
    out = capability_to_dict(intersect(_fold([ADDR_A, ADDR_B], block=B1), _blacklist([ADDR_B], block=None)))
    assert "last_indexed_block" not in out
    assert "exact_as_of" not in out


def test_subtraction_that_creates_emptiness_publishes_no_as_of_and_no_reason():
    """``{X} − {X}`` = ∅. Unlike ``_intersect_finite`` this path has no
    structural-AND diversion, so the empty set is REAL output — and it is an
    emptiness this operation created, which inherits no witness."""
    out = capability_to_dict(intersect(_fold([ADDR_A], block=B1), _blacklist([ADDR_A], block=B1)))
    assert out["members"] == []
    assert "exact_as_of" not in out
    assert "empty_reason" not in out
    # The staleness floor still carries — it says only how current the operands
    # were, which remains true of a created emptiness.
    assert out["last_indexed_block"] == B1


def test_already_empty_allow_list_carries_its_reason_through_subtraction():
    out = capability_to_dict(intersect(_fold([], block=B1, reason="owner_read_zero"), _blacklist([ADDR_A], block=B1)))
    assert out["members"] == []
    assert out["empty_reason"] == "owner_read_zero"
    assert out["exact_as_of"] == B1


# ---------------------------------------------------------------------------
# negate — all three arms
# ---------------------------------------------------------------------------


def test_negate_exact_finite_carries_the_height():
    out = capability_to_dict(negate(_fold([ADDR_A], block=B1)))
    assert out["kind"] == "cofinite_blacklist"
    assert out["blacklist"] == [ADDR_A]
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == B1


def test_negate_lower_bound_finite_carries_the_height_but_no_as_of():
    """A lower_bound exclusion complements to a lower_bound cofinite — not exact
    at any height, so no as-of."""
    cap = CapabilityExpr.finite_set([ADDR_A], quality="lower_bound", last_indexed_block=B1)
    out = capability_to_dict(negate(cap))
    assert out["blacklist_quality"] == "lower_bound"
    assert out["last_indexed_block"] == B1
    assert "exact_as_of" not in out


def test_negate_cofinite_carries_the_height_but_never_an_empty_reason():
    """The complement of an empty denylist is an empty allow-list. Why the
    denylist was empty says nothing about why its complement is, so no reason is
    minted — absence stays absence."""
    source = CapabilityExpr.cofinite_blacklist([], confidence="enumerable")
    source.last_indexed_block = B1
    source.empty_reason = "owner_read_zero"
    out = capability_to_dict(negate(source))
    assert out["kind"] == "finite_set"
    assert out["members"] == []
    assert out["last_indexed_block"] == B1
    assert "empty_reason" not in out


def test_negate_fails_closed_on_a_blockless_operand():
    for cap in (
        CapabilityExpr.finite_set([ADDR_A], quality="exact"),
        CapabilityExpr.finite_set([ADDR_A], quality="lower_bound"),
        CapabilityExpr.cofinite_blacklist([ADDR_A]),
    ):
        out = capability_to_dict(negate(cap))
        assert "last_indexed_block" not in out
        assert "exact_as_of" not in out


def test_negate_external_check_only_is_a_stated_non_site():
    """The tenth mint site, deliberately excluded: an ``external_check_only``
    operand is a probe interface, never an enumeration, so it carries no height
    and there is no exactness to date. Pinned so the omission cannot later read
    as an oversight."""
    probe = CapabilityExpr.external_check_only(ExternalCheck(target_address=ADDR_A, target_call_selector="0x12345678"))
    probe.last_indexed_block = B1  # even if something upstream set one
    out = capability_to_dict(negate(probe))
    assert out["kind"] == "cofinite_blacklist"
    assert "last_indexed_block" not in out
    assert "exact_as_of" not in out


# ---------------------------------------------------------------------------
# cofinite ∩ cofinite, cofinite ∪ cofinite, finite ∪ cofinite
# ---------------------------------------------------------------------------


def test_cofinite_pairs_and_union_finite_blacklist_propagate_min():
    both_ways = [
        intersect(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=B2)),
        union(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=B2)),
        union(_fold([ADDR_A], block=B1), _blacklist([ADDR_A, ADDR_B], block=B2)),
    ]
    for cap in both_ways:
        out = capability_to_dict(cap)
        assert out["last_indexed_block"] == B1, out
        assert out["exact_as_of"] == "not_determined", out


def test_cofinite_pairs_fail_closed_on_a_blockless_operand():
    both_ways = [
        intersect(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=None)),
        union(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=None)),
        union(_fold([ADDR_A], block=B1), _blacklist([ADDR_B], block=None)),
    ]
    for cap in both_ways:
        out = capability_to_dict(cap)
        assert "last_indexed_block" not in out, out
        assert "exact_as_of" not in out, out


# ---------------------------------------------------------------------------
# empty_reason: inherited vs created
# ---------------------------------------------------------------------------


def test_inherited_emptiness_keeps_its_reason():
    out = capability_to_dict(intersect(_fold([], block=B1, reason="empty_by_design"), _fold([ADDR_A], block=B1)))
    assert out["members"] == []
    assert out["empty_reason"] == "empty_by_design"


def test_created_emptiness_diverts_to_structural_and_and_mints_no_reason():
    """Two independently-resolved NON-empty sets with no overlap: the existing
    structural-AND diversion still fires, and no reason is invented for an
    emptiness nothing witnessed."""
    out = capability_to_dict(intersect(_fold([ADDR_A], block=B1), _fold([ADDR_B], block=B1)))
    assert out["kind"] == "AND"
    assert "empty_reason" not in out


def test_two_disagreeing_reasons_resolve_to_absent():
    out = capability_to_dict(
        union(_fold([], block=B1, reason="owner_read_zero"), _fold([], block=B1, reason="empty_by_design"))
    )
    assert out["members"] == []
    assert "empty_reason" not in out


def test_union_of_two_empties_carries_the_agreed_reason():
    out = capability_to_dict(
        union(_fold([], block=B1, reason="owner_read_zero"), _fold([], block=B1, reason="owner_read_zero"))
    )
    assert out["empty_reason"] == "owner_read_zero"
    assert out["exact_as_of"] == B1


# ---------------------------------------------------------------------------
# The refused as-of must not be re-minted downstream
# ---------------------------------------------------------------------------


def test_a_refused_as_of_poisons_every_later_composition():
    """After ``intersect(fold@b1, fold@b2)`` the result carries ONE height (the
    MIN) and ``exact_as_of == "not_determined"``. A second combinator sees a
    single height, would read "all heights equal", and would re-mint the refused
    as-of out of the staleness floor. It must not."""
    first = intersect(_fold([ADDR_A, ADDR_B], block=B1), _fold([ADDR_A], block=B2))
    assert first.exact_as_of == "not_determined"
    second = capability_to_dict(intersect(first, _fold([ADDR_A], block=B1)))
    assert second["last_indexed_block"] == B1
    assert second["exact_as_of"] == "not_determined"

    negated = capability_to_dict(negate(first))
    assert negated["exact_as_of"] == "not_determined"


def test_side_conditions_preserve_height_and_as_of():
    """``X ∩ conditional_universal(c)`` narrows WHEN the set applies, never WHO
    is in it."""
    folded = intersect(_fold([ADDR_A], block=B1), _fold([ADDR_A], block=B1))
    gated = intersect(folded, CapabilityExpr.conditional_universal(Condition(kind="business", description="paused")))
    out = capability_to_dict(gated)
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == B1
