"""A2: fold provenance survives the combinators, fail-closed.

Combinators rebuilt results through factories blind to the operands, dropping the adapter's fold height. A
height propagates only when every operand carries one; ``exact_as_of`` needs equal heights and inherited
emptiness (MIN is a staleness floor); ``empty_reason`` propagates only on inherited emptiness.
"""

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
from services.resolution.capability_resolver import capability_to_dict

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# Two heights measured inside one resolution job, 203 blocks apart yet presented as equally current.
B1 = 25619032
B2 = 25619235


def _fold(members: list[str], *, block: int | None, reason=None) -> CapabilityExpr:
    return CapabilityExpr.finite_set(
        members,
        quality="exact",
        confidence="enumerable",
        last_indexed_block=block,
        trace=[{"step": "enumerable_role_store"}],
        empty_reason=reason,
    )


def _blockless_live_getter(members: list[str]) -> CapabilityExpr:
    """Blockless because the eth_call falls back to ``"latest"``."""
    return CapabilityExpr.finite_set(
        members,
        quality="exact",
        confidence="enumerable",
        trace=[{"step": "live_getter_resolution"}],
    )


def test_leaf_height_is_preserved_on_the_wire():
    out = capability_to_dict(_fold([ADDR_A], block=B1))
    assert out["last_indexed_block"] == B1
    assert "exact_as_of" not in out


def test_equal_heights_license_an_exact_as_of():
    for combine in (intersect, union):
        out = capability_to_dict(combine(_fold([ADDR_A], block=B1), _fold([ADDR_A], block=B1)))
        assert out["last_indexed_block"] == B1
        assert out["exact_as_of"] == B1


def _blacklist(members: list[str], *, block: int | None, quality: str = "exact") -> CapabilityExpr:
    cap = CapabilityExpr.cofinite_blacklist(members, confidence="enumerable", blacklist_quality=quality)  # pyright: ignore[reportArgumentType]
    cap.last_indexed_block = block
    return cap


def test_subtraction_that_creates_emptiness_publishes_no_as_of_and_no_reason():
    """This path has no structural-AND diversion, so the empty set is created here and inherits no witness."""
    out = capability_to_dict(intersect(_fold([ADDR_A], block=B1), _blacklist([ADDR_A], block=B1)))
    assert out["members"] == []
    assert "exact_as_of" not in out
    assert "empty_reason" not in out
    assert out["last_indexed_block"] == B1


def test_already_empty_allow_list_carries_its_reason_through_subtraction():
    out = capability_to_dict(intersect(_fold([], block=B1, reason="owner_read_zero"), _blacklist([ADDR_A], block=B1)))
    assert out["members"] == []
    assert out["empty_reason"] == "owner_read_zero"
    assert out["exact_as_of"] == B1


def test_negate_exact_finite_carries_the_height():
    out = capability_to_dict(negate(_fold([ADDR_A], block=B1)))
    assert out["kind"] == "cofinite_blacklist"
    assert out["blacklist"] == [ADDR_A]
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == B1


def test_negate_lower_bound_finite_carries_the_height_but_no_as_of():
    cap = CapabilityExpr.finite_set([ADDR_A], quality="lower_bound", last_indexed_block=B1)
    out = capability_to_dict(negate(cap))
    assert out["blacklist_quality"] == "lower_bound"
    assert out["last_indexed_block"] == B1
    assert "exact_as_of" not in out


def test_negate_cofinite_carries_the_height_but_never_an_empty_reason():
    """Why a denylist was empty says nothing about why its complement is."""
    source = CapabilityExpr.cofinite_blacklist([], confidence="enumerable")
    source.last_indexed_block = B1
    source.empty_reason = "owner_read_zero"
    out = capability_to_dict(negate(source))
    assert out["kind"] == "finite_set"
    assert out["members"] == []
    assert out["last_indexed_block"] == B1
    assert "empty_reason" not in out


def test_negate_external_check_only_is_a_stated_non_site():
    """Deliberately excluded: a probe interface is never an enumeration.

    Pinned so the omission isn't read as an oversight.
    """
    probe = CapabilityExpr.external_check_only(ExternalCheck(target_address=ADDR_A, target_call_selector="0x12345678"))
    probe.last_indexed_block = B1  # even if something upstream set one
    out = capability_to_dict(negate(probe))
    assert out["kind"] == "cofinite_blacklist"
    assert "last_indexed_block" not in out
    assert "exact_as_of" not in out


# Heterogeneous heights are an earned refusal; the published height is the MIN.
@pytest.mark.parametrize(
    ("make", "expected"),
    [
        pytest.param(
            lambda: intersect(_fold([ADDR_A, ADDR_B], block=B1), _fold([ADDR_A], block=B2)),
            {"members": [ADDR_A]},
            id="intersect-two-folds",
        ),
        pytest.param(
            lambda: union(_fold([ADDR_A], block=B1), _fold([ADDR_B], block=B2)),
            {"members": [ADDR_A, ADDR_B]},
            id="union-two-folds",
        ),
        pytest.param(
            lambda: intersect(_fold([ADDR_A, ADDR_B], block=B1), _blacklist([ADDR_B], block=B2)),
            {"members": [ADDR_A]},
            id="intersect-finite-blacklist",
        ),
        pytest.param(
            lambda: intersect(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=B2)),
            {},
            id="intersect-cofinite-pair",
        ),
        pytest.param(
            lambda: union(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=B2)),
            {},
            id="union-cofinite-pair",
        ),
        pytest.param(
            lambda: union(_fold([ADDR_A], block=B1), _blacklist([ADDR_A, ADDR_B], block=B2)),
            {},
            id="union-finite-blacklist",
        ),
    ],
)
def test_combinators_propagate_min_height_and_refuse_as_of(make, expected):
    out = capability_to_dict(make())
    for key, value in expected.items():
        assert out[key] == value, out
    assert out["last_indexed_block"] == B1, out
    assert out["exact_as_of"] == "not_determined", out


@pytest.mark.parametrize(
    "make",
    [
        # The shape of all 261 solmate rows: ``OR(fold, live owner() read)``.
        pytest.param(
            lambda: intersect(_fold([ADDR_A], block=B1), _blockless_live_getter([ADDR_A])),
            id="intersect-with-live-getter",
        ),
        pytest.param(
            lambda: union(_fold([ADDR_A], block=B1), _blockless_live_getter([ADDR_B])),
            id="union-with-live-getter",
        ),
        pytest.param(
            lambda: intersect(_fold([ADDR_A, ADDR_B], block=B1), _blacklist([ADDR_B], block=None)),
            id="intersect-finite-blacklist",
        ),
        pytest.param(lambda: negate(CapabilityExpr.finite_set([ADDR_A], quality="exact")), id="negate-exact-finite"),
        pytest.param(
            lambda: negate(CapabilityExpr.finite_set([ADDR_A], quality="lower_bound")),
            id="negate-lower-bound-finite",
        ),
        pytest.param(lambda: negate(CapabilityExpr.cofinite_blacklist([ADDR_A])), id="negate-cofinite"),
        pytest.param(
            lambda: intersect(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=None)),
            id="intersect-cofinite-pair",
        ),
        pytest.param(
            lambda: union(_blacklist([ADDR_A], block=B1), _blacklist([ADDR_B], block=None)),
            id="union-cofinite-pair",
        ),
        pytest.param(
            lambda: union(_fold([ADDR_A], block=B1), _blacklist([ADDR_B], block=None)),
            id="union-finite-blacklist",
        ),
    ],
)
def test_blockless_operand_publishes_no_height(make):
    out = capability_to_dict(make())
    assert "last_indexed_block" not in out, out
    assert "exact_as_of" not in out, out


def test_inherited_emptiness_keeps_its_reason():
    out = capability_to_dict(intersect(_fold([], block=B1, reason="empty_by_design"), _fold([ADDR_A], block=B1)))
    assert out["members"] == []
    assert out["empty_reason"] == "empty_by_design"


def test_created_emptiness_diverts_to_structural_and_and_mints_no_reason():
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


def test_a_refused_as_of_poisons_every_later_composition():
    """A second combinator would read "all heights equal" off the MIN and re-mint the refused as-of."""
    first = intersect(_fold([ADDR_A, ADDR_B], block=B1), _fold([ADDR_A], block=B2))
    assert first.exact_as_of == "not_determined"
    second = capability_to_dict(intersect(first, _fold([ADDR_A], block=B1)))
    assert second["last_indexed_block"] == B1
    assert second["exact_as_of"] == "not_determined"

    assert capability_to_dict(negate(first))["exact_as_of"] == "not_determined"


def test_empty_result_at_heterogeneous_heights_still_refuses():
    """A member revoked from the later operand is absent while the true set at b1 still held it."""
    out = capability_to_dict(intersect(_fold([], block=B1, reason="owner_read_zero"), _fold([ADDR_A], block=B2)))
    assert out["members"] == []
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == "not_determined"
    assert out["exact_as_of"] != B1


# Early returns used to leave a heterogeneous MIN with no refusal recorded, so the next combinator minted the as-of; the
# refusal is now recorded before both.


def test_created_empty_subtraction_does_not_launder_a_heterogeneous_as_of():
    created_empty = intersect(_fold([ADDR_A], block=B1), _blacklist([ADDR_A], block=B2))
    assert created_empty.members == []
    assert created_empty.exact_as_of == "not_determined"

    composed = capability_to_dict(intersect(created_empty, _fold([ADDR_A], block=B1)))
    assert composed["exact_as_of"] == "not_determined"
    assert composed["exact_as_of"] != B1


def test_negating_a_created_empty_does_not_launder_a_heterogeneous_as_of():
    created_empty = intersect(_fold([ADDR_A], block=B1), _blacklist([ADDR_A], block=B2))
    out = capability_to_dict(negate(created_empty))
    assert out["kind"] == "cofinite_blacklist"
    assert out["exact_as_of"] == "not_determined"
    assert out["exact_as_of"] != B1


def test_lower_bound_cofinite_does_not_launder_a_heterogeneous_as_of():
    """The denylist was observed at b2."""
    lower_bound_cofinite = union(
        _fold([ADDR_A], block=B1),
        _blacklist([ADDR_A, ADDR_B], block=B2, quality="lower_bound"),
    )
    assert lower_bound_cofinite.exact_as_of == "not_determined"

    composed = capability_to_dict(intersect(_fold([ADDR_A, ADDR_B], block=B1), lower_bound_cofinite))
    assert composed["members"] == [ADDR_A]
    assert composed["exact_as_of"] == "not_determined"
    assert composed["exact_as_of"] != B1


def test_side_conditions_preserve_height_and_as_of():
    folded = intersect(_fold([ADDR_A], block=B1), _fold([ADDR_A], block=B1))
    gated = intersect(folded, CapabilityExpr.conditional_universal(Condition(kind="business", description="paused")))
    out = capability_to_dict(gated)
    assert out["last_indexed_block"] == B1
    assert out["exact_as_of"] == B1
