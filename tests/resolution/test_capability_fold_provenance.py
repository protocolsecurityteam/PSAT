"""A2: fold provenance survives the combinators, fail-closed.

Combinators rebuilt results through factories blind to the operands, dropping the adapter's fold height. A
height propagates only when every operand carries one; ``exact_as_of`` needs equal heights and inherited
emptiness (MIN is a staleness floor); ``empty_reason`` propagates only on inherited emptiness.
"""

from __future__ import annotations

import pytest

from services.resolution.capabilities import (
    CapabilityExpr,
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


def _blacklist(members: list[str], *, block: int | None, quality: str = "exact") -> CapabilityExpr:
    cap = CapabilityExpr.cofinite_blacklist(members, confidence="enumerable", blacklist_quality=quality)  # pyright: ignore[reportArgumentType]
    cap.last_indexed_block = block
    return cap


def test_already_empty_allow_list_carries_its_reason_through_subtraction():
    out = capability_to_dict(intersect(_fold([], block=B1, reason="owner_read_zero"), _blacklist([ADDR_A], block=B1)))
    assert out["members"] == []
    assert out["empty_reason"] == "owner_read_zero"
    assert out["exact_as_of"] == B1


def test_negate_lower_bound_finite_carries_the_height_but_no_as_of():
    cap = CapabilityExpr.finite_set([ADDR_A], quality="lower_bound", last_indexed_block=B1)
    out = capability_to_dict(negate(cap))
    assert out["blacklist_quality"] == "lower_bound"
    assert out["last_indexed_block"] == B1
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


def test_inherited_emptiness_keeps_its_reason():
    out = capability_to_dict(intersect(_fold([], block=B1, reason="empty_by_design"), _fold([ADDR_A], block=B1)))
    assert out["members"] == []
    assert out["empty_reason"] == "empty_by_design"


def test_union_of_two_empties_carries_the_agreed_reason():
    out = capability_to_dict(
        union(_fold([], block=B1, reason="owner_read_zero"), _fold([], block=B1, reason="owner_read_zero"))
    )
    assert out["empty_reason"] == "owner_read_zero"
    assert out["exact_as_of"] == B1


# Early returns used to leave a heterogeneous MIN with no refusal recorded, so the next combinator minted the as-of; the
# refusal is now recorded before both.


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
