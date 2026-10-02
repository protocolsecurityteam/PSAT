"""A3: the hoisted basis must never be attributed to members it did not resolve.

Merged finite sets concatenate operand traces, so one basis step can sit beside members an event fold
contributed. Stored rows also carry the pre-split ``internal_accessor_convention``, which can't be ranked, so an
unrecognised basis publishes nothing.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.policy.capability_surface import project_capability_surface

ADDR_A = "0x" + "aa" * 20
ADDR_B = "0x" + "bb" * 20


def _cap(members: list[str], trace: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "kind": "finite_set",
        "members": members,
        "membership_quality": "exact",
        "confidence": "enumerable",
        "trace": trace,
    }


def _details(cap: dict[str, Any]) -> list[dict[str, Any]]:
    return [row["details"] for row in project_capability_surface(cap).principal_rows]


BASIS_STEP = {"step": "authority_getter_basis", "basis": "deunderscore_convention", "selector": "0x0c340a24"}
CO_WITNESS = {"step": "live_getter_resolution", "selector": "0x0c340a24"}


_ABI_STEP = {"step": "authority_getter_basis", "basis": "abi_auto_getter", "selector": "0x8da5cb5b"}


@pytest.mark.parametrize(
    "trace",
    [
        # A fold contributed members beside the getter read.
        pytest.param([BASIS_STEP, {"step": "enumerable_role_store"}], id="second-resolution-step-suppresses"),
        pytest.param([BASIS_STEP, _ABI_STEP], id="two-basis-steps-that-disagree"),
        # Two steps mean two reads, and which bound the member isn't recorded.
        pytest.param([BASIS_STEP, dict(BASIS_STEP)], id="two-identical-basis-steps"),
        # The pre-split label is deliberately not mapped forward: absent is the honest weakest reading.
        pytest.param(
            [CO_WITNESS, {"step": "authority_getter_basis", "basis": "internal_accessor_convention"}],
            id="legacy-label-not-passed-through",
        ),
        pytest.param(
            [{"step": "authority_getter_basis", "basis": "some_future_arm"}], id="unknown-label-not-passed-through"
        ),
        pytest.param([{"step": "authority_getter_basis", "basis": 7}], id="non-string-basis"),
    ],
)
def test_hoist_is_suppressed_when_the_basis_is_not_attributable(trace):
    assert "authority_basis" not in _details(_cap([ADDR_A], trace))[0]
