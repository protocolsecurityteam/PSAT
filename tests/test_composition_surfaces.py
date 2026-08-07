"""The two composed-entry surfaces §8 ruled on, and the disclosures beside them.

B2's module. Each case is a *derivation* pinned by two carriers whose data
differs, never by one carrier against a literal the code could have hard-coded:
the mutation that de-interpolates a derived string into a constant has to fail
here, and a test that asserts only that the field exists does not count.
"""

from __future__ import annotations

from typing import Any

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests import composition_admission_fixtures as CA
from tests.test_scoring_redteam import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    KEY_C,
    KEY_V,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    fold,  # noqa: F401  — the fold fixture
)

_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_CONSTRAINS_THE_TARGET_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "constrained"),)
_GATING_AUTHORITY = "0x" + "9" * 40
_VAULT_CONSULTS_AN_AUTHORITY = {("ethereum", KEY_V.partition("::")[2], COMPOSED_SELECTOR): (_GATING_AUTHORITY,)}

# The token §7.2 named and CAP-A §R2 retired. Kept as a literal here on purpose:
# it is the one string this module asserts the ABSENCE of, and a symbol would
# make the assertion vacuous the day the symbol is deleted.
RETIRED_CALLEE_TOKEN = "destination_callee_is_restricted_by_the_intermediate"


def _withheld(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes_withheld") or [])


def _gate_only_document(fold, routes):  # noqa: F811
    """One withheld entry on the gate-only arm, under the token ``routes`` earns.

    The deletability plane returns no setter row, so arm 3 cannot republish and
    the route decides the arm — which is what makes the two route fixtures below
    differ in the token and in nothing else.
    """
    return fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(routes),
        **_composing_case(),
    )


# ---------------------------------------------------------------------------
# CAP-A §R2 — the token names the field it is earned from
# ---------------------------------------------------------------------------


def test_the_second_typed_reason_names_the_constrained_target_and_not_a_callee(fold):  # noqa: F811
    """CAP-A §R2. The token is read off ``target_constraint``, which pins the
    destination call's counterparty ARGUMENT. The callee of that call is an
    intra-unit AST name and no stored witness restricts it, so a token saying
    "the callee is restricted" asserted a security property the evidence does not
    earn — and did so on every carrier it had.

    The state and the boolean it is earned from now share one name, which is the
    disagreement that found the defect.
    """
    entry = _withheld(_gate_row(_gate_only_document(fold, _CONSTRAINS_THE_TARGET_AT_C)))[0]
    classification = entry["route_classification"]

    assert classification["state"] == P.ROUTE_TARGET_CONSTRAINED
    assert entry["withheld_reason"] == P.ROUTE_TARGET_CONSTRAINED
    # The token IS the name of the field it is read from, in the same block.
    assert classification[classification["state"]] is True
    assert "callee" not in P.ROUTE_TARGET_CONSTRAINED


@pytest.mark.parametrize(
    "routes",
    [_AUTHORS_THE_AMOUNT_AT_C, _CONSTRAINS_THE_TARGET_AT_C, ()],
    ids=["amount_authored", "target_constrained", "no_flow_witness"],
)
def test_no_published_route_state_claims_a_restricted_callee(fold, routes):  # noqa: F811
    """The retired token has no producer: the classifier cannot emit it under any
    of its outcomes, and it is not in the registry a state is checked against."""
    assert RETIRED_CALLEE_TOKEN not in P.ROUTE_CLASSIFICATIONS
    row = _gate_row(_gate_only_document(fold, routes))
    for entry in _withheld(row):
        assert entry["route_classification"]["state"] != RETIRED_CALLEE_TOKEN
        assert entry["withheld_reason"] != RETIRED_CALLEE_TOKEN
    assert RETIRED_CALLEE_TOKEN not in row["reach_composition_census"]["reading"]


# ---------------------------------------------------------------------------
# B1-R R2-a — the gate-only arm fires on two tokens and its cause names which
# ---------------------------------------------------------------------------


def test_the_census_cause_names_the_route_token_and_not_only_the_arm(fold):  # noqa: F811
    """B1-R R2-a. ``ARM_GATE_ONLY`` is taken on either of two route tokens and
    the census gave both the AUTHORING cause, so a target-constrained carrier
    read one thing in the census and another in its own ``withheld_reason``, two
    blocks apart on one row.

    The two documents differ only in the intermediate's stored flow witness. A
    cause keyed on the arm alone publishes one sentence for both and fails here.
    """
    authored = _gate_row(_gate_only_document(fold, _AUTHORS_THE_AMOUNT_AT_C))
    constrained = _gate_row(_gate_only_document(fold, _CONSTRAINS_THE_TARGET_AT_C))

    # Same arm, same count — only the token differs.
    for row, token in ((authored, P.ROUTE_AMOUNT_AUTHORED), (constrained, P.ROUTE_TARGET_CONSTRAINED)):
        assert _withheld(row)[0]["arm_taken"] == FOLD.ARM_GATE_ONLY
        assert _withheld(row)[0]["withheld_reason"] == token
        assert row["reach_composition_census"]["composed_withheld_by_arm"] == {FOLD.ARM_GATE_ONLY: 1}

    authored_reading = authored["reach_composition_census"]["reading"]
    constrained_reading = constrained["reach_composition_census"]["reading"]
    assert authored_reading != constrained_reading
    assert "AUTHORING" in authored_reading and "AUTHORING" not in constrained_reading
    assert "PINNING" in constrained_reading and "PINNING" not in authored_reading
    # ...and the census points at the field that separates the two tokens rather
    # than at composed_withheld_by_arm, which does not.
    assert "composed_withheld_by_reason" in constrained_reading
    assert constrained["reach_composition_census"]["composed_withheld_by_reason"] == {P.ROUTE_TARGET_CONSTRAINED: 1}


def test_a_cause_is_registered_per_arm_and_route_token_with_no_fall_through():
    """No default sentence: an unregistered pair raises rather than reaching the
    document through a cause nobody wrote for it. And the count the closing
    sentence prints is the registry's own size, so a frozen "three" cannot
    survive the day a fourth cause is registered."""
    assert (FOLD.ARM_GATE_ONLY, P.ROUTE_AMOUNT_AUTHORED) in FOLD._WITHHELD_CAUSE_ORDER
    assert (FOLD.ARM_GATE_ONLY, P.ROUTE_TARGET_CONSTRAINED) in FOLD._WITHHELD_CAUSE_ORDER
    assert (FOLD.ARM_GATE_ONLY, None) not in FOLD._WITHHELD_CAUSE_ORDER
    with pytest.raises(KeyError):
        FOLD._withheld_cause((FOLD.ARM_GATE_ONLY, P.ROUTE_NOT_DETERMINED))
    with pytest.raises(KeyError):
        FOLD._withheld_cause((FOLD.ARM_REPUBLISHED_DIRECT, None))
    assert f"The {len(FOLD._WITHHELD_CAUSE_ORDER)} registered causes" in FOLD._withheld_cause_clause(
        (_a_withheld_record(),)
    )
    # The empty case counts nothing and claims nothing about the registry.
    assert "registered causes" not in FOLD._withheld_cause_clause(())


def _a_withheld_record() -> FOLD._WithheldComposition:
    from utils import execution_record as EX

    return FOLD._WithheldComposition(
        entity=KEY_V,
        selector=COMPOSED_SELECTOR,
        function="exit",
        chain=(),
        execution=FOLD.EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_NOT_PERSISTED),
        arm=FOLD.ARM_NOT_DETERMINED,
        reason=P.ROUTE_NO_FLOW_WITNESS,
        route=P.RouteClassification(P.ROUTE_NOT_DETERMINED, P.ROUTE_NO_FLOW_WITNESS, (), None, None),
        deletability=P.authority_deletability(P.DeletabilityPlane({}, {}, {}), [], KEY_V, COMPOSED_SELECTOR),
    )
