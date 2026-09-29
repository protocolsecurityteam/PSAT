"""§7 (G7) — the authority-plane §9 direction.

Effects is the only stage that executes a call AS a resolved principal, so it can
falsify authority resolution: an EXACT ``finite_set`` whose member is rejected by
a CANONICAL gate-rejection selector named the wrong holder. The detector must key
on selectors ONLY (the first pass false-positived by substring-matching "not ").
"""

from __future__ import annotations

from typing import Any

import pytest

from services.effects import discrepancies
from services.effects.selection import _membership_exact
from utils.logging import degraded_errors_var

# Canonical OZ v5 gate-rejection selectors.
ACCESS_CONTROL_UNAUTHORIZED = "0xe2517d3f"  # AccessControlUnauthorizedAccount(address,bytes32)
OWNABLE_UNAUTHORIZED = "0x118cdaa7"  # OwnableUnauthorizedAccount(address)
# A STATE precondition, not a gate rejection: OZ TimelockController's
# TimelockUnexpectedOperationState / "operation is not ready" family.
STATE_PRECONDITION = "0x5ead8eb5"  # TimelockUnexpectedOperationState(bytes32,bytes32)

CONTRACT = "0x" + "cd" * 20
SELECTOR = "0x224d8703"


def _transcript(*revert_selectors: str, success_first: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    if success_first:
        results.append({"label": "value_probe", "success": True, "return_or_revert": "0x", "decoded": None})
    for sel in revert_selectors:
        results.append({"label": "value_probe", "success": False, "return_or_revert": sel + "00" * 32, "decoded": None})
    return {"results": results}


def _run(transcript, *, effect_class="value_out", membership_exact=True):
    token = degraded_errors_var.set([])
    try:
        filed = discrepancies.authority_contradiction(
            effect_class=effect_class,
            transcript=transcript,
            membership_exact=membership_exact,
            contract_address=CONTRACT,
            selector=SELECTOR,
            tier="tier1",
            transcript_ptr="ptr",
        )
        return filed, list(degraded_errors_var.get() or ())
    finally:
        degraded_errors_var.reset(token)


def test_membership_exact_requires_finite_set_and_exact_quality():
    assert _membership_exact({"kind": "finite_set", "membership_quality": "exact"}) is True
    # A public capability is ``exact`` too, but not a finite enumeration to contradict.
    assert _membership_exact({"kind": "conditional_universal", "membership_quality": "exact"}) is False
    assert _membership_exact({"kind": "unsupported", "membership_quality": "exact"}) is False
    assert _membership_exact({"kind": "finite_set", "membership_quality": "approximate"}) is False
    assert _membership_exact(None) is False


@pytest.mark.parametrize(
    ("selector", "success_first"),
    [
        pytest.param(ACCESS_CONTROL_UNAUTHORIZED, False, id="access_control_unauthorized"),
        pytest.param(OWNABLE_UNAUTHORIZED, True, id="ownable_unauthorized"),
    ],
)
def test_canonical_gate_rejection_on_an_exact_member_files_a_degraded_error(selector, success_first):
    filed, errors = _run(_transcript(selector, success_first=success_first))
    assert filed is True
    assert len(errors) == 1
    err = errors[0]
    assert err.severity == "degraded"
    assert err.context is not None
    assert err.context["discrepancy_kind"] == discrepancies.AUTHORITY_CONTRADICTION_KIND
    assert err.context["gate_rejection_selector"] == selector


@pytest.mark.parametrize(
    ("transcript", "run_kwargs"),
    [
        # THE case that matters (§7): a state error carries a different, published selector, so a
        # selector-keyed detector never mistakes it for a gate rejection, where a revert-string substring
        # match would.
        pytest.param(_transcript(STATE_PRECONDITION), {}, id="state_precondition_revert"),
        pytest.param(_transcript(ACCESS_CONTROL_UNAUTHORIZED), {"membership_exact": False}, id="non_exact_membership"),
        # ``authority_change`` rejects RANDOM identities at the gate by design, so a gate-rejection revert
        # there is expected behaviour, not a contradiction.
        pytest.param(
            _transcript(ACCESS_CONTROL_UNAUTHORIZED), {"effect_class": "authority_change"}, id="authority_change_class"
        ),
        pytest.param(_transcript(success_first=True), {}, id="probe_that_executed"),
    ],
)
def test_files_nothing(transcript, run_kwargs):
    filed, errors = _run(transcript, **run_kwargs)
    assert filed is False
    assert errors == []


# ---------------------------------------------------------------------------
# The worker routing seam (_route_section9): the wiring, not just the detector.
# ---------------------------------------------------------------------------


def test_route_section9_files_the_authority_contradiction_on_a_fresh_probe():
    from services.effects.harness import ObservedEffect
    from services.effects.selection import Candidate
    from workers.effects_worker import EffectsWorker, _Counters, _Item

    cand = Candidate(
        function_id=1,
        contract_id=1,
        contract_address=CONTRACT,
        selector=SELECTOR,
        function_name="sweepETH(address,uint256)",
        authority_public=False,
        principal_addresses=("0x" + "a0" * 20,),
        membership_exact=True,
    )
    probed = ObservedEffect(
        effect_class="value_out",
        verdict="unknown",
        tier="tier1",
        reason="value_probe_reverted",
        details={"observation": "reverted"},
        transcript=_transcript(ACCESS_CONTROL_UNAUTHORIZED),
    )
    item = _Item(
        candidate=cand,
        effect_class="value_out",
        scope="kernel",
        gate_ref="",
        behavior_hash="bh",
        surface_hash="sh",
        run=lambda: probed,
        cached=None,
        needs_audit=False,
        probed=probed,
    )
    counters = _Counters()
    token = degraded_errors_var.set([])
    try:
        # No ``self`` state is touched by the method — a bare instance is enough.
        EffectsWorker._route_section9(object.__new__(EffectsWorker), item, "unknown", "tier1", "ptr", None, counters)
        errors = list(degraded_errors_var.get() or ())
    finally:
        degraded_errors_var.reset(token)
    assert counters.discrepancies_filed == 1
    assert len(errors) == 1
    err = errors[0]
    assert err.context is not None
    assert err.context["discrepancy_kind"] == discrepancies.AUTHORITY_CONTRADICTION_KIND
