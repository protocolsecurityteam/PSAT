"""§7 (G7) — the authority-plane §9 direction.

Effects is the only stage that executes a call AS a resolved principal, so it is
uniquely able to falsify authority resolution. When the resolver marks a
function's caller set an EXACT ``finite_set`` and the probe — run as that member —
is rejected by a CANONICAL, published gate-rejection selector, the enumeration
named the wrong holder. The detector must key on selectors ONLY: the negative
below (a state-precondition revert-string) is the case that matters, because the
first pass of this investigation false-positived by substring-matching "not ".
"""

from __future__ import annotations

from typing import Any

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


def test_canonical_gate_rejection_on_an_exact_member_files_a_degraded_error():
    filed, errors = _run(_transcript(ACCESS_CONTROL_UNAUTHORIZED))
    assert filed is True
    assert len(errors) == 1
    err = errors[0]
    assert err.severity == "degraded"
    assert err.context is not None
    assert err.context["discrepancy_kind"] == discrepancies.AUTHORITY_CONTRADICTION_KIND
    assert err.context["gate_rejection_selector"] == ACCESS_CONTROL_UNAUTHORIZED


def test_ownable_unauthorized_also_files():
    filed, errors = _run(_transcript(OWNABLE_UNAUTHORIZED, success_first=True))
    assert filed is True
    err = errors[0]
    assert err.context is not None
    assert err.context["gate_rejection_selector"] == OWNABLE_UNAUTHORIZED


def test_a_state_precondition_revert_files_nothing():
    """THE test that matters (§7): a state error carries a different, published
    selector, so a selector-keyed detector never mistakes it for a gate rejection —
    where a revert-string substring match would."""
    filed, errors = _run(_transcript(STATE_PRECONDITION))
    assert filed is False
    assert errors == []


def test_a_non_exact_membership_files_nothing():
    filed, errors = _run(_transcript(ACCESS_CONTROL_UNAUTHORIZED), membership_exact=False)
    assert filed is False
    assert errors == []


def test_authority_change_class_is_excluded():
    """``authority_change`` rejects RANDOM identities at the gate by design, so a
    gate-rejection revert there is expected behaviour, not a contradiction."""
    filed, errors = _run(_transcript(ACCESS_CONTROL_UNAUTHORIZED), effect_class="authority_change")
    assert filed is False
    assert errors == []


def test_a_probe_that_executed_files_nothing():
    filed, errors = _run(_transcript(success_first=True))
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
        effect_targets=(),
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
