"""Phase 2 wiring tests: the differential probe's integration into the capability
resolver (DIFFERENTIAL_PROBE_PLAN §3.6). Hermetic — the wire is injected, no RPC.

Asserts the strictly-additive invariant (§7.1): the probe runs ONLY for the
gated-unknown population, a confirmed-public verdict re-projects to public, every
other outcome keeps the static gated verdict, and any failure is swallowed.
"""

from __future__ import annotations

from typing import Any

from services.clients.rpc import EthCallResult
from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution import differential_probe as dp
from services.resolution.capabilities import CapabilityExpr, ExternalCheck
from services.resolution.capability_resolver import (
    _apply_probe_result,
    _maybe_differential_probe,
    _should_differential_probe,
    capability_to_dict,
)


def ok(ret: str = "0x") -> EthCallResult:
    return EthCallResult(True, ret, None, None)


def revert(data: str) -> EthCallResult:
    return EthCallResult(False, "0x", data, "execution reverted")


def _gated_unknown_cap(selector_hint: str = "0xabcdef01") -> CapabilityExpr:
    return CapabilityExpr.external_check_only(
        ExternalCheck(
            target_address=None,
            target_call_selector=selector_hint,
            extra={"basis": ["caller_tainted_authority_unresolved"]},
        )
    )


# ---------------------------------------------------------------------------
# flag default + trigger population
# ---------------------------------------------------------------------------


def test_flag_defaults_on(monkeypatch):
    # Phase 3 gate green → default ON; delenv removes the conftest hermetic force-off.
    monkeypatch.delenv("PSAT_DIFFERENTIAL_PROBE", raising=False)
    assert dp.differential_probe_enabled() is True
    monkeypatch.setenv("PSAT_DIFFERENTIAL_PROBE", "0")  # kill-switch
    assert dp.differential_probe_enabled() is False


def test_should_probe_only_gated_unknown_external_check():
    assert _should_differential_probe(_gated_unknown_cap()) is True
    # Not a caller-gate external check (no basis tag) → downstream probe / adapter-pending, skip.
    assert (
        _should_differential_probe(
            CapabilityExpr.external_check_only(ExternalCheck(None, "0x1", extra={"basis": ["delegated_check"]}))
        )
        is False
    )
    # Cold-index self-heal deferral → NEVER probe (would freeze the cold result).
    deferred_extra = {"basis": ["caller_tainted_authority_unresolved"], "deferred_pending_index": True}
    assert (
        _should_differential_probe(CapabilityExpr.external_check_only(ExternalCheck(None, "0x1", extra=deferred_extra)))
        is False
    )
    # Other kinds are already resolved — not the probe's job.
    assert _should_differential_probe(CapabilityExpr.finite_set(["0x" + "11" * 20])) is False
    assert _should_differential_probe(CapabilityExpr.unsupported("x")) is False


# ---------------------------------------------------------------------------
# §3.6 verdict landing
# ---------------------------------------------------------------------------


def test_apply_public_result_mints_conditional_universal_that_projects_public():
    cap = _gated_unknown_cap()
    result = dp.ProbeResult(
        attribution="not_caller_discriminating",
        verdict="public",
        transcript={"feature": "differential_probe", "attribution": "not_caller_discriminating", "block_number": 5},
        reason="open_and_block_independent",
    )
    opened = _apply_probe_result(cap, result)
    assert opened.kind == "conditional_universal"
    # Transcript travels into the persisted capability (replayable, §6.1).
    cap_dict = capability_to_dict(opened)
    assert any(step.get("step") == "differential_probe" for step in cap_dict.get("trace", []))
    # And it re-projects to a PUBLIC verdict.
    surface = project_capability_surface(cap_dict)
    assert surface.authority_public is True
    assert capability_surface_status(cap_dict, surface) == "public"


def test_apply_gated_result_keeps_external_check_and_attaches_evidence():
    cap = _gated_unknown_cap()
    cases: list[tuple[dp.Verdict, dp.Attribution]] = [
        ("gated_confirmed", "caller_discriminating"),
        ("gated_observed", "caller_rejected_consistent"),
        ("keep_static", "indeterminate"),
    ]
    for verdict, attribution in cases:
        result = dp.ProbeResult(
            attribution=attribution, verdict=verdict, transcript={"attribution": attribution}, reason=attribution
        )
        out = _apply_probe_result(cap, result)
        assert out.kind == "external_check_only"
        assert out.check is not None
        assert out.check.extra["differential_probe"]["attribution"] == attribution
        # The original caller-gate basis tag survives (still gated-unknown).
        assert "caller_tainted_authority_unresolved" in out.check.extra["basis"]
        cap_dict = capability_to_dict(out)
        surface = project_capability_surface(cap_dict)
        assert surface.authority_public is False
        assert capability_surface_status(cap_dict, surface) is None  # gated, principals unknown


# ---------------------------------------------------------------------------
# _maybe_differential_probe end-to-end with an injected wire
# ---------------------------------------------------------------------------

CANON = {"setClaimingOpen(uint256)": "setClaimingOpen(uint256)"}


def test_maybe_probe_upgrades_open_function():
    cap = _gated_unknown_cap()
    out = _maybe_differential_probe(
        cap,
        chain_id=1,
        contract_address="0x" + "77" * 20,
        fn_signature="setClaimingOpen(uint256)",
        canonical_signatures=CANON,
        rpc_url="http://rpc",
        block=1_000_000,
        call_batch=lambda calls, tag: [ok() for _ in calls],  # success at both blocks
    )
    assert out.kind == "conditional_universal"


def test_maybe_probe_keeps_gated_for_rejecting_function():
    cap = _gated_unknown_cap()
    out = _maybe_differential_probe(
        cap,
        chain_id=1,
        contract_address="0x" + "77" * 20,
        fn_signature="setClaimingOpen(uint256)",
        canonical_signatures=CANON,
        rpc_url="http://rpc",
        block=1_000_000,
        call_batch=lambda calls, tag: [revert("0x08c379a0") for _ in calls],
    )
    assert out.kind == "external_check_only"
    assert out.check is not None
    assert "differential_probe" in out.check.extra


def test_maybe_probe_is_noop_for_non_gated_unknown_cap():
    cap = CapabilityExpr.finite_set(["0x" + "11" * 20])
    calls_made = []

    def wire(calls, tag):
        calls_made.append(calls)
        return [ok() for _ in calls]

    out = _maybe_differential_probe(
        cap,
        chain_id=1,
        contract_address="0x" + "77" * 20,
        fn_signature="setClaimingOpen(uint256)",
        canonical_signatures=CANON,
        rpc_url="http://rpc",
        block=1_000_000,
        call_batch=wire,
    )
    assert out is cap  # unchanged
    assert calls_made == []  # never hit the wire


def test_probe_cache_skips_wire_on_second_resolve(monkeypatch):
    # On the real-wire path (call_batch=None), the same (chain,addr,selector,block)
    # is probed once and cached; a second resolve reuses it without hitting the wire.
    import services.resolution.capability_resolver as cr

    cr.clear_probe_cache()
    calls = {"n": 0}

    def fake_wire(rpc_url, batch, block_tag, *, chain_id=1):
        calls["n"] += 1
        return [ok() for _ in batch]

    monkeypatch.setattr(cr, "eth_call_batch", fake_wire)
    kw: dict[str, Any] = dict(
        chain_id=1,
        contract_address="0x" + "99" * 20,
        fn_signature="setClaimingOpen(uint256)",
        canonical_signatures=CANON,
        rpc_url="http://rpc",
        block=2_000_000,
    )
    out1 = cr._maybe_differential_probe(_gated_unknown_cap(), **kw)
    batches_after_first = calls["n"]
    out2 = cr._maybe_differential_probe(_gated_unknown_cap(), **kw)
    assert out1.kind == out2.kind == "conditional_universal"
    assert batches_after_first > 0
    assert calls["n"] == batches_after_first  # second resolve hit the cache, not the wire
    cr.clear_probe_cache()


def test_maybe_probe_swallows_wire_failure_and_keeps_static():
    cap = _gated_unknown_cap()

    def boom(calls, tag):
        raise RuntimeError("rpc exploded")

    out = _maybe_differential_probe(
        cap,
        chain_id=1,
        contract_address="0x" + "77" * 20,
        fn_signature="setClaimingOpen(uint256)",
        canonical_signatures=CANON,
        rpc_url="http://rpc",
        block=1_000_000,
        call_batch=boom,
    )
    assert out is cap  # additive: a probe failure never changes the verdict
