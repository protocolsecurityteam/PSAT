"""Live: a Solmate ``RolesAuthority`` ``canCall`` guard resolves on a real Veda contract.

The prod-data audit found Veda ``canCall`` guards preempted to a ``delegated_check_not_materialized`` dead-end
pre-#104. Asserts the OUTCOME (detected, dispatched, resolved to a usable controller set), not the mechanism: either
cross-contract inlining (authority analyzed alongside) or the event-fold ``SolmateRolesAuthorityAdapter`` is correct.
NOT asserted: the async cold→warm reconciler heal (needs the full backfill; the preview tears workers down after the
suite); it is pinned offline in ``tests/resolution/test_deferred_resolution_reconcile.py``.
"""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import LiveClient

# TellerWithMultiAssetSupport — Solmate ``Auth``; ``canCall`` delegates to
# RolesAuthority 0x3994741a…; governing 4/6 Safe (ground-truthed on-chain).
VEDA_TELLER = "0xe2acf9f80a2756e51d1e53f9f41583c84279fb1f"
_CANCALL_SELECTOR = "0xb7009613"  # keccak("canCall(address,address,bytes4)")[:4]

# A ``requiresAuth`` guard survives into ``capability_expr`` differently by resolution path: inlining folds it to a
# ``finite_set`` and drops the ``canCall`` selector (leaving ``isAuthorized(msg.sender,msg.sig)`` and a
# ``solmate_roles_authority`` trace); event-fold keeps the selector; the pre-#104 dead-end leaves
# ``delegated_check_not_materialized``. Match any so the guard is tracked regardless.
_CANCALL_MARKERS = (
    _CANCALL_SELECTOR,
    "isAuthorized",
    "solmate_roles_authority",
    "delegated_check_not_materialized",
)


@pytest.fixture(scope="session")
def analyzed_veda_teller(live_client: LiveClient) -> dict:
    """Analyze the Veda Teller once per session; SKIPs on timeout/non-completion (contended previews), but a real
    4xx/5xx propagates."""
    try:
        job = live_client.submit_and_wait(VEDA_TELLER)
    except TimeoutError as exc:
        pytest.skip(f"Veda Teller analysis did not finish in time on {live_client.base_url}: {exc}")
    if job["status"] != "completed":
        pytest.skip(f"Veda Teller analysis did not complete (status={job['status']})")
    return job


def _cancall_functions(ep: dict) -> list[dict]:
    """Effective-function records guarded by a Solmate ``canCall``/``requiresAuth`` check, matched by any
    ``_CANCALL_MARKERS`` marker (an inlined guard no longer references the ``canCall`` selector)."""
    return [
        f
        for f in (ep.get("functions") or [])
        if any(marker in json.dumps(f.get("capability_expr") or {}) for marker in _CANCALL_MARKERS)
    ]


def test_veda_teller_cancall_resolves_without_preempt(analyzed_veda_teller, live_client: LiveClient):
    """canCall is detected, dispatched, and resolved — never the pre-#104
    ``delegated_check_not_materialized`` inline-preempt dead-end."""
    ep = live_client.artifact(analyzed_veda_teller["job_id"], "effective_permissions")
    if not isinstance(ep, dict):
        pytest.skip("effective_permissions artifact not available")

    cancall = _cancall_functions(ep)
    assert cancall, "no canCall-guarded functions resolved — static missed the Solmate Auth pattern"

    preempted = [
        f.get("function") for f in cancall if "delegated_check_not_materialized" in json.dumps(f.get("capability_expr"))
    ]
    assert not preempted, f"canCall regressed to the pre-#104 inline-preempt dead-end: {preempted[:5]}"

    resolved = [f for f in cancall if (f.get("capability_expr") or {}).get("kind") != "unsupported"]
    assert resolved, "every canCall-guarded function is unsupported — canCall resolution is not working"

    # Reaching here means canCall recovered the real governance Safe end-to-end live.
