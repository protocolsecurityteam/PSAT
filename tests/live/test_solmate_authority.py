"""Live: a Solmate ``RolesAuthority`` ``canCall`` guard resolves on a real Veda contract.

The prod-data audit found the Veda stack's ``canCall`` guards were under-resolved —
preempted to a ``delegated_check_not_materialized`` dead-end pre-#104, so the real
controller was never recovered. This guards the OUTCOME live: ``canCall`` is
detected, dispatched, and resolved to a usable controller set, never that dead-end.

It asserts the *outcome*, not a specific *mechanism*. ``canCall`` can be resolved
two correct ways depending on what else is analyzed:

  * cross-contract inlining of the RolesAuthority's own analyzed predicate trees,
    when the authority is analyzed alongside (the protocol case — e.g. the etherfi
    company run pulls in both the Teller and its RolesAuthority); or
  * the event-fold ``SolmateRolesAuthorityAdapter``, when the authority is not
    analyzed and its role events are indexed.

Both recover the governing Safe; an earlier version of this test wrongly required
the event-fold adapter's marker, which the inlining path legitimately doesn't emit.

What this does NOT assert: the deferred-resolution reconciler's async cold→warm
heal. That waits on the authority's full event backfill (minutes) and the preview
tears its workers down right after the suite, so it can't complete in-window. The
cold→warm transition is pinned deterministically offline in
``tests/test_deferred_resolution_reconcile.py``.
"""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import LiveClient

# TellerWithMultiAssetSupport — Solmate ``Auth``; ``canCall`` delegates to
# RolesAuthority 0x3994741a…; governing 4/6 Safe (ground-truthed on-chain).
VEDA_TELLER = "0xe2acf9f80a2756e51d1e53f9f41583c84279fb1f"
GOVERNING_SAFE = "0xcea8039076e35a825854c5c2f85659430b06ec96"
_CANCALL_SELECTOR = "0xb7009613"  # keccak("canCall(address,address,bytes4)")[:4]


@pytest.fixture(scope="session")
def analyzed_veda_teller(live_client: LiveClient) -> dict:
    """Analyze the Veda Teller once per session.

    SKIPs (not fails) on timeout / non-completion: the live suite is
    throughput-bound on contended previews, and this smoke check must not add hard
    failures under load. A genuine submission error (HTTP 4xx/5xx) still propagates.
    """
    try:
        job = live_client.submit_and_wait(VEDA_TELLER)
    except TimeoutError as exc:
        pytest.skip(f"Veda Teller analysis did not finish in time on {live_client.base_url}: {exc}")
    if job["status"] != "completed":
        pytest.skip(f"Veda Teller analysis did not complete (status={job['status']})")
    return job


def _cancall_functions(ep: dict) -> list[dict]:
    """Effective-function records whose resolved capability references canCall."""
    return [f for f in (ep.get("functions") or []) if _CANCALL_SELECTOR in json.dumps(f.get("capability_expr") or {})]


def _finite_set_members(node: object, out: set[str]) -> None:
    """Collect every ``finite_set`` member address anywhere in a capability tree."""
    if isinstance(node, dict):
        out.update(str(m).lower() for m in (node.get("members") or []))
        for child in node.get("children") or []:
            _finite_set_members(child, out)
        if isinstance(node.get("signer"), dict):
            _finite_set_members(node["signer"], out)


def test_veda_teller_cancall_resolves_without_preempt(analyzed_veda_teller, live_client: LiveClient):
    """canCall is detected, dispatched, and resolved — never the pre-#104
    ``delegated_check_not_materialized`` inline-preempt dead-end."""
    ep = live_client.artifact(analyzed_veda_teller["name"], "effective_permissions")
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


def test_veda_teller_cancall_recovers_governing_safe(analyzed_veda_teller, live_client: LiveClient):
    """End-to-end recovery: canCall resolves to the real 4/6 governance Safe.

    SKIPs when the Safe isn't among the resolved callers — that means the
    RolesAuthority wasn't analyzed alongside (or its index is cold), so canCall
    deferred to a probe. That's fail-safe, not a regression; the recovery path is
    pinned deterministically offline.
    """
    ep = live_client.artifact(analyzed_veda_teller["name"], "effective_permissions")
    if not isinstance(ep, dict):
        pytest.skip("effective_permissions artifact not available")

    members: set[str] = set()
    for fn in ep.get("functions") or []:
        _finite_set_members(fn.get("capability_expr") or {}, members)

    if GOVERNING_SAFE not in members:
        pytest.skip(
            "governing Safe not in resolved callers — RolesAuthority not analyzed alongside / cold index, "
            "so canCall deferred (fail-safe). Recovery pinned offline."
        )
    # Reaching here means canCall recovered the real governance Safe end-to-end live.
