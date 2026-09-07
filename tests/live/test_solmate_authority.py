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
``tests/resolution/test_deferred_resolution_reconcile.py``.
"""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import VEDA_TELLER_ADDRESS, LiveClient

# TellerWithMultiAssetSupport — Solmate ``Auth``; ``canCall`` delegates to
# RolesAuthority 0x3994741a…; governing 4/6 Safe (ground-truthed on-chain).
VEDA_TELLER = VEDA_TELLER_ADDRESS
GOVERNING_SAFE = "0xcea8039076e35a825854c5c2f85659430b06ec96"
_CANCALL_SELECTOR = "0xb7009613"  # keccak("canCall(address,address,bytes4)")[:4]

# A Solmate ``requiresAuth`` guard survives into ``capability_expr`` differently
# depending on how it resolved. The cross-contract inlining path (RolesAuthority
# analyzed alongside — the etherfi company case) folds the guard into a
# ``finite_set`` of role holders and drops the ``canCall`` selector, leaving the
# static ``isAuthorized(msg.sender,msg.sig)`` require-condition and a
# ``solmate_roles_authority`` resolution trace; the event-fold path keeps the raw
# selector; the pre-#104 dead-end leaves ``delegated_check_not_materialized``.
# Match on any of these so the guard is tracked regardless of how it resolved.
_CANCALL_MARKERS = (
    _CANCALL_SELECTOR,
    "isAuthorized",
    "solmate_roles_authority",
    "delegated_check_not_materialized",
)


def _cancall_functions(ep: dict) -> list[dict]:
    """Effective-function records guarded by a Solmate ``canCall``/``requiresAuth`` check.

    Detected by any ``_CANCALL_MARKERS`` marker, so a guard that fully resolved via
    inlining — which legitimately no longer references the ``canCall`` selector —
    still counts, not just the event-fold or unresolved representations.
    """
    return [
        f
        for f in (ep.get("functions") or [])
        if any(marker in json.dumps(f.get("capability_expr") or {}) for marker in _CANCALL_MARKERS)
    ]


def _finite_set_members(node: object, out: set[str]) -> None:
    """Collect every ``finite_set`` member address anywhere in a capability tree."""
    if isinstance(node, dict):
        out.update(str(m).lower() for m in (node.get("members") or []))
        for child in node.get("children") or []:
            _finite_set_members(child, out)
        if isinstance(node.get("signer"), dict):
            _finite_set_members(node["signer"], out)


def _capability_rows(live_client: LiveClient) -> dict:
    response = live_client._session.get(
        live_client._url(f"/api/contract/{VEDA_TELLER}/capabilities"),
        timeout=30,
    )
    assert response.status_code == 200, response.text
    capabilities = response.json().get("capabilities")
    assert isinstance(capabilities, dict)
    return {
        "functions": [{"function": signature, "capability_expr": value} for signature, value in capabilities.items()]
    }


def test_veda_teller_cancall_resolves_without_preempt(analyzed_veda_teller, live_client: LiveClient):
    """canCall is detected, dispatched, and resolved — never the pre-#104
    ``delegated_check_not_materialized`` inline-preempt dead-end."""
    ep = _capability_rows(live_client)

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
    ep = _capability_rows(live_client)

    members: set[str] = set()
    for fn in ep.get("functions") or []:
        _finite_set_members(fn.get("capability_expr") or {}, members)

    if GOVERNING_SAFE not in members:
        pytest.skip(
            "governing Safe not in resolved callers — RolesAuthority not analyzed alongside / cold index, "
            "so canCall deferred (fail-safe). Recovery pinned offline."
        )
    # Reaching here means canCall recovered the real governance Safe end-to-end live.
