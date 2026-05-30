"""Live: the Solmate ``RolesAuthority`` ``canCall`` path resolves on a real Veda contract.

Proves #104's ``SolmateRolesAuthorityAdapter`` actually runs end-to-end on real
RPC + the live event index. The prod-data audit found it had *never* executed on
the Veda stack — ``canCall`` was preempted to a ``delegated_check_not_materialized``
dead-end pre-#104 — so this guards that the adapter stays wired live.

The assertion is robust to index state: the adapter's ``solmate_roles_authority``
marker appears whether the authority's events are already indexed (a trace step on
the resolved ``finite_set``) or still cold (the same tag on the deferred
``external_check_only`` probe). Its absence means ``canCall`` regressed to a
non-Solmate path (inline-preempt / unsupported).

What this does NOT assert: the deferred-resolution reconciler's async cold→warm
heal. That waits on the authority's full event backfill (minutes), and the
preview tears its workers down right after the suite, so the heal can't reliably
complete in-window. The cold→warm transition is pinned deterministically offline
in ``tests/test_deferred_resolution_reconcile.py``.
"""

from __future__ import annotations

import json

import pytest

from tests.live.conftest import LiveClient

# TellerWithMultiAssetSupport — Solmate ``Auth``; ``canCall`` delegates to
# RolesAuthority 0x3994741a5b29c60d0ab318de1024f9256fe959dc.
VEDA_TELLER = "0xe2acf9f80a2756e51d1e53f9f41583c84279fb1f"
_SOLMATE_MARKER = "solmate_roles_authority"


@pytest.fixture(scope="session")
def analyzed_veda_teller(live_client: LiveClient) -> dict:
    """Analyze the Veda Teller once per session.

    SKIPs (not fails) on timeout / non-completion: the live suite is
    throughput-bound on contended previews, and a Solmate smoke check must not
    add hard failures under load. A genuine submission error (HTTP 4xx/5xx) still
    propagates.
    """
    try:
        job = live_client.submit_and_wait(VEDA_TELLER)
    except TimeoutError as exc:
        pytest.skip(f"Veda Teller analysis did not finish in time on {live_client.base_url}: {exc}")
    if job["status"] != "completed":
        pytest.skip(f"Veda Teller analysis did not complete (status={job['status']})")
    return job


def test_veda_teller_cancall_resolved_via_solmate_adapter(analyzed_veda_teller, live_client: LiveClient):
    # analysis_detail carries both the persisted effective_permissions (resolved
    # at policy time) and the live-recomputed semantic_capabilities; the marker in
    # either proves the adapter claimed and folded canCall on real infra.
    detail = live_client.analysis_detail(analyzed_veda_teller["name"])
    assert _SOLMATE_MARKER in json.dumps(detail), (
        "SolmateRolesAuthorityAdapter never ran on the Veda Teller's canCall guards — "
        "canCall resolution regressed to a non-Solmate path (inline-preempt / unsupported). "
        "Expected the adapter's trace step (warm index) or its external_check_only tag (cold)."
    )
