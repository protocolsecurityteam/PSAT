"""The score endpoint and the score loop's liveness, on a deployed preview.

Both are cheap and idempotent — they read, they never analyse. The endpoint
tests SKIP when no fold has landed yet: the live suite can run before any
effects job on this preview has completed, and a 404 there is the endpoint
answering correctly, not a failure. What is never skipped is the shape: once a
score exists, the ledger payload's keys and its three-state fields must be
present, because a consumer branches on them.
"""

from __future__ import annotations

import pytest

from tests.live.conftest import DEFAULT_TEST_COMPANY, LiveClient

LEDGER_KEYS = (
    "grade_state",
    "grade_lambda",
    "grade_exposure",
    "confidence_pct",
    "perimeter_state",
    "findings",
    "earned_negatives",
    "warnings",
    "model_parameters",
    "provenance",
)

GRADE_STATES = {"computed", "not_determined"}
PERIMETER_STATES = {"settled", "unsettled", "not_determined"}


def _score_or_skip(live_client: LiveClient) -> dict:
    """The score, or a skip — but ONLY for the one 404 that is legitimate.

    The endpoint 404s both for an unknown protocol and for a protocol with no
    fold yet. Skipping on the first would turn a missing test company (a real
    failure — every other test in the suite depends on it) into a green run, so
    existence is established against a different endpoint first and only then is
    a 404 read as "not scored yet".
    """
    response = live_client.company_score(DEFAULT_TEST_COMPANY)
    if response.status_code == 404:
        # ``/audits`` resolves the company the same way and answers in bytes
        # rather than the overview's 1-3 MB.
        probe = live_client._session.get(live_client._url(f"/api/company/{DEFAULT_TEST_COMPANY}/audits"), timeout=30)
        assert probe.status_code == 200, (
            f"'{DEFAULT_TEST_COMPANY}' does not exist on this deployment "
            f"(audits {probe.status_code}) — the score 404 is not a 'no fold yet'"
        )
        pytest.skip(f"no protocol score computed yet for '{DEFAULT_TEST_COMPANY}'")
    assert response.status_code == 200, f"score read failed: {response.status_code} {response.text[:300]}"
    return response.json()


def test_score_payload_shape(analyzed_company, live_client: LiveClient):
    body = _score_or_skip(live_client)
    missing = [key for key in LEDGER_KEYS if key not in body]
    assert not missing, f"score payload missing ledger keys {missing}: {sorted(body)}"
    assert isinstance(body["findings"], list)
    assert isinstance(body["earned_negatives"], list)
    assert isinstance(body["warnings"], list)
    assert isinstance(body["model_parameters"], dict)
    assert body["model_version"], "every score carries the constants version it was computed under"


def test_score_three_states_are_named_not_implied(analyzed_company, live_client: LiveClient):
    """The consumer branches on the state; it may never infer one from a null."""
    body = _score_or_skip(live_client)
    assert body["grade_state"] in GRADE_STATES, body["grade_state"]
    assert body["perimeter_state"] in PERIMETER_STATES, body["perimeter_state"]
    determined = (body["grade_lambda"], body["grade_exposure"], body["confidence_pct"])
    if body["grade_state"] == "computed":
        assert all(value is not None for value in determined), determined
    else:
        assert all(value is None for value in determined), (
            "an undetermined grade must publish nulls, never a zero a reader could use"
        )


def test_score_unknown_company_returns_a_distinguishable_404(live_client: LiveClient):
    response = live_client.company_score("psat-unknown-company-xyz")
    assert response.status_code == 404, f"unknown company should 404, got {response.status_code}"
    detail = (response.json() or {}).get("detail", "")
    assert "Company not found" in detail, f"an unknown protocol must not read as 'not scored yet': {detail!r}"


def test_score_loop_heartbeat_is_present(live_client: LiveClient):
    """The fold is a supervised thread; without a beat it is running unwatched."""
    daemons = live_client.fleet().get("daemons") or []
    entry = next((d for d in daemons if d.get("process") == "protocol_score"), None)
    assert entry is not None, f"protocol_score absent from /api/fleet daemons: {[d.get('process') for d in daemons]}"
    assert "alive" in entry and "stale" in entry
