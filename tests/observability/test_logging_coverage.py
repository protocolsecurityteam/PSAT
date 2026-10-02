"""Backlog #13: verdict fields live in ``extra``, a rebuild race is ``row_vanished``, and a mismatch-dominated pass
raises one WARNING plus a heartbeat rollup.
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.orm.exc import StaleDataError

import workers.coverage_verify as cv

LOGGER_NAME = "workers.coverage_verify"


def _worker() -> cv.CoverageVerifyWorker:
    # Bypass __init__ to avoid signal handlers and logging reconfiguration.
    w = cv.CoverageVerifyWorker.__new__(cv.CoverageVerifyWorker)
    w.worker_id = "CoverageVerify-test"
    return w


def test_log_outcome_proven_puts_verdict_facts_in_extra(caplog):
    w = _worker()
    ctx = {
        "audit_id": 7,
        "contract_id": 42,
        "matched_name": "Vault",
        "proof_kind": "clean",
        "matched_commit_sha": "abcdef1234567890",
    }
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        w._log_outcome(101, "proven", None, ctx)

    rec = next(r for r in caplog.records if r.name == LOGGER_NAME)
    assert rec.levelno == logging.INFO
    assert rec.equivalence_status == "proven"
    assert rec.audit_id == 7
    assert rec.contract_id == 42
    assert rec.matched_name == "Vault"
    assert rec.proof_kind == "clean"
    assert rec.sha == "abcdef123456"  # truncated to 12 chars
    assert "Vault" not in rec.getMessage()


def test_log_outcome_non_proven_carries_equivalence_status(caplog):
    w = _worker()
    ctx = {"audit_id": 1, "contract_id": 2, "matched_name": "Token", "reason": "hashes differ"}
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        w._log_outcome(5, "hash_mismatch", None, ctx)

    rec = next(r for r in caplog.records if r.name == LOGGER_NAME)
    assert rec.equivalence_status == "hash_mismatch"
    assert rec.reason == "hashes differ"


def test_log_outcome_crash_emits_warning_with_exc_and_crash_status(caplog):
    w = _worker()
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        w._log_outcome(9, None, StaleDataError("gone"), {})

    rec = next(r for r in caplog.records if r.name == LOGGER_NAME)
    assert rec.levelno == logging.WARNING
    assert rec.exc_type == "StaleDataError"
    assert rec.crash_status == "row_vanished"
    assert rec.row_present is False


def test_summarize_pass_warns_and_beats_on_high_hash_mismatch_rate(caplog, monkeypatch):
    beats: list[dict] = []
    monkeypatch.setattr(cv, "record_heartbeat", lambda *a, **k: beats.append(k.get("detail") or {}))
    w = _worker()
    verdicts = {"hash_mismatch": 3, "proven": 1}  # rate 0.75, total 4 >= min

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        rate = w._summarize_pass(4, verdicts)

    assert rate == 0.75
    assert beats and beats[0]["verdicts"] == verdicts
    assert beats[0]["hash_mismatch_rate"] == 0.75
    warn = next(r for r in caplog.records if r.levelno == logging.WARNING and r.name == LOGGER_NAME)
    assert warn.hash_mismatch_rate == 0.75
    assert warn.hash_mismatch == 3
    assert warn.verdicts_total == 4


@pytest.mark.parametrize(
    ("claimed", "verdicts", "expected_rate"),
    [
        pytest.param(10, {"hash_mismatch": 1, "proven": 9}, 0.1, id="rate_below_threshold"),
        # The min-sample guard keeps a single mismatch quiet.
        pytest.param(1, {"hash_mismatch": 1}, 1.0, id="small_sample"),
    ],
)
def test_summarize_pass_stays_quiet(caplog, monkeypatch, claimed, verdicts, expected_rate):
    monkeypatch.setattr(cv, "record_heartbeat", lambda *a, **k: None)
    w = _worker()

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        rate = w._summarize_pass(claimed, verdicts)

    assert rate == expected_rate
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING and r.name == LOGGER_NAME]
