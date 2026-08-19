"""Offline logging/observability tests for the coverage verify path.

Locks in the Backlog #13 behavior: the source-equivalence verdict and its
identity fields live in ``extra={}`` (queryable JSON), a benign rebuild
race is labeled ``row_vanished`` rather than ``github_fetch_failed``, and a
pass dominated by ``hash_mismatch`` raises a single WARNING with the rate in
``extra`` plus a heartbeat-detail rollup.

No DB / network: the methods under test are pure log/derivation helpers;
``record_heartbeat`` is stubbed.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm.exc import StaleDataError

import workers.coverage_verify as cv

LOGGER_NAME = "workers.coverage_verify"


def _worker() -> cv.CoverageVerifyWorker:
    # Bypass __init__ so we don't register signal handlers / reconfigure
    # logging — these helpers only touch the module logger + globals.
    w = cv.CoverageVerifyWorker.__new__(cv.CoverageVerifyWorker)
    w.worker_id = "CoverageVerify-test"
    return w


def test_crash_status_distinguishes_vanished_row_from_github_outage():
    assert cv._crash_status(StaleDataError("row gone")) == "row_vanished"
    assert cv._crash_status(RuntimeError("github 502")) == "github_fetch_failed"


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
    # Facts must NOT be interpolated into the message body.
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
    # Heartbeat carries the per-pass verdict rollup (daemon substitute for a metric).
    assert beats and beats[0]["verdicts"] == verdicts
    assert beats[0]["hash_mismatch_rate"] == 0.75
    warn = next(r for r in caplog.records if r.levelno == logging.WARNING and r.name == LOGGER_NAME)
    assert warn.hash_mismatch_rate == 0.75
    assert warn.hash_mismatch == 3
    assert warn.verdicts_total == 4


def test_summarize_pass_quiet_when_rate_below_threshold(caplog, monkeypatch):
    monkeypatch.setattr(cv, "record_heartbeat", lambda *a, **k: None)
    w = _worker()
    verdicts = {"hash_mismatch": 1, "proven": 9}  # rate 0.1

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        rate = w._summarize_pass(10, verdicts)

    assert rate == 0.1
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING and r.name == LOGGER_NAME]


def test_summarize_pass_does_not_trip_on_small_sample(caplog, monkeypatch):
    monkeypatch.setattr(cv, "record_heartbeat", lambda *a, **k: None)
    w = _worker()
    verdicts = {"hash_mismatch": 1}  # rate 1.0 but total 1 < warn min

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        w._summarize_pass(1, verdicts)

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING and r.name == LOGGER_NAME]
