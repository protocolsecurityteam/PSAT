"""Observability contract for the scoring boundary.

The fold and resolution planes are log-free (every refusal is published into the score document,
SCORING_INVARIANTS inv. 11/12), so the impure boundary around them is the only place a pricing
regression or unreadable execution record can become visible. Locked here: ``document_summary``
reads every field off the finished document; ``score_protocol`` times its impure steps and WARNs
for the two grade-integrity facts; the distiller's I/O edges name what they could not read (W2
refusal conjunct, absent vs malformed flow-asset artifact, NULL-``protocol_id`` contracts counted).
No database: fold and persist are substituted.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from services.scoring import distill, loop
from services.scoring.distill import (
    ASSET_IDENTITY_ARTIFACT_ABSENT,
    ASSET_IDENTITY_ARTIFACT_MALFORMED,
    ASSET_IDENTITY_LOADED,
    ASSET_IDENTITY_NO_RECEIVERS,
    W2_INVARIANT_NOT_DETERMINED,
    W2_NO_STATE_VAR_RECEIVER,
    W2_PLANE_ABSENT,
    W2_SELECTOR_UNRESOLVED,
    W2_STATUS_NOT_RESOLVED,
    _asset_identity,
    _ContractFacts,
    _token_identity,
)
from services.scoring.schema import ScoreDocument
from utils.logging import stage_metrics_var
from utils.scoring_status import (
    GRADE_STATE_COMPUTED,
    MODEL_VERSION,
    PERIMETER_SETTLED,
    SCORE_TRIGGER_DIRTY_LOOP,
)


def _document(**overrides) -> ScoreDocument:
    fields = {
        "protocol_id": 7,
        "model_version": MODEL_VERSION,
        "computed_at": datetime(2026, 8, 17, tzinfo=timezone.utc),
        "trigger": SCORE_TRIGGER_DIRTY_LOOP,
        "perimeter_state": PERIMETER_SETTLED,
        "grade_state": GRADE_STATE_COMPUTED,
        "grade_lambda": 71.5,
        "grade_exposure": 12.25,
        "confidence_pct": 44.2,
        "findings": [
            {"undetermined_instances": [{"entity": "ethereum::0x1"}, {"entity": "ethereum::0x2"}]},
            {"undetermined_instances": []},
        ],
        "earned_negatives": [],
        "warnings": [{"kind": "reach_floor_absent"}, {"kind": "reach_floor_absent"}, {"kind": "one_shot_latch"}],
        "model_parameters": {
            "confidence_detail": {
                "reachability_answered_pct": 61.0,
                "capability_scored_pct": 58.5,
                "value_priced_pct": 44.2,
                "reach_magnitude_witnessed_pct": 70.0,
                "flow_pricing_decidable": {"ethereum::0x1": [1, 3], "ethereum::0x2": [0, 2]},
            }
        },
        "provenance": {
            "population": {
                "signals": 120,
                "signals_entering_grade": 90,
                "subsumed_rows": 4,
                "disposition": "scored",
                "rows_withheld_malformed": 2,
            },
            "exposure_coverage": {"tracked_total_usd": 1234.5},
        },
    }
    fields.update(overrides)
    return ScoreDocument(**fields)


# ------------------------------------------------------------- document summary


def test_the_summary_reads_every_field_off_the_finished_document():
    summary = loop.document_summary(_document())

    assert summary["population_disposition"] == "scored"
    assert summary["signals"] == 120
    assert summary["signals_entering_grade"] == 90
    assert summary["rows_withheld_malformed"] == 2
    assert summary["findings"] == 2
    assert summary["warnings_by_kind"] == {"reach_floor_absent": 2, "one_shot_latch": 1}
    assert summary["undetermined_instances"] == 2
    assert (summary["flow_pricing_decidable"], summary["flow_pricing_seen"]) == (1, 5)
    assert summary["tracked_total_usd"] == 1234.5
    assert summary["confidence_pct"] == 44.2
    assert summary["confidence_value_priced_pct"] == 44.2
    assert summary["confidence_reach_magnitude_pct"] == 70.0
    assert summary["execution_records_faulted"] == 0


def test_a_document_with_no_provenance_blocks_omits_rather_than_guesses():
    summary = loop.document_summary(_document(provenance={}, model_parameters={}))
    assert summary["population_disposition"] is None
    assert summary["signals"] is None
    assert summary["tracked_total_usd"] is None
    assert summary["confidence_reachability_pct"] is None
    assert (summary["flow_pricing_decidable"], summary["flow_pricing_seen"]) == (None, None)


def test_an_empty_pricing_census_is_a_real_zero():
    """Present and empty is the fold saying no flow claim was scored: the one case where 0 is
    the answer rather than a stand-in for an unasked question."""
    summary = loop.document_summary(_document(model_parameters={"confidence_detail": {"flow_pricing_decidable": {}}}))
    assert (summary["flow_pricing_decidable"], summary["flow_pricing_seen"]) == (0, 0)


@pytest.mark.parametrize(
    "census",
    [
        pytest.param({"ethereum::0x1": [None, 3]}, id="none-in-the-pair"),
        pytest.param({"ethereum::0x1": [1, None]}, id="none-in-the-seen-count"),
        pytest.param({"ethereum::0x1": [1, 3], "ethereum::0x2": "not a pair"}, id="not-a-pair"),
        pytest.param({"ethereum::0x1": [1]}, id="short-pair"),
        pytest.param({"ethereum::0x1": ["1", "3"]}, id="strings"),
    ],
)
def test_an_unaddable_pricing_pair_publishes_null_rather_than_a_short_sum(census):
    """A partial sum presented as whole reads as a pricing regression that never happened, and
    raising would fail a fold that computed."""
    summary = loop.document_summary(
        _document(model_parameters={"confidence_detail": {"flow_pricing_decidable": census}})
    )
    assert (summary["flow_pricing_decidable"], summary["flow_pricing_seen"]) == (None, None)


def test_a_kindless_warning_is_bucketed_as_unknown_not_as_the_string_none():
    summary = loop.document_summary(_document(warnings=[{"note": "no kind here"}, {"kind": ""}, "not a dict"]))
    assert summary["warnings_by_kind"] == {"unknown": 3}


def test_the_execution_fault_census_is_counted_into_the_summary():
    summary = loop.document_summary(
        _document(execution_evidence_faults={"records_faulted": 3, "faulted_by_reason": {"fetch_failed": 3}}),
    )
    assert summary["execution_records_faulted"] == 3


def test_an_unreadable_fault_count_is_null_and_never_the_earned_zero():
    summary = loop.document_summary(_document(execution_evidence_faults={"records_faulted": None}))
    assert summary["execution_records_faulted"] is None


def test_the_summary_is_total_over_a_malformed_document():
    """Both entrypoints call this: a raise arms the loop's backoff and fails a computed score in the CLI."""
    summary = loop.document_summary(
        _document(
            findings=["not a dict", {"undetermined_instances": "not a list"}],
            warnings=["not a dict"],
            provenance={"population": "not a dict", "exposure_coverage": 7},
            model_parameters={"confidence_detail": "not a dict"},
            execution_evidence_faults={"records_faulted": "three"},
        ),
    )
    assert summary["undetermined_instances"] == 0
    assert summary["signals"] is None
    assert summary["tracked_total_usd"] is None
    assert (summary["flow_pricing_decidable"], summary["flow_pricing_seen"]) == (None, None)
    assert summary["execution_records_faulted"] is None


# ------------------------------------------------------------ the loop boundary


class _FakeQuery:
    def __init__(self, deleted: int = 0) -> None:
        self._deleted = deleted

    def filter(self, *args, **kwargs):
        return self

    def delete(self, **kwargs) -> int:
        return self._deleted

    def update(self, *args, **kwargs) -> int:
        return 0


class _FakeResult:
    def scalar_one(self):
        return datetime(2026, 8, 17, tzinfo=timezone.utc)


class _FakeSession:
    """Enough session for ``score_protocol``: a clock, a query, a commit."""

    def execute(self, *args, **kwargs):
        return _FakeResult()

    def query(self, *args, **kwargs):
        return _FakeQuery()

    def commit(self) -> None:
        return None


class _Row:
    storage_key = None


@pytest.fixture
def _substituted_fold(monkeypatch):
    """Substitute fold and persistence; retired delivery loading is absent."""
    state: dict[str, object] = {"document": _document()}
    monkeypatch.setattr(loop, "compute_protocol_score", lambda *a, **k: state["document"])
    monkeypatch.setattr(loop, "persist_score_document", lambda session, document: _Row())
    return state


_LOOP_LOGGER = "services.scoring.loop"


def _score(caplog):
    """Every assertion is scoped to the loop's own logger so a stray record can't move a count."""
    with caplog.at_level(logging.INFO, logger=_LOOP_LOGGER):
        loop.score_protocol(_FakeSession(), loop.DueProtocol(7, SCORE_TRIGGER_DIRTY_LOOP))  # pyright: ignore[reportArgumentType]
    return [r for r in caplog.records if r.name == _LOOP_LOGGER]


def test_an_execution_evidence_fault_warns_with_its_reasons(_substituted_fold, caplog):
    _substituted_fold["document"] = _document(
        execution_evidence_faults={
            "records_faulted": 2,
            "execution_records_examined": 40,
            "faulted_by_reason": {"fetch_failed": 2},
        }
    )
    records = _score(caplog)
    warnings = [r for r in records if r.levelno == logging.WARNING and r.name == _LOOP_LOGGER]
    assert len(warnings) == 1
    assert warnings[0].faulted_by_reason == {"fetch_failed": 2}
    assert warnings[0].records_faulted == 2


def test_a_failing_summary_never_unmakes_a_committed_score(_substituted_fold, caplog, monkeypatch):
    """The summary is emitted after the commit; a raise would arm the backoff for a durable score."""

    def _boom(document):
        raise RuntimeError("summary is broken")

    monkeypatch.setattr(loop, "document_summary", _boom)
    records = _score(caplog)
    warnings = [r for r in records if r.levelno == logging.WARNING and r.name == _LOOP_LOGGER]
    assert [r.message for r in warnings] == ["score summary emit failed"]


def test_the_cli_emits_the_same_summary_and_a_malformed_document_does_not_fail_it(monkeypatch, caplog):
    """The CLI calls the summary bare, so it must itself be total."""
    from services.scoring import cli

    document = _document(
        findings=["not a dict"],
        provenance={"population": "not a dict"},
        model_parameters={"confidence_detail": {"flow_pricing_decidable": {"ethereum::0x1": [None, 1]}}},
    )
    monkeypatch.setattr(cli, "distill_protocol_in_memory", lambda session, pid: [])
    monkeypatch.setattr(cli, "compute_protocol_score", lambda *a, **k: document)

    with caplog.at_level(logging.INFO, logger="services.scoring.cli"):
        assert cli.score(None, 7) is document  # pyright: ignore[reportArgumentType]

    summaries = [
        r for r in caplog.records if r.name == "services.scoring.cli" and r.message == "score document summary"
    ]
    assert len(summaries) == 1
    assert summaries[0].flow_pricing_decidable is None


# --------------------------------------------------- the W2 precondition's arms


def _facts(asset_identity=None, state=ASSET_IDENTITY_LOADED) -> _ContractFacts:
    return _ContractFacts(
        contract_id=1,
        protocol_id=7,
        chain="ethereum",
        address="0x" + "11" * 20,
        functions=[],
        asset_identity=asset_identity or {},
        asset_identity_state=state,
    )


def _entry(provenance="contract_state_unresolved", selector="0xdeadbeef"):
    receiver = {"receiver_provenance": provenance, "auto_getter_selector": selector}
    return {"witness": {"sink_receivers": {"s1": receiver}}}


@pytest.mark.parametrize(
    "facts,entries,expected",
    [
        (_facts(state=ASSET_IDENTITY_ARTIFACT_ABSENT), [_entry()], W2_PLANE_ABSENT),
        (_facts({"0xdeadbeef": {}}), [_entry(provenance="caller_named")], W2_NO_STATE_VAR_RECEIVER),
        (_facts({"0xother": {}}), [_entry()], W2_SELECTOR_UNRESOLVED),
        (
            _facts({"0xdeadbeef": {"asset_address_status": "unresolved"}}),
            [_entry()],
            W2_STATUS_NOT_RESOLVED,
        ),
        (
            _facts({"0xdeadbeef": {"asset_address_status": "resolved", "asset_identity_invariant": None}}),
            [_entry()],
            W2_INVARIANT_NOT_DETERMINED,
        ),
    ],
)
def test_every_w2_refusal_arm_names_itself(facts, entries, expected):
    """Five conjuncts reach one third state; a refusal indistinguishable from the other four
    can't be acted on."""
    tri, refusal = _token_identity(facts, entries)
    assert not tri.is_determined
    assert refusal == expected


def test_a_resolved_asset_identity_refuses_nothing():
    resolved = {"asset_address_status": "resolved", "asset_identity_invariant": "pinned", "asset_address": "0x1"}
    facts = _facts({"0xdeadbeef": resolved})
    tri, refusal = _token_identity(facts, [_entry()])
    assert tri.is_determined
    assert refusal is None


def test_the_refusal_travels_on_the_envelope_and_in_the_witness_notes():
    notes: set[str] = set()
    gates = distill._flow_gates(_facts(state=ASSET_IDENTITY_ARTIFACT_MALFORMED), [_entry()], [], notes)
    envelope = gates["asset_identity"]
    assert envelope["state"] == "not_determined"
    assert envelope["value"] is None
    assert envelope["not_determined_reason"] == W2_PLANE_ABSENT
    assert envelope["asset_identity_plane_state"] == ASSET_IDENTITY_ARTIFACT_MALFORMED
    assert notes == {W2_PLANE_ABSENT, f"asset_identity_plane_{ASSET_IDENTITY_ARTIFACT_MALFORMED}"}


# -------------------------------------------------- the flow-asset plane's edge


@pytest.mark.parametrize(
    "payload,expected_state,expected_keys",
    [
        (None, ASSET_IDENTITY_ARTIFACT_ABSENT, 0),
        ("not a dict", ASSET_IDENTITY_ARTIFACT_MALFORMED, 0),
        ({"receivers": "not a list"}, ASSET_IDENTITY_ARTIFACT_MALFORMED, 0),
        ({"receivers": []}, ASSET_IDENTITY_NO_RECEIVERS, 0),
        ({"receivers": [{"no_selector": 1}]}, ASSET_IDENTITY_ARTIFACT_MALFORMED, 0),
        ({"receivers": [{"asset_getter_selector": "0x1"}]}, ASSET_IDENTITY_LOADED, 1),
    ],
)
def test_an_absent_artifact_and_a_malformed_one_are_different_facts(
    monkeypatch, payload, expected_state, expected_keys
):
    import db.queue

    monkeypatch.setattr(db.queue, "get_artifact", lambda session, job_id, name: payload)
    receivers, state = _asset_identity(session=None, job_id="job-1")  # pyright: ignore[reportArgumentType]
    assert state == expected_state
    assert len(receivers) == expected_keys


# ------------------------------------------------------ orphaned contract rows


class _Contract:
    def __init__(self, contract_id: int, protocol_id: int | None) -> None:
        self.id = contract_id
        self.protocol_id = protocol_id
        self.job_id = "job-1"


class _ContractQuery:
    def __init__(self, contracts) -> None:
        self._contracts = contracts

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return self._contracts


class _ContractSession:
    def __init__(self, contracts) -> None:
        self._contracts = contracts

    def query(self, *args, **kwargs):
        return _ContractQuery(self._contracts)


class _Job:
    id = "job-1"


def test_contracts_with_no_protocol_are_counted_not_silently_skipped(monkeypatch, caplog):
    monkeypatch.setattr(distill.facts, "distill_contract_signals", lambda session, contract, job_id: [])
    session = _ContractSession([_Contract(1, 7), _Contract(2, None), _Contract(3, None)])
    metrics: dict[str, object] = {}
    token = stage_metrics_var.set(metrics)
    try:
        with caplog.at_level(logging.WARNING, logger="services.scoring.distill"):
            out = distill.distill_job_signals(session, _Job())  # pyright: ignore[reportArgumentType]
    finally:
        stage_metrics_var.reset(token)

    assert set(out) == {1}
    assert metrics["score_signal_contracts_skipped_null_protocol"] == 2
    record = next(r for r in caplog.records if "no protocol_id" in r.message)
    assert record.levelno == logging.WARNING
    assert record.contracts_skipped == 2
    assert record.contract_ids == [2, 3]


def test_no_orphans_means_no_warning(monkeypatch, caplog):
    monkeypatch.setattr(distill.facts, "distill_contract_signals", lambda session, contract, job_id: [])
    session = _ContractSession([_Contract(1, 7)])
    metrics: dict[str, object] = {}
    token = stage_metrics_var.set(metrics)
    try:
        with caplog.at_level(logging.WARNING, logger="services.scoring.distill"):
            distill.distill_job_signals(session, _Job())  # pyright: ignore[reportArgumentType]
    finally:
        stage_metrics_var.reset(token)

    assert metrics["score_signal_contracts_skipped_null_protocol"] == 0
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
