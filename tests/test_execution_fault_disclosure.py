"""A transport fault must be LOUD in the document it moved.

The composition rule's ``withheld`` arm fires on the four reasons in
``EX.FAULT_REASONS`` BEFORE the authority-deletability join is consulted, so a
document folded while the artifact store cannot answer publishes fewer composed
figures than the same database state otherwise yields — measured on the
reference corpus, a total fault takes lambda from 73.2508 to 84.0166. Undisclosed
that is indistinguishable from a code regression, so these cases pin the
disclosure itself: the census, the counts it reads off the rows, and its
absence where the fold walked every record and found none.

The arms themselves live in ``tests/test_three_arm_composition.py`` and the
record's own shape in ``tests/test_execution_record.py``; nothing here re-tests
either.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from services.scoring import fold as FOLD
from services.scoring.schema import Tri
from tests import composition_admission_fixtures as CA
from tests.support.scoring_builders import (
    KEY_V,
    _composing_signals,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
)
from utils import execution_record as EX
from utils.scoring_status import GRADE_FAULT_DEGRADED, GRADE_STATE_COMPUTED, GRADE_STATES

_FIELD = "execution_evidence_faults"
_WARNING = "execution_evidence_unreadable"


def _faulted_signals(reason: str = EX.REASON_FETCH_FAILED) -> list[Any]:
    """The composing case with the destination's execution unreadable."""
    signals = _composing_signals()
    destination = signals[-1]
    payload = Tri.proven(
        EX.GATE_STATE_NOT_RECORDED,
        EX.not_determined(reason, transcript_ptr="job::art").as_json(),
    ).to_json()
    signals[-1] = replace(destination, gate_inputs={**destination.gate_inputs, EX.PROVING_EXECUTION_KEY: payload})
    return signals


def _carrier(reason: str | None, entity: str = KEY_V) -> dict[str, Any]:
    """One published entry in the shape the fold emits, at the given reason."""
    return {
        "entity": entity,
        EX.PROVING_EXECUTION_KEY: EX.not_determined(reason or EX.REASON_NOT_PERSISTED).as_json(),
    }


def _row(*carriers: dict[str, Any]) -> dict[str, Any]:
    return {"reach_composed_magnitudes_withheld": list(carriers)}


def _published_fault_count(document: Any) -> int:
    """The faulted records counted from the ROWS, independently of the census."""
    rows = list(document.findings) + list(document.provenance["subsumed_rows"])
    return sum(
        1
        for row in rows
        for key in ("reach_composed_magnitudes", "reach_composed_magnitudes_withheld")
        for entry in (row.get(key) or [])
        if entry[EX.PROVING_EXECUTION_KEY].get("reason") in EX.FAULT_REASONS
    )


def _fault_warnings(document: Any) -> list[dict[str, Any]]:
    return [w for w in document.warnings if w["kind"] == _WARNING]


# --------------------------------------------------------------------------
# The document announces it
# --------------------------------------------------------------------------


def test_a_faulted_execution_is_announced_at_the_documents_top_level(fold):  # noqa: F811
    """A reader must not have to open forty execution blocks to learn the grade
    was computed over evidence that could not be read."""
    document = CA.composed_document(fold, signals=_faulted_signals(), deletability=CA.deletability_plane())

    census = document.execution_evidence_faults
    assert census is not None
    assert census["grade_qualifier"] == GRADE_FAULT_DEGRADED
    # The count is the rows', not the branch's: counted here from the published
    # entries and compared against what the census published.
    counted = _published_fault_count(document)
    assert counted >= 1
    assert census["records_faulted"] == counted
    assert census["faulted_by_reason"] == {EX.REASON_FETCH_FAILED: counted}
    assert census["entities_affected"] == [KEY_V]
    assert census["execution_records_examined"] >= counted
    assert census["registered_fault_reasons"] == sorted(EX.FAULT_REASONS)

    # Top level of the PERSISTED payload, not only of the dataclass.
    assert document.document()[_FIELD] == census


def test_the_warning_names_the_count_and_every_distinct_reason(fold):  # noqa: F811
    """The warnings list is the loud channel, and a reader scanning it must get
    the number, the reasons and the comparison ban without following a link."""
    document = CA.composed_document(fold, signals=_faulted_signals(), deletability=CA.deletability_plane())

    warning = _fault_warnings(document)[0]
    census = document.execution_evidence_faults
    assert warning["records_faulted"] == census["records_faulted"]
    assert warning["faulted_by_reason"] == census["faulted_by_reason"]

    note = warning["note"]
    assert f"{census['records_faulted']} of {census['execution_records_examined']}" in note
    assert f"{EX.REASON_FETCH_FAILED} x{census['records_faulted']}" in note
    assert "Do not compare this document against a fault-free run" in note
    # The claim is about what was READ, never about the store's availability.
    assert "not proof the artifact store was unavailable" in note


def test_the_grade_stays_computed_and_the_marker_is_not_a_grade_state(fold):  # noqa: F811
    """Two questions, two vocabularies. A fault-degraded grade is still a
    computed one — the DB pairing constraint binds that token to the three
    figures being present — so the marker cannot be a fourth grade_state."""
    document = CA.composed_document(fold, signals=_faulted_signals(), deletability=CA.deletability_plane())

    assert GRADE_FAULT_DEGRADED not in GRADE_STATES
    assert document.grade_state == GRADE_STATE_COMPUTED
    assert document.grade_lambda is not None


# --------------------------------------------------------------------------
# The counts come from the data
# --------------------------------------------------------------------------


@pytest.mark.parametrize("faulted", [1, 2, 5])
def test_the_published_count_follows_the_number_of_faulted_records(faulted: int) -> None:
    """Mutating how many records carry a fault moves the published number — a
    census that only proved its branch fired would pass at any count."""
    findings = [_row(*(_carrier(EX.REASON_FETCH_FAILED) for _ in range(faulted)))]
    census = FOLD._execution_fault_census(findings, [])

    assert census is not None
    assert census["records_faulted"] == faulted
    assert census["faulted_by_reason"] == {EX.REASON_FETCH_FAILED: faulted}
    assert FOLD._execution_fault_warning(census)["note"].startswith(f"{faulted} of {faulted} ")


def test_each_distinct_reason_keeps_its_own_count() -> None:
    """A transcript that was never stored and a fetch that did not return are
    different facts, and bucketing them would hide which one is happening."""
    findings = [
        _row(
            _carrier(EX.REASON_FETCH_FAILED),
            _carrier(EX.REASON_FETCH_FAILED),
            _carrier(EX.REASON_PTR_UNRESOLVABLE),
        )
    ]
    census = FOLD._execution_fault_census(findings, [])

    assert census is not None
    assert census["faulted_by_reason"] == {EX.REASON_FETCH_FAILED: 2, EX.REASON_PTR_UNRESOLVABLE: 1}
    assert census["records_faulted"] == 3


def test_both_populations_are_walked_and_counted_apart() -> None:
    """Subsumed rows carry execution blocks too, and a census that read only the
    findings would report a fault-free document while a third of the records
    could not be read."""
    census = FOLD._execution_fault_census(
        [_row(_carrier(EX.REASON_FETCH_FAILED))],
        [_row(_carrier(EX.REASON_STORAGE_KEY_MISSING), _carrier(EX.REASON_STORAGE_KEY_MISSING))],
    )

    assert census is not None
    assert census["faulted_by_population"] == {"findings": 1, "subsumed_rows": 2}
    assert census["records_faulted"] == 3


def test_a_reason_outside_the_fault_set_is_examined_and_never_counted() -> None:
    """The corpus's common case. Every verdict in it predates the record and
    reads ``execution_record_not_persisted``, which is a backfill gap the
    composition rule publishes THROUGH — counting it here would announce a
    forty-record fault on a document that lost nothing."""
    assert EX.REASON_NOT_PERSISTED not in EX.FAULT_REASONS
    findings = [_row(_carrier(EX.REASON_NOT_PERSISTED), _carrier(EX.REASON_NO_PROVING_CALL))]

    assert FOLD._execution_fault_census(findings, []) is None


def test_the_denominator_counts_every_record_the_walk_saw() -> None:
    """One unreadable block in forty and forty in forty are different situations,
    and the census must not publish a numerator alone."""
    findings = [_row(_carrier(EX.REASON_FETCH_FAILED), _carrier(EX.REASON_NOT_PERSISTED))]
    census = FOLD._execution_fault_census(findings, [_row(_carrier(EX.REASON_NOT_PERSISTED))])

    assert census is not None
    assert census["records_faulted"] == 1
    assert census["execution_records_examined"] == 3


# --------------------------------------------------------------------------
# Absence, pinned
# --------------------------------------------------------------------------


def test_a_fault_free_document_publishes_no_field_and_no_warning(fold):  # noqa: F811
    """The byte-identity invariant, as a test rather than as a diff somebody ran
    once: a fold that found no fault adds NOTHING to the document."""
    document = CA.composed_document(fold, deletability=CA.deletability_plane())

    assert _published_fault_count(document) == 0
    assert document.execution_evidence_faults is None
    # The key is absent, not present-and-null: a null would read as a census
    # that was attempted and came back empty-handed.
    assert _FIELD not in document.document()
    assert _fault_warnings(document) == []
    assert not any(_WARNING in str(warning) for warning in document.warnings)
