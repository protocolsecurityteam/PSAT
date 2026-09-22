from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy.orm import Session

from db.assessment import (
    get_assessment_section,
    get_recursive_assessment,
    load_assessment,
    store_assessment,
    store_assessment_section,
)
from schemas.assessment import ASSESSMENT_SECTIONS, Assessment, validate_assessment


class _Scalar:
    def __init__(self, value: object) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object:
        return self.value


class _Session:
    def __init__(self) -> None:
        self.statements: list[object] = []

    def execute(self, statement: object) -> _Scalar:
        self.statements.append(statement)
        return _Scalar("job")


def test_section_names_are_the_current_artifact_names() -> None:
    assert ASSESSMENT_SECTIONS == (
        "contract_analysis",
        "predicate_trees",
        "effects",
        "control_tracking_plan",
        "control_snapshot",
        "resolved_control_graph",
        "effective_permissions",
        "principal_labels",
        "principal_history",
    )


def test_absent_and_empty_or_degraded_sections_remain_distinct() -> None:
    session = _Session()
    assert load_assessment(cast(Session, session), "job", reader=lambda *_: None) is None
    assessment = {"schema_version": "assessment/1", "effects": {}, "predicate_trees": {"error": "degraded"}}

    def reader(*_: object) -> object:
        return assessment

    assert get_assessment_section(cast(Session, session), "job", "contract_analysis", reader=reader) is None
    assert get_assessment_section(cast(Session, session), "job", "effects", reader=reader) == {}
    assert get_assessment_section(cast(Session, session), "job", "predicate_trees", reader=reader) == {
        "error": "degraded"
    }


def test_staged_updates_lock_then_preserve_every_unrelated_section() -> None:
    session = _Session()
    stored: list[dict[str, Any]] = []
    original = {
        "schema_version": "assessment/1",
        "contract_analysis": {"schema_version": "contract-analysis.v1", "opaque": [1, None]},
        "effects": {},
        "recursive": {"0xchild": {"schema_version": "assessment/1", "principal_history": {"rows": []}}},
    }

    result = store_assessment_section(
        cast(Session, session),
        "job",
        "principal_labels",
        {"schema_version": "principal-labels.v1", "principals": []},
        reader=lambda *_: original,
        writer=lambda _session, _job, _name, data: stored.append(data),
    )

    assert session.statements and "FOR UPDATE" in str(session.statements[0])
    assert result.get("contract_analysis") == original["contract_analysis"]
    assert result.get("effects") == {}
    assert result.get("recursive") == original["recursive"]
    assert stored == [result]
    assert result is not original


def test_store_first_section_creates_versioned_envelope() -> None:
    session = _Session()
    writes: list[tuple[str, object]] = []
    result = store_assessment_section(
        cast(Session, session),
        "job",
        "effects",
        {"schema_version": "semantic-2", "error": "compile failed"},
        reader=lambda *_: None,
        writer=lambda _session, _job, name, data: writes.append((name, data)),
    )
    assert result == {
        "schema_version": "assessment/1",
        "effects": {"schema_version": "semantic-2", "error": "compile failed"},
    }
    assert writes == [("assessment", result)]


def test_store_assessment_preserves_payload_identity_for_writer() -> None:
    session = _Session()
    assessment = {"schema_version": "assessment/1", "principal_history": {"unknown_future_field": [1, 2]}}
    observed: list[object] = []
    store_assessment(
        cast(Session, session),
        "job",
        cast(Assessment, assessment),
        writer=lambda _session, _job, _name, data: observed.append(data),
    )
    assert observed == [assessment]
    assert observed[0] is assessment


@pytest.mark.parametrize(
    "value, message",
    [
        ([], "must be an object"),
        ({}, "schema_version"),
        ({"schema_version": "assessment/2"}, "schema_version"),
        ({"schema_version": "assessment/1", "effects": []}, "effects must be an object"),
        ({"schema_version": "assessment/1", "extra": {}}, "unknown fields"),
        ({"schema_version": "assessment/1", "recursive": []}, "recursive must be an object"),
        ({"schema_version": "assessment/1", "recursive": None}, "recursive must be an object"),
        (
            {"schema_version": "assessment/1", "recursive": {"child": {"schema_version": "wrong"}}},
            "schema_version",
        ),
    ],
)
def test_malformed_envelope_is_rejected(value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        validate_assessment(value)


def test_recursive_helper_validates_and_preserves_child() -> None:
    child = {"schema_version": "assessment/1", "effects": {"functions": {}}}
    parent = {"schema_version": "assessment/1", "recursive": {"0xabc": child}}
    assert get_recursive_assessment(cast(Assessment, parent), "0xabc") is child
    assert get_recursive_assessment(cast(Assessment, parent), "missing") is None


def test_unknown_section_is_rejected_before_read_or_write() -> None:
    session = _Session()
    with pytest.raises(ValueError, match="unknown assessment section"):
        get_assessment_section(cast(Session, session), "job", "other", reader=lambda *_: None)
    with pytest.raises(ValueError, match="unknown assessment section"):
        store_assessment_section(cast(Session, session), "job", "other", {}, reader=lambda *_: None)
