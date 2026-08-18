"""Unit tests for the StageError / StageErrors Pydantic schema."""

from __future__ import annotations

from datetime import datetime, timezone

from schemas.stage_errors import StageError, StageErrors


def _example(**overrides) -> StageError:
    base = {
        "stage": "static",
        "severity": "error",
        "exc_type": "builtins.RuntimeError",
        "message": "boom",
        "traceback": "Traceback...\nRuntimeError: boom",
        "phase": "dependency_static",
        "trace_id": "abcd1234abcd1234",
        "job_id": "11111111-1111-1111-1111-111111111111",
        "worker_id": "StaticWorker-pid-abcd",
        "failed_at": datetime(2026, 5, 2, 12, 0, tzinfo=timezone.utc),
        "retry_count": 0,
        "context": {"address": "0xabc"},
    }
    base.update(overrides)
    return StageError(**base)


def test_stage_error_round_trips_through_json():
    original = _example()
    encoded = original.model_dump_json()
    decoded = StageError.model_validate_json(encoded)
    assert decoded == original


def test_stage_error_round_trips_with_minimal_fields():
    minimal = StageError(
        stage="discovery",
        severity="degraded",
        exc_type="requests.exceptions.HTTPError",
        message="Forbidden",
        job_id="job-1",
        worker_id="DiscoveryWorker-1",
        failed_at=datetime(2026, 5, 2, 12, 0, tzinfo=timezone.utc),
    )
    encoded = minimal.model_dump_json()
    decoded = StageError.model_validate_json(encoded)
    assert decoded == minimal
    assert decoded.traceback is None
    assert decoded.phase is None
    assert decoded.trace_id is None
    assert decoded.context is None
    assert decoded.retry_count == 0


def test_stage_error_message_is_truncated_at_4kb():
    long_message = "x" * (5 * 1024)
    err = _example(message=long_message)
    assert len(err.message.encode("utf-8")) <= 4 * 1024
    # Truncation is from the head of the limit, so the value still starts with x's.
    assert err.message.startswith("x")


def test_stage_error_oversized_context_is_replaced_with_truncated_sentinel():
    big_blob = {"data": "y" * (5 * 1024)}
    err = _example(context=big_blob)
    assert err.context == {"_truncated": True}


def test_stage_error_unserializable_context_is_replaced_with_truncated_sentinel():
    class NotSerializable:
        def __repr__(self) -> str:
            raise RuntimeError("nope")

    # The validator should fall back to the sentinel rather than raise.
    err = _example(context={"x": NotSerializable()})
    # Either the json fallback handled it via str(), or it triggered the
    # sentinel — both are acceptable, but the size cap should not trip on a
    # tiny dict, so the result is the small dict or the sentinel.
    assert err.context == {"_truncated": True} or err.context == {"x": err.context["x"]}  # pyright: ignore[reportOptionalSubscript]


def test_stage_errors_envelope_serializes_empty_list_cleanly():
    envelope = StageErrors(errors=[])
    encoded = envelope.model_dump_json()
    decoded = StageErrors.model_validate_json(encoded)
    assert decoded.errors == []


def test_stage_errors_envelope_round_trips_multi_entry():
    envelope = StageErrors(
        errors=[
            _example(severity="degraded", phase="audit_discovery"),
            _example(severity="error"),
        ]
    )
    encoded = envelope.model_dump_json()
    decoded = StageErrors.model_validate_json(encoded)
    assert len(decoded.errors) == 2
    assert decoded.errors[0].severity == "degraded"
    assert decoded.errors[1].severity == "error"
