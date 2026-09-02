"""Validated read boundary for persisted monitoring configuration."""

from __future__ import annotations

from typing import cast

from pydantic import TypeAdapter, ValidationError

from schemas.observations import MonitoringConfig


class MonitoringConfigError(ValueError):
    """Stored monitoring configuration does not match its declared schema."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__(f"monitoring_config failed schema validation: {'; '.join(problems)}")


_ADAPTER = TypeAdapter(MonitoringConfig)


def load_monitoring_config(value: object) -> MonitoringConfig:
    """Validate JSON read from ``monitored_contracts.monitoring_config``.

    ``NULL`` means that no configuration has been recorded and normalizes to an
    empty configuration. Validation deliberately returns the original mapping:
    caller-owned extension keys survive the boundary instead of being discarded
    by Pydantic's TypedDict projection.
    """

    if value is None:
        return {}
    try:
        _ADAPTER.validate_python(value)
    except ValidationError as exc:
        problems = [
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}" for error in exc.errors()
        ]
        raise MonitoringConfigError(problems) from None
    return cast(MonitoringConfig, value)


__all__ = ["MonitoringConfigError", "load_monitoring_config"]
