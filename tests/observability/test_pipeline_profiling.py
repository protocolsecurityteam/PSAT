"""The per-phase field names are what Loki queries depend on, so drift fails in CI rather than after a slow live run."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

from services.static.contract_analysis_pipeline import predicate_artifacts


class _StubFn:
    def __init__(self, name: str, *, slow: bool = False) -> None:
        self.full_name = name
        self.name = name.split("(")[0]
        self.visibility = "external"
        self.view = False
        self.pure = False
        self.slow = slow
        self.is_constructor = False
        self.is_fallback = False
        self.is_receive = False
        self.contract = self


class _StubContract:
    def __init__(self, name: str, fns: list[_StubFn]) -> None:
        self.name = name
        # Both attrs are exposed so a revert to ``contract.functions`` still finds the fixtures.
        self.functions = fns
        self.functions_entry_points = fns


def test_predicate_summary_emits_structured_log_with_top_slow_functions(caplog, monkeypatch):
    # The prod default (500 ms) is tuned for live-test volume.
    monkeypatch.setenv("PSAT_PREDICATE_SUMMARY_MS", "100")
    fast = _StubFn("fast()", slow=False)
    slow = _StubFn("slow(uint256)", slow=True)
    contract = _StubContract("ProbeContract", [fast, slow])

    def _fake_build_predicate_tree(fn: Any, **_kwargs: Any) -> Any:
        if getattr(fn, "slow", False):
            import time as _t

            _t.sleep(0.3)  # > 250 ms slow-function threshold
        return None

    def _fake_build_return_predicate_tree(fn: Any) -> Any:
        return None

    with caplog.at_level(logging.INFO, logger=predicate_artifacts.logger.name):
        with (
            patch.object(predicate_artifacts, "build_predicate_tree", _fake_build_predicate_tree),
            patch.object(predicate_artifacts, "build_return_predicate_tree", _fake_build_return_predicate_tree),
            patch.object(predicate_artifacts, "apply_writer_gate_pass", lambda c, t: None),
            patch.object(predicate_artifacts, "apply_mapping_event_hint_pass", lambda c, t: None),
            patch.object(
                predicate_artifacts,
                "apply_reentrancy_pause_pass",
                lambda c, t: {
                    "pause_state_vars": [],
                    "pause_toggle_functions": [],
                    "reentrancy_state_vars": [],
                    "reentrancy_guarded_functions": [],
                },
            ),
        ):
            predicate_artifacts.build_predicate_artifacts_with_pause_info(contract)

    slow_records = [r for r in caplog.records if getattr(r, "profile_kind", None) == "predicate_function_slow"]
    summary_records = [r for r in caplog.records if getattr(r, "profile_kind", None) == "predicate_summary"]

    assert slow_records, "predicate_function_slow log line missing — Loki rank query depends on it"
    slow_record = slow_records[0]
    assert getattr(slow_record, "function", None) == "slow(uint256)"
    assert getattr(slow_record, "contract_name", None) == "ProbeContract"
    assert getattr(slow_record, "duration_ms", 0) >= 250, "slow stub should trip the per-function threshold"

    assert summary_records, "predicate_summary log line missing — pipeline_profile cross-ref depends on it"
    summary = summary_records[0]
    assert getattr(summary, "function_count", None) == 2
    assert getattr(summary, "contract_name", None) == "ProbeContract"
    top_slow = getattr(summary, "top_slow_functions", []) or []
    assert top_slow, "top_slow_functions list missing on summary"
    assert top_slow[0]["function"] == "slow(uint256)", "ranking must place slowest function first"
