"""Profiling instrumentation for ``collect_contract_analysis_with_artifacts``
and ``build_predicate_artifacts_with_pause_info``.

Asserts that the per-phase log lines are emitted with the structured
fields a Loki query expects (``phase``, ``duration_ms``, ``contract_name``,
``profile_kind``). The downstream consumer is a query like::

    {fly_app_name="psat-pr-N"}
      | json
      | profile_kind="pipeline_phase"
      | phase="predicate_trees"

so the field names are part of the contract. Adding a coverage gate
here makes accidental drift visible in CI rather than after a slow
live test run.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

from services.static.contract_analysis_pipeline import predicate_artifacts


class _StubFn:
    """Minimal Slither-function stand-in for the predicate builder tests.

    ``visibility`` keeps it eligible for ``_is_externally_callable``;
    ``view`` / ``pure`` / ``contract`` mirror the attributes the real
    builder consults. ``full_name`` is the dict key used in the
    artifact.
    """

    def __init__(self, name: str, *, slow: bool = False) -> None:
        self.full_name = name
        self.name = name.split("(")[0]
        self.visibility = "external"
        self.view = False
        self.pure = False
        # ``slow`` is the test knob — we patch ``build_predicate_tree``
        # below to sleep when called on a "slow" stub so the per-function
        # threshold actually fires.
        self.slow = slow
        self.is_constructor = False
        self.is_fallback = False
        self.is_receive = False
        # The real builder calls ``getattr(fn, 'contract', None).functions``
        # for cross-fn lookups; an empty list keeps the helper-engine
        # cache happy on this stub.
        self.contract = self


class _StubContract:
    def __init__(self, name: str, fns: list[_StubFn]) -> None:
        self.name = name
        # ``functions_entry_points`` is the iteration target after the
        # AccessControl-override dedup fix (see
        # ``tests/static/test_predicate_artifacts_entry_point_dedup.py``).
        # The stub exposes both attrs so an accidental revert to
        # ``contract.functions`` still finds the test fixtures.
        self.functions = fns
        self.functions_entry_points = fns


def test_predicate_summary_emits_structured_log_with_top_slow_functions(caplog, monkeypatch):
    """When the predicate stage crosses the summary threshold, the log
    line must carry ``profile_kind=predicate_summary``, the function
    count, and a top-N slowest list — the contract Loki queries depend on."""
    # Tighten the summary threshold so a 300 ms stub trips it; the prod
    # default (500 ms) is set for live-test signal volume, not unit tests.
    monkeypatch.setenv("PSAT_PREDICATE_SUMMARY_MS", "100")
    fast = _StubFn("fast()", slow=False)
    slow = _StubFn("slow(uint256)", slow=True)
    contract = _StubContract("ProbeContract", [fast, slow])

    # Patch the per-function builders to sleep on the "slow" function so
    # we don't need a real Slither subject to exercise the threshold.
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
            # ``apply_*_pass`` mutate the trees dict in place; replace
            # them with no-ops so the test doesn't depend on Slither IR.
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


def test_predicate_summary_suppressed_for_cheap_contract(caplog):
    """Cheap contracts (sub-threshold) must not emit the summary line —
    otherwise every leaf ERC20 in a live test produces a profile log.
    The per-function ``predicate_function_slow`` line is also gated so
    only the genuinely slow functions surface."""
    fast = _StubFn("fast()", slow=False)
    contract = _StubContract("CheapContract", [fast])

    with caplog.at_level(logging.INFO, logger=predicate_artifacts.logger.name):
        with (
            patch.object(predicate_artifacts, "build_predicate_tree", lambda fn, **_k: None),
            patch.object(predicate_artifacts, "build_return_predicate_tree", lambda fn: None),
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

    assert not [r for r in caplog.records if getattr(r, "profile_kind", None) == "predicate_summary"]
    assert not [r for r in caplog.records if getattr(r, "profile_kind", None) == "predicate_function_slow"]
