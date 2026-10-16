"""The static pipeline collects the young generation less often while it runs, and leaves the process's collector as it
found it once the last analysis in the process ends, however it ends.
"""

from __future__ import annotations

import gc
import threading

import pytest

from services.static.contract_analysis_pipeline import core


def test_the_threshold_is_raised_while_analyses_overlap_and_restored_after_the_last():
    before = gc.get_threshold()
    first_in = threading.Event()
    release_first = threading.Event()
    seen: list[tuple[int, int, int]] = []

    def first() -> None:
        with core._analysis_gc():
            first_in.set()
            release_first.wait(5)
            seen.append(gc.get_threshold())

    worker = threading.Thread(target=first)
    worker.start()
    assert first_in.wait(5)
    with core._analysis_gc():
        assert gc.get_threshold()[0] >= core._ANALYSIS_GC_THRESHOLD
    assert gc.get_threshold()[0] >= core._ANALYSIS_GC_THRESHOLD, "the other analysis is still running"
    release_first.set()
    worker.join(5)
    assert seen and seen[0][0] >= core._ANALYSIS_GC_THRESHOLD
    assert gc.get_threshold() == before


def test_a_failed_analysis_restores_the_threshold(monkeypatch, tmp_path):
    before = gc.get_threshold()

    def boom(project_dir):
        assert gc.get_threshold()[0] >= core._ANALYSIS_GC_THRESHOLD
        raise RuntimeError("no build")

    monkeypatch.setattr(core, "_collect_contract_analysis_with_artifacts", boom)
    with pytest.raises(RuntimeError):
        core.collect_contract_analysis_with_artifacts(tmp_path)
    assert gc.get_threshold() == before
