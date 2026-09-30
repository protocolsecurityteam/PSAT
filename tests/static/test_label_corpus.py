"""Golden gate over the frozen corpus (solc 0.8.27).

A silent relabel fails unless the PR regenerates via ``tests/regenerate_label_golden.py``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("slither")

from tests.support import label_corpus as harness


def test_manifest_and_golden_cover_the_same_contracts():
    manifest_addrs = {e["address"] for e in harness.corpus_entries()}
    golden_addrs = {c["address"] for c in harness.load_golden()["contracts"]}
    assert manifest_addrs == golden_addrs


def test_label_corpus_golden(tmp_path):
    try:
        actual = harness.build_golden(harness.corpus_entries(), workdir=tmp_path)
    except harness.SolcNotInstalled as exc:  # pragma: no cover - env-dependent skip
        pytest.skip(str(exc))

    expected = harness.load_golden()
    diff = harness.unified_diff(expected, actual, label="corpus")
    assert not diff, (
        "effect-labels golden drift over the frozen corpus.\n"
        "If this change is intended, regenerate with "
        "tests/regenerate_label_golden.py and commit the reviewed golden diff.\n\n" + diff
    )
