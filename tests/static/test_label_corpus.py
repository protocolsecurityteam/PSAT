"""A/B golden gate for effect labels over the frozen fixture corpus.

Drives the real static pipeline (compile with Slither, run
``build_predicate_artifacts_with_pause_info`` -> ``build_effects`` ->
compares the flattened ``(contract, address, function, selector,
claims)`` tuples against the checked-in golden. The whole corpus pins solc
``0.8.27`` (the version the offline CI ``test`` job installs), so a producer
change that silently relabels a corpus function fails here in the default suite
unless the PR carries the regenerated, reviewed golden diff.

Regenerate the golden for an intended, reviewed change with
``tests/regenerate_label_golden.py``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("slither")

from tests.support import label_corpus as harness


def test_manifest_and_golden_cover_the_same_contracts():
    """The manifest is the single source of truth; the golden must mirror it
    exactly (no orphaned or missing corpus entries)."""
    manifest_addrs = {e["address"] for e in harness.corpus_entries()}
    golden_addrs = {c["address"] for c in harness.load_golden()["contracts"]}
    assert manifest_addrs == golden_addrs


def test_label_corpus_golden(tmp_path):
    """Recompute the entire corpus and diff against the checked-in golden."""
    try:
        actual = harness.build_golden(harness.corpus_entries(), workdir=tmp_path)
    except harness.SolcNotInstalled as exc:  # pragma: no cover - env-dependent skip
        pytest.skip(str(exc))

    expected = harness.load_golden()
    diff = harness.unified_diff(expected, actual, label="corpus")
    assert not diff, (
        "Assessment golden drift over the frozen corpus.\n"
        "If this change is intended, regenerate with "
        "tests/regenerate_label_golden.py and commit the reviewed golden diff.\n\n" + diff
    )
