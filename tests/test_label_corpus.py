"""A/B golden gate for effect labels over the frozen fixture corpus.

Two entry points, both driving the real static pipeline (compile with Slither,
run ``build_predicate_artifacts_with_pause_info`` -> ``build_effects`` ->
``apply_authority_effect_labels``) and comparing flattened
``(contract, address, function, selector, effect_labels)`` tuples against the
checked-in golden:

- ``test_label_corpus_smoke`` runs in the default offline suite over a small,
  fast subset (contracts pinned to the solc version CI already installs), so a
  producer change that shifts those labels fails fast without the full corpus.
- ``test_label_corpus_full_golden`` is marked ``label_corpus`` and gated on
  ``PSAT_LABEL_CORPUS_FULL`` so it only runs in its own CI job; it recomputes
  the entire corpus and fails on any golden drift with a readable unified diff.

Regenerate the golden for an intended, reviewed change with
``tests/label_corpus/regenerate.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("slither")

sys.path.insert(0, str(Path(__file__).resolve().parent / "label_corpus"))

import harness  # noqa: E402  # pyright: ignore[reportMissingImports]

# Fast subset for the default offline suite: both pin solc 0.8.27 (installed in
# the offline CI job) and between them exercise the ownership/roles/authority
# and pause/upgrade/flow label families.
SMOKE_ADDRESSES = (
    "0x789cbbe0739f1458905c9ca6d6e74f7997622a9b",  # EtherFiNodesManager
    "0x83bc649fcdb2c8da146b2154a559ddedf937ef12",  # LiquidityPool
)


def _entries_for(addresses):
    by_addr = {e["address"]: e for e in harness.corpus_entries()}
    missing = [a for a in addresses if a not in by_addr]
    assert not missing, f"smoke addresses absent from manifest: {missing}"
    return [by_addr[a] for a in addresses]


def test_manifest_and_golden_cover_the_same_contracts():
    """The manifest is the single source of truth; the golden must mirror it
    exactly (no orphaned or missing corpus entries)."""
    manifest_addrs = {e["address"] for e in harness.corpus_entries()}
    golden_addrs = {c["address"] for c in harness.load_golden()["contracts"]}
    assert manifest_addrs == golden_addrs


def test_label_corpus_smoke(tmp_path):
    """Recompute the smoke subset and diff against the checked-in golden."""
    entries = _entries_for(SMOKE_ADDRESSES)
    expected = harness.golden_for_addresses(harness.load_golden(), SMOKE_ADDRESSES)
    try:
        actual = harness.build_golden(entries, workdir=tmp_path)
    except harness.SolcNotInstalled as exc:  # pragma: no cover - env-dependent skip
        pytest.skip(str(exc))

    diff = harness.unified_diff(expected, actual, label="smoke")
    assert not diff, (
        "effect-labels golden drift on the smoke subset.\n"
        "If this change is intended, regenerate with "
        "tests/label_corpus/regenerate.py and commit the reviewed golden diff.\n\n" + diff
    )


@pytest.mark.label_corpus
def test_label_corpus_full_golden(tmp_path):
    """Recompute the entire corpus and diff against the checked-in golden."""
    if not os.environ.get("PSAT_LABEL_CORPUS_FULL"):
        pytest.skip("full label corpus runs in its own CI job; set PSAT_LABEL_CORPUS_FULL=1 to run locally")

    expected = harness.load_golden()
    actual = harness.build_golden(harness.corpus_entries(), workdir=tmp_path)

    diff = harness.unified_diff(expected, actual, label="corpus")
    assert not diff, (
        "effect-labels golden drift over the frozen corpus.\n"
        "If this change is intended, regenerate with "
        "tests/label_corpus/regenerate.py and commit the reviewed golden diff.\n\n" + diff
    )
