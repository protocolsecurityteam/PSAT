"""YAML-driven corpus harness.

For every ``tests/corpus_manifests/*.yaml`` file:

  1. Compile the Solidity declared inline (or referenced via
     ``source_path:``) against Slither.
  2. Run ``build_predicate_artifacts`` on the named subject contract.
  3. Assert each function in ``expected_functions`` matches the semantic
     output's leaf fields (authority_role / kind / operator /
     confidence / unsupported_reason / references_msg_sender /
     parameter_indices).
  4. Assert every function in ``unguarded`` is absent from the semantic
     trees dict (resolver convention: absent = publicly callable).

Manifests live alongside this harness so #18's go/no-go gate has
authoritative expected output for the canonical real-protocol
shapes. See ``tests/corpus_manifests/README.md`` for the schema +
how to add a manifest.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)

_MANIFESTS_DIR = Path(__file__).parent / "corpus_manifests"


def _all_manifests() -> list[Path]:
    return sorted(_MANIFESTS_DIR.glob("*.yaml"))


def _manifest_id(path: Path) -> str:
    return path.stem


@pytest.mark.parametrize("manifest_path", _all_manifests(), ids=_manifest_id)
def test_corpus_manifest(manifest_path: Path, tmp_path: Path):
    manifest = _load_manifest(manifest_path)
    contract_name = manifest["contract_name"]
    source = _resolve_source(manifest, manifest_path)

    sl = _compile_source(tmp_path, source)
    contract = next(c for c in sl.contracts if c.name == contract_name)
    artifact = build_predicate_artifacts(contract)

    expected_functions: dict[str, dict[str, Any]] = manifest.get("expected_functions") or {}
    unguarded: list[str] = manifest.get("unguarded") or []

    overlap = set(expected_functions.keys()) & set(unguarded)
    if overlap:
        pytest.fail(
            f"manifest {manifest_path.name} lists {sorted(overlap)} in BOTH "
            "expected_functions and unguarded — pick one."
        )

    trees = artifact["trees"]

    # Guarded functions must have a tree with at least one leaf
    # matching the expected fields.
    for fn, expectations in expected_functions.items():
        assert fn in trees, f"manifest expected {fn} to be guarded; semantic trees dict has {sorted(trees.keys())}"
        leaves = list(_walk_leaves(trees[fn]))
        assert leaves, f"semantic tree for {fn} has no leaves"
        match_index = _find_matching_leaf(leaves, expectations)
        assert match_index is not None, _format_no_match(fn, leaves, expectations)

    # Unguarded functions must NOT appear (absent = public).
    for fn in unguarded:
        assert fn not in trees, (
            f"manifest expected {fn} to be unguarded but semantic pipeline produced a tree: {trees[fn]}"
        )


# ---------------------------------------------------------------------------
# Loader / matching
# ---------------------------------------------------------------------------


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"{path}: top-level must be a mapping, got {type(data)}")
    if "contract_name" not in data:
        raise RuntimeError(f"{path}: missing required key 'contract_name'")
    if "source" not in data and "source_path" not in data:
        raise RuntimeError(f"{path}: must declare either 'source' (inline) or 'source_path:'")
    return data


def _resolve_source(manifest: dict[str, Any], manifest_path: Path) -> str:
    if "source" in manifest:
        return str(manifest["source"])
    src_path = manifest_path.parent / manifest["source_path"]
    return src_path.read_text()


def _compile_source(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _walk_leaves(tree: dict[str, Any]):
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf:
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _walk_leaves(child)


# Manifest fields that are matched directly against the leaf's
# fields. Each is OPTIONAL — the manifest only pins fields it cares
# about. New fields can be added as the pipeline grows by extending
# this list.
_MATCHED_FIELDS = (
    "authority_role",
    "kind",
    "operator",
    "confidence",
    "unsupported_reason",
    "references_msg_sender",
    "parameter_indices",
)


def _find_matching_leaf(leaves: list[dict[str, Any]], expectations: dict[str, Any]) -> int | None:
    for idx, leaf in enumerate(leaves):
        if all(_field_matches(leaf, field, expectations[field]) for field in _MATCHED_FIELDS if field in expectations):
            return idx
    return None


def _field_matches(leaf: dict[str, Any], field: str, expected: Any) -> bool:
    actual = leaf.get(field)
    if isinstance(expected, list) and isinstance(actual, list):
        return list(actual) == list(expected)
    return actual == expected


def _format_no_match(fn: str, leaves: list[dict[str, Any]], expectations: dict[str, Any]) -> str:
    summaries = [{field: leaf.get(field) for field in _MATCHED_FIELDS} for leaf in leaves]
    return (
        f"no leaf for {fn} matched the manifest expectations.\n"
        f"  expected: {expectations}\n"
        f"  observed leaves: {summaries}"
    )
