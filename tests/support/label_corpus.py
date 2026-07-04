"""In-process runner for the frozen effect-labels fixture corpus.

Compiles each corpus contract with Slither and runs the exact production static
label sequence, then flattens the result into deterministic
``(contract, address, function, selector, effect_labels, claims)`` tuples for the
A/B golden gate in ``tests/test_label_corpus.py`` and the per-family assertions in
``tests/test_claims_behavior_families.py``. It has no import-time side effects.

Compilation is pinned to the solc-select binary named by each manifest entry's
``solc_version`` (via ``FOUNDRY_SOLC``), so the gate is deterministic and offline:
it never lets Foundry's svm reach the network to resolve a version. The whole
corpus pins solc ``0.8.27`` — the single version the offline CI ``test`` job
installs — so the gate runs (never skips) in the default suite.

The golden format carries a per-function ``claims`` list of
``{claim_id, tier}`` records, so the gate pins the Plane-1
``(contract, selector, claim_id, tier)`` tuples alongside the legacy
``effect_labels``. A matcher edit that silently mints or drops a claim on a
corpus function fails the gate.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_PATH = REPO_ROOT / "tests" / "fixtures" / "label_corpus" / "golden.json"

GOLDEN_SCHEMA_VERSION = 1

# Frozen fixture corpus for the effect-labels A/B golden gate. Each entry is a
# self-contained Foundry project under ``tests/fixtures/contracts/label_corpus``
# (four Etherscan-verified real contracts + one synthetic WETH-shaped token). The
# whole corpus is pinned to solc 0.8.27 so the gate runs in the default offline
# suite. This list is the single source of truth for corpus membership.
MANIFEST: list[dict[str, Any]] = [
    {
        "address": "0x39272ee125ebd9214404f735baae50acb9d334c0",
        "name": "L1SyncPoolETH",
        "chain": "mainnet",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/l1_sync_pool",
    },
    {
        "address": "0x3994741a5b29c60d0ab318de1024f9256fe959dc",
        "name": "RolesAuthority",
        "chain": "mainnet",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/roles_authority",
    },
    {
        "address": "0x417e1ef6eb82c3e6a60c2dc342e574e4c51b4d35",
        "name": "TellerWithMultiAssetSupport",
        "chain": "mainnet",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/teller",
    },
    {
        "address": "0x7223442cad8e9ca474fc40109ab981608f8c4273",
        "name": "BoringVault",
        "chain": "mainnet",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/boring_vault",
    },
    {
        # Synthetic WETH-shaped token (no real deployment); a fake address keeps
        # the golden keyed uniformly. Covers the weth.* / erc20.* / supply.* /
        # flow.out families with one small compile.
        "address": "0x000000000000000000000000000000000000dead",
        "name": "WrappedNative",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/wrapped_native",
    },
]

# Directories that are Foundry build output, never source; excluded from the
# working copy so every compile is fresh and the repo tree stays clean.
_BUILD_ARTIFACT_DIRS = frozenset({"out", "cache"})


class SolcNotInstalled(RuntimeError):
    """A corpus project pins a solc version that solc-select has not installed."""


def corpus_entries() -> list[dict[str, Any]]:
    entries = list(MANIFEST)
    entries.sort(key=lambda e: e["address"])
    return entries


def _solc_select_binary(version: str) -> Path:
    """Absolute path to the solc-select-managed solc binary for ``version``.

    Reads solc-select's own artifacts dir, so it resolves to wherever CI (or a
    dev venv) installed it -- no hard-coded path.
    """
    from solc_select.constants import ARTIFACTS_DIR

    return Path(ARTIFACTS_DIR) / f"solc-{version}" / f"solc-{version}"


def _copy_project(src: Path, dst: Path) -> None:
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns(*_BUILD_ARTIFACT_DIRS),
    )


@contextmanager
def _foundry_env(solc_binary: Path):
    """Force Foundry onto ``solc_binary`` and offline for the duration of a
    compile, restoring the prior environment afterward."""
    prior = {k: os.environ.get(k) for k in ("FOUNDRY_SOLC", "FOUNDRY_OFFLINE")}
    os.environ["FOUNDRY_SOLC"] = str(solc_binary)
    os.environ["FOUNDRY_OFFLINE"] = "true"
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _compile_subject(entry: dict[str, Any], workdir: Path):
    """Copy + Slither-compile one corpus project, returning
    ``(subject, effects, predicate_trees, claims_artifact)`` from the production
    static sequence. Raises :class:`SolcNotInstalled` when the pinned solc is
    absent so callers can skip cleanly."""
    from slither import Slither

    from services.static.claims import build_claims
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts_with_pause_info,
    )
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract

    version = entry["solc_version"]
    solc_binary = _solc_select_binary(version)
    if not solc_binary.exists():
        raise SolcNotInstalled(
            f"solc {version} for {entry['name']} is not installed via solc-select "
            f"(expected {solc_binary}); run: uv run solc-select install {version}"
        )

    source = REPO_ROOT / entry["source_path"]
    if not source.is_dir():
        raise FileNotFoundError(f"corpus source missing for {entry['name']}: {source}")

    project = workdir / entry["address"]
    _copy_project(source, project)

    with _foundry_env(solc_binary):
        slither = Slither(str(project))
        subject = _select_subject_contract(slither, entry["name"])
        if subject is None:
            raise RuntimeError(f"no analyzable subject contract for {entry['name']} ({entry['address']})")
        predicate_trees, _pause_info = build_predicate_artifacts_with_pause_info(subject)
        effects = build_effects(subject)
        claims_artifact = build_claims(subject, effects, predicate_trees)
    return subject, effects, predicate_trees, claims_artifact


def extract_contract(entry: dict[str, Any], workdir: Path) -> dict[str, Any]:
    """Compile one corpus contract and return its golden record.

    Copies the project into ``workdir`` (fresh, no cached build output),
    compiles it with Slither pinned to the manifest solc version, runs the
    production sequence, and flattens the effects artifact into sorted function
    tuples.
    """
    from services.resolution.capability_resolver import _selector_for_signature
    from services.static.claims import attach_claims_to_effects, project_effect_labels

    subject, effects, predicate_trees, claims_artifact = _compile_subject(entry, workdir)
    attach_claims_to_effects(effects, claims_artifact)
    project_effect_labels(effects)

    canonical = predicate_trees.get("canonical_signatures") or {}
    functions: list[dict[str, Any]] = []
    for full_name, info in (effects.get("functions") or {}).items():
        selector = _selector_for_signature(full_name, canonical) or info.get("selector") or ""
        functions.append(
            {
                "full_name": full_name,
                "selector": selector,
                "effect_labels": sorted(info.get("effect_labels") or []),
                # Plane-1 claims: only claim_id + tier are pinned (the witness is
                # replayable and verbose; the A/B gate diffs the sentence-bearing
                # tuple). Sorted for a deterministic golden.
                "claims": sorted(
                    ({"claim_id": c["claim_id"], "tier": c["tier"]} for c in (info.get("claims") or [])),
                    key=lambda c: (c["claim_id"], c["tier"]),
                ),
            }
        )
    functions.sort(key=lambda row: (row["full_name"], row["selector"]))

    return {
        "address": entry["address"],
        "chain": entry["chain"],
        "contract": subject.name,
        "solc_version": entry["solc_version"],
        "functions": functions,
    }


# Per-address cache of ``{function_full_name: [claim, ...]}`` so a module that
# asserts many families on one contract compiles it only once.
_CLAIMS_CACHE: dict[str, dict[str, list[Any]]] = {}


def claims_for_address(address: str) -> dict[str, list[Any]]:
    """``{function_full_name: [claim, ...]}`` for one corpus contract, compiled
    and run through the production static sequence. Cached per address; raises
    :class:`SolcNotInstalled` when the pinned solc is absent."""
    key = address.lower()
    if key in _CLAIMS_CACHE:
        return _CLAIMS_CACHE[key]

    import tempfile

    entry = next(e for e in corpus_entries() if e["address"].lower() == key)
    with tempfile.TemporaryDirectory() as tmp:
        _subject, _effects, _trees, claims_artifact = _compile_subject(entry, Path(tmp))
    functions = claims_artifact["functions"]
    _CLAIMS_CACHE[key] = functions
    return functions


def build_golden(
    entries: Iterable[dict[str, Any]] | None = None,
    *,
    workdir: Path,
) -> dict[str, Any]:
    """Compute the full golden document for ``entries`` under ``workdir``."""
    entries = list(entries) if entries is not None else corpus_entries()
    contracts = [extract_contract(entry, workdir) for entry in entries]
    contracts.sort(key=lambda c: c["address"])
    return {
        "schema_version": GOLDEN_SCHEMA_VERSION,
        "description": (
            "Golden effect-labels AND Plane-1 claim (claim_id, tier) tuples for the "
            "frozen fixture corpus, pinned to CURRENT producer behavior. Regenerate with "
            "tests/regenerate_label_golden.py only for reviewed, intended label/claim changes."
        ),
        "contracts": contracts,
    }


def format_golden(golden: dict[str, Any]) -> str:
    """Deterministic on-disk rendering of a golden document."""
    return json.dumps(golden, indent=2, ensure_ascii=False) + "\n"


def load_golden() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text())


def write_golden(golden: dict[str, Any]) -> None:
    GOLDEN_PATH.write_text(format_golden(golden))


def unified_diff(expected: dict[str, Any], actual: dict[str, Any], *, label: str = "corpus") -> str:
    """Readable unified diff between two golden documents (empty when equal)."""
    expected_text = format_golden(expected)
    actual_text = format_golden(actual)
    if expected_text == actual_text:
        return ""
    return "".join(
        difflib.unified_diff(
            expected_text.splitlines(keepends=True),
            actual_text.splitlines(keepends=True),
            fromfile=f"golden/{label} (checked in)",
            tofile=f"golden/{label} (recomputed)",
        )
    )
