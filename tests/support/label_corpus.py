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

It also pins the per-function ``value_flows`` — every field of every flow fact,
including the destination/amount lattice kinds, their per-site breakdowns and
the resolved ABI parameter slots. A claim id is far coarser than the flow fact
under it: a producer change can move a destination from ``immutable`` to
``param`` (the caller-redirect discriminator) without touching a single
``claim_id``, and pinning claims alone let exactly that class of change through
unseen. The gate exists to make a behavior change VISIBLE and force a reviewed
golden diff, not to certify that nothing changed.
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

GOLDEN_SCHEMA_VERSION = 3

# Frozen fixture corpus for the effect-labels A/B golden gate. Every entry is a
# small synthetic source that reproduces one real-world claim SHAPE — either a
# lone ``.sol`` (compiled directly with the pinned solc) or a self-contained
# Foundry project directory under ``tests/fixtures/contracts``. Two entries reuse
# fixtures already on main (``token/``, ``authority/``) at zero new-source cost.
# The whole corpus is pinned to solc 0.8.27 (the version the offline CI ``test``
# job installs) so the gate runs — never skips — in the default offline suite.
# This list is the single source of truth for corpus membership; fake addresses
# keep the golden keyed uniformly.
MANIFEST: list[dict[str, Any]] = [
    {
        # ERC-20 + OZ-Pausable + owner-gated mint. Covers pause.set / pause.unset
        # (standard require-based toggle) and the erc20.* / supply.mint families.
        "address": "0x0000000000000000000000000000000000000010",
        "name": "Token",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/token/token_erc20_ownable_pausable.sol",
    },
    {
        # OZ-v5 ERC-7201 namespaced Ownable (reused from main). Covers
        # ownership.transfer / ownership.renounce and pins the ghost-immune
        # namespaced-storage handling (no ownership claim on owner()/setTokenOut).
        "address": "0x0000000000000000000000000000000000000020",
        "name": "OzV5Ownable",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/authority/OzV5NamespacedOwnable.sol",
    },
    {
        # Solmate Auth + RolesAuthority: roles.configure (canonical selectors),
        # authority.replace (setAuthority + authority write), ownership.transfer.
        "address": "0x0000000000000000000000000000000000000030",
        "name": "SolmateRoles",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/solmate_roles.sol",
    },
    {
        # BoringVault-shaped share token: callee_pointer.rotate (hook setter +
        # sibling invoke) and supply.mint / supply.burn (enter/exit sign idiom).
        "address": "0x0000000000000000000000000000000000000040",
        "name": "VaultHook",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/vault_hook.sol",
    },
    {
        # LayerZero OApp on OZ-v5 namespaced storage: lz_oapp.set_peer /
        # set_delegate, and the setLockBox pseudo-slot callee_pointer near-miss.
        "address": "0x0000000000000000000000000000000000000050",
        "name": "LzOApp",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/lz_oapp.sol",
    },
    {
        # ERC-7201 namespaced pause latch (the etherfi Pausable.sol shape): the
        # flag is written through an assembly storage pointer, so Plane 0 records
        # a bytes32 slot pseudo-variable, not a bool state var. Pins that the
        # pause family is recognized on namespaced storage, and that the
        # unguarded sibling carries no pause claim.
        "address": "0x0000000000000000000000000000000000000060",
        "name": "NamespacedPausable",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/namespaced_pausable.sol",
    },
    {
        # Token-first safe-transfer library (SafeTransferLib / SafeERC20) called
        # in the contract's OWN body — the value move is invisible to both the
        # ERC-20 selector scan and the assembly-only callee body. Also pins the
        # ERC-721 tokenId slot (an identity, not a quantity) and a two-site fold
        # whose members are each resolved.
        "address": "0x0000000000000000000000000000000000000070",
        "name": "AssetRecovery",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/safe_transfer_lib.sol",
    },
    {
        # Router -> vault: the entry is neither source nor sink (``value_router``).
        # Pins the zero-amount guarded route, the ERC-4626 param x external-rate /
        # constant amount, and the payable msg.value reassignment.
        "address": "0x0000000000000000000000000000000000000080",
        "name": "Teller",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/value_router.sol",
    },
    {
        # Destinations and amounts that reach a sink as an internal helper's
        # RETURN value (a getter-read storage address, a ``_calculate*`` result),
        # plus the branch/echo/disagree negatives that must stay unresolved.
        "address": "0x0000000000000000000000000000000000000090",
        "name": "HelperReturns",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/helper_returns.sol",
    },
    {
        # WETH-shaped wrapped-native token: weth.* / erc20.* / supply.* / flow.out.
        "address": "0x000000000000000000000000000000000000dead",
        "name": "WrappedNative",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/wrapped_native",
    },
    {
        # G5: a library-wrapped pull whose token is a STATE VARIABLE behind a
        # double cast, so the receiver is a Slither temporary that must resolve to
        # the state var (safe_transfer_lib.sol takes the token as a PARAMETER and
        # cannot exercise this). Also carries a batch executor so the exec.arbitrary
        # "one array level up" shape has corpus-golden coverage.
        "address": "0x00000000000000000000000000000000000000a0",
        "name": "CastWrappedPull",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/cast_wrapped_pull.sol",
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

    version = entry["solc_version"]
    solc_binary = _solc_select_binary(version)
    if not solc_binary.exists():
        raise SolcNotInstalled(
            f"solc {version} for {entry['name']} is not installed via solc-select "
            f"(expected {solc_binary}); run: uv run solc-select install {version}"
        )

    source = REPO_ROOT / entry["source_path"]
    if source.is_dir():
        # Self-contained Foundry project: copy fresh (no cached build output) and
        # compile via FOUNDRY_SOLC so svm never reaches the network.
        project = workdir / entry["address"]
        _copy_project(source, project)
        with _foundry_env(solc_binary):
            slither = Slither(str(project))
            subject, effects, predicate_trees, claims_artifact = _run_static_sequence(slither, entry)
        return subject, effects, predicate_trees, claims_artifact
    if source.is_file() and source.suffix == ".sol":
        # Lone, dependency-free source: crytic-compile drives the pinned solc
        # binary directly (``solc=``), so this stays offline and deterministic.
        with _foundry_env(solc_binary):
            slither = Slither(str(source), solc=str(solc_binary))
            return _run_static_sequence(slither, entry)
    raise FileNotFoundError(f"corpus source missing for {entry['name']}: {source}")


def _run_static_sequence(slither: Any, entry: dict[str, Any]):
    from services.static.claims import build_claims
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts_with_pause_info,
    )
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract

    subject = _select_subject_contract(slither, entry["name"])
    if subject is None:
        raise RuntimeError(f"no analyzable subject contract for {entry['name']} ({entry['address']})")
    predicate_trees, _pause_info = build_predicate_artifacts_with_pause_info(subject)
    effects = build_effects(subject)
    claims_artifact = build_claims(subject, effects, predicate_trees)
    return subject, effects, predicate_trees, claims_artifact


# Every ``ValueFlow`` key, in declaration order. Listed explicitly rather than
# dumping the dict so a NEW producer field shows up as a deliberate golden schema
# change (and a reviewed diff) instead of silently appearing in the file.
_FLOW_KEYS = (
    "kind",
    "selector",
    "direction",
    "from_is_self",
    "origin",
    "target_kind",
    "amount_kind",
    "target_kinds",
    "amount_kinds",
    "target_param_index",
    "amount_param_index",
)


def _flow_record(flow: Any) -> dict[str, Any]:
    """One ``ValueFlow`` flattened for the golden, absent keys omitted.

    Omission is meaningful in the producer (``target_kinds`` appears only when a
    fold lost information, ``amount_param_index`` only when a slot was proven), so
    the golden reproduces presence/absence rather than filling in nulls."""
    if not isinstance(flow, dict):
        return {"malformed": repr(flow)}
    return {key: flow[key] for key in _FLOW_KEYS if key in flow}


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
                # Producer order, NOT sorted: the flow list's ordering is itself
                # part of the contract (same-contract flows precede routed ones),
                # so a reordering is a change the gate should show.
                "value_flows": [_flow_record(f) for f in (info.get("value_flows") or [])],
                # External-call sinks pinned (target, selector, origin) DIRECTLY
                # off the artifact — NOT laundered through _selector_for_signature
                # like the function ``selector`` above — so a change to the resolved
                # head (a library-wrapped/cast token receiver, G5) or to the
                # canonical callee selector (the cross-contract join) diffs the
                # gate. Without this pin those two shapes are invisible here.
                "external_calls": sorted(
                    (
                        {
                            "target": str(s.get("target") or ""),
                            "selector": str(s.get("selector") or ""),
                            "origin": str(s.get("origin") or ""),
                        }
                        for s in (info.get("sinks") or [])
                        if isinstance(s, dict) and s.get("kind") == "external_call"
                    ),
                    key=lambda s: (s["target"], s["selector"], s["origin"]),
                ),
                # The persisted compatibility display targets
                # (``EffectiveFunction.effect_targets``): a resolved head changes
                # this user-visible string, so pin it too.
                "effect_targets": sorted(str(t) for t in (info.get("effect_targets") or [])),
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
            "Golden effect-labels, Plane-1 claim (claim_id, tier) tuples AND value-flow "
            "facts for the frozen fixture corpus, pinned to CURRENT producer behavior. "
            "Regenerate with tests/regenerate_label_golden.py only for reviewed, intended "
            "changes — and justify each hunk of the diff, since a diff here is a change in "
            "what the pipeline publishes about real contracts."
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
