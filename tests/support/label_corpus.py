"""Runs the frozen corpus through the production static label sequence and flattens it into deterministic tuples
for the golden gate (``tests/static/test_label_corpus.py``) and the family assertions. Pinned to solc 0.8.27
via ``FOUNDRY_SOLC`` so it never skips or hits the network.

The golden pins every field a regression could move without changing ``(claim_id, tier)``: full claim
witnesses, a predicate-tree summary (a missed gate otherwise reads as "unguarded"), and every value-flow field
(``immutable`` vs ``param`` moves no claim id). The gate makes behavior changes visible for review; it doesn't
certify nothing changed.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_PATH = REPO_ROOT / "tests" / "fixtures" / "label_corpus" / "golden.json"

# 4: ``claims[].witness`` and ``predicate_tree`` per function.
# 5: ``action_summary``, the prose copy a narrowed witness doesn't move.
# 6: ``amount_record_*`` and ``record_ordering`` per flow, the self-service join's substrate.
GOLDEN_SCHEMA_VERSION = 6

# Single source of truth for corpus membership. Each entry is a small synthetic source reproducing one real claim shape;
# fake addresses keep the golden keyed uniformly.
MANIFEST: list[dict[str, Any]] = [
    {
        "address": "0x0000000000000000000000000000000000000010",
        "name": "Token",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/token/token_erc20_ownable_pausable.sol",
    },
    {
        "address": "0x0000000000000000000000000000000000000020",
        "name": "OzV5Ownable",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/authority/OzV5NamespacedOwnable.sol",
    },
    {
        "address": "0x0000000000000000000000000000000000000030",
        "name": "SolmateRoles",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/solmate_roles.sol",
    },
    {
        "address": "0x0000000000000000000000000000000000000040",
        "name": "VaultHook",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/vault_hook.sol",
    },
    {
        "address": "0x0000000000000000000000000000000000000050",
        "name": "LzOApp",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/lz_oapp.sol",
    },
    {
        # The etherfi Pausable shape: the flag is written through an assembly pointer, so Plane 0 records a bytes32
        # slot, not a bool.
        "address": "0x0000000000000000000000000000000000000060",
        "name": "NamespacedPausable",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/namespaced_pausable.sol",
    },
    {
        # Token-first SafeTransferLib in the contract's own body, invisible to both the ERC-20 selector scan and the
        # assembly callee.
        "address": "0x0000000000000000000000000000000000000070",
        "name": "AssetRecovery",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/safe_transfer_lib.sol",
    },
    {
        "address": "0x0000000000000000000000000000000000000080",
        "name": "Teller",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/value_router.sol",
    },
    {
        "address": "0x0000000000000000000000000000000000000090",
        "name": "HelperReturns",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/helper_returns.sol",
    },
    {
        "address": "0x000000000000000000000000000000000000dead",
        "name": "WrappedNative",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/wrapped_native",
    },
    {
        # G5: a state-var token behind a double cast, so the receiver is a Slither temporary. Also covers the batch
        # executor shape.
        "address": "0x00000000000000000000000000000000000000a0",
        "name": "CastWrappedPull",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/cast_wrapped_pull.sol",
    },
    {
        "address": "0x00000000000000000000000000000000000000b0",
        "name": "ConstrainedDestinations",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/constrained_destinations.sol",
    },
    {
        "address": "0x00000000000000000000000000000000000000c0",
        "name": "DelegatecallRoutes",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/delegatecall_routes.sol",
    },
    {
        # Two address parameters with the non-first as destination, plus branched/reassigned shapes that must be
        # not-determined. Shared with test_claims_upgrade_exec_matchers.py.
        "address": "0x00000000000000000000000000000000000000d0",
        "name": "ExecBinding",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/claims_upgrade_exec/exec_arbitrary_binding.sol",
    },
    {
        # G3 classes F and R: caller-gated functions with no predicate tree read as "unguarded".
        "address": "0x00000000000000000000000000000000000000e0",
        "name": "TreeAbsentPublics",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/tree_absent_publics.sol",
    },
    {
        "address": "0x00000000000000000000000000000000000000f0",
        "name": "TimedLatch",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/timed_latch.sol",
    },
    {
        # The limiter-free sibling must publish a byte-identical flow witness.
        "address": "0x0000000000000000000000000000000000000110",
        "name": "RateLimitedFlow",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/rate_limited_flow.sol",
    },
    {
        # The cancelBid / rescueTokens self-service pair; without it the ``amount_record_*`` / ``record_ordering`` pins
        # had no positive row.
        "address": "0x0000000000000000000000000000000000000120",
        "name": "SelfServicePayout",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/self_service_payout.sol",
    },
    {
        # etherfi's ERC-7201 PausableUntil: a timestamp latch beside the bool one, so the golden pins both witnesses.
        "address": "0x0000000000000000000000000000000000000130",
        "name": "NamespacedPauseUntil",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/pause/pause_until_namespaced.sol",
    },
    {
        # The only ``policy_derived`` producer. The AssetRecovery row joins only through ``abi_selector``; if it goes
        # empty the canonical join regressed.
        "address": "0x0000000000000000000000000000000000000100",
        "name": "PolicyCaller",
        "chain": "synthetic",
        "solc_version": "0.8.27",
        "source_path": "tests/fixtures/contracts/label_corpus/policy_caller.sol",
        # Stands in for a control snapshot.
        "policy_controller_values": {
            "vault": "0x00000000000000000000000000000000000000a0",
            "recovery": "0x0000000000000000000000000000000000000070",
        },
    },
]

# Excluded so every compile is fresh.
_BUILD_ARTIFACT_DIRS = frozenset({"out", "cache"})


class SolcNotInstalled(RuntimeError): ...


def corpus_entries() -> list[dict[str, Any]]:
    entries = list(MANIFEST)
    entries.sort(key=lambda e: e["address"])
    return entries


def _solc_select_binary(version: str) -> Path:
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
        project = workdir / entry["address"]
        _copy_project(source, project)
        with _foundry_env(solc_binary):
            slither = Slither(str(project))
            subject, effects, predicate_trees, claims_artifact = _run_static_sequence(slither, entry)
        return subject, effects, predicate_trees, claims_artifact
    if source.is_file() and source.suffix == ".sol":
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


# Listed explicitly so a new producer field is a deliberate schema change.
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
    # The mandatory-gate transparency join reads this.
    "router_ops",
    # ``writer_surface_closed`` is constant today; pinned so making it dynamic can't land silently.
    "target_variable",
    "target_variables",
    "target_writer_signatures",
    "target_writer_scan_complete",
    "target_writer_absent_reason",
    "writer_surface_closed",
    # The self-service join's substrate; unpinned, every verdict could fall to not_determined without a golden diff.
    "amount_record_variable",
    "amount_record_member_path",
    "amount_record_key_kinds",
    "amount_record_key_param_indexes",
    "amount_record_variables",
    "record_ordering",
)


def _json_safe(value: Any) -> Any:
    """Unrepresentable values become ``{"__unpinnable__": "<TypeName>"}``, never ``repr`` (it embeds ``id()``).

    Deliberately loud.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_json_safe(v) for v in value)
    return {"__unpinnable__": type(value).__name__}


def _tree_leaves(tree: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(tree, dict):
        return
    leaf = tree.get("leaf")
    if isinstance(leaf, dict):
        yield leaf
    for child in tree.get("children") or []:
        yield from _tree_leaves(child)


def _predicate_tree_record(tree: Any) -> dict[str, Any]:
    """``present: false`` is the G3 shape: labels, claims and flows all stay identical when the extractor starts
    finding the gate.
    """
    if tree is None:
        return {"present": False}
    leaves = list(_tree_leaves(tree))
    return {
        "present": True,
        "root_op": str(tree.get("op") or "") if isinstance(tree, dict) else "",
        "leaf_count": len(leaves),
        "authority_roles": sorted({str(leaf.get("authority_role") or "") for leaf in leaves}),
        "leaf_kinds": sorted({str(leaf.get("kind") or "") for leaf in leaves}),
        "references_msg_sender": any(bool(leaf.get("references_msg_sender")) for leaf in leaves),
    }


def _flow_record(flow: Any) -> dict[str, Any]:
    """The producer's presence/absence is meaningful, so absent keys aren't filled with nulls."""
    if not isinstance(flow, dict):
        return {"malformed": repr(flow)}
    return {key: flow[key] for key in _FLOW_KEYS if key in flow}


def _apply_policy_derivations(
    entry: dict[str, Any],
    effects: Mapping[str, Any],
    effects_by_address: Mapping[str, Mapping[str, Any]],
) -> None:
    """The only producer of ``policy_derived``, so without this the weakest tier had no golden row.

    The callee claims come from the other corpus contracts.
    """
    from services.static.claims import resolve_claim_precedence
    from services.static.cross_contract import build_callee_claim_map, derive_cross_contract_claims

    controller_values = {
        f"contract:{var}": {"value": address} for var, address in (entry.get("policy_controller_values") or {}).items()
    }
    if not controller_values:
        return
    enriched = derive_cross_contract_claims(
        effects,
        controller_values,
        build_callee_claim_map({addr: dict(art) for addr, art in effects_by_address.items()}),
    )
    for fn_sig, new_claims in enriched.items():
        record = (effects.get("functions") or {}).get(fn_sig)
        if not isinstance(record, dict):
            continue
        record["claims"] = resolve_claim_precedence(list(record.get("claims") or []) + list(new_claims))


def _compile_and_attach(entry: dict[str, Any], workdir: Path):
    from services.static.claims import attach_claims_to_effects, project_effect_labels

    subject, effects, predicate_trees, claims_artifact = _compile_subject(entry, workdir)
    attach_claims_to_effects(effects, claims_artifact)
    project_effect_labels(effects)
    return subject, effects, predicate_trees


def _flatten_record(
    entry: dict[str, Any],
    subject: Any,
    effects: Mapping[str, Any],
    predicate_trees: Mapping[str, Any],
) -> dict[str, Any]:
    from services.resolution.capability_resolver import _selector_for_signature

    canonical = predicate_trees.get("canonical_signatures") or {}
    trees = predicate_trees.get("trees") or {}
    functions: list[dict[str, Any]] = []
    for full_name, info in (effects.get("functions") or {}).items():
        selector = _selector_for_signature(full_name, canonical) or info.get("selector") or ""
        functions.append(
            {
                "full_name": full_name,
                "selector": selector,
                "effect_labels": sorted(info.get("effect_labels") or []),
                # The corpus has functions whose ``destination_kind`` is ``not_determined`` while this says "Executes
                # arbitrary external calldata"; the gate could only see the former.
                "action_summary": str(info.get("action_summary") or ""),
                # The witness is where the evidence lives, and none of it moves ``(claim_id, tier)``.
                "claims": sorted(
                    (
                        {
                            "claim_id": c["claim_id"],
                            "tier": c["tier"],
                            "witness": _json_safe(c.get("witness") or {}),
                        }
                        for c in (info.get("claims") or [])
                    ),
                    key=lambda c: (c["claim_id"], c["tier"], json.dumps(c["witness"], sort_keys=True)),
                ),
                # Producer order is part of the contract (same-contract flows precede routed ones).
                "value_flows": [_flow_record(f) for f in (info.get("value_flows") or [])],
                # Pinned straight off the artifact so a resolved-head or canonical-selector change diffs. ``receiver``
                # is a sink property, so it's pinned here, not in ``_FLOW_KEYS``.
                "external_calls": sorted(
                    (
                        {
                            "target": str(s.get("target") or ""),
                            "selector": str(s.get("selector") or ""),
                            "origin": str(s.get("origin") or ""),
                            "receiver": _json_safe(s.get("receiver")),
                        }
                        for s in (info.get("sinks") or [])
                        if isinstance(s, dict) and s.get("kind") == "external_call"
                    ),
                    key=lambda s: (
                        s["target"],
                        s["selector"],
                        s["origin"],
                        json.dumps(s["receiver"], sort_keys=True),
                    ),
                ),
                # Delegatecall sinks aren't ``external_call`` kind, so they were invisible above.
                "delegatecall_sinks": sorted(
                    (
                        {"target": str(s.get("target") or ""), "origin": str(s.get("origin") or "")}
                        for s in (info.get("sinks") or [])
                        if isinstance(s, dict) and s.get("kind") == "delegatecall"
                    ),
                    key=lambda s: (s["target"], s["origin"]),
                ),
                # A resolved head changes this user-visible string.
                "effect_targets": sorted(str(t) for t in (info.get("effect_targets") or [])),
                "predicate_tree": _predicate_tree_record(trees.get(full_name)),
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


_CLAIMS_CACHE: dict[str, dict[str, list[Any]]] = {}


def claims_for_address(address: str) -> dict[str, list[Any]]:
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
    """The cross-contract policy tier needs every sibling's claims first."""
    entries = list(entries) if entries is not None else corpus_entries()
    compiled = [(entry, *_compile_and_attach(entry, workdir)) for entry in entries]
    effects_by_address = {entry["address"].lower(): effects for entry, _subject, effects, _trees in compiled}
    for entry, _subject, effects, _trees in compiled:
        _apply_policy_derivations(entry, effects, effects_by_address)
    contracts = [_flatten_record(entry, subject, effects, trees) for entry, subject, effects, trees in compiled]
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
    return json.dumps(golden, indent=2, ensure_ascii=False) + "\n"


def load_golden() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text())


def write_golden(golden: dict[str, Any]) -> None:
    GOLDEN_PATH.write_text(format_golden(golden))


def unified_diff(expected: dict[str, Any], actual: dict[str, Any], *, label: str = "corpus") -> str:
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
