"""Top-level orchestration for contract analysis."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from slither.slither import Slither

from schemas.static_facts import AuditAlignment, StaticFacts, Summary
from utils.logging import record_degraded, record_stage_metric

from ..claims import attach_claims_to_effects, build_claims
from .effects import EffectsArtifact, build_effects
from .predicate_artifacts import (
    build_predicate_artifacts_with_pause_info,
)
from .reentrancy_pause import PauseInfo
from .secondary_impl import detect_secondary_impl_pointers
from .shared import _load_json, _select_subject_contract
from .summaries import (
    _build_semantic_control_summary,
    _build_tracking_hints,
    _detect_contract_classification,
    _detect_pausability,
    _detect_timelock,
    _detect_upgradeability,
    _determine_control_model,
)
from .tracking import build_controller_tracking

logger = logging.getLogger(__name__)


def _phase_log_threshold_ms() -> int:
    """Per-phase log threshold for the pipeline profiler.

    Phases shorter than this are folded into the aggregate-only line.
    Default 100 ms keeps log volume bounded on cheap contracts while
    still catching the 1–10 s outliers we expect to see on
    LayerZero / EtherFi-class contracts.

    Env: ``PSAT_PIPELINE_PROFILE_THRESHOLD_MS`` (default 100).
    """
    try:
        return max(0, int(os.getenv("PSAT_PIPELINE_PROFILE_THRESHOLD_MS", "100")))
    except ValueError:
        return 100


@contextmanager
def _phase(name: str, durations_ms: dict[str, int]) -> Iterator[None]:
    """Time the wrapped block and record its duration into ``durations_ms``.

    Exceptions are still timed (the duration reflects the partial work)
    and propagate so the caller's error path stays unchanged.
    """
    start = time.monotonic()
    try:
        yield
    finally:
        durations_ms[name] = int((time.monotonic() - start) * 1000)


_VYPER_PRAGMA_RE = re.compile(r"^\s*#\s*(?:@version|pragma\s+version)\s+([^\s]+)", re.MULTILINE)


def _detect_vyper_version(project_dir: Path, meta: dict) -> str | None:
    """Best-effort Vyper version detection.

    Reads ``contract_meta.json`` first (``compiler_version`` like
    ``"vyper:0.3.10"``), falls back to scanning ``*.vy`` files for a
    ``# @version X`` or ``# pragma version X`` line. Returns the bare
    version string (``"0.3.10"``) or ``None`` if not a Vyper project.
    """
    raw = str(meta.get("compiler_version", ""))
    if "vyper" in raw.lower():
        version = raw.split(":", 1)[-1].strip().lstrip("v")
        if version:
            return version
    for path in project_dir.rglob("*.vy"):
        try:
            match = _VYPER_PRAGMA_RE.search(path.read_text())
        except OSError:
            continue
        if match:
            return match.group(1).strip().lstrip("v").lstrip("^~>=<")
    return None


def _guard_vyper_version(project_dir: Path, meta: dict) -> None:
    """Hard-fail unsupported Vyper versions before invoking Slither.

    Vyper 0.4.x triggers an upstream crytic-compile bug
    (``platform/vyper.py:101`` splits a dict the new sourceMap format
    returns as an object). Raise a clear error instead of crashing
    deeper inside Slither/crytic-compile.
    """
    version = _detect_vyper_version(project_dir, meta)
    if version and version.startswith("0.4."):
        raise RuntimeError(
            f"Vyper {version} is not supported (upstream crytic-compile sourceMap bug). "
            "Pin the contract to Vyper 0.3.x."
        )


def _source_verified(meta: Mapping[str, Any]) -> bool | None:
    """Whether the SOURCE this pipeline is reading came back verified, in three states.

    The fact is the FETCH's, and both scaffolders carry it in ``contract_meta.json``:
    ``services.discovery.fetch.scaffold`` from the Etherscan payload it is scaffolding,
    ``static_worker._scaffold_project`` from ``contracts.source_verified``. ``None``
    when the key is absent — an older workspace, a hand-built project dir, or a meta
    file that could not be read — and it means "not recorded here", never "not
    verified": the nullable ``contract_summaries.source_verified`` column and the
    ``/api/company`` payload both have that third state, and the frontend's data
    tooltip now says which of the two it is.

    THIS IS NOT DERIVED FROM THE PROJECT TREE. It used to be
    ``bool(project_dir.rglob("src/**/*.sol"))`` — whether the scaffolder happened to
    write a Foundry ``src/`` layout, which is decided by the paths Etherscan's own
    verification bundle uses (``contracts/``, ``@openzeppelin/``, ``lib/`` are all
    normal). On the 2026-07-28 run that published FALSE for 9 of 90 contracts —
    UpgradeableBeacon, EndpointV2, OneSig, two TimelockControllers, FiatTokenV2_2,
    EtherfiL1SyncPoolETH, WithdrawalQueueERC721 and Lido — every one of them
    Etherscan-verified, analysed from that verified source in the same job, and
    ``contracts.source_verified = TRUE`` on all nine. The frontend renders the field
    as a data-confidence penalty and names the contract as an example of unverified
    source, so a layout accident scored and published as a fact about the contract.
    """
    value = meta.get("source_verified")
    return value if isinstance(value, bool) else None


def _slither_target(project_dir: Path, meta: dict) -> str:
    """For Vyper projects, hand Slither the main ``.vy`` file path
    instead of the project directory. The scaffolder writes a
    ``foundry.toml`` even for Vyper projects, which would otherwise
    route the project through crytic-compile's Foundry platform and
    crash on missing ``out/build-info``. Solidity projects fall through
    to the directory path."""
    if _detect_vyper_version(project_dir, meta) is None:
        return str(project_dir)
    contract_name = str(meta.get("contract_name", "")).strip()
    candidates = sorted(project_dir.rglob("*.vy"))
    if not candidates:
        return str(project_dir)
    if contract_name:
        for path in candidates:
            if path.stem == contract_name:
                return str(path)
    return str(candidates[0])


def analyze_contract(project_dir: Path) -> Path:
    """Generate static_facts.json + predicate_trees.json + effects.json
    for a scaffolded project. ``predicate_trees`` + ``effects`` are the
    semantic source of truth."""
    analysis, predicate_trees, effects = collect_static_inputs(project_dir)
    output_path = project_dir / "static_facts.json"
    output_path.write_text(json.dumps(analysis, indent=2) + "\n")

    if predicate_trees is not None:
        (project_dir / "predicate_trees.json").write_text(json.dumps(predicate_trees, indent=2) + "\n")
    if effects is not None:
        (project_dir / "effects.json").write_text(json.dumps(effects, indent=2) + "\n")

    return output_path


def collect_static_facts(project_dir: Path) -> StaticFacts:
    """Backwards-compatible accessor for the analysis dict only.

    Most callers (tests, resolution.recursive) only need the analysis
    dict. The static worker uses
    :func:`collect_static_inputs` to also receive
    the semantic ``predicate_trees`` and ``effects`` artifacts so it can
    persist them off a single Slither parse.
    """
    analysis, _trees, _effects = collect_static_inputs(project_dir)
    return analysis


def collect_static_inputs(
    project_dir: Path,
) -> tuple[StaticFacts, dict[str, Any] | None, Mapping[str, Any] | None]:
    """Collect the analysis dict plus semantic predicate/effect artifacts in
    a single pass. Returns ``(analysis, predicate_trees, effects)``.

    Emits a single ``pipeline_profile`` log line at the end with per-phase
    durations so the next live run can pinpoint which step dominates on
    pathological contracts (the PR-79 motivation: 60-150 s static_facts
    phases on LayerZero / EtherFi while PR-71 baselines stayed at 1-10 s).
    Per-phase durations exceeding ``_phase_log_threshold_ms()`` also emit
    their own ``pipeline_phase`` line so a Loki query can rank phases
    without parsing the aggregate JSON.

    Vyper projects flow through the same Slither path as Solidity.
    """
    durations_ms: dict[str, int] = {}
    pipeline_started = time.monotonic()

    meta = _load_json(project_dir / "contract_meta.json", {})
    _guard_vyper_version(project_dir, meta)

    with _phase("slither_parse", durations_ms):
        slither = Slither(_slither_target(project_dir, meta))

    subject_contract = _select_subject_contract(slither, meta.get("contract_name"))
    if subject_contract is None:
        raise RuntimeError(f"No analyzable contracts found in {project_dir}")

    subject_name = getattr(subject_contract, "name", None)
    external_fn_count = sum(
        1
        for fn in (getattr(subject_contract, "functions", []) or [])
        if getattr(fn, "visibility", "") in ("public", "external")
    )

    # Predicate trees + effects are the only source of truth for the static
    # stage's controller-tracking / semantic-control / pausability outputs.
    predicate_trees_artifact: dict[str, Any]
    pause_info: PauseInfo
    try:
        with _phase("predicate_trees", durations_ms):
            predicate_trees_artifact, pause_info = build_predicate_artifacts_with_pause_info(subject_contract)
    except Exception as exc:
        logger.warning(
            "semantic predicate_trees emit failed for %s",
            project_dir,
            extra={"exc_type": type(exc).__name__, "phase": "predicate_trees_emit"},
        )
        record_degraded(phase="predicate_trees_emit", exc=exc, context={"project_dir": str(project_dir)})
        predicate_trees_artifact = {"schema_version": "semantic", "error": str(exc)}
        pause_info = {
            "pause_state_vars": [],
            "pause_toggle_functions": [],
            "reentrancy_state_vars": [],
            "reentrancy_guarded_functions": [],
        }

    effects_artifact: EffectsArtifact | dict[str, Any]
    try:
        with _phase("effects", durations_ms):
            effects_artifact = build_effects(subject_contract)
    except Exception as exc:
        logger.warning(
            "semantic effects emit failed for %s",
            project_dir,
            extra={"exc_type": type(exc).__name__, "phase": "effects_emit"},
        )
        record_degraded(phase="effects_emit", exc=exc, context={"project_dir": str(project_dir)})
        effects_artifact = {"schema_version": "semantic", "error": str(exc)}

    # Mint typed claims from the static facts and attach them to the effects input.
    with _phase("claims", durations_ms):
        try:
            claims_artifact = build_claims(subject_contract, effects_artifact, predicate_trees_artifact)
            attach_claims_to_effects(effects_artifact, claims_artifact)
        except Exception as exc:
            logger.warning(
                "claims emit failed for %s",
                project_dir,
                extra={"exc_type": type(exc).__name__, "phase": "claims"},
            )
            record_degraded(phase="claims", exc=exc, context={"project_dir": str(project_dir)})

    with _phase("classification", durations_ms):
        classification = _detect_contract_classification(subject_contract, project_dir, effects_artifact)
    with _phase("semantic_control", durations_ms):
        semantic_control = _build_semantic_control_summary(
            subject_contract,
            project_dir,
            predicate_trees_artifact,
            effects_artifact,
        )
    with _phase("controller_tracking", durations_ms):
        controller_tracking = build_controller_tracking(
            subject_contract,
            project_dir,
            predicate_trees_artifact,
            effects_artifact,
            semantic_control,
        )
    with _phase("upgradeability", durations_ms):
        upgradeability = _detect_upgradeability(subject_contract, project_dir, effects_artifact)
    with _phase("pausability", durations_ms):
        # Post-``claims``: the Plane-1 ``pause.set`` / ``pause.unset`` claims
        # ride on the effects artifact and are the only detector that resolves a
        # struct-member or ERC-7201-namespaced latch. ``predicate_trees_artifact``
        # goes in as well because it is that matcher's input AND the source of
        # ``pause_info``: the block above can substitute a stub for it without
        # the claims block raising, and only the artifact itself records that.
        pausability = _detect_pausability(
            subject_contract, project_dir, pause_info, effects_artifact, predicate_trees_artifact
        )
    with _phase("timelock", durations_ms):
        timelock = _detect_timelock(
            subject_contract, project_dir, semantic_control["role_definitions"], effects_artifact
        )
    with _phase("secondary_impl_pointers", durations_ms):
        try:
            secondary_impl_pointers = detect_secondary_impl_pointers(subject_contract)
        except Exception as exc:
            logger.warning(
                "secondary-impl pointer detection failed for %s",
                project_dir,
                extra={"exc_type": type(exc).__name__, "phase": "secondary_impl_slot"},
            )
            record_degraded(phase="secondary_impl_slot", exc=exc, context={"project_dir": str(project_dir)})
            secondary_impl_pointers = []
    record_stage_metric("secondary_impl_pointers", len(secondary_impl_pointers))
    audit_alignment: AuditAlignment = {
        "status": "not_checked",
        "bytecode_match": "not_checked",
        "notes": [],
    }

    summary: Summary = {
        "control_model": _determine_control_model(subject_contract, semantic_control, timelock),
        "is_upgradeable": upgradeability["is_upgradeable"],
        "is_pausable": pausability["is_pausable"],
        "has_timelock": timelock["has_timelock"],
        "standards": classification["standards"],
        "is_factory": classification["is_factory"],
        "is_nft": classification["is_nft"],
    }

    analysis: StaticFacts = {
        "schema_version": "0.1",
        "subject": {
            "address": meta.get("address", ""),
            "name": subject_contract.name,
            "compiler_version": meta.get("compiler_version", ""),
            "source_verified": _source_verified(meta),
        },
        "static_status": {
            "static_analysis_completed": True,
            "errors": [],
        },
        "summary": summary,
        "contract_classification": classification,
        "semantic_control": semantic_control,
        "upgradeability": upgradeability,
        "pausability": pausability,
        "timelock": timelock,
        "audit_alignment": audit_alignment,
        "tracking_hints": _build_tracking_hints(semantic_control, upgradeability, pausability, timelock),
        "controller_tracking": controller_tracking,
        "secondary_impl_pointers": secondary_impl_pointers,
    }

    total_ms = int((time.monotonic() - pipeline_started) * 1000)
    _emit_pipeline_profile(
        contract_name=subject_name,
        external_fn_count=external_fn_count,
        durations_ms=durations_ms,
        total_ms=total_ms,
    )

    return analysis, predicate_trees_artifact, effects_artifact


def _emit_pipeline_profile(
    *,
    contract_name: str | None,
    external_fn_count: int,
    durations_ms: dict[str, int],
    total_ms: int,
) -> None:
    """Emit per-phase + aggregate log lines for the contract-analysis pipeline.

    Two log shapes so Loki queries can either drill into specific phases
    or rank contracts by total cost without parsing nested JSON:

      * ``pipeline_phase`` (one per phase that crosses the threshold):
        ``phase``, ``duration_ms``, ``contract_name``, ``external_fn_count``.
      * ``pipeline_profile`` (always, once per contract): aggregate
        ``durations_ms`` map and ``total_ms``.
    """
    threshold = _phase_log_threshold_ms()
    # Fold every phase duration into the stage_timing artifact so the monitor UI
    # can attribute analysis-phase cost — independent of the log-volume threshold
    # below, which only governs the human-readable per-phase INFO lines.
    for phase, ms in durations_ms.items():
        record_stage_metric(f"phase_ms_{phase}", ms)
    record_stage_metric("static_facts_total_ms", total_ms)
    for phase, ms in durations_ms.items():
        if ms < threshold:
            continue
        logger.info(
            "pipeline phase %s took %dms (%s)",
            phase,
            ms,
            contract_name or "<unknown>",
            extra={
                "phase": phase,
                "duration_ms": ms,
                "contract_name": contract_name,
                "external_fn_count": external_fn_count,
                "profile_kind": "pipeline_phase",
            },
        )

    logger.info(
        "pipeline profile: %s total=%dms fns=%d",
        contract_name or "<unknown>",
        total_ms,
        external_fn_count,
        extra={
            "total_ms": total_ms,
            "durations_ms": dict(durations_ms),
            "contract_name": contract_name,
            "external_fn_count": external_fn_count,
            "profile_kind": "pipeline_profile",
        },
    )
