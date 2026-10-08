"""Top-level orchestration for contract analysis."""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from slither.slither import Slither

from schemas.contract_analysis import AuditAlignment, ContractAnalysis, Summary
from utils.logging import record_degraded, record_stage_metric

from ..claims import attach_claims_to_effects, build_claims, project_effect_labels
from .effect_scope_codec import encode_effect_scopes
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
    """Phases faster than this only appear in the aggregate line.

    Env ``PSAT_PIPELINE_PROFILE_THRESHOLD_MS`` (default 100).
    """
    try:
        return max(0, int(os.getenv("PSAT_PIPELINE_PROFILE_THRESHOLD_MS", "100")))
    except ValueError:
        return 100


@contextmanager
def _phase(name: str, durations_ms: dict[str, int]) -> Iterator[None]:
    """Time the block into ``durations_ms``, including on exception (which still propagates)."""
    start = time.monotonic()
    try:
        yield
    finally:
        durations_ms[name] = int((time.monotonic() - start) * 1000)


_VYPER_PRAGMA_RE = re.compile(r"^\s*#\s*(?:@version|pragma\s+version)\s+([^\s]+)", re.MULTILINE)


def _detect_vyper_version(project_dir: Path, meta: dict) -> str | None:
    """Vyper version from ``contract_meta.json`` (``"vyper:0.3.10"``) or a ``# @version``/``# pragma version`` line,
    else ``None``.
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
    """Fail clearly on Vyper 0.4.x, which crashes crytic-compile's source-map parsing."""
    version = _detect_vyper_version(project_dir, meta)
    if version and version.startswith("0.4."):
        raise RuntimeError(
            f"Vyper {version} is not supported (upstream crytic-compile sourceMap bug). "
            "Pin the contract to Vyper 0.3.x."
        )


def _source_verified(meta: Mapping[str, Any]) -> bool | None:
    """Whether the fetched source was verified, from ``contract_meta.json`` (both scaffolders write it); ``None``
    means not recorded, never unverified.

    Not derived from the project tree: checking for a Foundry ``src/`` layout depends on Etherscan's bundle paths and
    once published nine verified contracts as unverified.
    """
    value = meta.get("source_verified")
    return value if isinstance(value, bool) else None


def _slither_target(project_dir: Path, meta: dict) -> str:
    """Give Slither the main ``.vy`` file for Vyper projects; the scaffolded ``foundry.toml`` would otherwise route
    them through the Foundry platform and crash.
    """
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


def collect_contract_analysis(project_dir: Path) -> ContractAnalysis:
    """The analysis dict only; the static worker uses :func:`collect_contract_analysis_with_artifacts` to also get
    the predicate and effects artifacts from one parse.
    """
    analysis, _trees, _effects = collect_contract_analysis_with_artifacts(project_dir)
    return analysis


def collect_contract_analysis_with_artifacts(
    project_dir: Path,
) -> tuple[ContractAnalysis, dict[str, Any] | None, Mapping[str, Any] | None]:
    """``(analysis, predicate_trees, effects)`` from one Slither parse, logging a ``pipeline_profile`` line with
    per-phase durations (and ``pipeline_phase`` lines above the threshold) so slow phases on pathological
    contracts can be ranked in Loki. Vyper uses the same path.
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

    # A whole-artifact build failure; the analysis then reports itself incomplete so it is never reused as complete.
    semantic_errors: list[str] = []
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
        semantic_errors.append(f"predicate_trees_emit: {type(exc).__name__}: {exc}")
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
        semantic_errors.append(f"effects_emit: {type(exc).__name__}: {exc}")
        effects_artifact = {"schema_version": "semantic", "error": str(exc)}

    # Mint claims from the facts and project them onto legacy ``effect_labels``; must run before semantic_control, which
    # reads them.
    with _phase("claims", durations_ms):
        try:
            claims_artifact = build_claims(subject_contract, effects_artifact, predicate_trees_artifact)
            attach_claims_to_effects(effects_artifact, claims_artifact)
            project_effect_labels(effects_artifact)
            # A matcher that raised published nothing; its claims are not determined, not absent.
            semantic_errors.extend(
                f"claim_matcher: {claim_id}" for claim_id in claims_artifact.get("failed_matchers") or []
            )
        except Exception as exc:
            logger.warning(
                "claims emit failed for %s",
                project_dir,
                extra={"exc_type": type(exc).__name__, "phase": "claims"},
            )
            record_degraded(phase="claims", exc=exc, context={"project_dir": str(project_dir)})
            semantic_errors.append(f"claims: {type(exc).__name__}: {exc}")

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
        # After claims: the pause claims are the only detector for struct-member and namespaced latches. The trees
        # artifact is passed too, since only it records whether the tree block substituted a stub.
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

    analysis: ContractAnalysis = {
        "schema_version": "0.1",
        "subject": {
            "address": meta.get("address", ""),
            "name": subject_contract.name,
            "compiler_version": meta.get("compiler_version", ""),
            "source_verified": _source_verified(meta),
        },
        "analysis_status": {
            "static_analysis_completed": not semantic_errors,
            "errors": semantic_errors,
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

    # Every in-process consumer of the site predicates has run; from here on the artifacts are in their stored form.
    encode_effect_scopes(predicate_trees_artifact, effects_artifact)

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
    """Log ``pipeline_phase`` per phase over the threshold and one ``pipeline_profile`` per contract (all durations
    and the total).
    """
    threshold = _phase_log_threshold_ms()
    # Every phase goes into the stage_timing artifact regardless of the log threshold.
    for phase, ms in durations_ms.items():
        record_stage_metric(f"phase_ms_{phase}", ms)
    record_stage_metric("contract_analysis_total_ms", total_ms)
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
