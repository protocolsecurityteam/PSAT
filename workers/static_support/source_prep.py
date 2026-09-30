"""Source / foundry-project string helpers."""

from __future__ import annotations

import logging
import re

from services.discovery.fetch import _MIN_SOLC, _remapping_target_is_safe

logger = logging.getLogger("workers.static_worker")


def _detect_solc_version(sources: dict[str, str]) -> str:
    min_tuple = tuple(int(x) for x in _MIN_SOLC.split("."))
    versions = []
    for content in sources.values():
        for m in re.finditer(r"pragma\s+solidity\s+(<=|>=|[<>^~=]?)\s*(0\.\d+\.\d+)", content):
            op, ver = m.group(1), m.group(2)
            # ``<``/``<=`` is a ceiling, not a target: pinning 0.9.0 fails ``forge build`` since no such release exists.
            if op in ("<", "<="):
                continue
            versions.append(ver)
    if not versions:
        return _MIN_SOLC
    detected = max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    detected_tuple = tuple(int(x) for x in detected.split("."))
    # Only the affected 0.8.x line is floored.
    if detected_tuple[:2] == min_tuple[:2] and detected_tuple < min_tuple:
        return _MIN_SOLC
    return detected


def _relax_pragmas(sources: dict[str, str]) -> dict[str, str]:
    """Rewrite exact pragmas to '^X.Y.Z': Foundry nightly validates them against solc_version even with auto-detect
    off.
    """
    relaxed = {}
    for path, content in sources.items():
        relaxed[path] = re.sub(
            r"(pragma\s+solidity\s+)=?\s*(0\.\d+\.\d+)",
            r"\1^\2",
            content,
        )
    return relaxed


def _detect_src_dir(sources: dict[str, str]) -> str:
    for path in sources:
        if path.startswith("src/"):
            return "src"
    for path in sources:
        if path.startswith("contracts/"):
            return "contracts"
    return "."


def _prune_remappings(remappings: list[str], source_paths: set[str]) -> list[str]:
    """Drop remappings whose target has no files in the bundle; they confuse solc/Slither."""
    kept: list[str] = []
    dropped: list[str] = []
    for entry in remappings:
        # Targets escaping the project tree would let solc/Slither read outside the scaffold.
        if not _remapping_target_is_safe(entry):
            dropped.append(entry)
            continue
        if "=" not in entry:
            kept.append(entry)
            continue
        _prefix, target = entry.split("=", 1)
        target = target.rstrip("/")
        if any(p == target or p.startswith(target + "/") for p in source_paths):
            kept.append(entry)
        else:
            dropped.append(entry)
    if dropped:
        logger.info(
            "Pruned %d/%d remappings with no matching source files: %s",
            len(dropped),
            len(remappings),
            ", ".join(d.split("=")[0] for d in dropped),
        )
    return kept
