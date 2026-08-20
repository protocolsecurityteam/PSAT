"""Source / foundry-project string helpers.

Minimum solc floor: ``services.discovery.fetch`` owns the value.
"""

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
            # ``<``/``<=`` is a *ceiling* (e.g. ``pragma solidity <0.9.0``), not a
            # target. Treating it as the compiler version pins a solc that may
            # not exist — 0.9.0 has no release artifact, so ``forge build`` dies
            # with "version not found in artifacts for this platform: 0.9.0".
            # Keep ^ ~ >= = and bare versions; drop upper bounds.
            if op in ("<", "<="):
                continue
            versions.append(ver)
    if not versions:
        return _MIN_SOLC
    detected = max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    detected_tuple = tuple(int(x) for x in detected.split("."))
    # Enforce the minimum only for the 0.8.x line that is affected by the bug.
    if detected_tuple[:2] == min_tuple[:2] and detected_tuple < min_tuple:
        return _MIN_SOLC
    return detected


def _relax_pragmas(sources: dict[str, str]) -> dict[str, str]:
    """Rewrite exact pragma constraints to '^X.Y.Z'.

    Foundry nightly validates pragma constraints against solc_version even with
    auto_detect_solc = false. Both bare '0.8.28' and '=0.8.28' are exact
    constraints that prevent using a newer patch-level compiler.
    """
    relaxed = {}
    for path, content in sources.items():
        # Match 'pragma solidity =0.8.28' or bare 'pragma solidity 0.8.28'
        relaxed[path] = re.sub(
            r"(pragma\s+solidity\s+)=?\s*(0\.\d+\.\d+)",
            r"\1^\2",
            content,
        )
    return relaxed


def _detect_src_dir(sources: dict[str, str]) -> str:
    """Pick the foundry `src` directory based on where source files live.

    Priority:
      1. "src" if any file starts with src/
      2. "contracts" if any file starts with contracts/
      3. "." to catch files at root or under lib/
    """
    for path in sources:
        if path.startswith("src/"):
            return "src"
    for path in sources:
        if path.startswith("contracts/"):
            return "contracts"
    return "."


def _prune_remappings(remappings: list[str], source_paths: set[str]) -> list[str]:
    """Keep only remappings whose target directory actually contains files in the source bundle.

    A remapping like ``@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/``
    is only useful if we have files under ``lib/openzeppelin-contracts/contracts/``.
    Remappings pointing to dirs with zero files just confuse solc/Slither.
    """
    kept: list[str] = []
    dropped: list[str] = []
    for entry in remappings:
        # Targets that escape the project tree would let solc/Slither read
        # outside the scaffold — drop before any existence check.
        if not _remapping_target_is_safe(entry):
            dropped.append(entry)
            continue
        # Parse "prefix=target" (Foundry remapping format)
        if "=" not in entry:
            kept.append(entry)
            continue
        _prefix, target = entry.split("=", 1)
        target = target.rstrip("/")
        # Check if any source file lives under this target path
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
