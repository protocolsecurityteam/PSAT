"""Source / foundry-project string helpers."""

from __future__ import annotations

import logging

from services.discovery.fetch import _remapping_target_is_safe

logger = logging.getLogger("workers.static_worker")


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
