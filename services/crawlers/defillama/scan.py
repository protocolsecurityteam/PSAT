"""
Callable entry point for DefiLlama adapter scanning.

Importable functions used by ``workers.defillama_worker``.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
import time
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable

from services.crawlers.defillama.core_assets import build_address_to_chain_map, load_core_assets
from services.crawlers.defillama.extract import extract_addresses_from_file, extract_protocol
from utils.logging import record_degraded, record_stage_metric, stream_subprocess

logger = logging.getLogger(__name__)

# Ephemeral cache: cloned once per container lifetime, pulled before each job.
# Lives in /tmp so restarts/deploys wipe it — acceptable since clone is cheap.
DEFAULT_REPO_PATH = Path(tempfile.gettempdir()) / "defillama-adapters"
ProgressCallback = Callable[[str], None]


def _emit_progress(progress: ProgressCallback | None, detail: str) -> None:
    if progress:
        progress(detail)


def clone_or_update_repo(repo_path: Path, progress: ProgressCallback | None = None) -> None:
    """Clone the DefiLlama-Adapters repo, or pull latest if it exists."""
    if (repo_path / ".git").exists():
        logger.info("Updating existing repo at %s", repo_path)
        _emit_progress(progress, "Refreshing DefiLlama adapters repo")
        rc = stream_subprocess(
            ["git", "-C", str(repo_path), "pull", "--ff-only"],
            logger=logger,
            source="git",
        )
        # A failed pull (network blip, non-fast-forward) is non-fatal: the
        # existing checkout is still scannable, just potentially stale. Surface
        # it as degraded so a silently-stale repo missing new protocols is
        # visible, rather than swallowing it via the old capture_output discard.
        if rc != 0:
            logger.warning(
                "DefiLlama repo pull failed; scanning existing (possibly stale) checkout",
                extra={"returncode": rc, "repo_path": str(repo_path)},
            )
            record_degraded(
                phase="defillama_repo_pull",
                exc=RuntimeError(f"git pull --ff-only exited {rc}"),
                context={"repo_path": str(repo_path)},
            )
    else:
        logger.info("Cloning DefiLlama-Adapters (shallow)...")
        _emit_progress(progress, "Cloning DefiLlama adapters repo")
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        clone_cmd = [
            "git",
            "clone",
            "--depth",
            "1",
            "https://github.com/DefiLlama/DefiLlama-Adapters.git",
            str(repo_path),
        ]
        rc = stream_subprocess(clone_cmd, logger=logger, source="git")
        # Clone failure is fatal — there's nothing to scan. Preserve the prior
        # check=True semantic by re-raising the same exception type.
        if rc != 0:
            raise subprocess.CalledProcessError(rc, clone_cmd)


def _discover_protocols(projects_dir: Path) -> list[Path]:
    """Find all protocol directories under projects/."""
    protocols = []
    for entry in sorted(projects_dir.iterdir()):
        if entry.is_dir() and entry.name != "helper":
            protocols.append(entry)
        elif entry.is_file() and entry.suffix in (".js", ".ts"):
            protocols.append(entry)
    return protocols


_SIMILARITY_THRESHOLD = 0.9


def _normalize_name(s: str) -> str:
    """Strip punctuation, dots, dashes, and lowercase for comparison."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _find_matching_protocol(protocol_name: str, protocol_dirs: list[Path]) -> list[Path]:
    """Find the best matching protocol directory via normalized string similarity."""
    name_norm = _normalize_name(protocol_name)
    if not name_norm:
        return []

    best_score = 0.0
    best_match: Path | None = None
    for p in protocol_dirs:
        score = max(
            SequenceMatcher(None, name_norm, _normalize_name(p.name)).ratio(),
            SequenceMatcher(None, name_norm, _normalize_name(p.stem)).ratio(),
        )
        if score > best_score:
            best_score = score
            best_match = p

    if best_match and best_score >= _SIMILARITY_THRESHOLD:
        if best_score < 1.0:
            logger.info("Fuzzy matched '%s' → '%s' (score=%.2f)", protocol_name, best_match.name, best_score)
        return [best_match]

    return []


def scan_protocol(
    protocol_name: str,
    repo_path: Path | None = None,
    no_clone: bool = False,
    progress: ProgressCallback | None = None,
) -> dict:
    """Scan a single protocol's adapters and return discovered addresses with chain context.

    Returns:
        {
            "protocol": "aave",
            "addresses": ["0x...", ...],
            "address_details": [{"address": "0x...", "chain": "ethereum", "source": "..."}],
            "scan_time": 1.2,
        }
    """
    repo_path = repo_path or DEFAULT_REPO_PATH

    if not no_clone:
        clone_or_update_repo(repo_path, progress=progress)

    projects_dir = repo_path / "projects"
    if not projects_dir.exists():
        raise FileNotFoundError(f"Projects directory not found: {projects_dir}")

    _emit_progress(progress, "Loading DefiLlama core assets")
    core_assets = load_core_assets(repo_path)
    addr_to_chain = build_address_to_chain_map(core_assets)

    # Find the matching protocol directory
    protocol_dirs = _discover_protocols(projects_dir)
    matching = _find_matching_protocol(protocol_name, protocol_dirs)
    if not matching:
        # A "not found" is indistinguishable from a matched-but-empty scan at
        # the address-count level, so flag it explicitly: the metric lets the
        # monitor chart the no-match rate, and record_degraded lands the miss
        # in /api/jobs/{id}/errors instead of completing as a silent success.
        logger.warning(
            "Protocol not found in DefiLlama-Adapters",
            extra={"protocol": protocol_name},
        )
        _emit_progress(progress, f"No adapter match found for {protocol_name}")
        record_stage_metric("protocol_matched", False)
        record_degraded(
            phase="defillama_match",
            exc=RuntimeError(f"protocol {protocol_name!r} not found in DefiLlama-Adapters"),
            context={"protocol": protocol_name},
        )
        return {
            "protocol": protocol_name,
            "addresses": [],
            "address_details": [],
            "scan_time": 0,
        }

    record_stage_metric("protocol_matched", True)
    start = time.time()
    proto_path = matching[0]
    _emit_progress(progress, f"Matched adapter {proto_path.stem}")

    if proto_path.is_file():
        _emit_progress(progress, f"Scanning adapter file {proto_path.name}")
        addrs = extract_addresses_from_file(proto_path)
        result = {
            "protocol": proto_path.stem,
            "files_scanned": 1,
            "addresses": [{"address": a, "chain": None, "source": proto_path.name} for a in addrs],
        }
    else:
        _emit_progress(progress, f"Scanning {proto_path.name} adapter files")
        result = extract_protocol(proto_path)

    # Enrich chain info from core assets
    for entry in result["addresses"]:
        if not entry["chain"] and entry["address"] in addr_to_chain:
            entry["chain"] = addr_to_chain[entry["address"]]

    elapsed = time.time() - start
    unique_addrs = sorted({e["address"] for e in result["addresses"]})

    return {
        "protocol": protocol_name,
        "addresses": unique_addrs,
        "address_details": result["addresses"],
        "scan_time": elapsed,
    }


def scan_all_protocols(
    repo_path: Path | None = None,
    no_clone: bool = False,
) -> dict:
    """Scan all protocols in the DefiLlama-Adapters repo.

    Returns the full scan results dict with protocols, chain_summary, etc.
    """
    repo_path = repo_path or DEFAULT_REPO_PATH

    if not no_clone:
        clone_or_update_repo(repo_path)

    projects_dir = repo_path / "projects"
    if not projects_dir.exists():
        raise FileNotFoundError(f"Projects directory not found: {projects_dir}")

    core_assets = load_core_assets(repo_path)
    addr_to_chain = build_address_to_chain_map(core_assets)

    protocol_dirs = _discover_protocols(projects_dir)
    logger.info("Found %d protocols to scan", len(protocol_dirs))

    start = time.time()
    all_protocols = []
    all_unique: set[str] = set()

    for i, proto_path in enumerate(protocol_dirs):
        if proto_path.is_file():
            addrs = extract_addresses_from_file(proto_path)
            result = {
                "protocol": proto_path.stem,
                "files_scanned": 1,
                "addresses": [{"address": a, "chain": None, "source": proto_path.name} for a in addrs],
            }
        else:
            result = extract_protocol(proto_path)

        for entry in result["addresses"]:
            if not entry["chain"] and entry["address"] in addr_to_chain:
                entry["chain"] = addr_to_chain[entry["address"]]
            all_unique.add(entry["address"])

        if result["addresses"]:
            all_protocols.append(result)

        if (i + 1) % 500 == 0:
            logger.info("Progress: %d/%d protocols", i + 1, len(protocol_dirs))

    elapsed = time.time() - start

    chain_counts: dict[str, int] = {}
    for proto in all_protocols:
        for entry in proto["addresses"]:
            chain = entry.get("chain") or "unknown"
            chain_counts[chain] = chain_counts.get(chain, 0) + 1

    return {
        "scan_time": elapsed,
        "protocols_scanned": len(protocol_dirs),
        "protocols_with_addresses": len(all_protocols),
        "unique_addresses": len(all_unique),
        "chain_summary": chain_counts,
        "protocols": all_protocols,
    }
