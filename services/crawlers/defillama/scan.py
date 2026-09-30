"""DefiLlama adapter scanning, used by ``workers.defillama_worker``."""

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

# In /tmp, so deploys wipe it; cloning is cheap.
DEFAULT_REPO_PATH = Path(tempfile.gettempdir()) / "defillama-adapters"
ProgressCallback = Callable[[str], None]


def _emit_progress(progress: ProgressCallback | None, detail: str) -> None:
    if progress:
        progress(detail)


def clone_or_update_repo(repo_path: Path, progress: ProgressCallback | None = None) -> None:
    if (repo_path / ".git").exists():
        logger.info("Updating existing repo at %s", repo_path)
        _emit_progress(progress, "Refreshing DefiLlama adapters repo")
        rc = stream_subprocess(
            ["git", "-C", str(repo_path), "pull", "--ff-only"],
            logger=logger,
            source="git",
        )
        # A stale but scannable checkout; degraded so missing new protocols is visible.
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
        # Nothing to scan.
        if rc != 0:
            raise subprocess.CalledProcessError(rc, clone_cmd)


def _discover_protocols(projects_dir: Path) -> list[Path]:
    protocols = []
    for entry in sorted(projects_dir.iterdir()):
        if entry.is_dir() and entry.name != "helper":
            protocols.append(entry)
        elif entry.is_file() and entry.suffix in (".js", ".ts"):
            protocols.append(entry)
    return protocols


_SIMILARITY_THRESHOLD = 0.9


def _normalize_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _find_matching_protocol(protocol_name: str, protocol_dirs: list[Path]) -> list[Path]:
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
    """``{protocol, addresses, address_details: [{address, chain, source}], scan_time}``."""
    repo_path = repo_path or DEFAULT_REPO_PATH

    if not no_clone:
        clone_or_update_repo(repo_path, progress=progress)

    projects_dir = repo_path / "projects"
    if not projects_dir.exists():
        raise FileNotFoundError(f"Projects directory not found: {projects_dir}")

    _emit_progress(progress, "Loading DefiLlama core assets")
    core_assets = load_core_assets(repo_path)
    addr_to_chain = build_address_to_chain_map(core_assets)

    protocol_dirs = _discover_protocols(projects_dir)
    matching = _find_matching_protocol(protocol_name, protocol_dirs)
    if not matching:
        # A miss looks like an empty scan by count, so flag it as a metric and degradation.
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
