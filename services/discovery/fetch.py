"""Fetch verified smart contract source code from Etherscan and scaffold a Foundry project."""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

from utils.etherscan import get_source


def fetch(address: str) -> dict:
    """Fetch verified source from Etherscan. Returns the raw result dict."""
    return get_source(address)


def _parse_source_code(raw: str) -> dict | None:
    """Parse Etherscan's SourceCode field into a dict when possible."""
    if not isinstance(raw, str):
        return None

    candidate = raw
    if candidate.startswith("{{") and candidate.endswith("}}"):
        candidate = candidate[1:-1]

    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return None

    return parsed if isinstance(parsed, dict) else None


def parse_verification_bundle(result: dict) -> dict | None:
    """Return the parsed standard-json verification bundle when present."""
    parsed = _parse_source_code(result.get("SourceCode", ""))
    if not parsed or "sources" not in parsed:
        return None
    return parsed


def is_vyper_result(result: dict) -> bool:
    compiler_version = str(result.get("CompilerVersion", "")).lower()
    if "vyper" in compiler_version:
        return True
    raw = str(result.get("SourceCode", "")).lstrip()
    return raw.startswith("# @version")


def parse_sources(result: dict) -> dict[str, str]:
    """Parse Etherscan response into {filepath: source_code} mapping."""
    bundle = parse_verification_bundle(result)
    contract_name = result.get("ContractName", "Contract")

    if bundle:
        sources = {}
        for filename, obj in bundle["sources"].items():
            content = obj["content"] if isinstance(obj, dict) else obj
            normalized = filename.lstrip("./")
            sources[normalized] = content
        return sources

    raw = result["SourceCode"]
    extension = ".vy" if is_vyper_result(result) else ".sol"
    return {f"src/{contract_name}{extension}": raw}


def parse_remappings(result: dict) -> list[str]:
    """Extract remappings from a standard-json verification payload."""
    bundle = parse_verification_bundle(result)
    settings = bundle.get("settings", {}) if bundle else {}
    remappings = settings.get("remappings", [])
    return [entry.strip() for entry in remappings if isinstance(entry, str) and entry.strip()]


_MIN_SOLC = "0.8.24"  # 0.8.21-0.8.23 have Natspec.cpp internal compiler errors on some OZ contracts


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


def _project_src_dir(sources: dict[str, str]) -> str:
    if any(filename.startswith("src/") for filename in sources):
        return "src"
    return "."


def scaffold(address: str, result: dict, project_dir: Path) -> Path:
    """Write source files into the given Foundry project dir and return the path.

    The caller owns ``project_dir`` — typically a tempdir. This function does
    not manage persistence of the scaffolded workspace.
    """
    sources = parse_sources(result)
    remappings = parse_remappings(result)
    bundle = parse_verification_bundle(result)
    language = "vyper" if is_vyper_result(result) else "solidity"
    solc_version = _detect_solc_version(sources)
    src_dir = _project_src_dir(sources)
    raw_evm = result.get("EVMVersion", "") or ""
    evm_version = raw_evm if raw_evm.lower() not in ("", "default") else "shanghai"

    project_dir.mkdir(parents=True, exist_ok=True)

    # foundry.toml
    (project_dir / "foundry.toml").write_text(
        textwrap.dedent(
            f"""\
            [profile.default]
            src = "{src_dir}"
            out = "out"
            libs = ["lib"]
            solc_version = "{solc_version}"
            evm_version = "{evm_version}"
            optimizer = {str(result.get("OptimizationUsed", "1") == "1").lower()}
            optimizer_runs = {int(result.get("Runs", "200") or 200)}
            auto_detect_solc = false
        """
        )
    )

    if remappings:
        (project_dir / "remappings.txt").write_text("\n".join(remappings) + "\n")

    if bundle:
        (project_dir / "etherscan_standard_input.json").write_text(json.dumps(bundle, indent=2) + "\n")

    # source files — relax exact pragmas so a single solc_version satisfies all
    sources = _relax_pragmas(sources)
    for filename, content in sources.items():
        filepath = project_dir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)

    # metadata
    meta = {
        "address": address,
        "chain_id": 1,
        "contract_name": result.get("ContractName", ""),
        "label": None,
        "compiler_version": result.get("CompilerVersion", ""),
        "language": language,
        "optimization_used": result.get("OptimizationUsed", ""),
        "runs": result.get("Runs", ""),
        "evm_version": result.get("EVMVersion", ""),
        "license": result.get("LicenseType", ""),
        "source_format": "standard_json" if bundle else "flat",
        "source_file_count": len(sources),
        "remappings": remappings,
        "is_proxy": False,
        "proxy_address": None,
        "implementation_addresses": [],
        "admin_addresses": [],
        "beacon_addresses": [],
        "deployer_address": None,
        "proxy_type": None,
    }
    (project_dir / "contract_meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    return project_dir
