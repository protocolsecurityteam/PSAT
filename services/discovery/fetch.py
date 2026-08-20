"""Fetch verified smart contract source code from Etherscan and scaffold a Foundry project."""

from __future__ import annotations

import hashlib
import json
import re
import textwrap
from pathlib import Path, PurePosixPath

from services.clients.etherscan import get_source

# EVMVersion comes from attacker-controlled Etherscan metadata and is
# interpolated into foundry.toml; an off-allowlist value could inject TOML keys.
# Canonical spellings solc/foundry accept, matched case-insensitively.
_ALLOWED_EVM_VERSIONS = (
    "homestead",
    "tangerineWhistle",
    "spuriousDragon",
    "byzantium",
    "constantinople",
    "petersburg",
    "istanbul",
    "berlin",
    "london",
    "paris",
    "shanghai",
    "cancun",
    "prague",
)
_EVM_VERSION_BY_KEY = {v.lower(): v for v in _ALLOWED_EVM_VERSIONS}
_DEFAULT_EVM_VERSION = "shanghai"


def sanitize_evm_version(raw: object) -> str:
    """Return an allowlisted EVM version keyword, or the safe default."""
    return _EVM_VERSION_BY_KEY.get(str(raw or "").strip().lower(), _DEFAULT_EVM_VERSION)


def _normalize_source_path(filename: str) -> str:
    """Confine a verified-source key to a project-relative path.

    Invariant: a scaffolded source key stays inside the project dir. Verified
    standard-json bundles routinely carry absolute keys rooted in the verifying
    developer's machine (common on mainnet), so a leading root anchor is
    stripped — relativized, not refused. Any ``..`` segment is still rejected
    rather than rewritten, before and after the anchor strip alike, and
    ``_confine`` re-checks containment at write time.
    """
    pure = PurePosixPath(filename)
    # ``pure.parts`` puts the root anchor ("/" or "//") first when absolute;
    # dropping it and "." segments leaves only real path components.
    parts = [p for p in pure.parts if p != "." and not p.startswith("/")]
    if any(p == ".." for p in parts):
        raise ValueError(f"Refusing source path with parent traversal: {filename!r}")
    normalized = "/".join(parts)
    if not normalized:
        raise ValueError(f"Empty source path: {filename!r}")
    return normalized


def _confine(project_dir: Path, name: str) -> Path:
    """Resolve ``name`` under ``project_dir`` and require it stay inside.

    Invariant: no scaffolded file resolves outside the project dir, even via a
    symlink — the resolved child must be relative to the resolved root.
    """
    root = project_dir.resolve()
    full = (project_dir / name).resolve()
    if not full.is_relative_to(root):
        raise ValueError(f"Refusing path outside project dir: {name!r}")
    return full


def _remapping_target_is_safe(entry: str) -> bool:
    """Whether a remapping's target stays inside the project tree.

    Invariant: remapping targets are compile-time read roots for solc/Slither;
    an absolute target or a ``..`` escape would let compilation read files
    outside the scaffold.

    A remapping is a single line by construction — ``scaffold`` writes entries
    with ``"\n".join(...)``. An embedded CR/LF would split one hostile entry
    into two ``remappings.txt`` lines, the second an unchecked read root, so any
    entry carrying ``\r``/``\n`` is rejected before the ``=`` split.
    """
    if "\n" in entry or "\r" in entry:
        return False
    if "=" not in entry:
        return True
    _prefix, target = entry.split("=", 1)
    target = target.strip()
    if not target:
        return True
    if target.startswith("~") or PurePosixPath(target).is_absolute():
        return False
    return not any(p == ".." for p in PurePosixPath(target).parts)


def fetch(address: str, *, chain_id: int) -> dict:
    """Fetch verified source from Etherscan. Returns the raw result dict."""
    return get_source(address, chain_id=chain_id)


def source_content_hash(result: dict) -> str:
    """Deterministic content hash of the verified-source *code plane* inputs.

    The static pipeline (``collect_contract_analysis_with_artifacts`` →
    ``build_control_tracking_plan``) is a pure function of the scaffolded
    project: it runs Slither over the source AST and never reads chain state or
    bytecode. So two deployments with the same hash produce a byte-identical
    analysis / tracking_plan / predicate_trees bundle and can share it, even on
    different chains and at different addresses.

    The hash therefore covers exactly the inputs that determine that bundle:

      * the verified source file set (``parse_sources`` — normalized paths +
        contents; the same mapping ``scaffold`` writes to disk), and
      * the compiler settings ``scaffold`` bakes into ``foundry.toml`` that
        change Slither's compiled IR: solidity-vs-vyper, EVM version, optimizer
        on/off, and optimizer runs, plus the import ``remappings``.

    It deliberately EXCLUDES everything deployment-specific — the address,
    constructor arguments, immutable *values*, and chain id — none of which are
    inputs to the source-only pipeline (immutable values live in bytecode and
    are resolved per deployment in the state plane). ``solc`` version is not
    added separately: ``scaffold`` derives it from the source pragmas, which are
    part of the hashed source.

    Returns a ``0x``-prefixed sha256 hex digest (66 chars, matching the column).
    """
    sources = parse_sources(result)
    payload = {
        "sources": sorted(sources.items()),
        "remappings": sorted(parse_remappings(result)),
        "language": "vyper" if is_vyper_result(result) else "solidity",
        "evm_version": str(result.get("EVMVersion", "") or "").strip().lower(),
        "optimizer": str(result.get("OptimizationUsed", "") or ""),
        "runs": str(result.get("Runs", "") or ""),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "0x" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


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
            normalized = _normalize_source_path(filename)
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
    return [
        entry.strip()
        for entry in remappings
        if isinstance(entry, str) and entry.strip() and _remapping_target_is_safe(entry.strip())
    ]


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
    evm_version = sanitize_evm_version(result.get("EVMVersion", ""))

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
        filepath = _confine(project_dir, filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)

    # metadata
    meta = {
        "address": address,
        "contract_name": result.get("ContractName", ""),
        "compiler_version": result.get("CompilerVersion", ""),
        "language": language,
        "optimization_used": result.get("OptimizationUsed", ""),
        "runs": result.get("Runs", ""),
        "evm_version": result.get("EVMVersion", ""),
        "license": result.get("LicenseType", ""),
        "source_format": "standard_json" if bundle else "flat",
        "source_file_count": len(sources),
        "remappings": remappings,
        # The verification fact, carried from the payload being scaffolded so the
        # static pipeline states it instead of guessing at the project layout
        # (``core._source_verified``). ``get_source`` raises on an empty
        # ``SourceCode``, so through ``fetch()`` this is always True — it is read off
        # the payload rather than hardcoded because that is what makes it a fact about
        # THIS result, and because ``scaffold`` accepts any result dict.
        "source_verified": bool(result.get("SourceCode")),
    }
    (project_dir / "contract_meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    return project_dir
