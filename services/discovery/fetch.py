"""Fetch verified source from Etherscan and scaffold a Foundry project."""

from __future__ import annotations

import hashlib
import json
import re
import textwrap
from pathlib import Path, PurePosixPath

from services.clients.etherscan import get_source

# EVMVersion comes from untrusted Etherscan metadata and goes into foundry.toml, so allowlist it to prevent TOML
# injection.
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
    return _EVM_VERSION_BY_KEY.get(str(raw or "").strip().lower(), _DEFAULT_EVM_VERSION)


def _normalize_source_path(filename: str) -> str:
    """Confine a verified-source key to a project-relative path.

    Bundles often carry absolute keys from the verifier's machine, so a leading root is stripped; ``..`` is rejected,
    and ``_confine`` re-checks at write time.
    """
    pure = PurePosixPath(filename)
    # Drop the root anchor and ``.`` segments.
    parts = [p for p in pure.parts if p != "." and not p.startswith("/")]
    if any(p == ".." for p in parts):
        raise ValueError(f"Refusing source path with parent traversal: {filename!r}")
    normalized = "/".join(parts)
    if not normalized:
        raise ValueError(f"Empty source path: {filename!r}")
    return normalized


def _confine(project_dir: Path, name: str) -> Path:
    """Resolve ``name`` under ``project_dir`` and require it stay inside, even via symlinks."""
    root = project_dir.resolve()
    full = (project_dir / name).resolve()
    if not full.is_relative_to(root):
        raise ValueError(f"Refusing path outside project dir: {name!r}")
    return full


def _remapping_target_is_safe(entry: str) -> bool:
    """Whether a remapping target stays inside the project (they're solc/Slither read roots).

    Entries containing ``\r``/``\n`` are rejected, since they'd split into an unchecked second line.
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
    return get_source(address, chain_id=chain_id)


def source_content_hash(result: dict) -> str:
    """Deterministic hash of the verified-source code-plane inputs.

    The static pipeline is a pure function of the scaffolded project (Slither over the source; no chain state), so equal
    hashes give identical analysis bundles across chains and addresses.

    Covers the source file set (``parse_sources``), the selected ``ContractName`` (one bundle can verify several
    contracts), and the compiler settings that change the IR: language, EVM version, optimizer on/off and runs, and
    remappings. Excludes address, constructor args, immutable values and chain id. The solc version comes from the
    hashed pragmas.

    Returns a ``0x``-prefixed sha256 (66 chars).
    """
    sources = parse_sources(result)
    payload = {
        "sources": sorted(sources.items()),
        "contract_name": str(result.get("ContractName", "") or ""),
        "remappings": sorted(parse_remappings(result)),
        "language": "vyper" if is_vyper_result(result) else "solidity",
        "evm_version": str(result.get("EVMVersion", "") or "").strip().lower(),
        "optimizer": str(result.get("OptimizationUsed", "") or ""),
        "runs": str(result.get("Runs", "") or ""),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "0x" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _parse_source_code(raw: str) -> dict | None:
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
            # ``<``/``<=`` is a ceiling, not a target (``<0.9.0`` would pin a nonexistent solc).
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
    """Rewrite exact pragmas to ``^X.Y.Z``: Foundry checks them against solc_version even with auto-detect off,
    blocking newer patch compilers.
    """
    relaxed = {}
    for path, content in sources.items():
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
    """Write source files into the caller-owned Foundry project dir and return the path."""
    sources = parse_sources(result)
    remappings = parse_remappings(result)
    bundle = parse_verification_bundle(result)
    language = "vyper" if is_vyper_result(result) else "solidity"
    solc_version = _detect_solc_version(sources)
    src_dir = _project_src_dir(sources)
    evm_version = sanitize_evm_version(result.get("EVMVersion", ""))

    project_dir.mkdir(parents=True, exist_ok=True)

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

    # Relax exact pragmas so one solc_version satisfies all files.
    sources = _relax_pragmas(sources)
    for filename, content in sources.items():
        filepath = _confine(project_dir, filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)

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
        # Read from the payload so the static pipeline states it rather than guessing from layout
        # (``core._source_verified``). Always True via ``fetch()``, but ``scaffold`` accepts any result.
        "source_verified": bool(result.get("SourceCode")),
    }
    (project_dir / "contract_meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    return project_dir
