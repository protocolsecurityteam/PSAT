"""Fetch verified source from Etherscan and scaffold a Foundry project."""

from __future__ import annotations

import copy
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
    "osaka",
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

    Covers the source file set (``parse_sources``) and the compiler settings that change the IR: language, EVM version,
    optimizer on/off and runs, and remappings. Excludes address, constructor args, immutable values and chain id. The
    verified compiler version and standard-JSON settings are part of the key.

    Returns a ``0x``-prefixed sha256 (66 chars).
    """
    sources = parse_sources(result)
    payload = {
        "sources": sorted(sources.items()),
        "contract_name": str(result.get("ContractName", "Contract")),
        "remappings": sorted(parse_remappings(result)),
        "language": "vyper" if is_vyper_result(result) else "solidity",
        "evm_version": str(result.get("EVMVersion", "") or "").strip().lower(),
        "optimizer": str(result.get("OptimizationUsed", "") or ""),
        "runs": str(result.get("Runs", "") or ""),
        "compiler_version": str(result.get("CompilerVersion", "")),
        "compiler_settings": parse_compiler_settings(result),
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
    if not parsed:
        return None
    if "sources" in parsed:
        return parsed
    # Explorers also return a bare filename -> source map without the standard
    # JSON envelope. Preserve the files rather than compiling the JSON as Solidity.
    if all(
        isinstance(name, str)
        and name.endswith((".sol", ".vy"))
        and isinstance(value.get("content") if isinstance(value, dict) else value, str)
        for name, value in parsed.items()
    ):
        return {"sources": parsed}
    return None


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


def parse_compiler_settings(result: dict) -> dict:
    """Carry verified settings without replacing compiler defaults with host-tool defaults."""
    bundle = parse_verification_bundle(result)
    settings = copy.deepcopy(bundle.get("settings", {})) if bundle else {}
    settings.pop("outputSelection", None)  # Analysis requests its own AST/bytecode outputs.
    if not is_vyper_result(result):
        settings["remappings"] = parse_remappings(result)
    if not is_vyper_result(result) and "optimizer" not in settings:
        settings["optimizer"] = {
            "enabled": str(result.get("OptimizationUsed", "0")) == "1",
            "runs": int(result.get("Runs", "200") or 200),
        }
    evm = str(settings.get("evmVersion", result.get("EVMVersion", "")) or "").strip()
    if evm.lower() in ("", "default"):
        settings.pop("evmVersion", None)
    elif evm.lower() in _EVM_VERSION_BY_KEY:
        settings["evmVersion"] = _EVM_VERSION_BY_KEY[evm.lower()]
    else:
        raise ValueError(f"Unsupported verified EVM target: {evm!r}")
    return settings


def verified_solc_version(raw: object, sources: dict[str, str]) -> str:
    value = str(raw or "").strip()
    if not value:
        return _detect_solc_version(sources)
    match = re.fullmatch(r"v?(0\.\d+\.\d+)(?:\+commit\.[0-9a-fA-F]+)?", value)
    if match is None:
        raise ValueError(f"Unsupported verified Solidity compiler version: {value!r}")
    return match.group(1)


def write_compiler_input(project_dir: Path, sources: dict[str, str], settings: dict, *, language: str) -> None:
    """Persist confined, inline sources so analysis never re-fetches compiler imports."""
    for filename in sources:
        _confine(project_dir, filename)
    normalized = copy.deepcopy(settings)
    if language.lower() != "vyper":
        normalized["remappings"] = [r for r in normalized.get("remappings", []) if _remapping_target_is_safe(r)]
    payload = {
        "language": "Vyper" if language.lower() == "vyper" else "Solidity",
        "sources": {name: {"content": content} for name, content in sources.items()},
        "settings": normalized,
    }
    (project_dir / "analysis_standard_input.json").write_text(json.dumps(payload))


_MIN_SOLC = "0.8.24"  # Preferred fallback when the source constraints permit it.


def _detect_solc_version(sources: dict[str, str]) -> str:
    from semantic_version import NpmSpec, Version

    preferred = Version(_MIN_SOLC)
    candidates = {preferred}
    constraints = []
    for content in sources.values():
        # Pragma-shaped text inside comments or literals is not a compiler constraint.
        code = re.sub(r"""//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""", " ", content)
        for expression in re.findall(r"\bpragma\s+solidity\s+([^;]+);", code):
            expression = re.sub(r"([<>=~^]+)\s+(?=\d)", r"\1", expression).strip()
            try:
                constraints.append(NpmSpec(expression))
            except ValueError as exc:
                raise ValueError("Cannot infer Solidity version; exact compiler metadata is required") from exc
            for op, version in re.findall(r"([<>]=?|[=~^]?)\s*(\d+\.\d+\.\d+)", expression):
                parsed = Version(version)
                candidates.add(parsed)
                if op == ">":
                    candidates.add(parsed.next_patch())
                elif op == "<" and parsed.patch:
                    candidates.add(Version(major=parsed.major, minor=parsed.minor, patch=parsed.patch - 1))
    eligible = [version for version in candidates if all(spec.match(version) for spec in constraints)]
    if not eligible:
        raise ValueError("No inferred compiler satisfies all Solidity pragmas; exact compiler metadata is required")
    return str(preferred if preferred in eligible else max(eligible))


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
    solc_version = (
        verified_solc_version(result.get("CompilerVersion"), sources) if language == "solidity" else _MIN_SOLC
    )
    src_dir = _project_src_dir(sources)
    compiler_settings = parse_compiler_settings(result)
    evm_version = compiler_settings.get("evmVersion")
    evm_line = f'evm_version = "{evm_version}"' if evm_version else ""

    project_dir.mkdir(parents=True, exist_ok=True)

    (project_dir / "foundry.toml").write_text(
        textwrap.dedent(
            f"""\
            [profile.default]
            src = "{src_dir}"
            out = "out"
            libs = ["lib"]
            solc_version = "{solc_version}"
            {evm_line}
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

    # Verified source and compiler version are an inseparable pair; do not rewrite pragmas.
    for filename, content in sources.items():
        filepath = _confine(project_dir, filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)

    write_compiler_input(project_dir, sources, compiler_settings, language=language)

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
