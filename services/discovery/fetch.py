"""Fetch verified source from Etherscan and scaffold a Foundry project."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from services.clients.etherscan import get_source

logger = logging.getLogger(__name__)

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


def _normalize_source_path(filename: str) -> str:
    """Confine a verified-source key to a project-relative path.

    A leading root and a leading run of ``..`` segments are dropped: both anchor the key to the verifier's machine
    (``../../node_modules/...``). Keys with the same leading run keep their relative layout, so relative imports
    between them still resolve. Any other ``..`` must stay inside the path it is collapsed into. ``_confine``
    re-checks at write time.
    """
    pure = PurePosixPath(filename)
    parts = [p for p in pure.parts if p != "." and not p.startswith("/")]
    while parts and parts[0] == "..":
        parts.pop(0)
    collapsed: list[str] = []
    for part in parts:
        if part != "..":
            collapsed.append(part)
        elif collapsed:
            collapsed.pop()
        else:
            raise ValueError(f"Refusing source path that escapes the project: {filename!r}")
    normalized = "/".join(collapsed)
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
    contracts), and the compiler inputs that change the build: language, verified compiler version, EVM version,
    optimizer on/off and runs, viaIR, and remappings. Excludes address, constructor args, immutable values and chain id.

    Returns a ``0x``-prefixed sha256 (66 chars).
    """
    sources = parse_sources(result)
    payload = {
        "sources": sorted(sources.items()),
        "contract_name": str(result.get("ContractName", "") or ""),
        "remappings": sorted(parse_remappings(result)),
        "language": "vyper" if is_vyper_result(result) else "solidity",
        **_verified_compile_inputs(result),
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
        sources: dict[str, str] = {}
        for filename, obj in bundle["sources"].items():
            content = obj["content"] if isinstance(obj, dict) else obj
            normalized = _normalize_source_path(filename)
            if normalized in sources and sources[normalized] != content:
                raise ValueError(f"Source paths collide after normalization: {filename!r} -> {normalized!r}")
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


def _verified_compile_inputs(result: dict) -> dict[str, Any]:
    """The compiler inputs the bundle was verified with: the standard-json ``settings`` the verifier compiled with, else
    Etherscan's flat fields. ``evm_version`` is empty or ``"default"`` when the verifier used the compiler's default.
    """
    bundle = parse_verification_bundle(result)
    settings = bundle.get("settings") if bundle else None
    settings = settings if isinstance(settings, dict) else {}
    optimizer = settings.get("optimizer")
    optimizer = optimizer if isinstance(optimizer, dict) else {}
    enabled = optimizer.get("enabled")
    if not isinstance(enabled, bool):
        enabled = str(result.get("OptimizationUsed", "1")) == "1"
    runs = optimizer.get("runs")
    if not isinstance(runs, int) or isinstance(runs, bool):
        runs = int(result.get("Runs", "200") or 200)
    evm_version = settings.get("evmVersion")
    if not isinstance(evm_version, str):
        evm_version = result.get("EVMVersion", "")
    return {
        "compiler_version": str(result.get("CompilerVersion", "") or "").strip(),
        "evm_version": str(evm_version or "").strip().lower(),
        "optimizer": enabled,
        "runs": runs,
        "via_ir": settings.get("viaIR") is True,
    }


_MIN_SOLC = "0.8.24"  # 0.8.21-0.8.23 have Natspec.cpp internal compiler errors on some OZ contracts

_Version = tuple[int, int, int]
# (version, inclusive); ``None`` is unbounded.
_Bound = tuple[_Version, bool] | None

# The body may span lines but holds only version-expression characters, so prose after a commented
# ``pragma solidity`` never reaches code further down.
_SOLIDITY_PRAGMA_RE = re.compile(r"(pragma\s+solidity\s+)([0-9xX*.^~<>=|\s-]*)(?=;)")
_VERSION_PATTERN = r"\d+\.\d+\.\d+"
_PRAGMA_TOKEN_RE = re.compile(
    rf"(?P<hyphen>(?P<hyphen_lo>{_VERSION_PATTERN})\s+-\s+(?P<hyphen_hi>{_VERSION_PATTERN}))"
    rf"|(?:(?P<op>\^|~|>=|<=|>|<|=)\s*)?(?P<version>{_VERSION_PATTERN})"
    r"|(?P<alt>\|\|)"
)


def _parse_version(raw: str) -> _Version:
    major, minor, patch = (int(x) for x in raw.split("."))
    return major, minor, patch


def _format_version(version: _Version) -> str:
    return ".".join(str(x) for x in version)


def _comparator_bounds(op: str, version: _Version) -> tuple[_Bound, _Bound]:
    """``(lower, upper)`` for one comparator, reading an exact pin as the ``^`` it is relaxed to."""
    major, minor, patch = version
    if op in ("", "=", "^"):
        if major > 0:
            ceiling = (major + 1, 0, 0)
        elif minor > 0:
            ceiling = (0, minor + 1, 0)
        else:
            ceiling = (0, 0, patch + 1)
        return (version, True), (ceiling, False)
    if op == "~":
        return (version, True), ((major, minor + 1, 0), False)
    if op == ">=":
        return (version, True), None
    if op == ">":
        return (version, False), None
    if op == "<=":
        return None, (version, True)
    return None, (version, False)


class _Range:
    """One ``||`` alternative of a pragma: the intersection of its comparators."""

    def __init__(self) -> None:
        self.lower: _Bound = None
        self.upper: _Bound = None

    def constrain(self, lower: _Bound, upper: _Bound) -> None:
        if lower is not None and (
            self.lower is None or lower[0] > self.lower[0] or (lower[0] == self.lower[0] and not lower[1])
        ):
            self.lower = lower
        if upper is not None and (
            self.upper is None or upper[0] < self.upper[0] or (upper[0] == self.upper[0] and not upper[1])
        ):
            self.upper = upper

    def admits(self, version: _Version) -> bool:
        if self.lower is not None:
            bound, inclusive = self.lower
            if version < bound or (version == bound and not inclusive):
                return False
        if self.upper is not None:
            bound, inclusive = self.upper
            if version > bound or (version == bound and not inclusive):
                return False
        return True

    def least(self) -> _Version | None:
        if self.lower is None:
            return None
        (major, minor, patch), inclusive = self.lower
        return (major, minor, patch) if inclusive else (major, minor, patch + 1)

    def greatest_nameable(self) -> _Version | None:
        """The highest version known to exist under the ceiling: ``<0.8.20`` names 0.8.19, ``<0.9.0`` names none."""
        if self.upper is None:
            return None
        (major, minor, patch), inclusive = self.upper
        if inclusive:
            return major, minor, patch
        return (major, minor, patch - 1) if patch > 0 else None


def _pragma_ranges(body: str) -> list[_Range]:
    ranges = [_Range()]
    for match in _PRAGMA_TOKEN_RE.finditer(body):
        if match.group("alt"):
            ranges.append(_Range())
        elif match.group("hyphen"):
            low = _parse_version(match.group("hyphen_lo"))
            high = _parse_version(match.group("hyphen_hi"))
            ranges[-1].constrain((low, True), (high, True))
        else:
            ranges[-1].constrain(*_comparator_bounds(match.group("op") or "", _parse_version(match.group("version"))))
    return [r for r in ranges if r.lower is not None or r.upper is not None]


def _solidity_pragmas(sources: dict[str, str]) -> list[list[_Range]]:
    pragmas = []
    for content in sources.values():
        for match in _SOLIDITY_PRAGMA_RE.finditer(content):
            ranges = _pragma_ranges(match.group(2))
            if ranges:
                pragmas.append(ranges)
    return pragmas


def _admits_all(pragmas: list[list[_Range]], version: _Version) -> bool:
    return all(any(r.admits(version) for r in ranges) for ranges in pragmas)


def _detect_solc_version(sources: dict[str, str]) -> str:
    """One solc that satisfies every ``pragma solidity`` in the bundle as ``_relax_pragmas`` rewrites it.

    Prefers the highest lower bound (of the newest ``||`` alternative), floored to ``_MIN_SOLC`` on its minor line.
    When a ceiling rules that out, the newest admissible version named by some bound is used; if nothing is admissible
    the preference stands and the compile reports the conflict.
    """
    pragmas = _solidity_pragmas(sources)
    floor = _parse_version(_MIN_SOLC)
    lowers = []
    for ranges in pragmas:
        bounded = [v for v in (r.least() for r in ranges) if v is not None]
        if bounded:
            lowers.append(max(bounded))
    preferred = max(lowers) if lowers else floor
    if preferred[:2] == floor[:2] and preferred < floor:
        preferred = floor

    if _admits_all(pragmas, preferred):
        return _format_version(preferred)
    candidates = {v for ranges in pragmas for r in ranges for v in (r.least(), r.greatest_nameable()) if v is not None}
    viable = sorted(v for v in candidates if _admits_all(pragmas, v))
    below = [v for v in viable if v <= preferred]
    if below:
        return _format_version(below[-1])
    if viable:
        return _format_version(viable[0])
    return _format_version(preferred)


_VERIFIED_SOLC_RE = re.compile(r"v?(\d+\.\d+\.\d+)(?:\+commit\.[0-9a-fA-F]+)?")


def select_solc_version(sources: dict[str, str], compiler_version: str | None) -> str:
    """The verified compiler release when it satisfies every ``pragma solidity`` as ``_relax_pragmas`` writes it.

    Pragma detection only stands in when the verified version is absent, not a release (nightlies), or rejected by a
    pragma, and each fallback is logged: a pragma admits releases the bundle was never compiled with (a ``^0.7.0``
    file-level function needs 0.7.1). ``_MIN_SOLC``'s floor doesn't apply: the verified compiler already built this
    bundle, metadata and NatSpec included.
    """
    raw = str(compiler_version or "").strip()
    match = _VERIFIED_SOLC_RE.fullmatch(raw)
    if match is None:
        detected = _detect_solc_version(sources)
        logger.info(
            "solc %s from pragmas: no release in the verified compiler version",
            detected,
            extra={"solc_source": "pragma", "verified_compiler": raw[:64]},
        )
        return detected
    verified = _parse_version(match.group(1))
    pragmas = _solidity_pragmas(sources)
    if not _admits_all(pragmas, verified):
        detected = _detect_solc_version(sources)
        logger.warning(
            "solc %s from pragmas: verified compiler %s does not satisfy every pragma",
            detected,
            _format_version(verified),
            extra={"solc_source": "pragma_conflict", "verified_compiler": raw[:64]},
        )
        return detected
    chosen = _format_version(verified)
    logger.info(
        "solc %s from the verified compiler", chosen, extra={"solc_source": "verified", "verified_compiler": raw[:64]}
    )
    return chosen


# solc's own default target per release, for bundles verified with "Default".
_SOLC_DEFAULT_EVM: tuple[tuple[_Version, str], ...] = (
    ((0, 8, 30), "prague"),
    ((0, 8, 25), "cancun"),
    ((0, 8, 20), "shanghai"),
    ((0, 8, 18), "paris"),
    ((0, 8, 7), "london"),
    ((0, 8, 5), "berlin"),
    ((0, 5, 14), "istanbul"),
    ((0, 5, 5), "petersburg"),
    ((0, 4, 21), "byzantium"),
)


def _resolve_evm_version(raw: object, solc_version: str) -> str:
    """The verified EVM target, or solc's default for ``solc_version`` when the verifier used the default.

    Allowlisted because it comes from untrusted metadata and goes into foundry.toml.
    """
    key = str(raw or "").strip().lower()
    if key in _EVM_VERSION_BY_KEY:
        return _EVM_VERSION_BY_KEY[key]
    if key not in ("", "default"):
        logger.warning("unrecognised verified EVM version %r; using solc %s's default", key[:32], solc_version)
    version = _parse_version(solc_version)
    return next((evm for since, evm in _SOLC_DEFAULT_EVM if version >= since), "homestead")


@dataclass(frozen=True)
class CompileSettings:
    solc_version: str
    evm_version: str
    optimizer: bool
    optimizer_runs: int
    via_ir: bool


def compile_settings(
    sources: dict[str, str],
    *,
    language: str,
    compiler_version: str | None,
    evm_version: str | None,
    optimizer: bool | None,
    optimizer_runs: int | None,
    via_ir: bool | None,
) -> CompileSettings:
    """The Foundry build settings for a verified bundle. Vyper keeps pragma detection; its compiler is chosen apart."""
    if language == "vyper":
        solc_version = _detect_solc_version(sources)
    else:
        solc_version = select_solc_version(sources, compiler_version)
    return CompileSettings(
        solc_version=solc_version,
        evm_version=_resolve_evm_version(evm_version, solc_version),
        optimizer=bool(optimizer),
        optimizer_runs=int(optimizer_runs or 200),
        via_ir=bool(via_ir),
    )


def verified_compile_settings(result: dict, sources: dict[str, str]) -> CompileSettings:
    inputs = _verified_compile_inputs(result)
    return compile_settings(
        sources,
        language="vyper" if is_vyper_result(result) else "solidity",
        compiler_version=inputs["compiler_version"],
        evm_version=inputs["evm_version"],
        optimizer=inputs["optimizer"],
        optimizer_runs=inputs["runs"],
        via_ir=inputs["via_ir"],
    )


_VIA_IR_OFF = "via_ir = false\n"


def render_foundry_toml(src_dir: str, settings: CompileSettings) -> str:
    """The first build is always without viaIR: Slither reads the AST, which viaIR doesn't change, and the legacy
    pipeline compiles faster. ``enable_via_ir`` turns it on for the one retry a viaIR-verified bundle gets.
    """
    return textwrap.dedent(
        f"""\
        [profile.default]
        src = "{src_dir}"
        out = "out"
        libs = ["lib"]
        solc_version = "{settings.solc_version}"
        evm_version = "{settings.evm_version}"
        optimizer = {str(settings.optimizer).lower()}
        optimizer_runs = {settings.optimizer_runs}
        via_ir = false
        auto_detect_solc = false
    """
    )


class CompilerUnavailableError(RuntimeError):
    """A build failed with its solc release not on disk, so the failure may be the release's download."""


def solc_installed(version: str | None) -> bool:
    """Whether Foundry has ``version`` on disk (``FOUNDRY_SOLC``, else the svm store it installs releases into)."""
    if not version:
        return False
    override = os.environ.get("FOUNDRY_SOLC")
    if override:
        return Path(override).is_file()
    xdg = os.environ.get("XDG_DATA_HOME")
    roots = (Path.home() / ".svm", Path(xdg) / "svm" if xdg else Path.home() / ".local" / "share" / "svm")
    return any((root / version / f"solc-{version}").is_file() for root in roots)


def scaffolded_solc_version(project_dir: Path) -> str | None:
    """The solc release a scaffolded Solidity project builds with, from its ``contract_meta.json``."""
    try:
        meta = json.loads((project_dir / "contract_meta.json").read_text())
    except (OSError, ValueError):
        return None
    value = meta.get("solc_version") if isinstance(meta, dict) else None
    return value if isinstance(value, str) and value else None


def enable_via_ir(project_dir: Path) -> bool:
    """Switch a scaffolded project's build to viaIR; ``False`` when it isn't a viaIR-off project from this writer."""
    toml = project_dir / "foundry.toml"
    try:
        text = toml.read_text()
    except OSError:
        return False
    if _VIA_IR_OFF not in text:
        return False
    toml.write_text(text.replace(_VIA_IR_OFF, "via_ir = true\n", 1))
    return True


def _relax_pragmas(sources: dict[str, str]) -> dict[str, str]:
    """Rewrite every exact constraint in each ``pragma solidity`` to ``^X.Y.Z``: Foundry checks pragmas against
    solc_version even with auto-detect off, which would block the newer patch compiler ``_detect_solc_version`` picks.
    """

    def relax_token(match: re.Match[str]) -> str:
        if match.group("version") and (match.group("op") or "=") == "=":
            return "^" + match.group("version")
        return match.group(0)

    def relax_pragma(match: re.Match[str]) -> str:
        return match.group(1) + _PRAGMA_TOKEN_RE.sub(relax_token, match.group(2))

    return {path: _SOLIDITY_PRAGMA_RE.sub(relax_pragma, content) for path, content in sources.items()}


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
    settings = verified_compile_settings(result, sources)
    src_dir = _project_src_dir(sources)

    project_dir.mkdir(parents=True, exist_ok=True)

    (project_dir / "foundry.toml").write_text(render_foundry_toml(src_dir, settings))

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
        "solc_version": settings.solc_version if language == "solidity" else None,
        "via_ir": settings.via_ir,
        "via_ir_used": False,
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
