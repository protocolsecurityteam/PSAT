"""Compile verified inputs with an exact compiler, without a host build system's defaults."""

from __future__ import annotations

import copy
import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from crytic_compile.compilation_unit import CompilationUnit
from crytic_compile.compiler.compiler import CompilerVersion
from crytic_compile.crytic_compile import CryticCompile
from crytic_compile.platform.exceptions import InvalidCompilation
from crytic_compile.platform.solc_standard_json import SolcStandardJson, parse_standard_json_output
from crytic_compile.platform.vyper import VyperStandardJson
from crytic_compile.utils.zip import load_from_zip, save_to_zip

from services.discovery.fetch import verified_solc_version


def solc_binary(version: str) -> Path:
    """Use per-version compiler artifacts; never change solc-select's global version."""
    from solc_select.solc_select import artifact_path, install_artifacts

    candidates = [artifact_path(version), Path.home() / ".svm" / version / f"solc-{version}"]
    for binary in candidates:
        if binary.is_file():
            return binary
    lock = Path(tempfile.gettempdir()) / f"psat-solc-install-{version}.lock"
    with lock.open("a") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        if not candidates[0].is_file() and not install_artifacts([version], silent=True):
            raise InvalidCompilation(f"Verified compiler solc {version} is unavailable")
    return candidates[0]


class VerifiedSolidity(SolcStandardJson):
    def __init__(self, payload: dict, version: str, project_dir: Path):
        self.version = version
        self.project_dir = project_dir
        payload = copy.deepcopy(payload)
        payload.setdefault("settings", {})["outputSelection"] = {
            "*": {"": ["ast"], "*": ["abi", "metadata", "devdoc", "userdoc", "evm.bytecode", "evm.deployedBytecode"]}
        }
        super().__init__(payload)

    def compile(self, crytic_compile: CryticCompile, **kwargs: Any) -> None:
        binary = solc_binary(self.version)
        timeout = float(os.getenv("PSAT_COMPILATION_TIMEOUT_S", "300"))
        try:
            result = subprocess.run(
                [str(binary), "--standard-json", "--allow-paths", str(self.project_dir.resolve())],
                input=json.dumps(self.to_dict()),
                capture_output=True,
                text=True,
                cwd=self.project_dir,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise InvalidCompilation(f"solc {self.version} exceeded the {timeout:g}s compilation deadline") from exc
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise InvalidCompilation(f"solc {self.version} returned invalid output: {result.stderr[:2000]}") from exc
        errors = [
            e.get("formattedMessage", e.get("message", ""))
            for e in output.get("errors", [])
            if e.get("severity") == "error"
        ]
        if result.returncode or errors:
            raise InvalidCompilation("\n".join(errors) or result.stderr)
        unit = CompilationUnit(crytic_compile, "verified_input")
        optimizer = self.to_dict().get("settings", {}).get("optimizer", {})
        unit.compiler_version = CompilerVersion(
            "solc", self.version, optimizer.get("enabled", False), optimizer.get("runs")
        )
        parse_standard_json_output(output, unit, solc_working_dir=str(self.project_dir))


def compile_verified(project_dir: Path, meta: dict) -> CryticCompile:
    payload = json.loads((project_dir / "analysis_standard_input.json").read_text())
    if payload.get("language") != "Vyper":
        sources = {name: obj["content"] for name, obj in payload["sources"].items()}
        version = verified_solc_version(meta.get("compiler_version"), sources)
        return CryticCompile(VerifiedSolidity(payload, version, project_dir))

    raw = str(meta.get("compiler_version", ""))
    match = re.fullmatch(r"vyper:v?(0\.\d+\.\d+)(?:\+[^\s]+)?", raw)
    if match is None:
        raise InvalidCompilation(f"Exact verified Vyper compiler version is required: {raw!r}")
    uv = shutil.which("uv")
    if uv is None:
        raise InvalidCompilation("uv is required to provision isolated Vyper compiler versions")
    # uv's tool cache provides separate environments for conflicting legacy Vyper dependencies.
    wrapper = project_dir / ".psat-vyper"
    command = [
        uv,
        "tool",
        "run",
        "--python",
        sys.executable,
        # Older verified Vyper releases import pkg_resources without declaring it.
        "--with",
        "setuptools<81",
        "--from",
        f"vyper=={match.group(1)}",
        "vyper",
    ]
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
    wrapper.chmod(0o700)
    # Crytic's Vyper filename resolver uses process cwd. Isolate it rather than
    # changing the shared worker's cwd while other jobs/threads are running.
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(Path(__file__).resolve().parents[2]), env.get("PYTHONPATH")]))
    archive = project_dir / "vyper-compilation.zip"
    try:
        result = _run_vyper_child(
            [sys.executable, "-m", __name__, str(wrapper), str(archive)],
            cwd=project_dir,
            env=env,
            timeout=float(os.getenv("PSAT_COMPILATION_TIMEOUT_S", "300")),
        )
    except subprocess.TimeoutExpired as exc:
        raise InvalidCompilation("Vyper compilation exceeded its deadline") from exc
    if result.returncode:
        raise InvalidCompilation(result.stderr[-10000:])
    compiled = load_from_zip(str(archive))[0]
    for unit in compiled.compilation_units.values():
        for source in unit.source_units.values():
            _normalize_vyper_ast(source.ast)
    return compiled


def _run_vyper_child(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: float
) -> subprocess.CompletedProcess:
    # The Crytic child launches uv and then Vyper. Terminating only the immediate
    # Python child leaves its compiler running after a job has timed out.
    with subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The process group exited between the deadline and cleanup.
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _normalize_vyper_ast(node: Any) -> None:
    """Normalize legacy AST shapes, preserving immutable/public/constant semantics.

    Older Vyper emits module variables as AnnAssign; Slither only declares VariableDecl.
    Function-local AnnAssign nodes must remain locals. Source and bytecode are untouched.
    """
    if isinstance(node, list):
        for child in node:
            _normalize_vyper_ast(child)
    elif isinstance(node, dict):
        if node.get("ast_type") == "Call" and node.get("func", {}).get("id") == "extract32":
            for keyword in node.get("keywords", []):
                if keyword.get("arg") == "output_type" and keyword.get("value", {}).get("id") != "bytes32":
                    raise InvalidCompilation("Vyper extract32 with a non-bytes32 output_type is not yet supported")
            # A language builtin, not a protocol recognizer. Keep its value
            # opaque in provenance; only its declared default return type is known.
            from slither.core.declarations.solidity_variables import SOLIDITY_FUNCTIONS

            SOLIDITY_FUNCTIONS.setdefault("extract32()", ["bytes32"])
        if node.get("ast_type") == "Module":
            for child in node.get("body", []):
                if child.get("ast_type") != "AnnAssign" or child.get("target", {}).get("id") == "implements":
                    continue
                annotation = child.get("annotation", {})
                qualifiers = set()
                while annotation.get("ast_type") == "Call" and len(annotation.get("args", [])) == 1:
                    qualifiers.add(annotation.get("func", {}).get("id"))
                    annotation = annotation["args"][0]
                child.update(
                    ast_type="VariableDecl",
                    is_public="public" in qualifiers,
                    is_constant="constant" in qualifiers,
                    is_immutable="immutable" in qualifiers,
                )
        if node.get("ast_type") == "Name" and node.get("id") == "MAX_UINT256":
            node.update(ast_type="Int", value=2**256 - 1)
        for child in list(node.values()):
            _normalize_vyper_ast(child)


def _vyper_child(wrapper: str, archive: str) -> None:
    payload = json.loads(Path("analysis_standard_input.json").read_text())
    # Vyper's CLI reads files with universal-newline translation. Older AST
    # tokenizers fail on CRLF received verbatim through standard JSON. Match
    # that CLI input normalization; retain the original verified source files.
    for source in payload.get("sources", {}).values():
        source["content"] = source["content"].replace("\r\n", "\n").replace("\r", "\n")
    platform = VyperStandardJson()
    outputs = platform.standard_json_input["settings"]["outputSelection"]
    platform.standard_json_input = payload
    platform.standard_json_input.setdefault("settings", {})["outputSelection"] = outputs
    save_to_zip([CryticCompile(platform, vyper=wrapper)], archive, zip_type="stored")


if __name__ == "__main__":
    _vyper_child(sys.argv[1], sys.argv[2])
