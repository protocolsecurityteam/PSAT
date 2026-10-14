from __future__ import annotations

import json
import subprocess

import pytest

from services.discovery.fetch import _detect_solc_version as detect_fetch_solc
from services.discovery.fetch import _relax_pragmas, scaffold
from workers.static_worker import StaticWorker
from workers.static_worker import _detect_solc_version as detect_static_solc

TELLER_PRAGMA = "pragma solidity <0.9.0 =0.8.21 >=0.8.0 ^0.8.0 ^0.8.20;"


@pytest.mark.parametrize(
    ("sources", "expected"),
    [
        pytest.param(
            {"src/Legacy.sol": "pragma solidity ^0.4.24;\ncontract Legacy {}"},
            "0.4.24",
            id="preserves_legacy_majors",
        ),
        pytest.param(
            {"src/Modern.sol": "pragma solidity ^0.8.21;\ncontract Modern {}"},
            "0.8.24",
            id="bumps_buggy_0_8_versions",
        ),
        # solc 0.9.0 has no release artifact, so foundry fails on it.
        pytest.param(
            {
                "src/Vault.sol": "pragma solidity ^0.8.26;\ncontract Vault {}",
                "src/IThing.sol": "pragma solidity <0.9.0;\ninterface IThing {}",
            },
            "0.8.26",
            id="ignores_standalone_upper_bound_pragma",
        ),
        pytest.param(
            {"src/M.sol": "pragma solidity >=0.8.0 <0.9.0;\ncontract M {}"},
            "0.8.24",
            id="two_sided_range_uses_lower_bound_not_ceiling",
        ),
        pytest.param({"src/T.sol": TELLER_PRAGMA + "\ncontract T {}"}, "0.8.24", id="compound_exact_pin_is_read"),
        pytest.param(
            {"src/C.sol": "pragma solidity >=0.8.0 <0.8.20;\ncontract C {}"},
            "0.8.19",
            id="ceiling_below_floor_is_honored",
        ),
        pytest.param(
            {"src/C.sol": "pragma solidity >= 0.8.0 < 0.8.20;\ncontract C {}"},
            "0.8.19",
            id="spaced_operators",
        ),
        pytest.param(
            {"src/C.sol": "pragma solidity >0.8.25 <=0.8.30;\ncontract C {}"},
            "0.8.26",
            id="exclusive_lower_bound",
        ),
        pytest.param(
            {
                "src/Pinned.sol": "pragma solidity 0.8.19;\ncontract Pinned {}",
                "src/Newer.sol": "pragma solidity ^0.8.25;\ncontract Newer {}",
            },
            "0.8.25",
            id="exact_pin_relaxes_to_newer_patch",
        ),
        pytest.param({"src/C.sol": "pragma solidity 0.8.0 - 0.8.20;\ncontract C {}"}, "0.8.20", id="hyphen_range"),
        pytest.param({"src/C.sol": "pragma solidity ^0.6.0 || ^0.7.0;\ncontract C {}"}, "0.7.0", id="alternatives"),
        pytest.param(
            {"src/C.sol": "pragma solidity ^0.8.0 || ^0.7.0;\ncontract C {}"}, "0.8.24", id="alternatives_newest_first"
        ),
        pytest.param(
            {
                "src/A.sol": "pragma solidity ^0.6.0 || ^0.7.0;\ncontract A {}",
                "src/B.sol": "pragma solidity ^0.6.12;\ncontract B {}",
            },
            "0.6.12",
            id="alternative_narrowed_by_another_file",
        ),
        pytest.param({"src/C.sol": "pragma solidity ~0.7.6;\ncontract C {}"}, "0.7.6", id="tilde"),
        pytest.param(
            {"src/C.sol": "pragma solidity >=0.6.0\n    <0.8.0;\ncontract C {}"}, "0.6.0", id="pragma_spans_lines"
        ),
        pytest.param(
            {"src/C.sol": "// pragma solidity version below\ncontract C {}"},
            "0.8.24",
            id="no_pragma_uses_default",
        ),
    ],
)
def test_detect_solc_version(sources, expected):
    assert detect_fetch_solc(sources) == expected
    assert detect_static_solc(sources) == expected
    # The version must not depend on whether the sources were relaxed first; the static worker relaxes before detecting.
    assert detect_fetch_solc(_relax_pragmas(sources)) == expected


@pytest.mark.parametrize(
    ("pragma", "relaxed"),
    [
        pytest.param(TELLER_PRAGMA, "pragma solidity <0.9.0 ^0.8.21 >=0.8.0 ^0.8.0 ^0.8.20;", id="compound"),
        pytest.param("pragma solidity 0.8.19;", "pragma solidity ^0.8.19;", id="bare_exact"),
        pytest.param("pragma solidity = 0.8.19;", "pragma solidity ^0.8.19;", id="spaced_equals"),
        pytest.param("pragma solidity >=0.8.0 <0.8.20;", "pragma solidity >=0.8.0 <0.8.20;", id="range_untouched"),
        pytest.param("pragma solidity 0.8.0 - 0.8.20;", "pragma solidity 0.8.0 - 0.8.20;", id="hyphen_untouched"),
        pytest.param("pragma solidity 0.6.12 || 0.7.6;", "pragma solidity ^0.6.12 || ^0.7.6;", id="alternatives"),
        pytest.param("pragma solidity\n    0.7.6;", "pragma solidity\n    ^0.7.6;", id="spans_lines"),
    ],
)
def test_relax_pragmas_rewrites_every_exact_constraint(pragma, relaxed):
    assert _relax_pragmas({"a.sol": pragma + "\ncontract A {}"})["a.sol"] == relaxed + "\ncontract A {}"


def test_relax_pragmas_leaves_non_pragma_text_alone():
    content = '// pragma solidity notes\nstring constant V = "1.2.3";\npragma solidity 0.8.25;\n'
    assert _relax_pragmas({"a.sol": content})["a.sol"] == content.replace("0.8.25;", "^0.8.25;")


def _foundry_solc(project) -> str:
    for line in (project / "foundry.toml").read_text().splitlines():
        if line.startswith("solc_version"):
            return line.split('"')[1]
    raise AssertionError("foundry.toml has no solc_version")


_SCAFFOLD_CASES = [
    pytest.param(TELLER_PRAGMA, "0.8.24", "pragma solidity <0.9.0 ^0.8.21 >=0.8.0 ^0.8.0 ^0.8.20;", id="teller"),
    pytest.param("pragma solidity >=0.8.0 <0.8.20;", "0.8.19", "pragma solidity >=0.8.0 <0.8.20;", id="ceiling"),
]


@pytest.mark.parametrize(("pragma", "solc", "written"), _SCAFFOLD_CASES)
def test_discovery_scaffold_compiler_and_pragma_agree(tmp_path, pragma, solc, written):
    bundle = {"language": "Solidity", "sources": {"src/T.sol": {"content": f"{pragma}\ncontract T {{}}\n"}}}
    result = {
        "ContractName": "T",
        "CompilerVersion": "v0.8.21+commit.d9974bed",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "SourceCode": "{" + json.dumps(bundle) + "}",
    }
    project = scaffold("0xabc", result, tmp_path / "proj")
    assert _foundry_solc(project) == solc
    assert (project / "src/T.sol").read_text().splitlines()[0] == written


@pytest.mark.parametrize(("pragma", "solc", "written"), _SCAFFOLD_CASES)
def test_static_scaffold_compiler_and_pragma_agree(tmp_path, pragma, solc, written):
    project = tmp_path / "proj"
    project.mkdir()
    StaticWorker()._scaffold_project(
        project,
        {"src/T.sol": f"{pragma}\ncontract T {{}}\n"},
        {"contract_name": "T"},
        {"evm_version": "shanghai", "optimization_used": True, "runs": 200},
        [],
    )
    assert _foundry_solc(project) == solc
    assert (project / "src/T.sol").read_text().splitlines()[0] == written


def _installed_solc(version: str) -> str:
    try:
        from solc_select import solc_select as ss
    except Exception:
        pytest.skip("solc-select unavailable")
    if version not in ss.installed_versions():
        pytest.skip(f"solc {version} not installed (run `solc-select install {version}`)")
    return str(ss.artifact_path(version))


@pytest.mark.compile
def test_selected_solc_compiles_relaxed_compound_pragma(tmp_path):
    sources = {
        "src/T.sol": "pragma solidity <0.9.0 =0.8.25 >=0.8.0 ^0.8.0 ^0.8.20;\ncontract T { uint256 public x; }\n",
        "src/I.sol": "pragma solidity <0.9.0;\ninterface I {}\n",
    }
    relaxed = _relax_pragmas(sources)
    version = detect_fetch_solc(sources)
    assert version == "0.8.25"
    solc = _installed_solc(version)
    for name, content in relaxed.items():
        path = tmp_path / name.replace("/", "_")
        path.write_text(content)
        proc = subprocess.run([solc, "--bin", str(path)], capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("path", ["discovery", "static"])
def test_verified_compiler_preserves_custom_error_require_syntax(tmp_path, path):
    # The loose pragma permits old compilers which cannot parse this newer syntax.
    source = (
        "pragma solidity ^0.8.0; contract T { error Denied(); "
        "function f(bool ok) external pure { require(ok, Denied()); } }"
    )
    project = tmp_path / "project"
    if path == "discovery":
        scaffold(
            "0xabc", {"SourceCode": source, "ContractName": "T", "CompilerVersion": "v0.8.27+commit.40a35a09"}, project
        )
    else:
        project.mkdir()
        StaticWorker()._scaffold_project(
            project, {"T.sol": source}, {"compiler_version": "v0.8.27+commit.40a35a09"}, {}, []
        )
    assert _foundry_solc(project) == "0.8.27"
    solc = _installed_solc(_foundry_solc(project))
    proc = subprocess.run([solc, "--bin", str(project / "T.sol")], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize(
    "preferred", ["v0.8.21+commit.abc", "v0.9.0+commit.abc", "nightly", '0.8.27"\nevm_version = "bad']
)
def test_incompatible_or_invalid_compiler_metadata_does_not_override_constraints(preferred):
    assert detect_fetch_solc({"T.sol": "pragma solidity >=0.8.20 <0.8.25; contract T {}"}, preferred) == "0.8.24"


@pytest.mark.parametrize("via_ir", [True, False, None, "true"])
def test_both_scaffolds_preserve_verified_via_ir(tmp_path, via_ir):
    from services.discovery.fetch import parse_compiler_settings

    sources = {"src/T.sol": "pragma solidity ^0.8.25; contract T {}"}
    bundle = {
        "language": "Solidity",
        "sources": {path: {"content": content} for path, content in sources.items()},
        "settings": {"viaIR": via_ir},
    }
    result = {"SourceCode": "{" + json.dumps(bundle) + "}", "CompilerVersion": "v0.8.25"}
    recursive = scaffold("0xabc", result, tmp_path / "recursive")
    top_level = tmp_path / "top_level"
    top_level.mkdir()
    StaticWorker()._scaffold_project(
        top_level,
        sources,
        {"compiler_version": result["CompilerVersion"]},
        {"via_ir": parse_compiler_settings(result).get("viaIR") is True},
        [],
    )
    expected = f"via_ir = {str(via_ir is True).lower()}"
    assert expected in (recursive / "foundry.toml").read_text()
    assert expected in (top_level / "foundry.toml").read_text()


def test_verified_compiler_fallback_is_limited_to_failed_compilation(monkeypatch, tmp_path):
    import workers.static_worker as module

    source = "// SPDX-License-Identifier: MIT & GPL-3.0\npragma solidity ^0.8.6; contract T {}"
    sources = {"src/T.sol": source}
    meta = {"compiler_version": "v0.8.6+commit.11564f7e", "contract_name": "T"}
    settings = {"evm_version": "shanghai"}
    artifacts = {
        "analysis_error": {"error": "compiler rejected source", "compilation_failed": True},
        "verified_build_metadata": {"compiler_version": meta["compiler_version"], "evm_version": "Default"},
    }
    monkeypatch.setattr(module, "get_artifact", lambda session, job_id, name: artifacts.get(name))
    monkeypatch.setattr(module, "store_artifact", lambda session, job_id, name, data: artifacts.__setitem__(name, data))
    worker = StaticWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *args: None)
    from types import SimpleNamespace

    job = SimpleNamespace(id="job")
    calls = []
    analysis = {"summary": {}}
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *args: calls.append(args) or analysis)
    worker._scaffold_project(tmp_path, sources, meta, settings, [])
    assert _foundry_solc(tmp_path) == "0.8.24"  # Successful primary behavior and cache semantics stay unchanged.
    result = worker._retry_verified_compiler(None, job, tmp_path, sources, meta, settings, [], "T", "0xabc")
    assert result is analysis and len(calls) == 1
    assert _foundry_solc(tmp_path) == "0.8.6"
    assert "evm_version" not in (tmp_path / "foundry.toml").read_text()
    assert artifacts["compiler_fallback"]["completed"] is True
    assert (tmp_path / "src/T.sol").read_text().startswith("// SPDX-License-Identifier: MIT & GPL-3.0")
    artifacts["analysis_error"] = {"error": "semantic lowering failed", "compilation_failed": False}
    assert worker._retry_verified_compiler(None, job, tmp_path, sources, meta, settings, [], "T", "0xabc") is None
    assert len(calls) == 1


def test_compiler_failure_marker_uses_exception_cause_not_error_text(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from crytic_compile.platform.exceptions import InvalidCompilation
    from slither.exceptions import SlitherError

    import workers.static_worker as module

    artifacts = {}
    monkeypatch.setattr(module, "store_artifact", lambda session, job_id, name, data: artifacts.__setitem__(name, data))
    worker = StaticWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *args: None)

    def compile_failure(*args):
        try:
            raise InvalidCompilation("compiler error")
        except InvalidCompilation:
            raise SlitherError("wrapped compiler error")

    monkeypatch.setattr(module, "collect_contract_analysis_with_artifacts", compile_failure)
    assert worker._run_analysis_phase(None, SimpleNamespace(id="job"), tmp_path, "T", "0xabc") is None
    assert artifacts["analysis_error"]["compilation_failed"] is True

    def semantic_failure(*args):
        raise RuntimeError("Invalid compilation is only text here")

    monkeypatch.setattr(module, "collect_contract_analysis_with_artifacts", semantic_failure)
    assert worker._run_analysis_phase(None, SimpleNamespace(id="job"), tmp_path, "T", "0xabc") is None
    assert artifacts["analysis_error"]["compilation_failed"] is False
