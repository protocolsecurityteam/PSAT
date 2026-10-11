"""The build compiles with the settings the bundle was verified with, not ones guessed from its pragmas."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from services.discovery.fetch import _detect_solc_version, parse_sources, scaffold, select_solc_version
from tests.support import label_corpus
from workers.static_worker import StaticWorker

FIXTURE = Path(__file__).parents[1] / "fixtures" / "verified_compile" / "balancer_v2_vault_subset.json"
TELLER_PRAGMA = "pragma solidity <0.9.0 =0.8.21 >=0.8.0 ^0.8.0 ^0.8.20;"


def _balancer_result() -> dict:
    return json.loads(FIXTURE.read_text())


def _foundry(project: Path) -> dict[str, str]:
    values = {}
    for line in (project / "foundry.toml").read_text().splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key] = value.strip('"')
    return values


def _one_file(pragma: str) -> dict[str, str]:
    return {"src/C.sol": f"{pragma}\ncontract C {{}}\n"}


@pytest.mark.parametrize(
    ("pragma", "compiler_version", "expected"),
    [
        pytest.param(
            "pragma solidity ^0.7.0;", "v0.7.1+commit.f4a555be", "0.7.1", id="verified_patch_over_pragma_floor"
        ),
        pytest.param("pragma solidity ^0.8.0;", "v0.8.13+commit.abaa5c0e", "0.8.13", id="verified_below_default_floor"),
        pytest.param("pragma solidity ^0.8.20;", "v0.8.27+commit.40a35a09", "0.8.27", id="verified_newer_patch"),
        pytest.param("pragma solidity ^0.8.20;", "v0.8.24", "0.8.24", id="release_without_commit"),
        pytest.param("pragma solidity ^0.8.20;", "v0.8.22+commit.4fc1097e", "0.8.22", id="verified_below_floor_patch"),
        pytest.param(TELLER_PRAGMA, "v0.8.21+commit.d9974bed", "0.8.21", id="compound_pragma_admits"),
        pytest.param(TELLER_PRAGMA, "v0.8.20+commit.a1b79de6", "0.8.24", id="compound_pragma_rejects"),
        pytest.param("pragma solidity ^0.8.0;", "v0.7.6+commit.7338295f", "0.8.24", id="verified_rejected_by_pragma"),
        pytest.param(
            "pragma solidity ^0.4.23;", "v0.4.24-nightly.2018.5.9+commit.1e953355", "0.4.23", id="nightly_unparseable"
        ),
        pytest.param("pragma solidity ^0.8.20;", "", "0.8.24", id="absent"),
        pytest.param("pragma solidity ^0.8.20;", None, "0.8.24", id="none"),
        pytest.param("pragma solidity ^0.8.20;", "vyper:0.3.7", "0.8.24", id="not_solc"),
    ],
)
def test_select_solc_version(pragma, compiler_version, expected):
    assert select_solc_version(_one_file(pragma), compiler_version) == expected


def test_a_pragma_fallback_is_logged(caplog):
    with caplog.at_level("INFO", logger="services.discovery.fetch"):
        select_solc_version(_one_file("pragma solidity ^0.8.0;"), "v0.7.6+commit.7338295f")
        select_solc_version(_one_file("pragma solidity ^0.8.0;"), "")
        select_solc_version(_one_file("pragma solidity ^0.8.0;"), "v0.8.13+commit.abaa5c0e")
    assert [r.__dict__.get("solc_source") for r in caplog.records] == ["pragma_conflict", "pragma", "verified"]
    assert caplog.records[0].levelname == "WARNING"


def test_scaffold_carries_the_verified_settings(tmp_path):
    project = scaffold("0xba12222222228d8ba445958a75a0704d566bf2c8", _balancer_result(), tmp_path / "proj")
    assert _foundry(project) == {
        "src": ".",
        "out": "out",
        "libs": '["lib"]',
        "solc_version": "0.7.1",
        # Verified with "Default": solc 0.7.1's own target.
        "evm_version": "istanbul",
        "optimizer": "true",
        "optimizer_runs": "1500",
        "via_ir": "false",
        "auto_detect_solc": "false",
    }
    meta = json.loads((project / "contract_meta.json").read_text())
    assert meta["solc_version"] == "0.7.1"


def _standard_json(settings: dict, *, pragma: str = "pragma solidity ^0.8.20;", **flat) -> dict:
    bundle = {"language": "Solidity", "sources": {"src/C.sol": {"content": f"{pragma}\ncontract C {{}}\n"}}}
    bundle["settings"] = settings
    return {
        "ContractName": "C",
        "CompilerVersion": "v0.8.27+commit.40a35a09",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "SourceCode": "{" + json.dumps(bundle) + "}",
        **flat,
    }


def test_standard_json_settings_win_over_the_flat_fields(tmp_path):
    result = _standard_json({"viaIR": True, "evmVersion": "cancun", "optimizer": {"enabled": False, "runs": 999}})
    toml = _foundry(scaffold("0xabc", result, tmp_path / "proj"))
    assert (toml["solc_version"], toml["via_ir"], toml["evm_version"]) == ("0.8.27", "true", "cancun")
    assert (toml["optimizer"], toml["optimizer_runs"]) == ("false", "999")


def test_flat_fields_fill_in_what_settings_omit(tmp_path):
    result = _standard_json({"optimizer": {}}, EVMVersion="paris", OptimizationUsed="0", Runs="77")
    toml = _foundry(scaffold("0xabc", result, tmp_path / "proj"))
    assert (toml["via_ir"], toml["evm_version"], toml["optimizer"], toml["optimizer_runs"]) == (
        "false",
        "paris",
        "false",
        "77",
    )


@pytest.mark.parametrize(
    ("compiler_version", "pragma", "expected"),
    [
        ("v0.8.30+commit.73712a01", "pragma solidity ^0.8.20;", "prague"),
        ("v0.8.27+commit.40a35a09", "pragma solidity ^0.8.20;", "cancun"),
        ("v0.8.24+commit.e11b9ed9", "pragma solidity ^0.8.20;", "shanghai"),
        ("v0.8.19+commit.7dd6d404", "pragma solidity ^0.8.0;", "paris"),
        ("v0.8.13+commit.abaa5c0e", "pragma solidity ^0.8.0;", "london"),
        ("v0.7.6+commit.7338295f", "pragma solidity ^0.7.0;", "istanbul"),
        ("v0.5.12+commit.7709ece9", "pragma solidity ^0.5.0;", "petersburg"),
        ("v0.4.24+commit.e67f0147", "pragma solidity ^0.4.24;", "byzantium"),
    ],
)
def test_a_default_evm_target_is_the_compilers_default(tmp_path, compiler_version, pragma, expected):
    result = _standard_json({}, pragma=pragma, CompilerVersion=compiler_version, EVMVersion="Default")
    assert _foundry(scaffold("0xabc", result, tmp_path / "proj"))["evm_version"] == expected


def test_static_worker_builds_with_the_row_settings(tmp_path):
    sources = parse_sources(_balancer_result())
    project = tmp_path / "proj"
    project.mkdir()
    StaticWorker()._scaffold_project(
        project,
        sources,
        {"contract_name": "ProtocolFeesCollector"},
        {
            "language": "solidity",
            "compiler_version": "v0.7.1+commit.f4a555be",
            "evm_version": "istanbul",
            "optimization_used": True,
            "runs": 1500,
            "via_ir": True,
        },
        [],
    )
    toml = _foundry(project)
    assert (toml["solc_version"], toml["evm_version"], toml["optimizer_runs"], toml["via_ir"]) == (
        "0.7.1",
        "istanbul",
        "1500",
        "true",
    )


def _require_solc(version: str) -> Path:
    """FAIL, never skip: a skipped compile proof reports green while proving nothing."""
    binary = label_corpus._solc_select_binary(version)
    if not binary.exists():
        raise AssertionError(
            f"solc {version} is not provisioned at {binary}: run `uv run solc-select install {version}`. "
            "CI installs it in _ci-checks.yml."
        )
    return binary


@pytest.mark.compile
def test_the_balancer_bundle_compiles_with_its_verified_compiler(tmp_path):
    from services.static.contract_analysis_pipeline.core import collect_contract_analysis_with_artifacts

    result = _balancer_result()
    project = scaffold("0xba12222222228d8ba445958a75a0704d566bf2c8", result, tmp_path / "proj")
    chosen = _foundry(project)["solc_version"]
    guessed = _detect_solc_version(parse_sources(result))
    assert (guessed, chosen) == ("0.7.0", "0.7.1")

    # The pragma's choice can't parse BalancerErrors.sol's file-level function.
    env = {**os.environ, "FOUNDRY_SOLC": str(_require_solc(guessed)), "FOUNDRY_OFFLINE": "true"}
    proc = subprocess.run(["forge", "build", "--force"], cwd=project, env=env, capture_output=True, text=True)
    output = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "Error (7858)" in output and "BalancerErrors.sol" in output

    with label_corpus._foundry_env(_require_solc(chosen)):
        analysis, _trees, _effects = collect_contract_analysis_with_artifacts(project)
    assert analysis["subject"]["name"] == "ProtocolFeesCollector"
    assert analysis["analysis_status"]["static_analysis_completed"] is True
