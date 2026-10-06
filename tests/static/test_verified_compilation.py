"""Verified build inputs must survive source ingestion and compiler selection."""

import copy
import json
import os
import shutil
import signal
import subprocess
import sys
from unittest.mock import MagicMock

import pytest
from slither import Slither

from services.discovery.fetch import parse_compiler_settings, parse_sources, scaffold, source_content_hash
from services.static.compilation import _normalize_vyper_ast, _run_vyper_child, compile_verified
from workers.static_worker import StaticWorker


def result(settings=None, version="v0.8.27+commit.40a35a09"):
    return {
        "ContractName": "C",
        "CompilerVersion": version,
        "EVMVersion": "Default",
        "OptimizationUsed": "1",
        "Runs": "0",
        "SourceCode": "{"
        + json.dumps(
            {
                "language": "Solidity",
                "sources": {"src/C.sol": {"content": "pragma solidity 0.8.27; contract C {}"}},
                "settings": settings or {},
            }
        )
        + "}",
    }


def test_exact_compiler_and_sources_are_not_rewritten(tmp_path):
    data = result()
    scaffold("0x" + "11" * 20, data, tmp_path)
    assert "pragma solidity 0.8.27;" in (tmp_path / "src/C.sol").read_text()
    assert 'solc_version = "0.8.27"' in (tmp_path / "foundry.toml").read_text()
    standard = json.loads((tmp_path / "analysis_standard_input.json").read_text())
    assert "evmVersion" not in standard["settings"]
    assert standard["settings"]["optimizer"]["runs"] == 0


def test_explorer_bare_file_map_compiles_as_sources(tmp_path):
    data = result(version="v0.8.27+commit.40a35a09")
    sources = {
        "Base.sol": {"content": "pragma solidity 0.8.27; contract Base {}"},
        "C.sol": {"content": 'pragma solidity 0.8.27; import "./Base.sol"; contract C is Base {}'},
    }
    data["SourceCode"] = json.dumps(sources)
    assert parse_sources(data) == {name: value["content"] for name, value in sources.items()}
    scaffold("0x" + "11" * 20, data, tmp_path)
    assert any(
        c.name == "C"
        for c in Slither(compile_verified(tmp_path, {"compiler_version": data["CompilerVersion"]})).contracts
    )


@pytest.mark.parametrize(
    "kind,declaration",
    [
        ("library", "library C { function add(uint a, uint b) internal pure returns(uint) { return a+b; } }"),
        ("interface", "interface C { function action() external; }"),
    ],
)
def test_verified_source_only_subject_is_not_replaced_by_another_contract(tmp_path, kind, declaration):
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    data = result()
    data["SourceCode"] = "pragma solidity 0.8.27; " + declaration + " contract Other { function action() external {} }"
    scaffold("0x" + "11" * 20, data, tmp_path)
    analysis, _, _ = collect_contract_analysis_with_artifacts(tmp_path)
    assert analysis["subject"]["name"] == "C"
    assert analysis["subject"].get("kind") == kind


def test_all_compiler_settings_participate_in_source_cache_key():
    original = result({"viaIR": True, "optimizer": {"enabled": True, "runs": 17, "details": {"yul": True}}})
    assert parse_compiler_settings(original)["optimizer"]["details"] == {"yul": True}
    other_version = {**original, "CompilerVersion": "v0.8.29+commit.ab55807c"}
    assert source_content_hash(other_version) != source_content_hash(original)
    # A bundle can verify several deployed contracts. Their selected subjects differ.
    assert source_content_hash({**original, "ContractName": "Other"}) != source_content_hash(original)
    assert source_content_hash(result({"viaIR": False})) != source_content_hash(result({"viaIR": True}))


@pytest.mark.compile
def test_worker_scaffold_compiles_via_ir_and_explicit_evm_target(tmp_path):
    settings = {"viaIR": True, "evmVersion": "cancun", "optimizer": {"enabled": True, "runs": 17}}
    meta = {"compiler_version": "v0.8.27+commit.40a35a09", "language": "solidity", "contract_name": "C"}
    src = """pragma solidity 0.8.27;
        contract C { function write(uint x) external { assembly { tstore(0, x) } } }
    """
    StaticWorker()._scaffold_project(
        tmp_path, {"src/C.sol": src}, meta, {"verified_settings": settings, "evm_version": "cancun"}, []
    )
    before = copy.deepcopy(settings)
    compiled = compile_verified(tmp_path, meta)
    assert settings == before
    unit = next(iter(compiled.compilation_units.values()))
    assert unit.compiler_version.version == "0.8.27"
    assert unit.compiler_version.optimize_runs == 17
    assert Slither(compiled).contracts[0].name == "C"


def test_compilation_timeout_is_explicit(tmp_path, monkeypatch):
    scaffold("0x" + "11" * 20, result(), tmp_path)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)

    monkeypatch.setattr("services.static.compilation.subprocess.run", timeout)
    monkeypatch.setenv("PSAT_COMPILATION_TIMEOUT_S", "1")
    with pytest.raises(Exception, match="compilation deadline"):
        compile_verified(tmp_path, {"compiler_version": "v0.8.27"})


def test_vyper_deadline_terminates_the_compiler_process_group(tmp_path, monkeypatch):
    process = MagicMock(pid=1234)
    process.__enter__.return_value = process
    process.communicate.side_effect = [subprocess.TimeoutExpired("compiler", 1), ("", "")]
    popen = MagicMock(return_value=process)
    kill = MagicMock()
    monkeypatch.setattr("services.static.compilation.subprocess.Popen", popen)
    monkeypatch.setattr("services.static.compilation.os.killpg", kill)
    with pytest.raises(subprocess.TimeoutExpired):
        _run_vyper_child(["compiler"], cwd=tmp_path, env={}, timeout=1)
    assert popen.call_args.kwargs["start_new_session"] is True
    kill.assert_called_once_with(1234, signal.SIGKILL)
    assert process.communicate.call_count == 2


def test_missing_input_does_not_override_compiler_default():
    assert "evmVersion" not in parse_compiler_settings(result())
    assert parse_compiler_settings(result({"evmVersion": "osaka"}))["evmVersion"] == "osaka"


def test_legacy_vyper_state_declarations_preserve_qualifiers_and_locals():
    declaration = {
        "ast_type": "AnnAssign",
        "target": {"id": "controller"},
        "annotation": {
            "ast_type": "Call",
            "func": {"id": "immutable"},
            "args": [{"ast_type": "Name", "id": "address"}],
        },
        "value": None,
    }
    local = {"ast_type": "AnnAssign", "target": {"id": "x"}, "annotation": {"ast_type": "Name", "id": "uint256"}}
    ast = {"ast_type": "Module", "body": [declaration, {"ast_type": "FunctionDef", "body": [local]}]}
    _normalize_vyper_ast(ast)
    assert declaration["ast_type"] == "VariableDecl"
    assert declaration["is_immutable"] is True
    assert declaration["is_constant"] is False
    assert local["ast_type"] == "AnnAssign"


@pytest.mark.compile
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_legacy_vyper_reaches_semantic_parser_with_exact_compiler(tmp_path, monkeypatch, newline):
    if not shutil.which("uv"):
        pytest.skip("uv not installed")
    env = {**os.environ, "UV_OFFLINE": "1"}
    probe = subprocess.run(
        ["uv", "tool", "run", "--python", sys.executable, "--from", "vyper==0.3.1", "vyper", "--version"],
        capture_output=True,
        env=env,
        timeout=30,
    )
    if probe.returncode:
        pytest.skip("Vyper 0.3.1 is not cached; offline tests never install it")
    monkeypatch.setenv("UV_OFFLINE", "1")
    data = {
        "ContractName": "Gate",
        "CompilerVersion": "vyper:0.3.1",
        "SourceCode": """
# @version 0.3.1
AUTHORITY: immutable(address)
@external
def __init__(who: address):
    AUTHORITY = who
@external
def action():
    assert msg.sender == AUTHORITY
@external
@pure
def word(data: Bytes[64]) -> bytes32:
    return extract32(data, 0)
""".lstrip(),
    }
    data["SourceCode"] = data["SourceCode"].replace("\n", newline)
    scaffold("0x" + "11" * 20, data, tmp_path)
    if newline == "\r\n":
        assert b"\r\n" in (tmp_path / "src/Gate.vy").read_bytes()
    parsed = Slither(compile_verified(tmp_path, {"compiler_version": "vyper:0.3.1"}))
    contract = next(c for c in parsed.contracts if c.name == "Gate")
    assert next(v for v in contract.state_variables if v.name == "AUTHORITY").is_immutable
    assert any(f.name == "action" for f in contract.functions)
