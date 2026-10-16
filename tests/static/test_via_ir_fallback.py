"""A viaIR-verified bundle builds without viaIR first and retries once with it only when that build fails; a bundle
verified without viaIR gets one build. A fallback that succeeds is a success, never a remembered failure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.discovery.fetch import scaffold
from services.static.contract_analysis_pipeline import core
from tests.conftest import requires_postgres
from tests.support import label_corpus
from tests.support.materializations import cm_db  # noqa: F401  (fixture, registered by import)

pytestmark = pytest.mark.compile

SOLC = "0.8.27"
ADDRESS = "0xdee0000000000000000000000000000000000dee"
KECCAK = "0x" + "de" * 32

_PARAMS = ", ".join(f"uint256 a{i}" for i in range(10))
_LOCALS = "\n".join(f"        uint256 b{i} = a{i} * {i + 2};" for i in range(10))
_SUM = " + ".join([f"a{i}" for i in range(10)] + [f"b{i}" for i in range(10)])
# Twenty live words: the legacy pipeline stops at "Stack too deep"; viaIR moves them to memory.
STACK_TOO_DEEP = (
    "pragma solidity ^0.8.20;\n"
    "contract Deep {\n"
    "    uint256 public total;\n"
    f"    function deep({_PARAMS}) external returns (uint256) {{\n{_LOCALS}\n"
    f"        total = {_SUM};\n"
    "        return total;\n"
    "    }\n"
    "}\n"
)
SHALLOW = (
    "pragma solidity ^0.8.20;\n"
    "contract Deep {\n"
    "    uint256 public total;\n"
    "    function set(uint256 v) external { total = v; }\n"
    "}\n"
)
BROKEN = "pragma solidity ^0.8.20;\ncontract Deep { function f( }\n"


def _result(source: str, *, via_ir: bool) -> dict:
    bundle = {
        "language": "Solidity",
        "sources": {"src/Deep.sol": {"content": source}},
        "settings": {"optimizer": {"enabled": True, "runs": 200}, "evmVersion": "cancun", "viaIR": via_ir},
    }
    return {
        "ContractName": "Deep",
        "CompilerVersion": f"v{SOLC}+commit.40a35a09",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "cancun",
        "SourceCode": "{" + json.dumps(bundle) + "}",
    }


@pytest.fixture()
def parses(monkeypatch):
    """Counts Slither parses (each one a forge build) and pins the offline compiler."""
    binary = label_corpus._solc_select_binary(SOLC)
    if not binary.exists():
        raise AssertionError(f"solc {SOLC} is not provisioned at {binary}; CI installs it in _ci-checks.yml.")
    monkeypatch.setenv("FOUNDRY_SOLC", str(binary))
    monkeypatch.setenv("FOUNDRY_OFFLINE", "true")
    calls: list[str] = []
    real = core.Slither

    def counting(target, *args, **kwargs):
        toml = (Path(target) / "foundry.toml").read_text()
        calls.append("via_ir" if "via_ir = true" in toml else "legacy")
        return real(target, *args, **kwargs)

    monkeypatch.setattr(core, "Slither", counting)
    return calls


def _build(tmp_path: Path, source: str, *, via_ir: bool):
    project = scaffold(ADDRESS, _result(source, via_ir=via_ir), tmp_path / "proj")
    analysis, _trees, _effects = core.collect_contract_analysis_with_artifacts(project)
    return analysis, json.loads((project / "contract_meta.json").read_text())


def test_a_via_ir_bundle_that_compiles_without_it_builds_once(tmp_path, parses):
    analysis, meta = _build(tmp_path, SHALLOW, via_ir=True)
    assert parses == ["legacy"]
    assert analysis["analysis_status"]["static_analysis_completed"] is True
    assert (meta["via_ir"], meta["via_ir_used"]) == (True, False)


def test_a_via_ir_bundle_that_needs_it_falls_back_once(tmp_path, parses):
    analysis, meta = _build(tmp_path, STACK_TOO_DEEP, via_ir=True)
    assert parses == ["legacy", "via_ir"]
    assert analysis["subject"]["name"] == "Deep"
    assert analysis["analysis_status"]["static_analysis_completed"] is True
    assert (meta["via_ir"], meta["via_ir_used"]) == (True, True)


def test_a_bundle_verified_without_via_ir_gets_one_build(tmp_path, parses):
    with pytest.raises(Exception, match="Invalid compilation"):
        _build(tmp_path, STACK_TOO_DEEP, via_ir=False)
    assert parses == ["legacy"]


def test_the_fallback_failing_is_the_build_failing(tmp_path, parses):
    with pytest.raises(Exception, match="Invalid compilation"):
        _build(tmp_path, BROKEN, via_ir=True)
    assert parses == ["legacy", "via_ir"]


@requires_postgres
def test_a_fallback_success_is_materialized_not_remembered_as_failed(cm_db, parses, monkeypatch):  # noqa: F811
    import importlib

    from db.models import ContractMaterialization
    from services.resolution import recursive

    monkeypatch.setenv("PSAT_CONTRACT_MATERIALIZATIONS", "1")
    monkeypatch.setattr(
        importlib.import_module("services.discovery.fetch"),
        "get_source",
        lambda *_a, **_k: _result(STACK_TOO_DEEP, via_ir=True),
    )
    name, analysis, _plan, _trees = recursive._materialize_with_cross_process_cache(
        effective_address=ADDRESS, bytecode_keccak=KECCAK, workspace_prefix="t", chain="ethereum"
    )
    assert (name, analysis["analysis_status"]["static_analysis_completed"]) == ("Deep", True)
    assert parses == ["legacy", "via_ir"]
    row = cm_db.query(ContractMaterialization).filter_by(bytecode_keccak=KECCAK).one()
    assert (row.status, row.deterministic_failure, row.error) == ("ready", False, None)
