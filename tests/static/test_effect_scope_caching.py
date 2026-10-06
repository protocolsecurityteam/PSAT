"""Effect-scope and structural caches are pure performance: published artifacts must not depend on them, or on where
Slither objects happen to sit in memory."""

import json
from pathlib import Path

import pytest

from services.static.contract_analysis_pipeline import (
    collect_contract_analysis_with_artifacts,
    effect_scopes,
    revert_detect,
    structural_evidence,
    structural_ir,
)
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/contracts/authorization/structural_controls.sol"

SHARED_HELPERS = """pragma solidity ^0.8.19;
contract SharedHelpers {
 address owner; address guardian; mapping(address => bool) operators;
 uint256 fee; uint256 cap; bool paused; uint256 total; uint256 last;
 modifier onlyOperator() { require(_isOperator(msg.sender)); _; }
 function _isOperator(address who) internal view returns (bool) { if (!operators[who]) revert(); return true; }
 function _checkpoint(uint256 v) internal returns (uint256, uint256) { last = total; total = v; return (last, v); }
 function _record(uint256 a, uint256 b) internal { last = a + b; }
 function configure(uint256 newFee, uint256 newCap, bool pause) external onlyOperator {
  if (pause) { require(msg.sender == guardian); paused = true; }
  else if (newCap > 0) { require(msg.sender == owner); cap = newCap; fee = newFee; }
  else { require(msg.sender == owner); fee = newFee; }
 }
 function setFee(uint256 f) external onlyOperator { fee = f; last = block.timestamp; }
 function setCap(uint256 c) external onlyOperator { cap = c; }
 function move(uint256 v) external onlyOperator { (uint256 a, uint256 b) = _checkpoint(v); _record(a, b); }
}"""


class _Disabled:
    """Stands in for a cache ContextVar: setting is accepted, reads always miss."""

    def set(self, _value):
        return None

    def reset(self, _token):
        pass

    def get(self):
        return None


def _analyze(project):
    _, trees, effects = collect_contract_analysis_with_artifacts(project)
    return json.dumps({"trees": trees, "effects": effects}, sort_keys=True, default=str)


@pytest.fixture(scope="module", params=["structural_controls", "shared_helpers"])
def project(request, tmp_path_factory):
    tmp = tmp_path_factory.mktemp(request.param)
    if request.param == "structural_controls":
        return write_foundry_project(tmp, "StructuralControls", FIXTURE.read_text())
    return write_foundry_project(tmp, "SharedHelpers", SHARED_HELPERS)


def test_artifacts_are_identical_with_and_without_caches(project, monkeypatch):
    cached = _analyze(project)
    with monkeypatch.context() as patch:
        patch.setattr(effect_scopes, "_helper_engine_cache", _Disabled())
        patch.setattr(effect_scopes, "_reachable_cache", _Disabled())
        patch.setattr(effect_scopes, "_lowered_cache", _Disabled())
        patch.setattr(structural_ir, "guards_cache", _Disabled())
        patch.setattr(structural_evidence, "guards_cache", _Disabled())
        patch.setattr(structural_evidence, "expression_text_cache", _Disabled())
        patch.setattr(revert_detect, "expression_text_cache", _Disabled())
        uncached = _analyze(project)
    assert cached == uncached


def test_artifacts_carry_no_memory_addresses(project):
    # A second run in the same process allocates every Slither object somewhere else.
    first, second = _analyze(project), _analyze(project)
    assert first == second
    assert " object at 0x" not in first
