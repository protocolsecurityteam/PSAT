"""A nested contract whose compile fails with its compiler on disk is built once: later graph builds in the run get the
remembered failure, and the node is not determined (``attempt_failed``) every time. Without the compiler on disk the
failure may be its download, so the next graph build tries again.
"""

from __future__ import annotations

import importlib
from typing import cast

import pytest

from db.models import ContractMaterialization
from schemas.resolved_control_graph import ResolvedGraphNode
from services.resolution import recursive
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from tests.conftest import requires_postgres
from tests.support import label_corpus
from tests.support.materializations import cm_db  # noqa: F401  (fixture, registered by import)

pytestmark = [pytest.mark.compile, pytest.mark.usefixtures("_stub_rpc_bytecode", "_stub_classifier_rpc")]

ROOT = "0x1111111111111111111111111111111111111111"
CHILD = "0xbad0000000000000000000000000000000000bad"
CHILD_KECCAK = "0x" + "be" * 32
SOLC = "0.8.27"

BROKEN = {
    "ContractName": "Broken",
    "CompilerVersion": f"v{SOLC}+commit.40a35a09",
    "OptimizationUsed": "1",
    "Runs": "200",
    "EVMVersion": "cancun",
    "SourceCode": "pragma solidity ^0.8.20;\ncontract Broken { function f( }\n",
}


def _root() -> LoadedArtifacts:
    return cast(
        LoadedArtifacts,
        {
            "analysis": {"subject": {"address": ROOT, "name": "Root"}},
            "tracking_plan": {
                "schema_version": "0.1",
                "contract_address": ROOT,
                "contract_name": "Root",
                "tracking_strategy": "event_first_with_polling_fallback",
                "tracked_controllers": [],
            },
            "snapshot": {
                "schema_version": "0.1",
                "contract_address": ROOT,
                "contract_name": "Root",
                "block_number": 1,
                "controller_values": {
                    "state_variable:registry": {
                        "source": "registry",
                        "value": CHILD,
                        "block_number": 1,
                        "observed_via": "eth_call",
                        "resolved_type": "contract",
                        "details": {"address": CHILD},
                    }
                },
            },
        },
    )


@pytest.fixture()
def _wire(monkeypatch, cm_db):  # noqa: F811
    binary = label_corpus._solc_select_binary(SOLC)
    if not binary.exists():
        raise AssertionError(f"solc {SOLC} is not provisioned at {binary}; CI installs it in _ci-checks.yml.")
    monkeypatch.setenv("PSAT_CONTRACT_MATERIALIZATIONS", "1")
    monkeypatch.setenv("FOUNDRY_OFFLINE", "true")
    monkeypatch.setenv("FOUNDRY_SOLC", str(binary))
    monkeypatch.setattr(
        importlib.import_module("services.discovery.fetch"), "get_source", lambda *_a, **_k: dict(BROKEN)
    )
    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", lambda *a, **k: ("0x6080", CHILD_KECCAK))
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address_with_status",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}, True),
    )
    monkeypatch.setattr(
        "services.resolution.recursive.classify_resolved_address",
        lambda rpc_url, address, block_tag="latest", **_kw: ("contract", {"address": address}),
    )
    builds = {"n": 0}
    real = recursive.collect_contract_analysis_with_artifacts

    def counting(project_dir):
        builds["n"] += 1
        return real(project_dir)

    monkeypatch.setattr(recursive, "collect_contract_analysis_with_artifacts", counting)
    return builds


def _child_after_graph_build() -> ResolvedGraphNode:
    graph, nested = resolve_control_graph(root_artifacts=_root(), rpc_url="http://rpc.example", chain_id=1, max_depth=2)
    assert CHILD not in nested
    return next(node for node in graph["nodes"] if node.get("address") == CHILD)


@requires_postgres
def test_a_failed_nested_build_is_attempted_once_across_graph_builds(_wire, cm_db):  # noqa: F811
    first = _child_after_graph_build()
    second = _child_after_graph_build()

    assert _wire["n"] == 1
    for node in (first, second):
        assert node["analyzed"] is False
        assert node.get("analysis_state") == "attempt_failed"
        assert "SlitherError: Invalid compilation" in str((node.get("details") or {}).get("materialize_error"))
    row = cm_db.query(ContractMaterialization).filter_by(bytecode_keccak=CHILD_KECCAK).one()
    assert (row.status, row.deterministic_failure) == ("failed", True)


@requires_postgres
def test_a_failure_without_the_compiler_on_disk_is_retried(_wire, monkeypatch, tmp_path):
    monkeypatch.setenv("FOUNDRY_SOLC", str(tmp_path / "missing-solc"))
    for _ in range(2):
        assert _child_after_graph_build().get("analysis_state") == "attempt_failed"
    assert _wire["n"] == 2
