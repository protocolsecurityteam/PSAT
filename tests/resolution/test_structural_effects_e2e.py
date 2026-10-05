"""A public withdrawal and privileged call in one entry must stay separate through execution and scoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from db.models import Contract, EffectiveFunction, Job, JobStatus, Protocol
from services.policy.effective_permissions import build_effective_permissions
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.effect_scopes import resolve_effect_scopes
from services.scoring.cli import distill_protocol_in_memory
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from tests.conftest import requires_postgres
from tests.support.anvil import _start_anvil, _terminate
from tests.support.canonical_safe import call, calldata, rpc, send
from tests.support.foundry_project import write_foundry_project

pytestmark = [pytest.mark.compile, pytest.mark.anvil]


@requires_postgres
def test_execution_and_scoring_preserve_effect_specific_authority(tmp_path, db_session):
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    source = (fixtures / "contracts/authorization/structural_controls.sol").read_text()
    source += "\ncontract Target { uint256 public value; function setValue(uint256 next) external { value = next; } }\n"
    project = write_foundry_project(tmp_path, "StructuralControls", source)
    collect_contract_analysis_with_artifacts(project)
    proc, port = _start_anvil()
    try:
        url = f"http://127.0.0.1:{port}"
        accounts = rpc(url, "eth_accounts", [])

        def deploy(name):
            artifact = json.loads((project / "out/StructuralControls.sol" / (name + ".json")).read_text())
            receipt = send(url, accounts[0], artifact["bytecode"]["object"])
            assert int(receipt["status"], 16) == 1
            return receipt["contractAddress"]

        address, target = deploy("StructuralControls"), deploy("Target")
        receipt = send(url, accounts[1], calldata("deposit()"), address, value=100)
        assert int(receipt["status"], 16) == 1
        signature = "mixed(bool,address,bytes,uint256)"
        payload = bytes.fromhex(calldata("setValue(uint256)", [42])[2:])
        with pytest.raises(RuntimeError):
            call(url, address, signature, [False, target, payload, 0], sender=accounts[1])
        assert int(send(url, accounts[0], calldata(signature, [False, target, payload, 0]), address)["status"], 16) == 1
        assert call(url, target, "value()", returns=["uint256"])[0] == 42
        assert int(send(url, accounts[1], calldata(signature, [True, target, b"", 40]), address)["status"], 16) == 1
        assert call(url, address, "credits(address)", [accounts[1]], ["uint256"])[0] == 60
        meta = json.loads((project / "contract_meta.json").read_text())
        meta["address"] = address
        (project / "contract_meta.json").write_text(json.dumps(meta))
        analysis, trees, effects = collect_contract_analysis_with_artifacts(project)
        assert trees is not None and effects is not None
        block = int(rpc(url, "eth_blockNumber", []), 16)
        owner = call(url, address, "owner()", returns=["address"], block=hex(block))[0]
        ctx = EvaluationContext(
            chain_id=1, contract_address=address, rpc_url=url, block=block, state_var_values={"owner": owner}
        )
        aggregate, scopes = resolve_effect_scopes(
            trees["effect_scopes"][signature], AdapterRegistry(), ctx, all_scopes=trees["effect_scopes"]
        )
        assert aggregate is not None
        caps = {signature: {**capability_to_dict(aggregate), "effect_capabilities": scopes}}
        protocol = Protocol(name="structural-mixed")
        job = Job(address=address, status=JobStatus.completed, request={"chain": "ethereum"})
        db_session.add_all([protocol, job])
        db_session.flush()
        contract = Contract(address=address, chain="ethereum", protocol_id=protocol.id, job_id=job.id)
        db_session.add(contract)
        db_session.flush()
        permissions = build_effective_permissions(
            analysis, predicate_trees=trees, capability_resolver_output=caps, effects=effects
        )
        write_effective_function_rows(
            db_session,
            contract_id=contract.id,
            function_records=cast(list[dict[str, Any]], permissions["functions"]),
            capability_by_function=caps,
            deployment_address=address,
        )
        db_session.flush()
        row = db_session.query(EffectiveFunction).filter_by(contract_id=contract.id, abi_signature=signature).one()
        assert row.authority_openness == "open"
        signals = distill_protocol_in_memory(db_session, protocol.id)
        arbitrary = next(s for s in signals if s.selector == row.selector and s.claim_id == "exec.arbitrary")
        assert arbitrary.authority_openness == "restricted"
        assert [p.address for p in arbitrary.principal_refs] == [owner]
    finally:
        _terminate(proc)
