"""Cross-contract inlining reads the registry's state-variable values on the caller's chain."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import Contract, ControllerValue, Job, JobStage, JobStatus
from db.queue import create_job, store_artifact
from services.resolution.adapters import AdapterRegistry, CallFrame
from services.resolution.adapters import EvaluationContext as ResolverContext
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = [requires_postgres]

ETH_OWNER = "0x" + "e0" * 20
BASE_OWNER = "0x" + "b0" * 20
CALLER = "0x" + "c5" * 20
_CAN_CALL = "canCall(address,address,bytes4)"

_CALLER_TREE = {
    "op": "LEAF",
    "leaf": {
        "kind": "external_bool",
        "operator": "truthy",
        "authority_role": "delegated_authority",
        "operands": [{"source": "msg_sender"}],
        "set_descriptor": {
            "kind": "external_set",
            "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
            "callee_signature": _CAN_CALL,
        },
        "references_msg_sender": True,
    },
}

_TREES = {
    "schema_version": "semantic",
    "contract_name": "Registry",
    "trees": {
        _CAN_CALL: {
            "op": "LEAF",
            "leaf": {
                "kind": "equality",
                "operator": "eq",
                "authority_role": "caller_authority",
                "operands": [
                    {"source": "parameter", "parameter_index": 0},
                    {"source": "state_variable", "state_variable_name": "owner"},
                ],
                "references_msg_sender": False,
            },
        }
    },
}


@pytest.fixture()
def session():
    engine = create_engine(DATABASE_URL)
    s = Session(engine, expire_on_commit=False)
    minted: list[str] = []
    s.info["minted"] = minted
    try:
        yield s
    finally:
        s.rollback()
        if minted:
            s.query(Contract).filter(Contract.address.in_(minted)).delete(synchronize_session=False)
            s.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
            s.commit()
        s.close()
        engine.dispose()


def _job(session, address, chain, status, version=ANALYSIS_SCHEMA_VERSION):
    job = create_job(session, {"address": address, "chain": chain})
    job.status = status
    job.stage = JobStage.done
    job.analysis_schema_version = version
    session.commit()
    return job


def _row(session, address, chain, job, owner):
    c = Contract(job_id=job.id, address=address, chain=chain, contract_name="Registry")
    session.add(c)
    session.flush()
    session.add(ControllerValue(contract_id=c.id, controller_id="state_variable:owner", value=owner))
    session.commit()
    return c


def _evaluate(session, registry, chain_id):
    ctx = ResolverContext(
        chain_id=chain_id,
        contract_address=CALLER,
        state_var_values={"authority": registry},
        session=session,
        call_frame=CallFrame.root(contract_address=CALLER, function_signature="setX()", function_selector="0x12345678"),
    )
    return evaluate_tree_with_registry(_CALLER_TREE, AdapterRegistry(), ctx)  # pyright: ignore[reportArgumentType]


def test_mainnet_inlining_never_reads_the_base_twins_owner(session):
    registry = ("0x" + uuid.uuid4().hex[:8] + "ae" * 16).lower()
    session.info["minted"].append(registry)
    analysed = _job(session, registry, "ethereum", JobStatus.completed)
    store_artifact(session, analysed.id, "predicate_trees", data=_TREES)
    session.commit()
    # A later same-chain re-run took the row over (copy_static_cache) and then failed.
    rerun = _job(session, registry, "ethereum", JobStatus.failed)
    _row(session, registry, "ethereum", rerun, ETH_OWNER)
    base_job = _job(session, registry, "base", JobStatus.completed)
    _row(session, registry, "base", base_job, BASE_OWNER)

    cap = _evaluate(session, registry, 1)
    assert BASE_OWNER not in (cap.members or [])
    assert (cap.kind, cap.members) == ("finite_set", [ETH_OWNER])
