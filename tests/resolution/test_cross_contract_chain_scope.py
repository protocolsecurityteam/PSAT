"""Cross-contract inlining reads the registry on the caller's own chain.

A registry deployed at the same address on two chains has two analyses. When the caller's chain only has a stale one,
the read comes back unresolved (the existing third state), never the other chain's current twin.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import Job, JobStage, JobStatus
from db.queue import create_job, store_artifact
from services.resolution.adapters import AdapterRegistry, CallFrame
from services.resolution.adapters import EvaluationContext as ResolverContext
from services.resolution.capability_resolver import find_analysis_job_for_address
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = [requires_postgres]

STALE = 6
TWIN_OWNER = "0x" + "7e" * 20
CALLER = "0x" + "c4" * 20

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

# Inlined, the callee's msg.sender is the caller contract, so the twin answers with an exact empty set: read across
# chains it would publish ``resolved_empty`` for a gate it never saw.
_TWIN_TREES = {
    "schema_version": "semantic",
    "contract_name": "Registry",
    "trees": {
        _CAN_CALL: {
            "op": "LEAF",
            "leaf": {
                "kind": "equality",
                "operator": "eq",
                "authority_role": "caller_authority",
                "operands": [{"source": "msg_sender"}, {"source": "constant", "constant_value": TWIN_OWNER}],
                "references_msg_sender": True,
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
            s.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
            s.commit()
        s.close()
        engine.dispose()


def _registry_job(session: Session, address: str, *, chain: str, version: int) -> Job:
    session.info["minted"].append(address)
    job = create_job(session, {"address": address, "chain": chain})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.analysis_schema_version = version
    session.commit()
    store_artifact(session, job.id, "predicate_trees", data=_TWIN_TREES)
    session.commit()
    return job


def _evaluate(session: Session, registry: str, chain_id: int) -> Any:
    ctx = ResolverContext(
        chain_id=chain_id,
        contract_address=CALLER,
        state_var_values={"authority": registry},
        session=session,
        call_frame=CallFrame.root(contract_address=CALLER, function_signature="setX()", function_selector="0x12345678"),
    )
    return evaluate_tree_with_registry(_CALLER_TREE, AdapterRegistry(), ctx)  # pyright: ignore[reportArgumentType]


def test_a_stale_own_chain_registry_never_reads_the_current_twin(session):
    registry = ("0x" + uuid.uuid4().hex[:8] + "ab" * 16).lower()
    _registry_job(session, registry, chain="ethereum", version=STALE)
    _registry_job(session, registry, chain="base", version=ANALYSIS_SCHEMA_VERSION)

    cap = _evaluate(session, registry, chain_id=1)

    assert cap.kind == "external_check_only"
    assert cap.check is not None and cap.check.target_address == registry


def test_the_twin_still_answers_on_its_own_chain(session):
    registry = ("0x" + uuid.uuid4().hex[:8] + "ac" * 16).lower()
    _registry_job(session, registry, chain="ethereum", version=STALE)
    _registry_job(session, registry, chain="base", version=ANALYSIS_SCHEMA_VERSION)

    cap = _evaluate(session, registry, chain_id=8453)

    assert (cap.kind, cap.members, cap.membership_quality) == ("finite_set", [], "exact")


def test_a_chainless_mainnet_registry_job_is_found_on_mainnet(session):
    registry = ("0x" + uuid.uuid4().hex[:8] + "ad" * 16).lower()
    session.info["minted"].append(registry)
    job = create_job(session, {"address": registry})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    session.commit()
    store_artifact(session, job.id, "predicate_trees", data=_TWIN_TREES)
    session.commit()

    lookup = find_analysis_job_for_address(session, registry, chain="ethereum")
    assert lookup is not None and lookup.analysis_job.id == job.id
    assert find_analysis_job_for_address(session, registry, chain="base") is None
