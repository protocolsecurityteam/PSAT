"""An unset Solmate-style ``authority`` is proven by the controller read at the snapshot block: no dependency job is
spawned for the zero address, and the ``canCall`` branch admits nobody, so ``requiresAuth`` publishes owner-only. A
failed ``authority`` read proves nothing and stays undetermined.

Real compile, real tracking plan, real snapshot, real dependency emission and real resolver; only the JSON-RPC HTTP wire
is stubbed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import select

from tests.conftest import requires_postgres

pytestmark = [requires_postgres, pytest.mark.compile]

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "composed" / "auth_modifier_controller.sol"
SUBJECT = "0x" + "5a" * 20
OWNER = "0x" + "0e" * 20
ZERO = "0x" + "0" * 40
BLOCK = 21_000_000
RPC_URL = "http://rpc.unset-authority.test"
REQUIRES_AUTH = ("setHook(address)", "manage(PingTarget,uint256)", "transferOwnership(address)")


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _word(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


class _Wire:
    """The JSON-RPC HTTP session. ``authority()`` answers with ``authority``, or an RPC error when it is ``None``."""

    def __init__(self, authority: str | None):
        self.getters = {_selector("owner()"): OWNER, _selector("authority()"): authority}

    def post(self, _url, *, json, **_kwargs):
        if isinstance(json, list):
            return _Response([self._answer(item) for item in json])
        return _Response(self._answer(json))

    def _answer(self, item: dict[str, Any]) -> dict[str, Any]:
        method, params = item["method"], item["params"]
        result: Any = None
        if method == "eth_blockNumber":
            result = hex(BLOCK)
        elif method == "eth_chainId":
            result = "0x1"
        elif method == "eth_getCode":
            result = "0x"
        elif method == "eth_call" and params[0]["to"].lower() == SUBJECT:
            value = self.getters.get(params[0]["data"][:10])
            result = _word(value) if value is not None else None
        if result is None:
            return {"jsonrpc": "2.0", "id": item.get("id"), "error": {"code": -32000, "message": "header not found"}}
        return {"jsonrpc": "2.0", "id": item.get("id"), "result": result}


class _Response:
    status_code = 200

    def __init__(self, payload: Any):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self.payload


@pytest.fixture(scope="module")
def compiled(tmp_path_factory) -> tuple[dict[str, Any], dict[str, Any]]:
    from services.resolution.tracking_plan import build_control_tracking_plan
    from services.static.contract_analysis_pipeline.core import collect_contract_analysis_with_artifacts

    project = tmp_path_factory.mktemp("unset_authority") / "AuthModifierController"
    (project / "src").mkdir(parents=True)
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project / "src" / "AuthModifierController.sol").write_text(FIXTURE.read_text())
    (project / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": SUBJECT,
                "contract_name": "AuthModifierController",
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
    )
    analysis, trees, _effects = collect_contract_analysis_with_artifacts(project)
    assert isinstance(trees, dict)
    return cast(dict[str, Any], build_control_tracking_plan(analysis)), trees


def _run(db_session, monkeypatch, compiled, *, authority: str | None) -> tuple[Any, dict[str, Any]]:
    """Snapshot, dependency emission and controller rows as the resolution stage writes them, then the resolver."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, ControllerValue, JobStage, JobStatus
    from db.queue import create_job, store_artifact
    from services.resolution.capability_resolver import resolve_contract_capabilities
    from services.resolution.tracking import build_control_snapshot
    from workers.resolution_worker import ResolutionWorker

    plan, trees = compiled
    monkeypatch.setattr("services.clients.rpc._get_session", lambda: _Wire(authority))

    job = create_job(db_session, {"address": SUBJECT, "chain": "ethereum", "name": "AuthModifierController"})
    job.status = JobStatus.processing
    job.stage = JobStage.resolution
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    db_session.commit()
    store_artifact(db_session, job.id, "predicate_trees", data=trees)
    contract = Contract(address=SUBJECT, chain="ethereum", job_id=job.id)
    db_session.add(contract)
    db_session.commit()

    snapshot = build_control_snapshot(cast(Any, plan), RPC_URL, chain_id=1)
    ResolutionWorker()._emit_dependency_edges_from_predicate_trees(db_session, job, snapshot, RPC_URL)
    for cid, entry in snapshot["controller_values"].items():
        db_session.add(
            ControllerValue(
                contract_id=contract.id,
                controller_id=cid,
                value=entry.get("value"),
                resolved_type=entry.get("resolved_type"),
                source=entry.get("source"),
                block_number=snapshot.get("block_number"),
                observed_via=entry.get("observed_via"),
            )
        )
    db_session.commit()

    out = resolve_contract_capabilities(
        db_session, address=SUBJECT, chain_id=1, block=BLOCK, job_id=job.id, chain="ethereum"
    )
    assert out is not None
    return job, out


def _spawned(db_session, depender) -> tuple[list[str], list[str]]:
    from db.models import Job, JobDependency

    db_session.expire_all()
    jobs = [job.address for job in db_session.execute(select(Job).where(Job.id != depender.id)).scalars()]
    edges = [
        edge.provider_address
        for edge in db_session.execute(
            select(JobDependency).where(JobDependency.depender_job_id == depender.id)
        ).scalars()
    ]
    return jobs, edges


def test_an_unset_authority_spawns_no_job_and_publishes_owner_only(db_session, monkeypatch, compiled):
    from services.policy.capability_surface import project_capability_surface

    job, out = _run(db_session, monkeypatch, compiled, authority=ZERO)

    assert _spawned(db_session, job) == ([], [])
    for signature in REQUIRES_AUTH:
        cap = out[signature]
        owner_only = ("finite_set", [OWNER], "exact")
        assert (cap["kind"], cap.get("members"), cap.get("membership_quality")) == owner_only, signature
        surface = project_capability_surface(cap)
        assert not surface.authority_public, signature
        assert [row["address"] for row in surface.principal_rows] == [OWNER], signature


def test_a_failed_authority_read_is_not_published_as_owner_only(db_session, monkeypatch, compiled):
    job, out = _run(db_session, monkeypatch, compiled, authority=None)

    assert _spawned(db_session, job) == ([], [])
    for signature in REQUIRES_AUTH:
        cap = out[signature]
        # The owner branch stands beside an unresolved authority check, never folded into an exact owner-only set.
        assert cap["kind"] == "OR", signature
        assert any(child["kind"] == "external_check_only" for child in cap["children"]), signature


def test_a_set_authority_still_spawns_its_provider(db_session, monkeypatch, compiled):
    authority = "0x" + "a7" * 20
    job, _out = _run(db_session, monkeypatch, compiled, authority=authority)

    assert _spawned(db_session, job) == ([authority], [authority])


def _gate_leaf(operator: str, authority_contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "operator": operator,
            "authority_role": "delegated_authority",
            "operands": [{"source": "msg_sender"}],
            "references_msg_sender": True,
            "callee_state_mutability": "view",
            "gate_kind": "require",
            "callee_signature": "isAllowed(address)",
            "set_descriptor": {
                "kind": "external_set",
                "key_sources": [{"source": "msg_sender"}],
                "authority_contract": authority_contract,
                "callee_signature": "isAllowed(address)",
            },
        },
    }


@pytest.mark.parametrize("operator", ["truthy", "falsy"])
@pytest.mark.parametrize(
    "authority_contract",
    [
        pytest.param({"address_source": {"source": "state_variable", "state_variable_name": "gate"}}, id="read-zero"),
        pytest.param({"address": ZERO}, id="literal-zero"),
    ],
)
def test_a_call_to_the_zero_address_admits_nobody_whichever_way_the_result_is_read(operator, authority_contract):
    from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree

    cap = evaluate_tree(
        cast(Any, _gate_leaf(operator, authority_contract)),
        EvaluationContext(contract_address=SUBJECT, state_var_values={"gate": ZERO}),
    )

    assert (cap.kind, cap.members, cap.membership_quality) == ("finite_set", [], "exact")


def test_an_unread_call_target_is_not_taken_as_zero():
    from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree

    unread = {"address_source": {"source": "state_variable", "state_variable_name": "gate"}}
    cap = evaluate_tree(
        cast(Any, _gate_leaf("truthy", unread)), EvaluationContext(contract_address=SUBJECT, state_var_values={})
    )

    assert cap.kind == "external_check_only"
