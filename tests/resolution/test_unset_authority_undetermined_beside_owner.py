"""An unset (read-zero) Solmate-style ``authority`` spawns no dependency job for the zero address, so nothing holds the
contract's policy stage; its ``requiresAuth`` capability is the honest undetermined result, the owner beside an
unresolved ``canCall`` check. Nothing short of a read at the subject (a failed read, an implementation's storage) is
taken as that read.

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
IMPL = "0x" + "1d" * 20
OVERRIDE = "0x" + "a8" * 20
ZERO = "0x" + "0" * 40
BLOCK = 21_000_000
RPC_URL = "http://rpc.unset-authority.test"
REQUIRES_AUTH = ("setHook(address)", "manage(PingTarget,uint256)", "transferOwnership(address)")

# The value the guard compares isn't only ``authority``: a set ``zOverride`` replaces it.
_OVERRIDE_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface AuthorityLike { function canCall(address user, address target, bytes4 sig) external view returns (bool); }
contract OverrideAuth {
    address public owner;
    AuthorityLike public authority;
    AuthorityLike public zOverride;
    uint256 public hook;
    modifier requiresAuth() { require(isAuthorized(msg.sender, msg.sig), "UNAUTHORIZED"); _; }
    function isAuthorized(address user, bytes4 sig) internal view returns (bool) {
        AuthorityLike a = authority;
        if (address(zOverride) != address(0)) a = zOverride;
        return (address(a) != address(0) && a.canCall(user, address(this), sig)) || user == owner;
    }
    function setHook(uint256 v) external requiresAuth { hook = v; }
}
"""

# The call runs before the owner check and reverts on a zero authority, so nobody passes.
_CALL_FIRST_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface AuthorityLike { function canCall(address user, address target, bytes4 sig) external view returns (bool); }
contract CallFirst {
    address public owner;
    AuthorityLike public authority;
    uint256 public hook;
    function setHook(uint256 v) external {
        require(authority.canCall(msg.sender, address(this), msg.sig) || msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }
}
"""


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _word(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


class _Wire:
    """The JSON-RPC HTTP session. Each address answers its getters from its own map; a getter mapped to ``None`` (or
    absent) answers with an RPC error.
    """

    def __init__(self, getters: dict[str, dict[str, str | None]]):
        self.getters = {
            address: {_selector(sig): value for sig, value in by_sig.items()} for address, by_sig in getters.items()
        }

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
        elif method == "eth_call":
            value = self.getters.get(params[0]["to"].lower(), {}).get(params[0]["data"][:10])
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
def compile_contract(tmp_path_factory):
    from services.resolution.tracking_plan import build_control_tracking_plan
    from services.static.contract_analysis_pipeline.core import collect_contract_analysis_with_artifacts

    built: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}

    def compile_(name: str, source: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if name not in built:
            project = tmp_path_factory.mktemp(name) / name
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
            )
            (project / "src" / f"{name}.sol").write_text(source)
            (project / "contract_meta.json").write_text(
                json.dumps({"address": SUBJECT, "contract_name": name, "compiler_version": "v0.8.19+commit.7dd6d404"})
            )
            analysis, trees, _effects = collect_contract_analysis_with_artifacts(project)
            assert isinstance(trees, dict)
            built[name] = (cast(dict[str, Any], build_control_tracking_plan(analysis)), trees)
        return built[name]

    return compile_


@pytest.fixture(scope="module")
def compiled(compile_contract) -> tuple[dict[str, Any], dict[str, Any]]:
    return compile_contract("AuthModifierController", FIXTURE.read_text())


def _run(
    db_session,
    monkeypatch,
    compiled,
    *,
    authority: str | None,
    owner: str | None = OWNER,
    implementation: dict[str, str | None] | None = None,
    extra_getters: dict[str, str | None] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Snapshot, dependency emission and controller rows as the resolution stage writes them, then the resolver."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, ControllerValue, JobStage, JobStatus
    from db.queue import create_job, store_artifact
    from services.resolution.capability_resolver import resolve_contract_capabilities
    from services.resolution.tracking import build_control_snapshot
    from workers.resolution_worker import ResolutionWorker

    plan, trees = compiled
    getters: dict[str, dict[str, str | None]] = {
        SUBJECT: {"owner()": owner, "authority()": authority, **(extra_getters or {})}
    }
    if implementation is not None:
        getters[IMPL] = implementation
    monkeypatch.setattr("services.clients.rpc._get_session", lambda: _Wire(getters))

    job = create_job(db_session, {"address": SUBJECT, "chain": "ethereum", "name": "AuthModifierController"})
    job.status = JobStatus.processing
    job.stage = JobStage.resolution
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    db_session.commit()
    store_artifact(db_session, job.id, "predicate_trees", data=trees)
    contract = Contract(address=SUBJECT, chain="ethereum", job_id=job.id)
    db_session.add(contract)
    db_session.commit()

    snapshot = build_control_snapshot(
        cast(Any, plan), RPC_URL, chain_id=1, getter_fallback_address=IMPL if implementation is not None else None
    )
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


def test_an_unset_authority_spawns_no_job_and_stays_undetermined_beside_the_owner(db_session, monkeypatch, compiled):
    job, out = _run(db_session, monkeypatch, compiled, authority=ZERO)

    # No job and no edge, so nothing pending or degraded on a dependency.
    assert _spawned(db_session, job) == ([], [])
    for signature in REQUIRES_AUTH:
        cap = out[signature]
        assert not (cap["kind"] == "finite_set" and cap.get("membership_quality") == "exact"), signature
        assert _undetermined_beside_owner(cap), signature
        owners = [child for child in cap["children"] if child["kind"] == "finite_set"]
        assert [child["members"] for child in owners] == [[OWNER]], signature


def test_a_failed_authority_read_is_not_published_as_owner_only(db_session, monkeypatch, compiled):
    job, out = _run(db_session, monkeypatch, compiled, authority=None)

    assert _spawned(db_session, job) == ([], [])
    for signature in REQUIRES_AUTH:
        cap = out[signature]
        # The owner branch stands beside an unresolved authority check, never folded into an exact owner-only set.
        assert cap["kind"] == "OR", signature
        assert any(child["kind"] == "external_check_only" for child in cap["children"]), signature


def test_a_proxy_whose_authority_read_fails_is_not_answered_by_the_implementations_zero(
    db_session, monkeypatch, compiled
):
    job, out = _run(
        db_session, monkeypatch, compiled, authority=None, implementation={"owner()": ZERO, "authority()": ZERO}
    )

    assert _spawned(db_session, job) == ([], [])
    for signature in REQUIRES_AUTH:
        cap = out[signature]
        assert cap["kind"] == "OR", signature
        assert any(child["kind"] == "external_check_only" for child in cap["children"]), signature


def test_a_proxy_whose_owner_read_fails_is_not_published_as_owned_by_nobody(db_session, monkeypatch, compiled):
    _job, out = _run(
        db_session,
        monkeypatch,
        compiled,
        authority=ZERO,
        owner=None,
        implementation={"owner()": ZERO, "authority()": ZERO},
    )

    for signature in REQUIRES_AUTH:
        cap = out[signature]
        assert not (cap["kind"] == "finite_set" and cap.get("membership_quality") == "exact"), (signature, cap)


def _undetermined_beside_owner(cap: dict[str, Any]) -> bool:
    return cap["kind"] == "OR" and any(child["kind"] == "external_check_only" for child in cap["children"])


def test_a_set_authority_keeps_todays_path_and_spawns_its_provider(db_session, monkeypatch, compiled):
    authority = "0x" + "a7" * 20
    job, out = _run(db_session, monkeypatch, compiled, authority=authority)

    assert _spawned(db_session, job) == ([authority], [authority])
    for signature in REQUIRES_AUTH:
        assert _undetermined_beside_owner(out[signature]), signature


def test_an_overridable_zero_authority_is_not_exact_and_spawns_no_zero_job(db_session, monkeypatch, compile_contract):
    job, out = _run(
        db_session,
        monkeypatch,
        compile_contract("OverrideAuth", _OVERRIDE_SOURCE),
        authority=ZERO,
        extra_getters={"zOverride()": OVERRIDE},
    )

    assert ZERO not in _spawned(db_session, job)[0]
    cap = out["setHook(uint256)"]
    assert not (cap["kind"] == "finite_set" and cap.get("membership_quality") == "exact"), cap
    assert _undetermined_beside_owner(cap), cap


def test_a_zero_authority_called_before_the_owner_check_is_not_exact(db_session, monkeypatch, compile_contract):
    job, out = _run(db_session, monkeypatch, compile_contract("CallFirst", _CALL_FIRST_SOURCE), authority=ZERO)

    assert _spawned(db_session, job) == ([], [])
    cap = out["setHook(uint256)"]
    assert not (cap["kind"] == "finite_set" and cap.get("membership_quality") == "exact"), cap
    assert _undetermined_beside_owner(cap), cap
