"""A failed ``predicate_trees`` or ``effects`` build is a degraded analysis end to end: reported incomplete, stored
apart from the facts policy reads, never reused as a cache donor, and read as not determined wherever an older job
stored the error shape under the artifact's own name.
"""

from __future__ import annotations

import shutil
import textwrap

import pytest

from db.queue import failed_semantic_artifact, usable_semantic_artifact
from tests.cache_helpers import ADDR_A, _create_completed_job_with_static_data, db_session  # noqa: F401
from tests.conftest import requires_postgres
from tests.support.materializations import cm_db  # noqa: F401

SOURCE = textwrap.dedent(
    """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        uint256 public value;
        constructor() { owner = msg.sender; }
        function set(uint256 v) external { require(msg.sender == owner); value = v; }
    }
    """
).strip()

ERROR_SHAPE = {"schema_version": "semantic", "error": "forced"}


def _boom(*_a, **_k):
    raise RuntimeError("forced build failure")


@pytest.mark.parametrize(
    ("builder", "phase", "artifact_index"),
    [
        ("build_predicate_artifacts_with_pause_info", "predicate_trees_emit", 1),
        ("build_effects", "effects_emit", 2),
    ],
)
def test_a_failed_semantic_build_reports_the_analysis_incomplete(tmp_path, monkeypatch, builder, phase, artifact_index):
    from services.static.contract_analysis_pipeline import core
    from tests.support.foundry_project import write_foundry_project

    healthy = core.collect_contract_analysis_with_artifacts(write_foundry_project(tmp_path / "ok", "C", SOURCE))
    assert healthy[0]["analysis_status"] == {"static_analysis_completed": True, "errors": []}

    monkeypatch.setattr(core, builder, _boom)
    degraded = core.collect_contract_analysis_with_artifacts(write_foundry_project(tmp_path / "bad", "C", SOURCE))

    status = degraded[0]["analysis_status"]
    assert status["static_analysis_completed"] is False
    assert [error.split(":", 1)[0] for error in status["errors"]] == [phase]
    assert failed_semantic_artifact(phase.removesuffix("_emit"), degraded[artifact_index])


def test_the_error_shape_reads_as_no_artifact():
    assert usable_semantic_artifact("predicate_trees", ERROR_SHAPE) is None
    assert usable_semantic_artifact("effects", ERROR_SHAPE) is None
    trees = {"schema_version": "semantic", "trees": {}, "error": "a stray key next to a payload is still a payload"}
    assert usable_semantic_artifact("predicate_trees", trees) is trees


@requires_postgres
def test_the_static_worker_keeps_a_failed_build_away_from_the_facts(db_session, tmp_path, monkeypatch):  # noqa: F811
    from db.queue import create_job, get_artifact
    from services.static.contract_analysis_pipeline import core
    from tests.support.foundry_project import write_foundry_project
    from workers.static_worker import StaticWorker

    job = create_job(db_session, {"address": ADDR_A, "name": "C"})
    monkeypatch.setattr(core, "build_predicate_artifacts_with_pause_info", _boom)
    worker = StaticWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    analysis = worker._run_analysis_phase(
        db_session, job, write_foundry_project(tmp_path, "C", SOURCE), "C", ADDR_A.lower()
    )

    assert analysis is not None and analysis["analysis_status"]["static_analysis_completed"] is False
    assert get_artifact(db_session, job.id, "predicate_trees") is None
    stored_error = get_artifact(db_session, job.id, "predicate_trees_error")
    assert isinstance(stored_error, dict) and "forced build failure" in stored_error["error"]
    effects = get_artifact(db_session, job.id, "effects")
    assert isinstance(effects, dict) and "functions" in effects


@requires_postgres
@pytest.mark.parametrize(
    "degradation",
    ["legacy_trees_error_shape", "legacy_effects_error_shape", "effects_error_artifact", "effects_missing"],
)
def test_a_degraded_donor_is_never_a_static_cache(db_session, degradation):  # noqa: F811
    from db.models import Artifact
    from db.queue import find_completed_static_cache, store_artifact

    donor = _create_completed_job_with_static_data(db_session, address=ADDR_A)
    assert find_completed_static_cache(db_session, ADDR_A) is not None, "guard: the healthy donor is reusable"

    if degradation == "legacy_trees_error_shape":
        store_artifact(db_session, donor.id, "predicate_trees", data=dict(ERROR_SHAPE))
    elif degradation == "legacy_effects_error_shape":
        store_artifact(db_session, donor.id, "effects", data=dict(ERROR_SHAPE))
    elif degradation == "effects_error_artifact":
        store_artifact(db_session, donor.id, "effects_error", data=dict(ERROR_SHAPE))
    else:
        db_session.query(Artifact).filter(Artifact.job_id == donor.id, Artifact.name == "effects").delete()
    db_session.commit()

    assert find_completed_static_cache(db_session, ADDR_A) is None


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            {"analysis": {"analysis_status": {"static_analysis_completed": False, "errors": ["effects_emit: x"]}}},
            id="analysis_reports_failure",
        ),
        pytest.param({"predicate_trees": dict(ERROR_SHAPE)}, id="legacy_trees_error_shape"),
    ],
)
@requires_postgres
def test_a_degraded_bundle_is_never_materialized(cm_db, overrides):  # noqa: F811
    from db.contract_materializations import (
        PRODUCED_BY_PIPELINE,
        PUBLISH_INCOMPLETE_BUNDLE,
        PUBLISH_WRITTEN,
        build_provenance,
        publish_materialization,
    )
    from db.models import ContractMaterialization

    kwargs = {
        "chain": "ethereum",
        "address": ADDR_A,
        "bytecode_keccak": "0x" + "11" * 32,
        "contract_name": "C",
        "analysis": {"subject": {"address": ADDR_A, "name": "C"}},
        "tracking_plan": {"contract_address": ADDR_A, "tracked_controllers": []},
        "predicate_trees": {"schema_version": "semantic", "trees": {}},
        "provenance": build_provenance(PRODUCED_BY_PIPELINE, source_job_id="job-1"),
    }
    degraded = {**kwargs, **overrides}
    if "analysis" in overrides:
        degraded["analysis"] = {**kwargs["analysis"], **overrides["analysis"]}

    assert publish_materialization(**degraded) == PUBLISH_INCOMPLETE_BUNDLE
    assert cm_db.query(ContractMaterialization).count() == 0
    assert publish_materialization(**kwargs) == PUBLISH_WRITTEN


def test_a_degraded_nested_build_fails_the_node_instead_of_caching(tmp_path, monkeypatch):
    from services.resolution import recursive
    from services.static.contract_analysis_pipeline import core
    from tests.support.foundry_project import write_foundry_project

    monkeypatch.setattr(recursive, "fetch", lambda address, chain_id: {"ContractName": "C"})
    template = write_foundry_project(tmp_path, "C", SOURCE)
    monkeypatch.setattr(
        recursive, "scaffold", lambda address, result, project_dir: shutil.copytree(template, project_dir)
    )
    name, analysis, _plan, _trees = recursive._build_static_artifacts(ADDR_A, "t", chain_id=1)
    assert (name, analysis["analysis_status"]["static_analysis_completed"]) == ("C", True)

    monkeypatch.setattr(core, "build_effects", _boom)
    with pytest.raises(recursive.DegradedStaticAnalysisError, match="effects_emit"):
        recursive._build_static_artifacts(ADDR_A, "t", chain_id=1)
