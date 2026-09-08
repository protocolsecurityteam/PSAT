"""Canonical publication retains updates, deduplicates facts, and projects offline."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import cast

from sqlalchemy import func, select

from db.models import (
    Artifact,
    AssessmentAnalysis,
    AssessmentAnalysisOutput,
    AssessmentClaim,
    AssessmentClaimEvidence,
    AssessmentEvidence,
    AssessmentImportManifest,
    AssessmentPayload,
    AssessmentSubject,
    Job,
    JobStage,
    JobStatus,
)
from db.queue import get_artifact, store_artifact
from schemas.assessment import Assessment
from schemas.temporal_assessment import CorrectionReason, CorrectionTargetKind
from services.assessment import add_observations, add_policy, build_static_assessment
from services.assessment.migrate import import_legacy_artifacts
from services.assessment.repository import load_temporal_assessment, publication_history, record_correction
from tests.conftest import requires_postgres

ADDRESS = "0x" + "11" * 20
ALICE = "0x" + "aa" * 20
BOB = "0x" + "bb" * 20


def _job(session):
    job = Job(
        id=uuid.uuid4(),
        address=ADDRESS,
        chain_id=1,
        request={"address": ADDRESS, "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
    )
    session.add(job)
    session.commit()
    return job


def _assessment(owner: str, block: int, *, block_hash: str | None = None) -> Assessment:
    base = build_static_assessment(
        chain_id=1,
        address=ADDRESS,
        contract_name="Vault",
        code_hash="0x" + "01" * 32,
        source_hash="0x" + "02" * 32,
        static_facts={
            "controller_tracking": [
                {
                    "controller_id": "state_variable:owner",
                    "label": "owner",
                    "kind": "state_variable",
                    "source": "owner",
                    "read_spec": {"strategy": "getter_call", "target": "owner"},
                    "confidence": "exact",
                    "tracking_mode": "state_only",
                    "writer_functions": [],
                    "associated_events": [],
                    "polling_sources": [],
                    "notes": [],
                }
            ]
        },
        effects={
            "functions": {
                "setOwner(address)": {
                    "abi_signature": "setOwner(address)",
                    "state_changing": True,
                    "claims": [],
                }
            }
        },
        predicate_trees={"trees": {}},
    )
    observed = add_observations(
        base,
        {
            "block_number": block,
            "controller_values": {
                "state_variable:owner": {
                    "value": owner,
                    "resolved_type": "eoa",
                    "block_number": block,
                    **({"block_hash": block_hash} if block_hash else {}),
                    "observed_via": "eth_call",
                    "details": {},
                }
            },
            **({"block_hash": block_hash} if block_hash else {}),
        },
    )
    return add_policy(
        observed,
        [
            {
                "function": "setOwner(address)",
                "abi_signature": "setOwner(address)",
                "capability_expr": {"kind": "finite_set", "members": [owner], "membership_quality": "exact"},
            }
        ],
        chain_id=1,
    )


@requires_postgres
def test_assessment_artifact_is_a_projection_of_canonical_rows(db_session):
    job = _job(db_session)
    expected = _assessment(ALICE, 100)
    store_artifact(db_session, job.id, "assessment", data=expected)

    assert (
        db_session.scalar(
            select(func.count()).select_from(Artifact).where(Artifact.job_id == job.id, Artifact.name == "assessment")
        )
        == 0
    )
    assert get_artifact(db_session, job.id, "assessment") == expected
    temporal = load_temporal_assessment(db_session, job.id)
    assert temporal is not None
    assert isinstance(temporal["subjects"], list)
    assert isinstance(temporal["claims"], list)
    assert all("id" in row for row in temporal["subjects"] + temporal["claims"])


@requires_postgres
def test_identical_rerun_reuses_claims_and_retains_analysis_attempts(db_session):
    job = _job(db_session)
    value = _assessment(ALICE, 100)
    store_artifact(db_session, job.id, "assessment", data=value)
    claims = db_session.scalar(select(func.count()).select_from(AssessmentClaim))
    analyses = db_session.scalar(select(func.count()).select_from(AssessmentAnalysis))
    outputs = db_session.scalar(select(func.count()).select_from(AssessmentAnalysisOutput))
    store_artifact(db_session, job.id, "assessment", data=value)

    assert db_session.scalar(select(func.count()).select_from(AssessmentClaim)) == claims
    assert db_session.scalar(select(func.count()).select_from(AssessmentAnalysis)) == analyses * 2
    assert db_session.scalar(select(func.count()).select_from(AssessmentAnalysisOutput)) == outputs * 2
    assert len(publication_history(db_session, job.id)) == 2


@requires_postgres
def test_owner_update_keeps_history_and_latest_projection(db_session):
    job = _job(db_session)
    alice = _assessment(ALICE, 100)
    bob = _assessment(BOB, 200)
    store_artifact(db_session, job.id, "assessment", data=alice)
    store_artifact(db_session, job.id, "assessment", data=bob)

    latest = cast(Assessment, get_artifact(db_session, job.id, "assessment"))
    authorities = [
        claim["proposition"].get("authority")
        for claim in latest["claims"].values()
        if claim["proposition"]["kind"] == "function_authority"
    ]
    assert any(BOB in str(authority) for authority in authorities)
    assert not any(ALICE in str(authority) for authority in authorities)
    assert len(publication_history(db_session, job.id)) == 2
    # Old and new proof rows remain; the latest publication chooses only Bob.
    assert db_session.scalar(select(func.count()).select_from(AssessmentClaim)) >= 2


@requires_postgres
def test_a_to_b_to_a_preserves_occurrences_without_duplicate_subjects(db_session):
    job = _job(db_session)
    for owner, block in ((ALICE, 100), (BOB, 200), (ALICE, 300)):
        store_artifact(db_session, job.id, "assessment", data=_assessment(owner, block))
    history = publication_history(db_session, job.id)
    assert [row["block_number"] for row in history] == ["100", "200", "300"]
    address_subjects = db_session.scalars(select(AssessmentSubject).where(AssessmentSubject.kind == "address")).all()
    identities = {(row.identity.get("chain_id"), row.identity.get("address")) for row in address_subjects}
    assert (1, ALICE) in identities and (1, BOB) in identities
    assert len([item for item in identities if item[1] == ALICE]) == 1


@requires_postgres
def test_repeated_static_statement_can_have_distinct_temporal_proofs(db_session):
    job = _job(db_session)
    first = _assessment(ALICE, 100)
    second = _assessment(ALICE, 200)
    store_artifact(db_session, job.id, "assessment", data=first)
    store_artifact(db_session, job.id, "assessment", data=second)
    rows = db_session.scalars(select(AssessmentClaim)).all()
    authorities = [row for row in rows if row.kind.value == "function_authority"]
    assert len(authorities) == 2


@requires_postgres
def test_exact_as_of_update_uses_hash_anchored_publication(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment(ALICE, 100, block_hash="0x" + "10" * 32))
    store_artifact(db_session, job.id, "assessment", data=_assessment(BOB, 200, block_hash="0x" + "20" * 32))

    at_100 = load_temporal_assessment(db_session, job.id, at_block=100)
    at_200 = load_temporal_assessment(db_session, job.id, at_block=200)
    assert at_100 is not None and at_200 is not None
    assert at_100["view"]["scope"]["block_hash"] == "0x" + "10" * 32
    assert at_200["view"]["scope"]["block_hash"] == "0x" + "20" * 32
    assert at_100["view"]["scope"]["kind"] == at_200["view"]["scope"]["kind"] == "point"


@requires_postgres
def test_hashless_update_is_reported_not_fabricated_exact_point(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment(ALICE, 100))

    current = load_temporal_assessment(db_session, job.id)
    assert current is not None
    assert current["view"]["scope"]["kind"] == "reported"
    assert all(claim["scope_kind"].value != "point" for claim in current["claims"])
    assert load_temporal_assessment(db_session, job.id, at_block=100) is None


@requires_postgres
def test_reorg_correction_preserves_rows_but_removes_dependent_answers(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment(ALICE, 100, block_hash="0x" + "10" * 32))
    before = load_temporal_assessment(db_session, job.id)
    assert before is not None
    authority = next(claim for claim in before["claims"] if claim["kind"].value == "function_authority")
    observed_evidence = next(
        evidence_id
        for evidence_id in authority["evidence"]
        if db_session.get(AssessmentEvidence, evidence_id).block_hash is not None
    )
    known_before = datetime.fromisoformat(publication_history(db_session, job.id)[-1]["recorded_at"])
    claim_count = db_session.scalar(select(func.count()).select_from(AssessmentClaim))
    evidence_count = db_session.scalar(select(func.count()).select_from(AssessmentEvidence))

    record_correction(
        db_session,
        job.id,
        target_kind=CorrectionTargetKind.evidence,
        target_id=observed_evidence,
        reason=CorrectionReason.reorg,
        detail={"canonical_block_hash": "0x" + "99" * 32},
    )
    db_session.commit()

    current = load_temporal_assessment(db_session, job.id)
    historical_knowledge = load_temporal_assessment(db_session, job.id, known_at=known_before)
    assert current is not None and historical_knowledge is not None
    assert not any(claim["kind"].value == "function_authority" for claim in current["claims"])
    assert any(claim["kind"].value == "function_authority" for claim in historical_knowledge["claims"])
    assert current["corrections"][0]["reason"] == CorrectionReason.reorg
    assert db_session.scalar(select(func.count()).select_from(AssessmentClaim)) == claim_count
    assert db_session.scalar(select(func.count()).select_from(AssessmentEvidence)) == evidence_count
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AssessmentClaimEvidence)
            .where(AssessmentClaimEvidence.evidence_id == observed_evidence)
        )
        >= 1
    )


@requires_postgres
def test_legacy_import_archives_source_and_is_idempotent(db_session):
    job = _job(db_session)
    assessment = _assessment(ALICE, 100)
    assessment_row = Artifact(job_id=job.id, name="assessment", data=assessment)
    history = {
        "schema_version": "principal_history.v1",
        "contract_address": ADDRESS,
        "chain_id": 1,
        "status": "no_external_authority",
        "sources": [],
        "role_membership": [],
        "capability_roles": [],
        "function_permissions": [],
        "public_capabilities": [],
    }
    history_row = Artifact(job_id=job.id, name="principal_history", data=history)
    db_session.add_all([assessment_row, history_row])
    db_session.commit()

    first = import_legacy_artifacts(db_session)
    second = import_legacy_artifacts(db_session)

    assert first["imported"] == {"assessment": 1, "principal_history": 1}
    assert second["imported"] == {"assessment": 0, "principal_history": 0}
    assert (
        db_session.scalar(
            select(func.count()).select_from(Artifact).where(Artifact.name.in_(("assessment", "principal_history")))
        )
        == 0
    )
    manifests = db_session.scalars(select(AssessmentImportManifest)).all()
    assert {row.artifact_id for row in manifests} == {assessment_row.id, history_row.id}
    assert all(db_session.get(AssessmentPayload, row.source_payload_id) is not None for row in manifests)
    assert get_artifact(db_session, job.id, "assessment") == assessment
    assert get_artifact(db_session, job.id, "principal_history") == {
        key: value for key, value in history.items() if key != "schema_version"
    }


@requires_postgres
def test_closed_permission_update_keeps_exact_event_ordered_interval(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment(ALICE, 100))
    history = {
        "contract_address": ADDRESS,
        "chain_id": 1,
        "status": "ok",
        "sources": [{"authority_address": ADDRESS, "status": "ok"}],
        "role_membership": [],
        "capability_roles": [],
        "public_capabilities": [],
        "function_permissions": [
            {
                "authority_address": ADDRESS,
                "function": "setOwner(address)",
                "selector": "0x13af4035",
                "principal": ALICE,
                "roles": [1],
                "granted_at_block": 100,
                "granted_at_block_hash": "0x" + "10" * 32,
                "granted_at_tx": "0x" + "a1" * 32,
                "granted_at_transaction_index": 2,
                "granted_at_log_index": 3,
                "revoked_at_block": 200,
                "revoked_at_block_hash": "0x" + "20" * 32,
                "revoked_at_tx": "0x" + "b2" * 32,
                "revoked_at_transaction_index": 4,
                "revoked_at_log_index": 5,
                "status": "revoked",
            }
        ],
    }
    store_artifact(db_session, job.id, "principal_history", data=history)

    historical_claim = db_session.scalars(
        select(AssessmentClaim).where(AssessmentClaim.rule == "historical_interval")
    ).one()
    assert historical_claim.scope_kind.value == "interval"
    assert historical_claim.scope["from_transaction_index"] == 2
    assert historical_claim.scope["from_log_index"] == 3
    assert historical_claim.scope["through_transaction_index"] == 4
    assert historical_claim.scope["through_log_index"] == 5


@requires_postgres
def test_one_role_event_can_support_membership_and_function_history(db_session):
    """One emitted grant can legitimately produce several derived history rows."""
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment(ALICE, 100))
    occurrence = {
        "authority_address": ADDRESS,
        "principal": ALICE,
        "role": 1,
        "granted_at_block": 100,
        "granted_at_block_hash": "0x" + "10" * 32,
        "granted_at_tx": "0x" + "a1" * 32,
        "granted_at_transaction_index": 2,
        "granted_at_log_index": 3,
        "status": "active",
    }
    history = {
        "contract_address": ADDRESS,
        "chain_id": 1,
        "status": "ok",
        "sources": [{"authority_address": ADDRESS, "status": "ok"}],
        "role_membership": [{**occurrence}],
        "capability_roles": [],
        "function_permissions": [
            {
                **occurrence,
                "function": "setOwner(address)",
                "selector": "0x13af4035",
                "roles": [1],
            }
        ],
        "public_capabilities": [],
    }

    store_artifact(db_session, job.id, "principal_history", data=history)
    projected = get_artifact(db_session, job.id, "principal_history")

    assert isinstance(projected, dict)
    assert len(projected["role_membership"]) == 1
    assert len(projected["function_permissions"]) == 1
    assert projected["function_permissions"][0]["granted_at_block_hash"] == occurrence["granted_at_block_hash"]

    historical_claims = db_session.scalars(
        select(AssessmentClaim).where(AssessmentClaim.rule == "historical_interval")
    ).all()
    assert len(historical_claims) == 2
    assert all(claim.scope["from_block_hash"] == occurrence["granted_at_block_hash"] for claim in historical_claims)
    history_evidence = db_session.scalars(
        select(AssessmentEvidence).where(AssessmentEvidence.source["component"].astext == "principal_history")
    ).all()
    assert len(history_evidence) == 2
    assert all(row.kind.value == "artifact" and row.block_hash is None for row in history_evidence)

    updated_occurrence = {
        **occurrence,
        "principal": BOB,
        "granted_at_block": 110,
        "granted_at_block_hash": "0x" + "11" * 32,
        "granted_at_tx": "0x" + "b1" * 32,
        "granted_at_log_index": 4,
    }
    updated_history = {
        **history,
        "role_membership": [],
        "function_permissions": [
            {
                **updated_occurrence,
                "function": "setOwner(address)",
                "selector": "0x13af4035",
                "roles": [1],
            }
        ],
    }
    store_artifact(db_session, job.id, "principal_history", data=updated_history)

    latest = get_artifact(db_session, job.id, "principal_history")
    assert isinstance(latest, dict)
    assert latest["role_membership"] == []
    assert [row["principal"] for row in latest["function_permissions"]] == [BOB]
    current = load_temporal_assessment(db_session, job.id)
    assert current is not None
    current_history = [claim for claim in current["claims"] if claim["rule"].value == "historical_interval"]
    assert len(current_history) == 1
    assert current_history[0]["scope"]["from_block_hash"] == updated_occurrence["granted_at_block_hash"]
    assert len(publication_history(db_session, job.id)) == 3
    # Old immutable proof rows remain reachable from the earlier publication;
    # the current publication selects only the replacement slice.
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AssessmentEvidence)
            .where(AssessmentEvidence.source["component"].astext == "principal_history")
        )
        == 3
    )
