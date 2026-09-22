"""A pipeline refresh preserves independent canonical governance observations."""

from __future__ import annotations

from db.queue import get_artifact, publish_assessment_projection, store_artifact
from db.queue.typed import load_assessment, load_assessment_projection
from schemas.temporal_assessment import ConfigurationParameter
from services.assessment.governance import record_configuration
from tests.assessment.test_temporal_repository import ADDRESS, ALICE, BOB, _assessment, _job
from tests.conftest import requires_postgres


@requires_postgres
def test_governance_claim_survives_pipeline_refresh(db_session):
    job = _job(db_session)
    publish_assessment_projection(db_session, job.id, _assessment(ALICE, 90))
    claim_id = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point={"chain_id": 1, "block_number": 100, "block_hash": "0x" + "12" * 32},
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"adapter": "test"},
    )
    db_session.commit()

    before = load_assessment(get_artifact, db_session, job.id)
    projection = load_assessment_projection(db_session, job.id)
    assert before is not None and projection is not None
    assert claim_id in {row["id"] for row in before["claims"]}
    assert projection["contract"]["address"] == ADDRESS

    publish_assessment_projection(db_session, job.id, _assessment(BOB, 110))
    after = load_assessment(get_artifact, db_session, job.id)
    refreshed_projection = load_assessment_projection(db_session, job.id)
    assert after is not None and refreshed_projection is not None
    assert claim_id in {row["id"] for row in after["claims"]}
    assert refreshed_projection["contract"]["address"] == ADDRESS
    assert all("schema_version" not in after for _ in [0])


@requires_postgres
def test_mutable_display_metadata_does_not_rekey_address_subject(db_session):
    job = _job(db_session)
    first = _assessment(ALICE, 90)
    publish_assessment_projection(db_session, job.id, first)
    earlier = load_assessment(get_artifact, db_session, job.id)
    assert earlier is not None

    second = _assessment(BOB, 110)
    second["contract"]["name"] = "Vault V2"
    next(iter(second["entities"].values()))["tags"] = ["governance"]
    publish_assessment_projection(db_session, job.id, second)
    latest = load_assessment(get_artifact, db_session, job.id)
    projection = load_assessment_projection(db_session, job.id)
    assert latest is not None and projection is not None
    assert latest["view"]["subject"] == earlier["view"]["subject"]
    assert projection["contract"]["name"] == "Vault V2"
    assert any("governance" in entity["tags"] for entity in projection["entities"].values())


@requires_postgres
def test_principal_history_provenance_survives_pipeline_refresh(db_session):
    job = _job(db_session)
    publish_assessment_projection(db_session, job.id, _assessment(ALICE, 90))
    history = {
        "contract_address": ADDRESS,
        "chain_id": 1,
        "status": "ok",
        "sources": [],
        "role_membership": [{"authority_address": ADDRESS, "principal": ALICE, "role": 1}],
        "capability_roles": [{"authority_address": ADDRESS, "function": "setOwner(address)", "role": 1}],
        "function_permissions": [{"authority_address": ADDRESS, "function": "setOwner(address)", "principal": ALICE}],
        "public_capabilities": [{"authority_address": ADDRESS, "function": "setOwner(address)"}],
    }
    store_artifact(db_session, job.id, "principal_history", data=history)
    before = load_assessment(get_artifact, db_session, job.id)
    compact = load_assessment_projection(db_session, job.id)
    assert before is not None and compact is not None
    history_claims = {row["id"] for row in before["claims"] if row["rule"] == "historical_interval"}
    assert len(history_claims) == 4

    refreshed = _assessment(BOB, 110)
    refreshed["contract"]["code_hash"] = "0x" + "f1" * 32
    publish_assessment_projection(db_session, job.id, refreshed)
    after = load_assessment(get_artifact, db_session, job.id)
    compact_after = load_assessment_projection(db_session, job.id)
    assert after is not None and compact_after is not None
    assert history_claims <= {row["id"] for row in after["claims"]}
    assert not any(key.startswith("principal_history:") for key in compact_after["claims"])


@requires_postgres
def test_domain_proof_retains_old_pipeline_claim_and_evidence(db_session):
    from db.models import AssessmentClaimEvidence
    from schemas.temporal_assessment import (
        AnalysisProducer,
        ClaimKind,
        DerivationRule,
        EvidenceKind,
        ScopeKind,
        SubjectKind,
        SubjectRole,
    )
    from services.assessment.repository import publish_scoped_claim

    job = _job(db_session)
    publish_assessment_projection(db_session, job.id, _assessment(ALICE, 90))
    initial = load_assessment(get_artifact, db_session, job.id)
    assert initial is not None
    old_claim = next(row for row in initial["claims"] if row["kind"] == ClaimKind.function_authority)
    old_evidence_id = old_claim["evidence"][0]
    _publication, _evidence, domain_claim_id, _context = publish_scoped_claim(
        db_session,
        job.id,
        producer=AnalysisProducer.governance,
        subject_kind=SubjectKind.address,
        subject_identity={"chain_id": 1, "address": ADDRESS},
        subject_role=SubjectRole.entity,
        natural_key="dependency:on-old-policy",
        evidence_kind=EvidenceKind.chain_read,
        evidence_payload={"dependency": "old-policy"},
        evidence_source={"kind": "chain_read", "method": "test"},
        claim_kind=ClaimKind.dependency,
        proposition={"kind": "dependency", "old_claim": old_claim["id"]},
        scope_kind=ScopeKind.point,
        scope={"kind": "point", "at": {"chain_id": 1, "block_number": "100", "block_hash": "0x" + "12" * 32}},
        rule=DerivationRule.dependency,
        implementation={"adapter": "test"},
        prerequisite_claims=[old_claim["id"]],
    )
    db_session.add(AssessmentClaimEvidence(claim_id=domain_claim_id, evidence_id=old_evidence_id))
    db_session.commit()

    refreshed = _assessment(BOB, 110)
    refreshed["contract"]["code_hash"] = "0x" + "f1" * 32
    publish_assessment_projection(db_session, job.id, refreshed)
    current = load_assessment(get_artifact, db_session, job.id)
    projection = load_assessment_projection(db_session, job.id)
    assert current is not None and projection is not None
    by_claim = {row["id"]: row for row in current["claims"]}
    assert domain_claim_id in by_claim and old_claim["id"] in by_claim
    assert old_claim["id"] in by_claim[domain_claim_id]["claims"]
    assert old_evidence_id in by_claim[domain_claim_id]["evidence"]
    assert old_evidence_id in {row["id"] for row in current["evidence"]}
    subject_ids = {row["id"] for row in current["subjects"]}

    def references(value):
        if isinstance(value, str):
            return {value} if value.startswith("subject:") else set()
        if isinstance(value, dict):
            return {reference for item in value.values() for reference in references(item)}
        if isinstance(value, list):
            return {reference for item in value for reference in references(item)}
        return set()

    assert references(by_claim[old_claim["id"]]["proposition"]) <= subject_ids
    assert all(references(row["identity"]) <= subject_ids for row in current["subjects"])
    assert any(row["identity"].get("address") == ALICE for row in current["subjects"])
    assert projection["contract"]["code_hash"] == refreshed["contract"]["code_hash"]


@requires_postgres
def test_canonical_payload_metadata_never_selects_payload_bytes(db_session):
    from sqlalchemy import event

    from services.assessment.repository import load_temporal_assessment

    job = _job(db_session)
    publish_assessment_projection(db_session, job.id, _assessment(ALICE, 90))
    statements: list[str] = []

    def record_sql(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    event.listen(db_session.bind, "before_cursor_execute", record_sql)
    try:
        view = load_temporal_assessment(db_session, job.id)
    finally:
        event.remove(db_session.bind, "before_cursor_execute", record_sql)
    assert view is not None and view["payloads"]
    payload_selects = [sql for sql in statements if "from assessment_payloads" in sql]
    assert len(payload_selects) == 1
    assert "assessment_payloads.data" not in payload_selects[0]


@requires_postgres
def test_scenario_view_carries_later_observed_correction_receipt(db_session):
    from schemas.temporal_assessment import CorrectionReason, CorrectionTargetKind
    from services.assessment.governance import ChainPoint, record_scenario_configuration
    from services.assessment.repository import load_temporal_assessment, record_correction

    job = _job(db_session)
    publish_assessment_projection(db_session, job.id, _assessment(ALICE, 90))
    point: ChainPoint = {"chain_id": 1, "block_number": 100, "block_hash": "0x" + "12" * 32}
    baseline = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=point,
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"adapter": "test"},
    )
    _scenario_claim, context_id = record_scenario_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        baseline=point,
        step=1,
        parameter=ConfigurationParameter.minimum_delay,
        value="21600",
        unit="seconds",
        actions=[{"kind": "call", "chain_id": 1, "sender": BOB, "target": ADDRESS, "calldata": "0x", "value": "0"}],
        assumptions=[],
        prerequisite_claims=[baseline],
        implementation={"engine": "test", "mode": "fork"},
        execution={"success": True, "fork_block_number": 100, "transaction_hash": "0x" + "ab" * 32},
    )
    record_correction(
        db_session,
        job.id,
        target_kind=CorrectionTargetKind.claim,
        target_id=baseline,
        reason=CorrectionReason.rule_error,
    )
    db_session.commit()
    scenario = load_temporal_assessment(db_session, job.id, context_id=context_id)
    assert scenario is not None
    analysis_ids = {row["id"] for row in scenario["analyses"]}
    assert scenario["corrections"]
    assert all(row["analysis"] in analysis_ids for row in scenario["corrections"])
