"""Canonical temporal Assessment publication, selection, and legacy projection.

The current pipeline still constructs the compact legacy value in memory.  This
module atomically interns its immutable records, records every analysis attempt,
and publishes an exact set of outputs.  Readers reconstruct the compact shape
from these tables; no mutable Assessment artifact is authoritative.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, cast

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import (
    AssessmentAnalysis,
    AssessmentAnalysisInput,
    AssessmentAnalysisOutput,
    AssessmentClaim,
    AssessmentClaimDependency,
    AssessmentClaimEvidence,
    AssessmentContext,
    AssessmentCorrection,
    AssessmentCoverage,
    AssessmentDiagnostic,
    AssessmentEvidence,
    AssessmentImplementation,
    AssessmentPayload,
    AssessmentPublication,
    AssessmentPublicationAnalysis,
    AssessmentPublicationClaim,
    AssessmentPublicationEvidence,
    AssessmentPublicationSubject,
    AssessmentSubject,
)
from schemas.assessment import Assessment
from schemas.temporal_assessment import (
    AnalysisOutcome,
    AnalysisProducer,
    ClaimKind,
    ContextKind,
    CorrectionReason,
    CorrectionTargetKind,
    CoverageCompleteness,
    CoverageKind,
    DerivationRule,
    DiagnosticCode,
    DiagnosticSeverity,
    EvidenceKind,
    ScopeKind,
    SubjectKind,
    SubjectRole,
    TemporalAnalysisDict,
    TemporalAssessmentDict,
    TemporalClaimDict,
    TemporalContextDict,
    TemporalCorrectionDict,
    TemporalEvidenceDict,
    TemporalImplementationDict,
    TemporalPayloadDict,
    TemporalSubjectDict,
)


def _json(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _bytes(value: Any) -> bytes:
    return json.dumps(_json(value), sort_keys=True, separators=(",", ":")).encode()


def _key(prefix: str, value: Any) -> str:
    return f"{prefix}:{hashlib.sha256(_bytes(value)).hexdigest()}"


def _insert(session: Session, model: type, **values: Any) -> None:
    session.execute(pg_insert(model).values(**values).on_conflict_do_nothing())


def _subject(session: Session, kind: SubjectKind, identity: Mapping[str, Any]) -> str:
    normalized = _json(identity)
    key = _key("subject", {"kind": kind.value, "identity": normalized})
    _insert(session, AssessmentSubject, id=key, kind=kind, identity=normalized)
    return key


def _payload(session: Session, value: Any, media_type: str = "application/json") -> str:
    data = _bytes(value)
    key = f"payload:{hashlib.sha256(data).hexdigest()}"
    _insert(session, AssessmentPayload, id=key, media_type=media_type, data=data, byte_length=len(data))
    return key


def intern_payload(session: Session, value: Any, media_type: str = "application/json") -> str:
    """Retain exact canonical source content and return its stable identity."""
    return _payload(session, value, media_type)


def _context(session: Session, context: Mapping[str, Any]) -> str:
    normalized = _json(context)
    kind = ContextKind.scenario if normalized.get("kind") == "scenario" else ContextKind.observed
    key = _key("context", {"kind": kind.value, "context": normalized})
    _insert(session, AssessmentContext, id=key, kind=kind, context=normalized)
    return key


def _producer(detector: object) -> AnalysisProducer:
    text = str(detector or "")
    if text.startswith("static") or text.startswith("pause."):
        return AnalysisProducer.static
    if text.startswith("observe"):
        return AnalysisProducer.observation
    if text.startswith("resolution"):
        return AnalysisProducer.resolution
    if text.startswith("policy.principal"):
        return AnalysisProducer.principal
    if text.startswith("policy"):
        return AnalysisProducer.policy
    if text.startswith("effects"):
        return AnalysisProducer.execution
    if text.startswith(("proposal", "operation", "governance")):
        return AnalysisProducer.governance
    if text.startswith("scenario"):
        return AnalysisProducer.scenario
    return AnalysisProducer.migration


def _implementation(session: Session, producer: AnalysisProducer, manifest: Mapping[str, Any]) -> str:
    normalized = _json(manifest)
    key = _key("implementation", {"producer": producer.value, "manifest": normalized})
    _insert(session, AssessmentImplementation, id=key, producer=producer, manifest=normalized)
    return key


def _legacy_subjects(
    session: Session, assessment: Assessment
) -> tuple[str, dict[tuple[str, str], str], list[tuple[str, SubjectRole, str]]]:
    contract = assessment["contract"]
    chain_id = contract["chain_id"]
    by_legacy: dict[tuple[str, str], str] = {}
    links: list[tuple[str, SubjectRole, str]] = []

    root = _subject(
        session,
        SubjectKind.address,
        {"chain_id": chain_id, "address": contract["address"], "legacy_value": contract},
    )
    by_legacy[("contract", contract["address"])] = root
    by_legacy[("contract", contract["deployment_address"])] = _subject(
        session,
        SubjectKind.address,
        {"chain_id": chain_id, "address": contract["deployment_address"]},
    )
    links.append((root, SubjectRole.contract, "contract"))

    code_identity = {
        "runtime_code_hash": contract.get("code_hash"),
        "source_hash": contract.get("source_hash"),
        "contract": contract["address"],
    }
    code = _subject(session, SubjectKind.code, code_identity)
    for natural_key, function in assessment["functions"].items():
        subject = _subject(
            session,
            SubjectKind.function,
            {"code": code, "source_signature": natural_key, "identity": function, "legacy_value": function},
        )
        by_legacy[("function", natural_key)] = subject
        links.append((subject, SubjectRole.function, natural_key))
    for natural_key, controller in assessment["controllers"].items():
        subject = _subject(
            session,
            SubjectKind.controller,
            {
                "deployment": by_legacy[("contract", contract["deployment_address"])],
                "code": code,
                "controller_key": natural_key,
                "legacy_value": controller,
            },
        )
        by_legacy[("controller", natural_key)] = subject
        links.append((subject, SubjectRole.controller, natural_key))
    for natural_key, entity in assessment["entities"].items():
        subject = _subject(
            session,
            SubjectKind.address,
            {"chain_id": entity["chain_id"], "address": entity["address"], "legacy_value": entity},
        )
        by_legacy[("entity", natural_key)] = subject
        links.append((subject, SubjectRole.entity, natural_key))
    return root, by_legacy, links


def _subject_for(kind: object, natural_key: object, root: str, lookup: Mapping[tuple[str, str], str]) -> str:
    key = (str(kind), str(natural_key))
    return lookup.get(key, root)


def _canonical_authority(value: Any, lookup: Mapping[tuple[str, str], str]) -> Any:
    if not isinstance(value, Mapping):
        return _json(value)
    result = dict(value)
    for field, kind in (("entity", "entity"), ("controller", "controller")):
        if isinstance(result.get(field), str):
            result[field] = lookup.get((kind, result[field]), result[field])
    if isinstance(result.get("entities"), list):
        result["entities"] = [lookup.get(("entity", str(item)), item) for item in result["entities"]]
    if isinstance(result.get("children"), list):
        result["children"] = [_canonical_authority(item, lookup) for item in result["children"]]
    return _json(result)


def _canonical_proposition(value: Mapping[str, Any], lookup: Mapping[tuple[str, str], str]) -> dict[str, Any]:
    result = dict(value)
    if isinstance(result.get("function"), str):
        result["function"] = lookup.get(("function", result["function"]), result["function"])
    if isinstance(result.get("entity"), str):
        result["entity"] = lookup.get(("entity", result["entity"]), result["entity"])
    if isinstance(result.get("target"), str):
        result["target"] = lookup.get(("entity", result["target"]), result["target"])
    if "authority" in result:
        result["authority"] = _canonical_authority(result["authority"], lookup)
    effect = result.get("effect")
    if isinstance(effect, Mapping):
        effect = dict(effect)
        affected = effect.get("affected_functions")
        if isinstance(affected, list):
            effect["affected_functions"] = [lookup.get(("function", str(item)), item) for item in affected]
        result["effect"] = effect
    return _json(result)


def _block_data(value: Any) -> tuple[int | None, str | None]:
    found: list[tuple[int, str | None]] = []

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            number = item.get("block_number")
            block_hash = item.get("block_hash") or item.get("observed_block_hash")
            if isinstance(number, int):
                found.append((number, str(block_hash) if isinstance(block_hash, str) else None))
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return max(found, default=(None, None), key=lambda pair: pair[0] or -1)


def _evidence_kind(method: object) -> EvidenceKind:
    if method == "event":
        return EvidenceKind.chain_event
    if method in ("rpc", "storage"):
        return EvidenceKind.chain_read
    if method in ("execution", "fork_execution"):
        return EvidenceKind.execution
    if method == "external":
        return EvidenceKind.external
    return EvidenceKind.artifact


def _claim_kind(value: object) -> ClaimKind:
    try:
        return ClaimKind(str(value))
    except ValueError:
        return ClaimKind.dependency


def _rule(kind: ClaimKind) -> DerivationRule:
    try:
        return DerivationRule(kind.value)
    except ValueError:
        return DerivationRule.imported


def _scope(
    claim_kind: ClaimKind,
    chain_id: int,
    code_subject: str | None,
    evidence_rows: list[AssessmentEvidence],
) -> tuple[ScopeKind, dict[str, Any]]:
    if claim_kind == ClaimKind.function_effect and code_subject is not None:
        return ScopeKind.code, {"kind": ScopeKind.code.value, "code": code_subject}
    # A block number without its hash is useful ordering information, but it is
    # not an exact chain point: the number can name another block after a reorg.
    # Retain such imported/legacy observations as reported evidence instead of
    # claiming the stronger point scope.
    points = [row for row in evidence_rows if row.block_number is not None and row.block_hash]
    if points:
        latest = max(points, key=lambda row: int(cast(Decimal, row.block_number)))
        point = {
            "kind": ScopeKind.point.value,
            "at": {
                "chain_id": latest.chain_id or chain_id,
                "block_number": str(latest.block_number),
                "block_hash": latest.block_hash,
            },
        }
        return ScopeKind.point, point
    return ScopeKind.reported, {"kind": ScopeKind.reported.value, "chain_id": chain_id}


def publish_legacy_assessment(session: Session, job_id: Any, assessment: Assessment) -> uuid.UUID:
    """Append one atomic canonical publication from an in-memory pipeline view."""
    from services.assessment.validation import checked

    assessment = checked(assessment)
    now = datetime.now(timezone.utc)
    root, subjects, subject_links = _legacy_subjects(session, assessment)
    context_id = _context(session, {"kind": ContextKind.observed.value})
    publication = AssessmentPublication(
        id=uuid.uuid4(),
        job_id=job_id,
        root_subject_id=root,
        context_id=context_id,
        chain_id=assessment["contract"]["chain_id"],
    )
    session.add(publication)
    session.flush()
    for subject_id, role, natural_key in subject_links:
        session.add(
            AssessmentPublicationSubject(
                publication_id=publication.id,
                subject_id=subject_id,
                role=role,
                natural_key=natural_key,
            )
        )

    canonical_evidence: dict[str, str] = {}
    evidence_rows: dict[str, AssessmentEvidence] = {}
    for natural_key, legacy in assessment["evidence"].items():
        subject_id = _subject_for(legacy["subject_kind"], legacy["subject"], root, subjects)
        payload_id = _payload(session, legacy["observation"])
        kind = _evidence_kind(legacy["method"])
        block_number, block_hash = _block_data(legacy["observation"])
        source = {
            "kind": kind.value,
            "method": legacy["method"],
            "producer": legacy["producer"],
            "locator": legacy["locator"],
            "implementation": legacy.get("version"),
        }
        evidence_id = _key(
            "evidence",
            {
                "subject": subject_id,
                "source": source,
                "payload": payload_id,
                "block_number": block_number,
                "block_hash": block_hash,
            },
        )
        _insert(
            session,
            AssessmentEvidence,
            id=evidence_id,
            subject_id=subject_id,
            kind=kind,
            payload_id=payload_id,
            source=source,
            obtained_at=now,
            chain_id=assessment["contract"]["chain_id"] if block_number is not None else None,
            block_number=block_number,
            block_hash=block_hash,
        )
        row = session.get(AssessmentEvidence, evidence_id)
        assert row is not None
        canonical_evidence[natural_key] = evidence_id
        evidence_rows[natural_key] = row
        session.add(
            AssessmentPublicationEvidence(
                publication_id=publication.id,
                evidence_id=evidence_id,
                natural_key=natural_key,
            )
        )

    code_subject: str | None = None
    for linked_subject, role, _natural in subject_links:
        if role != SubjectRole.function:
            continue
        function_subject = session.get(AssessmentSubject, linked_subject)
        candidate = function_subject.identity.get("code") if function_subject is not None else None
        if isinstance(candidate, str):
            code_subject = candidate
            break
    canonical_claims: dict[str, str] = {}
    building: set[str] = set()

    def intern_claim(natural_key: str) -> str:
        if natural_key in canonical_claims:
            return canonical_claims[natural_key]
        if natural_key in building:
            raise ValueError(f"cyclic legacy claim dependency at {natural_key}")
        building.add(natural_key)
        legacy = assessment["claims"][natural_key]
        proposition = _canonical_proposition(legacy["proposition"], subjects)
        kind = _claim_kind(proposition.get("kind"))
        dependencies = [intern_claim(key) for key in legacy["claims"]]
        evidence_ids = [canonical_evidence[key] for key in legacy["evidence"]]
        rows = [evidence_rows[key] for key in legacy["evidence"]]
        scope_kind, scope = _scope(kind, assessment["contract"]["chain_id"], code_subject, rows)
        producer = _producer(legacy["rule"].split(".", 1)[0])
        implementation_id = _implementation(
            session,
            producer,
            {"rule": legacy["rule"], "source": "legacy_assessment_ingestion"},
        )
        subject_id = root
        for field, legacy_kind in (("function", "function"), ("entity", "entity"), ("target", "entity")):
            value = legacy["proposition"].get(field)
            if isinstance(value, str) and (legacy_kind, value) in subjects:
                subject_id = subjects[(legacy_kind, value)]
                break
        claim_id = _key(
            "claim",
            {
                "subject": subject_id,
                "proposition": proposition,
                "scope": scope,
                "evidence": sorted(evidence_ids),
                "claims": sorted(dependencies),
                "rule": _rule(kind).value,
                "implementation": implementation_id,
            },
        )
        _insert(
            session,
            AssessmentClaim,
            id=claim_id,
            subject_id=subject_id,
            kind=kind,
            proposition=proposition,
            scope_kind=scope_kind,
            scope=scope,
            rule=_rule(kind),
            implementation_id=implementation_id,
        )
        for evidence_id in evidence_ids:
            _insert(session, AssessmentClaimEvidence, claim_id=claim_id, evidence_id=evidence_id)
        for dependency in dependencies:
            _insert(
                session,
                AssessmentClaimDependency,
                claim_id=claim_id,
                prerequisite_claim_id=dependency,
            )
        canonical_claims[natural_key] = claim_id
        building.remove(natural_key)
        return claim_id

    for natural_key in assessment["claims"]:
        claim_id = intern_claim(natural_key)
        session.add(
            AssessmentPublicationClaim(
                publication_id=publication.id,
                claim_id=claim_id,
                natural_key=natural_key,
            )
        )

    for position, receipt in enumerate(assessment["analyses"]):
        producer = _producer(receipt["detector"])
        implementation_id = _implementation(
            session,
            producer,
            {"detector": receipt["detector"], "implementation": receipt.get("version")},
        )
        outcome = AnalysisOutcome(receipt["status"])
        analysis = AssessmentAnalysis(
            id=uuid.uuid4(),
            job_id=job_id,
            producer=producer,
            implementation_id=implementation_id,
            context_id=context_id,
            outcome=outcome,
            receipt=_json(receipt),
            started_at=now,
            finished_at=now,
        )
        session.add(analysis)
        session.flush()
        session.add(
            AssessmentPublicationAnalysis(
                publication_id=publication.id,
                analysis_id=analysis.id,
                position=position,
            )
        )
        for natural_key in receipt["claims"]:
            claim_id = canonical_claims.get(natural_key)
            if claim_id is not None:
                _insert(session, AssessmentAnalysisOutput, analysis_id=analysis.id, claim_id=claim_id)
        completeness = (
            CoverageCompleteness.complete
            if outcome == AnalysisOutcome.completed and not receipt["omissions"]
            else CoverageCompleteness.partial
            if receipt["targets_completed"]
            else CoverageCompleteness.unknown
        )
        coverage_kind = CoverageKind.authority
        if producer == AnalysisProducer.static:
            coverage_kind = CoverageKind.code
        elif producer == AnalysisProducer.observation:
            coverage_kind = CoverageKind.state_reads
        elif producer == AnalysisProducer.execution:
            coverage_kind = CoverageKind.effects
        session.add(
            AssessmentCoverage(
                id=uuid.uuid4(),
                analysis_id=analysis.id,
                subject_id=root,
                kind=coverage_kind,
                scope_kind=ScopeKind.reported,
                scope={"kind": ScopeKind.reported.value, "chain_id": assessment["contract"]["chain_id"]},
                completeness=completeness,
                detail={
                    "targets_total": receipt["targets_total"],
                    "targets_completed": receipt["targets_completed"],
                    "omissions": receipt["omissions"],
                },
            )
        )
        for diagnostic in receipt["diagnostics"]:
            severity = DiagnosticSeverity.error if diagnostic["severity"] == "error" else DiagnosticSeverity.degraded
            session.add(
                AssessmentDiagnostic(
                    id=uuid.uuid4(),
                    analysis_id=analysis.id,
                    severity=severity,
                    code=DiagnosticCode.pipeline_diagnostic,
                    original_code=str(diagnostic.get("code") or "PipelineDiagnostic"),
                    message=str(diagnostic.get("message") or "analysis diagnostic"),
                    subject_id=root,
                    scope=None,
                    detail_payload_id=None,
                )
            )

    block_number, block_hash = _block_data(assessment["evidence"])
    publication.block_number = block_number
    publication.block_hash = block_hash
    return publication.id


def _publication_for_view(
    session: Session,
    job_id: Any,
    *,
    at_block: int | None = None,
    known_at: datetime | None = None,
    context_id: str | None = None,
) -> AssessmentPublication | None:
    statement = select(AssessmentPublication).where(AssessmentPublication.job_id == job_id)
    if context_id is not None:
        statement = statement.where(AssessmentPublication.context_id == context_id)
    else:
        # Scenario publications never become observed current state merely by
        # being newer. They are selected explicitly by reusable context ID.
        statement = statement.join(
            AssessmentContext,
            AssessmentContext.id == AssessmentPublication.context_id,
        ).where(AssessmentContext.kind == ContextKind.observed)
    if known_at is not None:
        statement = statement.where(AssessmentPublication.recorded_at <= known_at)
    if at_block is not None:
        # Only hash-anchored publications can answer an exact historical point.
        # A legacy report with merely a block number remains searchable as a
        # report, but must never masquerade as the canonical block at N.
        statement = statement.where(
            AssessmentPublication.block_number <= at_block,
            AssessmentPublication.block_hash.is_not(None),
        )
        statement = statement.order_by(
            AssessmentPublication.block_number.desc(),
            AssessmentPublication.sequence.desc(),
        )
    else:
        statement = statement.order_by(AssessmentPublication.sequence.desc())
    return session.execute(statement.limit(1)).scalar_one_or_none()


def _latest_publication(session: Session, job_id: Any) -> AssessmentPublication | None:
    return _publication_for_view(session, job_id)


def publish_scoped_claim(
    session: Session,
    job_id: Any,
    *,
    producer: AnalysisProducer,
    subject_kind: SubjectKind,
    subject_identity: Mapping[str, Any],
    subject_role: SubjectRole,
    natural_key: str,
    evidence_kind: EvidenceKind,
    evidence_payload: Any,
    evidence_source: Mapping[str, Any],
    claim_kind: ClaimKind,
    proposition: Mapping[str, Any],
    scope_kind: ScopeKind,
    scope: Mapping[str, Any],
    rule: DerivationRule,
    implementation: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
    prerequisite_claims: list[str] | None = None,
) -> tuple[uuid.UUID, str, str, str]:
    """Append one governance/scenario fact through the shared temporal model."""
    if producer not in {AnalysisProducer.governance, AnalysisProducer.scenario}:
        raise ValueError("scoped domain publication requires governance or scenario producer")
    context_value = context or {"kind": ContextKind.observed.value}
    context_id = _context(session, context_value)
    source_publication = (
        _publication_for_view(session, job_id, context_id=context_id)
        if producer == AnalysisProducer.scenario
        else _latest_publication(session, job_id)
    )
    if source_publication is None and producer == AnalysisProducer.scenario:
        source_publication = _latest_publication(session, job_id)
    if source_publication is None:
        raise ValueError("scoped claim requires an existing observed Assessment publication")
    publication = _clone_publication(session, source_publication)
    publication.context_id = context_id
    canonical_scope = dict(scope)
    if scope_kind == ScopeKind.scenario:
        canonical_scope["context"] = context_id
    now = datetime.now(timezone.utc)
    subject_id = _subject(session, subject_kind, subject_identity)
    _insert(
        session,
        AssessmentPublicationSubject,
        publication_id=publication.id,
        subject_id=subject_id,
        role=subject_role,
        natural_key=natural_key,
    )
    payload_id = _payload(session, evidence_payload)
    source = cast(dict[str, Any], _json(evidence_source))
    at_value = canonical_scope.get("at")
    at: dict[str, Any] = dict(at_value) if isinstance(at_value, Mapping) else {}
    if scope_kind == ScopeKind.point:
        publication.chain_id = int(at["chain_id"])
        publication.block_number = int(at["block_number"])
        publication.block_hash = str(at["block_hash"])
    evidence_id = _key(
        "evidence",
        {
            "subject": subject_id,
            "kind": evidence_kind.value,
            "source": source,
            "payload": payload_id,
            "scope": canonical_scope,
        },
    )
    _insert(
        session,
        AssessmentEvidence,
        id=evidence_id,
        subject_id=subject_id,
        kind=evidence_kind,
        payload_id=payload_id,
        source=source,
        obtained_at=now,
        chain_id=at.get("chain_id"),
        block_number=at.get("block_number"),
        block_hash=at.get("block_hash"),
        transaction_hash=source.get("transaction_hash"),
        transaction_index=source.get("transaction_index"),
        log_index=source.get("log_index"),
    )
    _insert(
        session,
        AssessmentPublicationEvidence,
        publication_id=publication.id,
        evidence_id=evidence_id,
        natural_key=f"{natural_key}:evidence:{evidence_id}",
    )
    implementation_id = _implementation(session, producer, implementation)
    prerequisites = sorted(set(prerequisite_claims or []))
    claim_id = _key(
        "claim",
        {
            "subject": subject_id,
            "kind": claim_kind.value,
            "proposition": proposition,
            "scope": canonical_scope,
            "evidence": [evidence_id],
            "claims": prerequisites,
            "rule": rule.value,
            "implementation": implementation_id,
        },
    )
    _insert(
        session,
        AssessmentClaim,
        id=claim_id,
        subject_id=subject_id,
        kind=claim_kind,
        proposition=_json(proposition),
        scope_kind=scope_kind,
        scope=_json(canonical_scope),
        rule=rule,
        implementation_id=implementation_id,
    )
    _insert(session, AssessmentClaimEvidence, claim_id=claim_id, evidence_id=evidence_id)
    for prerequisite in prerequisites:
        if session.get(AssessmentClaim, prerequisite) is None:
            raise ValueError(f"unknown prerequisite claim {prerequisite}")
        _insert(
            session,
            AssessmentClaimDependency,
            claim_id=claim_id,
            prerequisite_claim_id=prerequisite,
        )
    analysis = AssessmentAnalysis(
        id=uuid.uuid4(),
        job_id=job_id,
        producer=producer,
        implementation_id=implementation_id,
        context_id=context_id,
        outcome=AnalysisOutcome.completed,
        receipt={"kind": claim_kind.value, "natural_key": natural_key},
        started_at=now,
        finished_at=now,
    )
    session.add(analysis)
    session.flush()
    _insert(session, AssessmentAnalysisOutput, analysis_id=analysis.id, claim_id=claim_id)
    _insert(
        session,
        AssessmentAnalysisInput,
        analysis_id=analysis.id,
        input_kind=CorrectionTargetKind.evidence,
        input_id=evidence_id,
    )
    for prerequisite in prerequisites:
        _insert(
            session,
            AssessmentAnalysisInput,
            analysis_id=analysis.id,
            input_kind=CorrectionTargetKind.claim,
            input_id=prerequisite,
        )
    _insert(
        session,
        AssessmentPublicationClaim,
        publication_id=publication.id,
        claim_id=claim_id,
        natural_key=f"{natural_key}:claim:{claim_id}",
    )
    next_position = session.scalar(
        select(func.max(AssessmentPublicationAnalysis.position)).where(
            AssessmentPublicationAnalysis.publication_id == publication.id
        )
    )
    session.add(
        AssessmentPublicationAnalysis(
            publication_id=publication.id,
            analysis_id=analysis.id,
            position=(next_position if isinstance(next_position, int) else -1) + 1,
        )
    )
    return publication.id, evidence_id, claim_id, context_id


def _ineligible_claims(
    session: Session,
    publication: AssessmentPublication,
    claim_ids: list[str],
    *,
    known_at: datetime,
) -> set[str]:
    """Return corrected claims plus their transitive dependants.

    Corrections are knowledge-time facts. A correction recorded after an old
    world point invalidates that proof in today's view of the past, while an
    earlier knowledge cutoff still reproduces what was known then.
    """
    corrections = (
        session.execute(
            select(AssessmentCorrection)
            .join(AssessmentAnalysis, AssessmentAnalysis.id == AssessmentCorrection.analysis_id)
            .where(
                AssessmentAnalysis.job_id == publication.job_id,
                AssessmentAnalysis.recorded_at <= known_at,
            )
        )
        .scalars()
        .all()
    )
    corrected_claims = {row.target_id for row in corrections if row.target_kind == CorrectionTargetKind.claim}
    corrected_evidence = {row.target_id for row in corrections if row.target_kind == CorrectionTargetKind.evidence}
    if corrected_evidence:
        corrected_claims.update(
            session.execute(
                select(AssessmentClaimEvidence.claim_id).where(
                    AssessmentClaimEvidence.evidence_id.in_(corrected_evidence)
                )
            ).scalars()
        )
    dependencies = session.execute(
        select(
            AssessmentClaimDependency.claim_id,
            AssessmentClaimDependency.prerequisite_claim_id,
        ).where(AssessmentClaimDependency.claim_id.in_(claim_ids))
    ).all()
    changed = True
    while changed:
        changed = False
        for dependant, prerequisite in dependencies:
            if prerequisite in corrected_claims and dependant not in corrected_claims:
                corrected_claims.add(dependant)
                changed = True
    return corrected_claims


def record_correction(
    session: Session,
    job_id: Any,
    *,
    target_kind: CorrectionTargetKind,
    target_id: str,
    reason: CorrectionReason,
    detail: Mapping[str, Any] | None = None,
) -> uuid.UUID:
    """Append a correction without deleting the target or its history."""
    source = _latest_publication(session, job_id)
    if source is None:
        raise ValueError("correction requires an existing Assessment publication")
    target_model = AssessmentEvidence if target_kind == CorrectionTargetKind.evidence else AssessmentClaim
    if session.get(target_model, target_id) is None:
        raise ValueError(f"unknown {target_kind.value} target {target_id}")
    publication = _clone_publication(session, source)
    now = datetime.now(timezone.utc)
    context_id = source.context_id
    implementation_id = _implementation(
        session,
        AnalysisProducer.correction,
        {"component": "assessment_correction", "reason": reason.value},
    )
    analysis = AssessmentAnalysis(
        id=uuid.uuid4(),
        job_id=job_id,
        producer=AnalysisProducer.correction,
        implementation_id=implementation_id,
        context_id=context_id,
        outcome=AnalysisOutcome.completed,
        receipt={
            "kind": "correction",
            "target_kind": target_kind.value,
            "target_id": target_id,
            "reason": reason.value,
            "detail": _json(detail or {}),
        },
        started_at=now,
        finished_at=now,
    )
    session.add(analysis)
    session.flush()
    session.add(
        AssessmentCorrection(
            analysis_id=analysis.id,
            target_kind=target_kind,
            target_id=target_id,
            reason=reason,
            detail=_json(detail or {}),
        )
    )
    next_position = session.scalar(
        select(func.max(AssessmentPublicationAnalysis.position)).where(
            AssessmentPublicationAnalysis.publication_id == publication.id
        )
    )
    session.add(
        AssessmentPublicationAnalysis(
            publication_id=publication.id,
            analysis_id=analysis.id,
            position=(next_position if isinstance(next_position, int) else -1) + 1,
        )
    )
    return publication.id


def publish_diagnostic(
    session: Session,
    job_id: Any,
    *,
    producer: AnalysisProducer,
    code: DiagnosticCode,
    message: str,
    implementation: Mapping[str, Any],
    outcome: AnalysisOutcome = AnalysisOutcome.partial,
) -> uuid.UUID:
    """Append a failed/partial attempt without manufacturing a Claim."""
    source = _latest_publication(session, job_id)
    if source is None:
        raise ValueError("diagnostic requires an existing Assessment publication")
    publication = _clone_publication(session, source)
    now = datetime.now(timezone.utc)
    implementation_id = _implementation(session, producer, implementation)
    analysis = AssessmentAnalysis(
        id=uuid.uuid4(),
        job_id=job_id,
        producer=producer,
        implementation_id=implementation_id,
        context_id=source.context_id,
        outcome=outcome,
        receipt={"kind": "diagnostic", "code": code.value, "message": message},
        started_at=now,
        finished_at=now,
    )
    session.add(analysis)
    session.flush()
    session.add(
        AssessmentDiagnostic(
            id=uuid.uuid4(),
            analysis_id=analysis.id,
            severity=DiagnosticSeverity.degraded,
            code=code,
            original_code=None,
            message=message,
            subject_id=source.root_subject_id,
            scope=None,
            detail_payload_id=None,
        )
    )
    next_position = session.scalar(
        select(func.max(AssessmentPublicationAnalysis.position)).where(
            AssessmentPublicationAnalysis.publication_id == publication.id
        )
    )
    session.add(
        AssessmentPublicationAnalysis(
            publication_id=publication.id,
            analysis_id=analysis.id,
            position=(next_position if isinstance(next_position, int) else -1) + 1,
        )
    )
    return publication.id


def has_publication(session: Session, job_id: Any) -> bool:
    return _latest_publication(session, job_id) is not None


def load_legacy_assessment(session: Session, job_id: Any) -> Assessment | None:
    """Project the latest publication into the compact pipeline compatibility view."""
    publication = _latest_publication(session, job_id)
    if publication is None:
        return None
    subject_links = (
        session.execute(
            select(AssessmentPublicationSubject).where(AssessmentPublicationSubject.publication_id == publication.id)
        )
        .scalars()
        .all()
    )
    natural_by_subject: dict[str, tuple[SubjectRole, str]] = {
        link.subject_id: (link.role, link.natural_key) for link in subject_links
    }
    contract: dict[str, Any] | None = None
    functions: dict[str, Any] = {}
    controllers: dict[str, Any] = {}
    entities: dict[str, Any] = {}
    for link in subject_links:
        row = session.get(AssessmentSubject, link.subject_id)
        if row is None:
            continue
        value = row.identity.get("legacy_value")
        if link.role == SubjectRole.contract:
            contract = dict(value or {})
        elif link.role == SubjectRole.function:
            functions[link.natural_key] = dict(value or {})
        elif link.role == SubjectRole.controller:
            controllers[link.natural_key] = dict(value or {})
        elif link.role == SubjectRole.entity:
            entities[link.natural_key] = dict(value or {})
    if contract is None:
        raise ValueError(f"publication {publication.id} has no contract subject")

    evidence: dict[str, Any] = {}
    evidence_links = (
        session.execute(
            select(AssessmentPublicationEvidence).where(AssessmentPublicationEvidence.publication_id == publication.id)
        )
        .scalars()
        .all()
    )
    for link in evidence_links:
        row = session.get(AssessmentEvidence, link.evidence_id)
        payload = session.get(AssessmentPayload, row.payload_id) if row is not None else None
        if row is None or payload is None:
            raise ValueError(f"publication {publication.id} has missing evidence {link.evidence_id}")
        source = row.source
        role, natural_subject = natural_by_subject.get(row.subject_id, (SubjectRole.contract, contract["address"]))
        subject_kind = "contract" if role == SubjectRole.contract else role.value
        evidence[link.natural_key] = {
            "method": source["method"],
            "subject_kind": subject_kind,
            "subject": contract["address"] if role == SubjectRole.contract else natural_subject,
            "observation": json.loads(payload.data),
            "producer": source["producer"],
            "version": source.get("implementation") or "unknown",
            "locator": source["locator"],
        }

    claim_links = (
        session.execute(
            select(AssessmentPublicationClaim).where(AssessmentPublicationClaim.publication_id == publication.id)
        )
        .scalars()
        .all()
    )
    corrected_claims = _ineligible_claims(
        session,
        publication,
        [link.claim_id for link in claim_links],
        known_at=datetime.now(timezone.utc),
    )
    claim_links = [link for link in claim_links if link.claim_id not in corrected_claims]
    natural_claim_by_id = {link.claim_id: link.natural_key for link in claim_links}
    natural_evidence_by_id = {link.evidence_id: link.natural_key for link in evidence_links}

    def legacy_authority(value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        result = dict(value)
        for field in ("entity", "controller"):
            if isinstance(result.get(field), str) and result[field] in natural_by_subject:
                result[field] = natural_by_subject[result[field]][1]
        if isinstance(result.get("entities"), list):
            result["entities"] = [natural_by_subject.get(item, (None, item))[1] for item in result["entities"]]
        if isinstance(result.get("children"), list):
            result["children"] = [legacy_authority(item) for item in result["children"]]
        return result

    def legacy_proposition(row: AssessmentClaim) -> dict[str, Any]:
        result = dict(row.proposition)
        for field in ("function", "entity", "target"):
            if isinstance(result.get(field), str) and result[field] in natural_by_subject:
                result[field] = natural_by_subject[result[field]][1]
        if "authority" in result:
            result["authority"] = legacy_authority(result["authority"])
        effect = result.get("effect")
        if isinstance(effect, Mapping):
            effect = dict(effect)
            if isinstance(effect.get("affected_functions"), list):
                effect["affected_functions"] = [
                    natural_by_subject.get(item, (None, item))[1] for item in effect["affected_functions"]
                ]
            result["effect"] = effect
        return result

    claims: dict[str, Any] = {}
    for link in claim_links:
        row = session.get(AssessmentClaim, link.claim_id)
        if row is None:
            raise ValueError(f"publication {publication.id} has missing claim {link.claim_id}")
        if row.kind not in {
            ClaimKind.function_effect,
            ClaimKind.function_authority,
            ClaimKind.authority_capability,
            ClaimKind.authority_relationship,
            ClaimKind.entity_classification,
        }:
            continue
        evidence_ids = (
            session.execute(
                select(AssessmentClaimEvidence.evidence_id).where(AssessmentClaimEvidence.claim_id == row.id)
            )
            .scalars()
            .all()
        )
        dependencies = (
            session.execute(
                select(AssessmentClaimDependency.prerequisite_claim_id).where(
                    AssessmentClaimDependency.claim_id == row.id
                )
            )
            .scalars()
            .all()
        )
        implementation = session.get(AssessmentImplementation, row.implementation_id)
        claims[link.natural_key] = {
            "proposition": legacy_proposition(row),
            "rule": (implementation.manifest.get("rule") if implementation else None) or row.rule.value,
            "evidence": [natural_evidence_by_id[key] for key in evidence_ids if key in natural_evidence_by_id],
            "claims": [natural_claim_by_id[key] for key in dependencies if key in natural_claim_by_id],
        }

    analyses: list[dict[str, Any]] = []
    analysis_links = (
        session.execute(
            select(AssessmentPublicationAnalysis)
            .where(AssessmentPublicationAnalysis.publication_id == publication.id)
            .order_by(AssessmentPublicationAnalysis.position)
        )
        .scalars()
        .all()
    )
    for link in analysis_links:
        row = session.get(AssessmentAnalysis, link.analysis_id)
        if row is not None and "detector" in row.receipt:
            analyses.append(dict(row.receipt))
    return cast(
        Assessment,
        {
            "schema_version": "assessment/5",
            "contract": contract,
            "functions": functions,
            "controllers": controllers,
            "entities": entities,
            "claims": claims,
            "evidence": evidence,
            "analyses": analyses,
        },
    )


def load_temporal_assessment(
    session: Session,
    job_id: Any,
    *,
    at_block: int | None = None,
    known_at: datetime | None = None,
    context_id: str | None = None,
) -> TemporalAssessmentDict | None:
    """Return a row-shaped view selected by world time and knowledge time."""
    publication = _publication_for_view(
        session,
        job_id,
        at_block=at_block,
        known_at=known_at,
        context_id=context_id,
    )
    if publication is None:
        return None
    subject_ids = (
        session.execute(
            select(AssessmentPublicationSubject.subject_id).where(
                AssessmentPublicationSubject.publication_id == publication.id
            )
        )
        .scalars()
        .all()
    )
    evidence_ids = (
        session.execute(
            select(AssessmentPublicationEvidence.evidence_id).where(
                AssessmentPublicationEvidence.publication_id == publication.id
            )
        )
        .scalars()
        .all()
    )
    claim_ids = (
        session.execute(
            select(AssessmentPublicationClaim.claim_id).where(
                AssessmentPublicationClaim.publication_id == publication.id
            )
        )
        .scalars()
        .all()
    )
    effective_known_at = known_at or datetime.now(timezone.utc)
    corrected_claims = _ineligible_claims(
        session,
        publication,
        list(claim_ids),
        known_at=effective_known_at,
    )
    claim_ids = [claim_id for claim_id in claim_ids if claim_id not in corrected_claims]
    analysis_ids = (
        session.execute(
            select(AssessmentPublicationAnalysis.analysis_id)
            .where(AssessmentPublicationAnalysis.publication_id == publication.id)
            .order_by(AssessmentPublicationAnalysis.position)
        )
        .scalars()
        .all()
    )
    subjects: list[TemporalSubjectDict] = []
    for key in dict.fromkeys(subject_ids):
        row = session.get(AssessmentSubject, key)
        if row is not None:
            subjects.append(
                {
                    "id": row.id,
                    "recorded_at": row.recorded_at.isoformat(),
                    "kind": row.kind,
                    "identity": {key: value for key, value in row.identity.items() if key != "legacy_value"},
                }
            )
    evidences: list[TemporalEvidenceDict] = []
    for key in evidence_ids:
        row = session.get(AssessmentEvidence, key)
        if row is not None:
            evidences.append(
                {
                    "id": row.id,
                    "recorded_at": row.recorded_at.isoformat(),
                    "subject": row.subject_id,
                    "kind": row.kind,
                    "source": row.source,
                    "payload": row.payload_id,
                    "obtained_at": row.obtained_at.isoformat(),
                    "chain_id": row.chain_id,
                    "block_number": str(row.block_number) if row.block_number is not None else None,
                    "block_hash": row.block_hash,
                    "transaction_hash": row.transaction_hash,
                    "transaction_index": row.transaction_index,
                    "log_index": row.log_index,
                }
            )
    claims: list[TemporalClaimDict] = []
    for key in claim_ids:
        row = session.get(AssessmentClaim, key)
        if row is None:
            continue
        claim_evidence = (
            session.execute(
                select(AssessmentClaimEvidence.evidence_id).where(AssessmentClaimEvidence.claim_id == row.id)
            )
            .scalars()
            .all()
        )
        dependencies = (
            session.execute(
                select(AssessmentClaimDependency.prerequisite_claim_id).where(
                    AssessmentClaimDependency.claim_id == row.id
                )
            )
            .scalars()
            .all()
        )
        claims.append(
            {
                "id": row.id,
                "recorded_at": row.recorded_at.isoformat(),
                "subject": row.subject_id,
                "kind": row.kind,
                "proposition": row.proposition,
                "scope_kind": row.scope_kind,
                "scope": row.scope,
                "rule": row.rule,
                "evidence": list(claim_evidence),
                "claims": list(dependencies),
            }
        )
    analyses: list[TemporalAnalysisDict] = []
    for key in analysis_ids:
        row = session.get(AssessmentAnalysis, key)
        if row is None:
            continue
        outputs = (
            session.execute(
                select(AssessmentAnalysisOutput.claim_id).where(AssessmentAnalysisOutput.analysis_id == row.id)
            )
            .scalars()
            .all()
        )
        input_rows = (
            session.execute(select(AssessmentAnalysisInput).where(AssessmentAnalysisInput.analysis_id == row.id))
            .scalars()
            .all()
        )
        coverage = (
            session.execute(select(AssessmentCoverage).where(AssessmentCoverage.analysis_id == row.id)).scalars().all()
        )
        diagnostics = (
            session.execute(select(AssessmentDiagnostic).where(AssessmentDiagnostic.analysis_id == row.id))
            .scalars()
            .all()
        )
        analyses.append(
            {
                "id": str(row.id),
                "recorded_at": row.recorded_at.isoformat(),
                "producer": row.producer,
                "implementation": row.implementation_id,
                "context": row.context_id,
                "started_at": row.started_at.isoformat(),
                "finished_at": row.finished_at.isoformat(),
                "outcome": row.outcome,
                "receipt": row.receipt,
                "inputs": {
                    "evidence": [
                        item.input_id for item in input_rows if item.input_kind == CorrectionTargetKind.evidence
                    ],
                    "claims": [item.input_id for item in input_rows if item.input_kind == CorrectionTargetKind.claim],
                },
                "outputs": list(outputs),
                "coverage": [
                    {
                        "id": str(item.id),
                        "kind": item.kind,
                        "scope_kind": item.scope_kind,
                        "scope": item.scope,
                        "completeness": item.completeness,
                        "detail": item.detail,
                    }
                    for item in coverage
                ],
                "diagnostics": [
                    {
                        "id": str(item.id),
                        "severity": item.severity,
                        "code": item.code,
                        "original_code": item.original_code,
                        "message": item.message,
                    }
                    for item in diagnostics
                ],
            }
        )
    correction_rows = session.execute(
        select(AssessmentCorrection, AssessmentAnalysis.recorded_at)
        .join(AssessmentAnalysis, AssessmentAnalysis.id == AssessmentCorrection.analysis_id)
        .where(
            AssessmentAnalysis.job_id == publication.job_id,
            AssessmentAnalysis.recorded_at <= effective_known_at,
        )
        .order_by(AssessmentAnalysis.recorded_at, AssessmentCorrection.id)
    ).all()
    corrections: list[TemporalCorrectionDict] = [
        {
            "id": str(row.id),
            "recorded_at": recorded_at.isoformat(),
            "analysis": str(row.analysis_id),
            "target_kind": row.target_kind,
            "target": row.target_id,
            "reason": row.reason,
            "detail": row.detail,
        }
        for row, recorded_at in correction_rows
    ]
    context_ids = list(dict.fromkeys([publication.context_id, *(row["context"] for row in analyses)]))
    contexts: list[TemporalContextDict] = []
    for context_key in context_ids:
        context_row = session.get(AssessmentContext, context_key)
        if context_row is not None:
            contexts.append(
                {
                    "id": context_row.id,
                    "recorded_at": context_row.recorded_at.isoformat(),
                    "kind": context_row.kind,
                    "context": context_row.context,
                }
            )
    implementation_ids = list(dict.fromkeys(row["implementation"] for row in analyses))
    implementations: list[TemporalImplementationDict] = []
    for implementation_key in implementation_ids:
        implementation_row = session.get(AssessmentImplementation, implementation_key)
        if implementation_row is not None:
            implementations.append(
                {
                    "id": implementation_row.id,
                    "recorded_at": implementation_row.recorded_at.isoformat(),
                    "producer": implementation_row.producer,
                    "manifest": implementation_row.manifest,
                }
            )
    payload_ids = list(dict.fromkeys(row["payload"] for row in evidences))
    payloads: list[TemporalPayloadDict] = []
    for payload_key in payload_ids:
        payload_row = session.get(AssessmentPayload, payload_key)
        if payload_row is not None:
            payloads.append(
                {
                    "id": payload_row.id,
                    "recorded_at": payload_row.recorded_at.isoformat(),
                    "media_type": payload_row.media_type,
                    "byte_length": payload_row.byte_length,
                }
            )
    view: dict[str, Any] = {
        "kind": "chain",
        "subject": publication.root_subject_id,
        "known_at": publication.recorded_at.isoformat(),
        "scope": {
            "kind": "point" if publication.block_number is not None and publication.block_hash else "reported",
            "chain_id": publication.chain_id,
            "block_number": str(publication.block_number) if publication.block_number is not None else None,
            "block_hash": publication.block_hash,
        },
    }
    return {
        "view": view,
        "subjects": subjects,
        "evidence": evidences,
        "claims": claims,
        "analyses": analyses,
        "corrections": corrections,
        "contexts": contexts,
        "implementations": implementations,
        "payloads": payloads,
    }


def _clone_publication(session: Session, source: AssessmentPublication) -> AssessmentPublication:
    clone = AssessmentPublication(
        id=uuid.uuid4(),
        job_id=source.job_id,
        root_subject_id=source.root_subject_id,
        context_id=source.context_id,
        chain_id=source.chain_id,
        block_number=source.block_number,
        block_hash=source.block_hash,
    )
    session.add(clone)
    session.flush()
    for model, fields in (
        (AssessmentPublicationSubject, ("subject_id", "role", "natural_key")),
        (AssessmentPublicationEvidence, ("evidence_id", "natural_key")),
        (AssessmentPublicationClaim, ("claim_id", "natural_key")),
        (AssessmentPublicationAnalysis, ("analysis_id", "position")),
    ):
        rows = session.execute(select(model).where(model.publication_id == source.id)).scalars().all()
        for row in rows:
            session.add(model(publication_id=clone.id, **{field: getattr(row, field) for field in fields}))
    return clone


def publish_principal_history(session: Session, job_id: Any, history: Mapping[str, Any]) -> uuid.UUID:
    """Append legacy principal-history behavior as reported temporal claims."""
    source_publication = _latest_publication(session, job_id)
    if source_publication is None:
        raise ValueError("principal history requires an existing Assessment publication")
    publication = _clone_publication(session, source_publication)
    now = datetime.now(timezone.utc)
    root = source_publication.root_subject_id
    context_id = source_publication.context_id
    producer = AnalysisProducer.policy
    implementation_id = _implementation(
        session,
        producer,
        {"component": "principal_history", "mode": "role_capability_event_replay"},
    )
    analysis = AssessmentAnalysis(
        id=uuid.uuid4(),
        job_id=job_id,
        producer=producer,
        implementation_id=implementation_id,
        context_id=context_id,
        outcome=(
            AnalysisOutcome.completed
            if history.get("status") == "ok"
            else AnalysisOutcome.partial
            if any(
                history.get(section)
                for section in ("role_membership", "capability_roles", "function_permissions", "public_capabilities")
            )
            else AnalysisOutcome.failed
        ),
        receipt={
            "kind": "principal_history",
            "status": history.get("status"),
            "reason": history.get("reason"),
            "sources": history.get("sources") or [],
        },
        started_at=now,
        finished_at=now,
    )
    session.add(analysis)
    session.flush()
    next_position = session.scalar(
        select(func.max(AssessmentPublicationAnalysis.position)).where(
            AssessmentPublicationAnalysis.publication_id == publication.id
        )
    )
    session.add(
        AssessmentPublicationAnalysis(
            publication_id=publication.id,
            analysis_id=analysis.id,
            position=(next_position if isinstance(next_position, int) else -1) + 1,
        )
    )
    subject_links = (
        session.execute(
            select(AssessmentPublicationSubject).where(AssessmentPublicationSubject.publication_id == publication.id)
        )
        .scalars()
        .all()
    )
    functions = {link.natural_key: link.subject_id for link in subject_links if link.role == SubjectRole.function}
    published_subjects = {(link.subject_id, link.role, link.natural_key) for link in subject_links}
    published_subject_ids = {link.subject_id for link in subject_links}

    def publish_subject(subject_id: str, role: SubjectRole, natural_key: str) -> None:
        identity = (subject_id, role, natural_key)
        if identity in published_subjects or subject_id in published_subject_ids:
            return
        session.add(
            AssessmentPublicationSubject(
                publication_id=publication.id,
                subject_id=subject_id,
                role=role,
                natural_key=natural_key,
            )
        )
        published_subjects.add(identity)
        published_subject_ids.add(subject_id)

    chain_id = int(history.get("chain_id") or source_publication.chain_id)

    count = 0
    for section, claim_kind in (
        ("role_membership", ClaimKind.role_membership),
        ("capability_roles", ClaimKind.function_authority),
        ("function_permissions", ClaimKind.function_authority),
        ("public_capabilities", ClaimKind.function_authority),
    ):
        rows = history.get(section)
        if not isinstance(rows, list):
            continue
        for index, interval in enumerate(rows):
            if not isinstance(interval, Mapping):
                continue
            authority = interval.get("authority_address")
            authority_subject = (
                _subject(session, SubjectKind.address, {"chain_id": chain_id, "address": str(authority).lower()})
                if isinstance(authority, str)
                else root
            )
            principal = interval.get("principal")
            principal_subject = (
                _subject(session, SubjectKind.address, {"chain_id": chain_id, "address": str(principal).lower()})
                if isinstance(principal, str)
                else None
            )
            role_value = interval.get("role")
            role_subject = (
                _subject(
                    session,
                    SubjectKind.role,
                    {"authority": authority_subject, "kind": "integer", "value": str(role_value)},
                )
                if isinstance(role_value, int)
                else None
            )
            publish_subject(authority_subject, SubjectRole.entity, f"authority:{authority_subject}")
            if principal_subject is not None:
                publish_subject(principal_subject, SubjectRole.entity, f"principal:{principal_subject}")
            if role_subject is not None:
                publish_subject(role_subject, SubjectRole.role, f"role:{role_subject}")
            function_name = interval.get("function")
            function_subject = functions.get(str(function_name)) if isinstance(function_name, str) else None
            payload_id = _payload(session, interval)
            evidence_id = _key(
                "evidence",
                {
                    "subject": principal_subject or function_subject or root,
                    "source": "principal_history_report",
                    "payload": payload_id,
                },
            )
            _insert(
                session,
                AssessmentEvidence,
                id=evidence_id,
                subject_id=principal_subject or function_subject or root,
                kind=(EvidenceKind.chain_event if interval.get("granted_at_block_hash") else EvidenceKind.artifact),
                payload_id=payload_id,
                source={"kind": "artifact", "component": "principal_history", "section": section},
                obtained_at=now,
                chain_id=chain_id,
                block_number=interval.get("granted_at_block"),
                block_hash=interval.get("granted_at_block_hash"),
                transaction_hash=interval.get("granted_at_tx"),
                transaction_index=interval.get("granted_at_transaction_index"),
                log_index=interval.get("granted_at_log_index"),
            )
            natural_key = f"principal_history:{section}:{index}"
            session.add(
                AssessmentPublicationEvidence(
                    publication_id=publication.id,
                    evidence_id=evidence_id,
                    natural_key=natural_key,
                )
            )
            if section == "role_membership":
                proposition = {
                    "kind": claim_kind.value,
                    "role": role_subject,
                    "principal": principal_subject,
                    "present": True,
                }
                subject_id = principal_subject or root
            else:
                proposition = {
                    "kind": claim_kind.value,
                    "function": function_subject,
                    "authority": (
                        {"kind": "public"}
                        if section == "public_capabilities"
                        else {"kind": "entity", "entity": principal_subject}
                        if principal_subject is not None
                        else {"kind": "role", "role": role_subject}
                    ),
                }
                subject_id = function_subject or root
            interval_is_exact = bool(
                interval.get("granted_at_block_hash")
                and interval.get("revoked_at_block_hash")
                and interval.get("status") == "revoked"
            )
            scope_kind = ScopeKind.interval if interval_is_exact else ScopeKind.reported
            scope = {
                "kind": scope_kind.value,
                "chain_id": chain_id,
                "from_block": interval.get("granted_at_block"),
                "from_block_hash": interval.get("granted_at_block_hash"),
                "from_transaction": interval.get("granted_at_tx"),
                "from_transaction_index": interval.get("granted_at_transaction_index"),
                "from_log_index": interval.get("granted_at_log_index"),
                "through_block": interval.get("revoked_at_block"),
                "through_block_hash": interval.get("revoked_at_block_hash"),
                "through_transaction": interval.get("revoked_at_tx"),
                "through_transaction_index": interval.get("revoked_at_transaction_index"),
                "through_log_index": interval.get("revoked_at_log_index"),
                "status": interval.get("status"),
            }
            claim_id = _key(
                "claim",
                {
                    "subject": subject_id,
                    "proposition": proposition,
                    "scope": scope,
                    "evidence": [evidence_id],
                    "rule": DerivationRule.historical_interval.value,
                    "implementation": implementation_id,
                },
            )
            _insert(
                session,
                AssessmentClaim,
                id=claim_id,
                subject_id=subject_id,
                kind=claim_kind,
                proposition=proposition,
                scope_kind=scope_kind,
                scope=scope,
                rule=DerivationRule.historical_interval,
                implementation_id=implementation_id,
            )
            _insert(session, AssessmentClaimEvidence, claim_id=claim_id, evidence_id=evidence_id)
            _insert(session, AssessmentAnalysisOutput, analysis_id=analysis.id, claim_id=claim_id)
            session.add(
                AssessmentPublicationClaim(
                    publication_id=publication.id,
                    claim_id=claim_id,
                    natural_key=f"principal_history:{section}:{index}",
                )
            )
            count += 1
    session.add(
        AssessmentCoverage(
            id=uuid.uuid4(),
            analysis_id=analysis.id,
            subject_id=root,
            kind=CoverageKind.authority,
            scope_kind=ScopeKind.reported,
            scope={"kind": ScopeKind.reported.value, "chain_id": chain_id},
            completeness=(
                CoverageCompleteness.complete if history.get("status") == "ok" else CoverageCompleteness.partial
            ),
            detail={"historical_claims": count, "sources": history.get("sources") or []},
        )
    )
    return publication.id


def load_principal_history(session: Session, job_id: Any) -> dict[str, Any] | None:
    """Project historical permission rows from canonical evidence payloads."""
    publication = _latest_publication(session, job_id)
    if publication is None:
        return None
    links = (
        session.execute(
            select(AssessmentPublicationEvidence).where(
                AssessmentPublicationEvidence.publication_id == publication.id,
                AssessmentPublicationEvidence.natural_key.like("principal_history:%"),
            )
        )
        .scalars()
        .all()
    )
    analyses = (
        session.execute(
            select(AssessmentAnalysis)
            .join(AssessmentPublicationAnalysis, AssessmentPublicationAnalysis.analysis_id == AssessmentAnalysis.id)
            .where(
                AssessmentPublicationAnalysis.publication_id == publication.id,
                AssessmentAnalysis.receipt["kind"].astext == "principal_history",
            )
            .order_by(AssessmentPublicationAnalysis.position.desc())
        )
        .scalars()
        .all()
    )
    if not links and not analyses:
        return None
    root_subject = session.get(AssessmentSubject, publication.root_subject_id)
    if root_subject is None:
        raise ValueError(f"publication {publication.id} has no root subject")
    result: dict[str, Any] = {
        "contract_address": root_subject.identity["address"],
        "chain_id": publication.chain_id,
        "status": "ok",
        "sources": [],
        "role_membership": [],
        "capability_roles": [],
        "function_permissions": [],
        "public_capabilities": [],
    }
    for link in links:
        row = session.get(AssessmentEvidence, link.evidence_id)
        payload = session.get(AssessmentPayload, row.payload_id) if row is not None else None
        if row is None or payload is None:
            continue
        _prefix, section, _index = link.natural_key.split(":", 2)
        result[section].append(json.loads(payload.data))
    if analyses:
        result["status"] = analyses[0].receipt.get("status") or "unsupported"
        result["sources"] = analyses[0].receipt.get("sources") or []
        if analyses[0].receipt.get("reason"):
            result["reason"] = analyses[0].receipt["reason"]
    for section in ("role_membership", "capability_roles", "function_permissions", "public_capabilities"):
        result[section].sort(
            key=lambda item: (
                str(item.get("function") or ""),
                str(item.get("principal") or ""),
                int(item.get("granted_at_block") or 0),
            )
        )
    return result


def publication_history(session: Session, job_id: Any) -> list[dict[str, Any]]:
    """List every retained publication for one job in chronological order."""
    rows = (
        session.execute(
            select(AssessmentPublication)
            .where(AssessmentPublication.job_id == job_id)
            .order_by(AssessmentPublication.sequence)
        )
        .scalars()
        .all()
    )
    history: list[dict[str, Any]] = []
    for row in rows:
        context = session.get(AssessmentContext, row.context_id)
        if context is None:
            raise ValueError(f"publication {row.id} has no context")
        history.append(
            {
                "id": str(row.id),
                "recorded_at": row.recorded_at.isoformat(),
                "chain_id": row.chain_id,
                "block_number": str(row.block_number) if row.block_number is not None else None,
                "block_hash": row.block_hash,
                "context": row.context_id,
                "context_kind": context.kind.value,
            }
        )
    return history


__all__ = [
    "has_publication",
    "intern_payload",
    "load_legacy_assessment",
    "load_temporal_assessment",
    "load_principal_history",
    "publication_history",
    "publish_diagnostic",
    "publish_scoped_claim",
    "publish_legacy_assessment",
    "publish_principal_history",
    "record_correction",
]
