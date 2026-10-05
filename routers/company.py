from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import aliased

from db.models import AuditContractCoverage, AuditReport, Contract, Protocol
from schemas.api_responses import (
    AuditBrief,
    AuditCoverageEntry,
    CompanyAddressesResponse,
    CompanyAuditCoverageResponse,
    CompanyAuditsResponse,
    CompanyFunctionsResponse,
    CompanyOverviewResponse,
    CompanyScoreResponse,
)
from services.aggregations import CompanyNotFound, build_company_overview
from services.aggregations.company_overview import (
    all_addresses_for_protocol,
    build_functions_for_protocol,
    resolve_company_jobs,
)
from services.aggregations.company_overview.jobs import eligible_company_names
from services.audits.serializers import _audit_brief, _audit_report_to_dict
from services.company_pages import cache_tag, enabled, prepared_or_pending

from . import deps

router = APIRouter()
logger = logging.getLogger("routers.company")


def _coverage_key(chain: str | None, address: str | None) -> tuple[str, str] | None:
    chain_key = (chain or "").lower()
    address_key = (address or "").lower()
    if not chain_key or not address_key:
        return None
    return (chain_key, address_key)


def _is_reusable_verified_coverage(row: Any) -> bool:
    return (
        str(getattr(row, "equivalence_status", "") or "").lower() == "proven"
        and str(getattr(row, "match_type", "") or "").lower() == "reviewed_commit"
        and str(getattr(row, "proof_kind", "") or "").lower() != "cited_only"
    )


def _inherit_verified_dependency_coverage(
    *,
    inherited_pairs: Iterable[Any],
    target_contract_ids_by_key: dict[tuple[str, str], set[int]],
    coverage_by_contract: dict[int, list[Any]],
    audits_by_id: dict[int, Any],
) -> list[Any]:
    inherited_rows: list[Any] = []
    for row, audit, covered_contract, source_protocol in inherited_pairs:
        if not _is_reusable_verified_coverage(row):
            continue
        key = _coverage_key(getattr(covered_contract, "chain", None), getattr(covered_contract, "address", None))
        target_ids = target_contract_ids_by_key.get(key) if key else None
        if not target_ids:
            continue
        audits_by_id[audit.id] = audit
        setattr(row, "_coverage_source", "inherited")
        setattr(row, "_inherited_from_protocol", source_protocol.name)
        setattr(row, "_inherited_contract_address", covered_contract.address)
        for target_id in target_ids:
            coverage_by_contract.setdefault(target_id, []).append(row)
        inherited_rows.append(row)
    return inherited_rows


def _log_endpoint(route: str, *, company: str, started: float, **extras: Any) -> None:
    """One line per hit with elapsed time, grepable by trace_id."""
    elapsed_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "%s elapsed_ms=%d company=%s",
        route,
        elapsed_ms,
        company,
        extra={"phase": "http_endpoint", "route": route, "duration_ms": elapsed_ms, "company": company, **extras},
    )


@router.get("/api/company/{company_name}", response_model=None)
def company_overview(company_name: str, response: Response, request: Request) -> CompanyOverviewResponse | Response:
    started = time.monotonic()
    with deps.SessionLocal() as session:
        if enabled():
            return prepared_or_pending(session, request, company_name)
        response.headers["X-PSAT-Response-Source"] = "live"
        response.headers["X-PSAT-Fresh-Until"] = str(time.time() + 60)
        response.headers["Cache-Tag"] = cache_tag(company_name)
        try:
            payload = build_company_overview(session, company_name)
        except CompanyNotFound:
            _log_endpoint("/api/company/{name}", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")
    _log_endpoint(
        "/api/company/{name}",
        company=company_name,
        started=started,
        outcome="success",
        contract_count=len(payload.get("contracts") or []),
    )
    return payload


@router.get("/api/company/{company_name}/addresses", response_model=None)
def company_addresses(company_name: str, response: Response) -> CompanyAddressesResponse:
    """Split out so the ~167 KB list isn't shipped on every page load."""
    started = time.monotonic()
    response.headers["X-PSAT-Fresh-Until"] = str(time.time() + 60)
    response.headers["Cache-Tag"] = cache_tag(company_name)
    with deps.SessionLocal() as session:
        protocol_row, _ = resolve_company_jobs(session, company_name)
        if protocol_row is None:
            _log_endpoint("/api/company/{name}/addresses", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")
        addresses = all_addresses_for_protocol(session, protocol_row)
    _log_endpoint(
        "/api/company/{name}/addresses",
        company=company_name,
        started=started,
        outcome="success",
        address_count=len(addresses),
    )
    return {"all_addresses": addresses}


@router.get("/api/company/{company_name}/functions", response_model=None)
def company_functions(company_name: str, response: Response, request: Request) -> CompanyFunctionsResponse | Response:
    """Function entries keyed by ``"<chain>::<address>"``.

    Split out: ~2 MB and 120-290ms TTFB the canvas doesn't need to render.
    """
    started = time.monotonic()
    with deps.SessionLocal() as session:
        if enabled():
            return prepared_or_pending(session, request, company_name, section="functions")
        response.headers["X-PSAT-Response-Source"] = "live"
        response.headers["X-PSAT-Fresh-Until"] = str(time.time() + 60)
        response.headers["Cache-Tag"] = cache_tag(company_name)
        try:
            functions_by_entity = build_functions_for_protocol(session, company_name)
        except CompanyNotFound:
            _log_endpoint("/api/company/{name}/functions", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")
    _log_endpoint(
        "/api/company/{name}/functions",
        company=company_name,
        started=started,
        outcome="success",
        contract_count=len(functions_by_entity),
        function_count=sum(len(v) for v in functions_by_entity.values()),
    )
    return {"functions": functions_by_entity}


@router.get("/api/company/{company_name}/audits", response_model=None)
def company_audits(company_name: str) -> CompanyAuditsResponse:
    started = time.monotonic()
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            _log_endpoint("/api/company/{name}/audits", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")

        audit_rows = (
            session.execute(
                select(AuditReport)
                .where(AuditReport.protocol_id == protocol_row.id)
                .order_by(AuditReport.date.desc().nullslast())
            )
            .scalars()
            .all()
        )
        result: CompanyAuditsResponse = {
            "company": company_name,
            "protocol_id": protocol_row.id,
            "audit_count": len(audit_rows),
            "audits": [_audit_report_to_dict(ar) for ar in audit_rows],
        }
    _log_endpoint(
        "/api/company/{name}/audits",
        company=company_name,
        started=started,
        outcome="success",
        audit_count=len(audit_rows),
    )
    return result


@router.get("/api/company/{company_name}/audit_coverage", response_model=None)
def company_audit_coverage(company_name: str) -> CompanyAuditCoverageResponse:
    """Audits covering each inventory contract, from ``audit_contract_coverage``.

    ``last_audit`` is newest by date (nulls last, then id desc).

    - ``audit_count`` — every report on file. Must match ``/audits`` and the chat ``protocol_brief``: the hero stat
    links to that modal.
    - ``scoped_audit_count`` — reports with successful scope extraction, which can contribute coverage.
    """
    started = time.monotonic()
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            _log_endpoint(
                "/api/company/{name}/audit_coverage",
                company=company_name,
                started=started,
                outcome="not_found",
            )
            raise HTTPException(status_code=404, detail="Company not found")

        contracts = session.execute(select(Contract).where(Contract.protocol_id == protocol_row.id)).scalars().all()

        total_audit_count = session.execute(
            select(func.count(AuditReport.id)).where(AuditReport.protocol_id == protocol_row.id)
        ).scalar_one()
        audit_rows = (
            session.execute(
                select(AuditReport)
                .where(
                    AuditReport.protocol_id == protocol_row.id,
                    AuditReport.scope_extraction_status == "success",
                )
                .order_by(AuditReport.date.desc().nullslast(), AuditReport.id.desc())
            )
            .scalars()
            .all()
        )
        audits_by_id = {a.id: a for a in audit_rows}

        coverage_rows = (
            session.execute(
                select(AuditContractCoverage).where(
                    AuditContractCoverage.protocol_id == protocol_row.id,
                )
            )
            .scalars()
            .all()
        )
        coverage_by_contract: dict[int, list[Any]] = {}
        for row in coverage_rows:
            coverage_by_contract.setdefault(row.contract_id, []).append(row)

        # Reuse strict proofs for the same deployed contract from another protocol (Lido/WETH dependencies), never
        # heuristic matches.
        target_contract_ids_by_key: dict[tuple[str, str], set[int]] = {}
        for c in contracts:
            if key := _coverage_key(c.chain, c.address):
                target_contract_ids_by_key.setdefault(key, set()).add(c.id)
            if c.is_proxy and (key := _coverage_key(c.chain, c.implementation)):
                target_contract_ids_by_key.setdefault(key, set()).add(c.id)

        inherited_rows: list[AuditContractCoverage] = []
        if target_contract_ids_by_key:
            CoveredContract = aliased(Contract)
            inherited_pairs = session.execute(
                select(AuditContractCoverage, AuditReport, CoveredContract, Protocol)
                .join(CoveredContract, AuditContractCoverage.contract_id == CoveredContract.id)
                .join(AuditReport, AuditContractCoverage.audit_report_id == AuditReport.id)
                .join(Protocol, AuditContractCoverage.protocol_id == Protocol.id)
                .where(
                    AuditContractCoverage.protocol_id != protocol_row.id,
                    AuditContractCoverage.equivalence_status == "proven",
                    AuditContractCoverage.match_type == "reviewed_commit",
                    or_(
                        AuditContractCoverage.proof_kind.is_(None),
                        AuditContractCoverage.proof_kind != "cited_only",
                    ),
                    CoveredContract.address.in_({addr for _chain, addr in target_contract_ids_by_key}),
                )
            ).all()
            inherited_rows = _inherit_verified_dependency_coverage(
                inherited_pairs=inherited_pairs,
                target_contract_ids_by_key=target_contract_ids_by_key,
                coverage_by_contract=coverage_by_contract,
                audits_by_id=audits_by_id,
            )

        def _sort_key(row: Any) -> tuple:
            audit = audits_by_id.get(row.audit_report_id)
            date = (audit.date if audit else None) or ""
            return (date, row.audit_report_id)

        # Coverage rows sit on the impl; union the proxy's with its current impl's.
        contracts_by_addr = {c.address.lower(): c for c in contracts if c.address}

        coverage: list[AuditCoverageEntry] = []
        for c in contracts:
            entries = list(coverage_by_contract.get(c.id, []))
            seen_audit_ids = {e.audit_report_id for e in entries}
            if c.is_proxy and c.implementation:
                impl = contracts_by_addr.get(c.implementation.lower())
                if impl:
                    for e in coverage_by_contract.get(impl.id, []):
                        if e.audit_report_id not in seen_audit_ids:
                            entries.append(e)
                            seen_audit_ids.add(e.audit_report_id)
            entries = sorted(entries, key=_sort_key, reverse=True)
            matching: list[AuditBrief] = []
            for e in entries:
                audit = audits_by_id.get(e.audit_report_id)
                if audit is None:
                    continue
                brief = _audit_brief(audit, e)
                if getattr(e, "_coverage_source", None) == "inherited":
                    brief["coverage_source"] = "inherited"
                    brief["inherited_from_protocol"] = getattr(e, "_inherited_from_protocol", None)
                    brief["inherited_contract_address"] = getattr(e, "_inherited_contract_address", None)
                matching.append(brief)
            # Inventory-only entries (~67% of rows) add nothing; filtered here so analyzed-but-unaudited contracts still
            # show.
            if not c.contract_name and not matching:
                continue
            coverage.append(
                {
                    "address": c.address,
                    "chain": c.chain,
                    "contract_name": c.contract_name,
                    "audit_count": len(matching),
                    "last_audit": matching[0] if matching else None,
                    "audits": matching,
                }
            )
        result: CompanyAuditCoverageResponse = {
            "company": company_name,
            "protocol_id": protocol_row.id,
            "contract_count": len(coverage),
            "audit_count": total_audit_count,
            "scoped_audit_count": len(audit_rows),
            "coverage": coverage,
        }
    _log_endpoint(
        "/api/company/{name}/audit_coverage",
        company=company_name,
        started=started,
        outcome="success",
        contract_count=len(coverage),
        audit_count=total_audit_count,
        scoped_audit_count=len(audit_rows),
        coverage_row_count=len(coverage_rows) + len(inherited_rows),
    )
    return result


@router.get("/api/company/{company_name}/score", response_model=None)
def company_score(company_name: str) -> CompanyScoreResponse:
    """The latest score document, verbatim: every projection tried collapsed a three-state into two.

    ``grade_state = not_determined`` is a computed verdict, hence null figures.

    Two 404s told apart by ``detail`` (no such protocol vs not scored yet); an unreadable spilled document is 503.
    """
    from db.models import ProtocolScoreLatest
    from services.scoring.persist import ScoreDocumentUnavailable, load_score_document

    started = time.monotonic()
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            _log_endpoint("/api/company/{name}/score", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")

        row = session.execute(
            select(ProtocolScoreLatest).where(ProtocolScoreLatest.protocol_id == protocol_row.id)
        ).scalar_one_or_none()
        if row is None:
            _log_endpoint("/api/company/{name}/score", company=company_name, started=started, outcome="no_score")
            raise HTTPException(status_code=404, detail="No score has been computed for this protocol yet")

        try:
            document = load_score_document(row)
        except ScoreDocumentUnavailable as exc:
            _log_endpoint(
                "/api/company/{name}/score",
                company=company_name,
                started=started,
                outcome="document_unavailable",
            )
            raise HTTPException(status_code=503, detail=f"Score document could not be read: {exc}") from exc

        payload: CompanyScoreResponse = {
            "company": company_name,
            "protocol_id": protocol_row.id,
            "score_id": row.id,
            "model_version": row.model_version,
            "computed_at": row.computed_at.isoformat() if row.computed_at else None,
            "trigger": row.trigger,
            "trigger_job_id": str(row.trigger_job_id) if row.trigger_job_id else None,
            # From the document: the Numeric columns would arrive as Decimal strings.
            "grade_state": document.get("grade_state"),
            "grade_lambda": document.get("grade_lambda"),
            "grade_exposure": document.get("grade_exposure"),
            "confidence_pct": document.get("confidence_pct"),
            "perimeter_state": document.get("perimeter_state"),
            "findings": document.get("findings"),
            "earned_negatives": document.get("earned_negatives"),
            "warnings": document.get("warnings"),
            "model_parameters": document.get("model_parameters"),
            "uncalibrated_arms": document.get("uncalibrated_arms"),
            "provenance": row.provenance,
        }
    _log_endpoint(
        "/api/company/{name}/score",
        company=company_name,
        started=started,
        outcome="success",
        grade_state=payload["grade_state"],
        perimeter_state=payload["perimeter_state"],
        finding_count=len(payload["findings"] or []),
    )
    return payload


@router.get("/api/company/{company_name}/summary", response_model=None)
def company_summary(company_name: str, request: Request) -> Response | dict:
    from services.aggregations.company_overview.payload import build_company_summary

    with deps.SessionLocal() as session:
        if enabled():
            return prepared_or_pending(session, request, company_name, section="summary")
        try:
            return build_company_summary(session, company_name)
        except CompanyNotFound:
            raise HTTPException(404, "Company not found") from None


@router.post("/api/company/{company_name}/refresh", dependencies=[Depends(deps.require_admin)], status_code=202)
def refresh_company(company_name: str) -> dict:
    with deps.SessionLocal() as session:
        identities = eligible_company_names(session)
        if company_name not in identities:
            raise HTTPException(404, "Company not found")
        protocol_id = identities[company_name]
        if not enabled():
            raise HTTPException(409, "Prepared company responses are disabled")
        # Touch revisions, never lock the result row held by a running builder.
        keys = [f"protocol:{protocol_id}:manual", f"summary:protocol:{protocol_id}:manual"]
        session.execute(text("SELECT psat_page_touch(:keys)"), {"keys": keys})
        session.commit()
    return {"status": "preparing"}
