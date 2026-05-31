"""Company / protocol overview + audit views."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from typing import Any

from fastapi import APIRouter, HTTPException, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import aliased

from db.models import AuditContractCoverage, AuditReport, Contract, Protocol
from services.aggregations import CompanyNotFound, build_company_overview
from services.aggregations.company_overview import (
    all_addresses_for_protocol,
    build_functions_for_protocol,
    resolve_company_jobs,
)
from services.audits.serializers import _audit_brief, _audit_report_to_dict

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
    """Emit one structured log line per endpoint hit with elapsed time.

    Pairs with the ``x-psat-trace-id`` middleware so each line is grepable
    by trace_id in Loki. Matches the ``duration_ms`` field already used by
    ``workers/base.py`` for stage timings.
    """
    elapsed_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "%s elapsed_ms=%d company=%s",
        route,
        elapsed_ms,
        company,
        extra={"phase": "http_endpoint", "route": route, "duration_ms": elapsed_ms, "company": company, **extras},
    )


@router.get("/api/company/{company_name}")
def company_overview(company_name: str, response: Response) -> dict:
    """Aggregated governance overview for all contracts in a company."""
    # Largest payload on the site (1-3 MB). Letting the browser hold it for
    # 15s + serve-stale-while-revalidate makes back/forward navigation and
    # tab switches inside the company page instant — both CompanyOverview
    # and ProtocolSurface read this URL on mount.
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    started = time.monotonic()
    with deps.SessionLocal() as session:
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


@router.get("/api/company/{company_name}/addresses")
def company_addresses(company_name: str, response: Response) -> dict[str, Any]:
    """Full inventory of contract addresses for a protocol.

    Split out from the main ``/api/company/{name}`` payload so the
    167 KB list isn't shipped on every page-load — ``AddressesModal``
    fetches this lazily when the user opens it.
    """
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    started = time.monotonic()
    with deps.SessionLocal() as session:
        protocol_row, jobs = resolve_company_jobs(session, company_name)
        if protocol_row is None and not jobs:
            _log_endpoint("/api/company/{name}/addresses", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")
        addresses = all_addresses_for_protocol(session, protocol_row, jobs)
    _log_endpoint(
        "/api/company/{name}/addresses",
        company=company_name,
        started=started,
        outcome="success",
        address_count=len(addresses),
    )
    return {"all_addresses": addresses}


@router.get("/api/company/{company_name}/functions")
def company_functions(company_name: str, response: Response) -> dict[str, Any]:
    """Per-contract function entries for a protocol, keyed by address.

    Split out of the main ``/api/company/{name}`` payload — the
    ``EffectiveFunction`` table accounts for ~2.13 MB of payload and
    120-290ms of TTFB on ether.fi, neither of which the Surface canvas
    needs to render. ``ProtocolSurface`` fetches this in parallel with
    the main payload and populates the function inspector when it
    arrives.
    """
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    started = time.monotonic()
    with deps.SessionLocal() as session:
        try:
            functions_by_address = build_functions_for_protocol(session, company_name)
        except CompanyNotFound:
            _log_endpoint("/api/company/{name}/functions", company=company_name, started=started, outcome="not_found")
            raise HTTPException(status_code=404, detail="Company not found")
    _log_endpoint(
        "/api/company/{name}/functions",
        company=company_name,
        started=started,
        outcome="success",
        contract_count=len(functions_by_address),
        function_count=sum(len(v) for v in functions_by_address.values()),
    )
    return {"functions": functions_by_address}


@router.get("/api/company/{company_name}/audits")
def company_audits(company_name: str) -> dict[str, Any]:
    """List all known audit reports for a company."""
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
        result = {
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


@router.get("/api/company/{company_name}/audit_coverage")
def company_audit_coverage(company_name: str) -> dict[str, Any]:
    """For each contract in the company's inventory, list audits covering it.

    Reads from the persisted ``audit_contract_coverage`` join table — rows
    are written proxy-aware by ``services.audits.coverage`` when scope
    extraction completes or a live upgrade event is detected. The
    ``last_audit`` pointer is the most recent matching audit by ``date``
    (nulls last, then id desc to break ties). Each audit entry carries
    ``match_type`` + ``match_confidence`` so the UI can flag low-confidence
    links differently.
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

        # Pull every coverage row for the protocol in one query, then
        # bucket in Python — cheaper than N queries for N contracts.
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

        # Reuse strict proofs already established for the same deployed
        # contract under another protocol. This lets dependency rows such as
        # Lido/WETH/LayerZero carry their own verified audits when they appear
        # in a dependent protocol, without crediting heuristic matches.
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
                    CoveredContract.chain.in_({chain for chain, _addr in target_contract_ids_by_key}),
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

        # Proxy rows don't hold their own coverage rows — the scope
        # matcher writes against the impl Contract row. For the
        # company-level "is this contract audited?" view the user really
        # means "is the code this address is running audited?", so union
        # the proxy's entries with its current implementation's.
        contracts_by_addr = {c.address.lower(): c for c in contracts if c.address}

        coverage: list[dict[str, Any]] = []
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
            matching = []
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
            # Inventory-only entries (discovered but never analyzed) have no
            # name and no audits — they contribute nothing to the coverage
            # view and otherwise inflate the payload (~67% of rows for a
            # mature protocol). Drop them at the serializer rather than at
            # the query, so analyzed contracts without audits still surface.
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
        result = {
            "company": company_name,
            "protocol_id": protocol_row.id,
            "contract_count": len(coverage),
            "audit_count": len(audit_rows),
            "coverage": coverage,
        }
    _log_endpoint(
        "/api/company/{name}/audit_coverage",
        company=company_name,
        started=started,
        outcome="success",
        contract_count=len(coverage),
        audit_count=len(audit_rows),
        coverage_row_count=len(coverage_rows) + len(inherited_rows),
    )
    return result
