"""Build the per-analysis detail payload used by the SPA's analysis page.

Routes ``/api/analyses/{run_name}`` through here. Returns ``None`` when no
matching job is found so the caller can map to a 404 — services don't
import FastAPI.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStatus

# Indirect through ``routers.deps`` so tests get a single patch point for
# ``SessionLocal``/``get_all_artifacts``.
from routers import deps
from schemas.assessment import Assessment

logger = logging.getLogger(__name__)


def _artifacts_or_degrade(
    session: Session,
    job_id: Any,
    not_determined: dict[str, str],
    proven_absent: dict[str, str],
) -> dict[str, Any]:
    """``get_all_artifacts`` for a page that may render partially.

    ``get_all_artifacts`` fails closed, because a short dict is
    indistinguishable from "the job produced fewer artifacts". This page is
    allowed to render what did load — but only by naming what did not, in the
    two maps published as ``artifacts_not_determined`` (the bucket could not be
    asked) and ``artifacts_body_absent`` (the bucket answered; the row asserts a
    key nothing is stored under). Every artifact this payload carries is
    consumed as evidence about the contract, and the two shortfalls are not the
    same evidence — one may resolve itself, the other never will.

    NO ``site/`` CONSUMER, and this is why. Nothing in the SPA
    fetches this merged payload at all: ``grep`` over ``site/src`` finds
    ``/api/analyses`` only as the LISTING (``App.jsx``) plus two per-artifact reads
    (``EntityActivity`` → ``upgrade_history``, ``layout/dependencies`` →
    ``dependency_graph_viz``), both of which go through
    ``routers/analyses``'s artifact endpoint and already receive the same three
    answers on the wire via ``X-PSAT-Artifact-State``. So wiring a consumer for
    these two maps means building a page that reads the multi-MB payload, which is
    a feature and not a consumer-side split. The maps stay published for API
    consumers; the SPA's equivalent distinction is served by the header.
    """
    try:
        return deps.get_all_artifacts(session, job_id)
    except deps.StorageContentIncomplete as exc:
        logger.error(
            "analysis detail for job %s is missing %d artifact bodies (%d not determined, %d proven absent)",
            job_id,
            len(exc.not_determined) + len(exc.proven_absent),
            len(exc.not_determined),
            len(exc.proven_absent),
        )
        not_determined.update(exc.not_determined)
        proven_absent.update(exc.proven_absent)
        return dict(exc.values or {})


def build_analysis_detail(session: Session, run_name: str) -> dict[str, Any] | None:
    # Try by name first, then by id, then by address
    stmt = select(Job).where(Job.name == run_name).order_by(Job.updated_at.desc()).limit(1)
    job = session.execute(stmt).scalar_one_or_none()
    if job is None:
        try:
            job = session.get(Job, run_name)
        except Exception:
            session.rollback()
    if job is None:
        # Try by address
        job = session.execute(
            select(Job)
            .where(Job.address == run_name, Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc())
            .limit(1)
        ).scalar_one_or_none()
    if job is None:
        return None

    # Load artifacts (for those still stored as artifacts)
    not_determined: dict[str, str] = {}
    body_absent: dict[str, str] = {}
    all_artifacts = _artifacts_or_degrade(session, job.id, not_determined, body_absent)

    # Fall back to address lookup when copy_static_cache has reassigned
    # the Contract row to a newer job. Chain-scoped so we don't pick up
    # the same address on a different chain.
    contract_row = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
    if contract_row is None and job.address:
        fallback_stmt = select(Contract).where(Contract.address == job.address.lower())
        job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
        if job_chain:
            fallback_stmt = fallback_stmt.where(Contract.chain == job_chain)
        contract_row = session.execute(fallback_stmt.limit(1)).scalar_one_or_none()

    def _company_for(j: Job) -> str | None:
        seen: set[str] = set()
        current: Job | None = j
        while current is not None:
            if current.company:
                return current.company
            req = current.request if isinstance(current.request, dict) else {}
            parent_id = req.get("parent_job_id")
            if not isinstance(parent_id, str) or parent_id in seen:
                return None
            seen.add(parent_id)
            current = session.get(Job, parent_id)
        return None

    payload: dict[str, Any] = {
        "run_name": job.name or str(job.id),
        "job_id": str(job.id),
        "address": job.address,
        "contract_id": contract_row.id if contract_row else None,
        "company": _company_for(job),
        "deployer": contract_row.deployer if contract_row else None,
        "available_artifacts": sorted(all_artifacts.keys()),
    }

    for artifact_name in (
        "assessment",
        "dependencies",
        "dependency_graph_viz",
        "upgrade_history",
    ):
        if artifact_name in all_artifacts and isinstance(all_artifacts[artifact_name], dict):
            payload[artifact_name] = all_artifacts[artifact_name]

    # Resolved semantic capabilities. Computed lazily from Assessment evidence;
    # resolving predicate trees to the typed
    # CapabilityExpr requires the AdapterRegistry + repos. Defensive: a
    # capability-resolution failure MUST NOT fail the whole analysis_detail
    # response; the rest of the detail payload is still useful.
    if "assessment" in all_artifacts and job.address:
        try:
            from services.resolution.capability_resolver import resolve_contract_capabilities

            # Per C.1 cutover: scope by (job_id, chain) so a re-analysis
            # on a different chain or a follow-up job on the same address
            # doesn't leak controller rows into this job's resolution.
            # Chain comes from the Contract row when present, falling
            # back to job.request['chain'].
            req_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            chain = (contract_row.chain if contract_row and contract_row.chain else None) or req_chain
            # chain_id is required: bind the resolver's live reads to the
            # job's first-class chain_id, falling back to the registry-backed
            # derivation from the job's chain string (mirrors the M0.2 backfill).
            from db.models import derive_job_chain_id

            chain_id = getattr(job, "chain_id", None)
            if not isinstance(chain_id, int):
                chain_id = derive_job_chain_id(chain if isinstance(chain, str) else req_chain, job.address)
                # ``job.address`` is truthy here (guarded above), so the
                # derivation never hits its address-less ``None`` case.
                assert chain_id is not None
            semantic_caps = resolve_contract_capabilities(
                session,
                address=job.address.lower(),
                chain_id=chain_id,
                job_id=job.id,
                chain=chain if isinstance(chain, str) else None,
            )
            if semantic_caps is not None:
                payload["semantic_capabilities"] = semantic_caps
        except Exception as exc:
            logger.warning(
                "semantic capability resolution failed for job %s; omitting capability enrichment: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

    if contract_row:
        _populate_from_contract(session, payload, contract_row)

    # For impl jobs, inherit proxy-specific artifacts from the proxy job
    request = job.request if isinstance(job.request, dict) else {}
    proxy_address = request.get("proxy_address")
    if proxy_address:
        proxy_stmt = select(Job).where(Job.address == proxy_address).order_by(Job.updated_at.desc()).limit(1)
        proxy_job = session.execute(proxy_stmt).scalar_one_or_none()
        if proxy_job:
            proxy_artifacts = _artifacts_or_degrade(session, proxy_job.id, not_determined, body_absent)
            for fallback_name in ("upgrade_history", "dependency_graph_viz", "dependencies"):
                if fallback_name in payload:
                    continue
                fallback = proxy_artifacts.get(fallback_name)
                if isinstance(fallback, dict):
                    payload[fallback_name] = fallback
    payload["proxy_address"] = proxy_address

    # For proxy jobs, inherit analysis from the impl child job
    is_proxy = contract_row.is_proxy if contract_row else False
    impl_addr = contract_row.implementation if contract_row else None
    if is_proxy and impl_addr:
        impl_stmt = select(Job).where(Job.address == impl_addr).order_by(Job.updated_at.desc()).limit(1)
        impl_job = session.execute(impl_stmt).scalar_one_or_none()
        if impl_job:
            _inherit_from_impl(session, payload, job, impl_job, impl_addr, not_determined, body_absent)

    # Canonical claims + detector coverage own the compatibility boolean.
    if isinstance(all_artifacts.get("assessment"), dict):
        from services.assessment import effect_presence

        assessment = cast(Assessment, all_artifacts["assessment"])
        payload["assessment"] = assessment
        summary = payload.get("summary")
        summary = dict(summary) if isinstance(summary, dict) else {}
        summary["is_pausable"] = effect_presence(assessment, "pause.set")
        payload["summary"] = summary

    # Synthesis fallback for upgrade_history. Mirrors the per-artifact
    # endpoint at /api/analyses/{job}/artifact/upgrade_history. Runs after
    # all other paths (artifact body, proxy-impl inheritance) so it only
    # fires when nothing else surfaced one — typically a storage outage or
    # a never-materialized artifact. Gated on is_proxy because UpgradeEvent
    # rows only ever exist for proxies.
    if "upgrade_history" not in payload and contract_row is not None and getattr(contract_row, "is_proxy", False):
        from services.discovery.upgrade_history import synthesize_from_events

        synthesized = synthesize_from_events(session, contract_row)
        if synthesized:
            payload["upgrade_history"] = synthesized

    if not_determined:
        # Names whose row exists but whose body the bucket could not be asked
        # about. Without this the SPA reads their absence from ``payload`` as
        # proof the analysis never produced them.
        payload["artifacts_not_determined"] = dict(sorted(not_determined.items()))
    if body_absent:
        # Names whose row exists and whose object the bucket says it does not
        # hold. Also not "the analysis never produced them" — but unlike the map
        # above, re-asking will not change the answer.
        payload["artifacts_body_absent"] = dict(sorted(body_absent.items()))

    if contract_row is not None:
        payload.setdefault("contract_name", contract_row.contract_name or payload["run_name"])

    return payload


def _populate_from_contract(session: Session, payload: dict[str, Any], contract_row: Contract) -> None:
    del session
    if not contract_row.is_proxy:
        payload["contract_name"] = contract_row.contract_name or payload["run_name"]
    if not contract_row.is_proxy and contract_row.summary:
        payload["summary"] = {
            "control_model": contract_row.summary.control_model,
            "is_upgradeable": contract_row.summary.is_upgradeable,
            "is_pausable": contract_row.summary.is_pausable,
            "has_timelock": contract_row.summary.has_timelock,
            "standards": list(contract_row.summary.standards or []),
        }


def _inherit_from_impl(
    session: Session,
    payload: dict[str, Any],
    job: Job,
    impl_job: Job,
    impl_addr: str,
    not_determined: dict[str, str] | None = None,
    body_absent: dict[str, str] | None = None,
) -> None:
    impl_artifacts = _artifacts_or_degrade(
        session,
        impl_job.id,
        not_determined if not_determined is not None else {},
        body_absent if body_absent is not None else {},
    )
    for fallback_name in ("assessment",):
        if fallback_name not in payload:
            val = impl_artifacts.get(fallback_name)
            if val is not None:
                payload[fallback_name] = val

    impl_c = session.execute(select(Contract).where(Contract.job_id == impl_job.id).limit(1)).scalar_one_or_none()
    if impl_c:
        if "contract_name" not in payload and impl_c.contract_name:
            payload["contract_name"] = impl_c.contract_name
        if "summary" not in payload and impl_c.summary:
            payload["summary"] = {
                "control_model": impl_c.summary.control_model,
                "is_upgradeable": impl_c.summary.is_upgradeable,
                "is_pausable": impl_c.summary.is_pausable,
                "has_timelock": impl_c.summary.has_timelock,
                "standards": list(impl_c.summary.standards or []),
            }

    payload["proxy_address"] = payload.get("proxy_address") or job.address
    payload["implementation_address"] = impl_addr
