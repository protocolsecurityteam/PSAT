from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select

from db.models import Artifact, Contract, Job, JobStatus
from db.storage import StorageContentAbsent, StorageKeyAbsent, StorageKeyMissing
from schemas.api_responses import AnalysisListEntry
from services.aggregations import build_analysis_detail
from services.aggregations.company_overview.entity_keys import _coalesce_chain
from services.aggregations.company_overview.jobs import _job_chain_name
from services.governance.proxies import _merge_proxy_impl_entries
from utils.chains import UnknownChainError, chain_by_name

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()

# Artifacts the consumer frontend fetches; any other name requires the admin key. Compared after extension-stripping and
# lowercasing.
_CONSUMER_SAFE_ARTIFACTS = frozenset({"upgrade_history", "dependencies", "dependency_graph_viz", "policy_state"})

# Hidden from the public listing so their existence isn't enumerable.
_INTERNAL_ARTIFACT_NAMES = frozenset({"stage_errors", "stage_timings", "predicate_trees", "control_tracking_plan"})


def _is_internal_artifact_name(name: str) -> bool:
    n = name.lower()
    return n in _INTERNAL_ARTIFACT_NAMES or n.startswith("stage_timing_") or n.endswith("error") or n.endswith("plan")


# Recorded by ``workers/static_worker`` when the upgrade-history build raised and was swallowed.
_UPGRADE_HISTORY_PHASE = "dependency_upgrade_history"


def _upgrade_history_stage_raised(session: Any, job: Job) -> str | None:
    """A reason when the phase failed or we couldn't find out; ``None`` only when ``stage_errors`` was read and has
    no such entry (a missing artifact means no degraded errors, which is an answer).
    """
    try:
        body = deps.get_artifact(session, job.id, "stage_errors")
    except (StorageKeyMissing, StorageContentAbsent):
        return None
    except Exception as exc:  # storage down, undeserializable, key never recorded
        logger.error("stage_errors for job %s unreadable: %s", job.id, exc, extra={"exc_type": type(exc).__name__})
        return "stage_errors unreadable: cannot rule out a failed upgrade-history stage"
    if not isinstance(body, dict):
        return None
    for error in body.get("errors") or []:
        if isinstance(error, dict) and error.get("phase") == _UPGRADE_HISTORY_PHASE:
            return (
                "the upgrade-history stage recorded a degraded failure "
                f"({error.get('exc_type') or 'unknown error'}); absence of the artifact is not a proven negative"
            )
    return None


def _upgrade_history_absence_reason(session: Any, job: Job, contract: Contract | None) -> str | None:
    """Why a missing ``upgrade_history`` is not determined, or ``None`` if absence is proven.

    Proven only for a self-consistent non-proxy row whose stage recorded no failure. Open otherwise: no Contract row;
    ``is_proxy`` true; or ``is_proxy`` false with ``proxy_type``/``implementation`` set (``0x3c55986c…`` is exactly that
    and has 14 ``Upgraded`` logs).

    Blind spot: a proxy the classifier missed entirely reads as proven non-proxy.
    """
    if contract is None:
        return "no contract row for this job: whether the target is a proxy was never recorded"
    proxy_signals = [name for name in ("proxy_type", "implementation") if getattr(contract, name, None)]
    if contract.is_proxy:
        return "the contract is a proxy and no upgrade-history artifact was stored for it"
    if proxy_signals:
        return (
            f"the contract row is inconsistent about proxyhood (is_proxy is false but {', '.join(proxy_signals)} "
            "is set), so its non-proxy status cannot carry the absence"
        )
    return _upgrade_history_stage_raised(session, job)


@router.get("/api/analyses", response_model=None)
def analyses(response: Response) -> list[AnalysisListEntry]:
    # Multi-MB payload; SWR lets back/forward reuse it.
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    with deps.SessionLocal() as session:
        stmt = (
            select(Job)
            .where(Job.status == JobStatus.completed, Job.request["effects_resume_work_id"].astext.is_(None))
            .order_by(Job.updated_at.desc())
        )
        jobs = session.execute(stmt).scalars().all()

        jobs_by_id = {str(job.id): job for job in jobs}
        # (chain, address) keys keep CREATE2 twins distinct, so an impl completed only on another chain doesn't un-hide
        # this chain's proxy.
        jobs_by_key: dict[tuple[str, str], Job] = {}
        for job in jobs:
            if job.address:
                jobs_by_key.setdefault((_coalesce_chain(_job_chain_name(job)), job.address.lower()), job)

        # Everything comes from columns to skip the per-job ``contract_flags`` storage GET, formerly the dominant cost.
        contracts_by_key: dict[tuple[str, str], Contract] = {}
        addresses_from_jobs = list({addr for (_chain, addr) in jobs_by_key})
        if addresses_from_jobs:
            for c in session.execute(select(Contract).where(Contract.address.in_(addresses_from_jobs))).scalars():
                addr_lower = (c.address or "").lower()
                if addr_lower:
                    contracts_by_key.setdefault((_coalesce_chain(c.chain), addr_lower), c)

        job_ids = [job.id for job in jobs]
        # Artifact names only; fetching each ``contract_analysis`` body just for name/summary was the dominant cost.
        artifact_names_by_job: dict[Any, list[str]] = {}
        if job_ids:
            for row in session.execute(
                select(Artifact.job_id, Artifact.name).where(Artifact.job_id.in_(job_ids))
            ).all():
                artifact_names_by_job.setdefault(row[0], []).append(row[1])

    def company_for_job(job: Job) -> str | None:
        seen: set[str] = set()
        current: Job | None = job
        while current is not None:
            if current.company:
                return current.company
            request = current.request if isinstance(current.request, dict) else {}
            parent_job_id = request.get("parent_job_id")
            if not isinstance(parent_job_id, str) or parent_job_id in seen:
                return None
            seen.add(parent_job_id)
            current = jobs_by_id.get(parent_job_id)
        return None

    results: list[AnalysisListEntry] = []
    for job in jobs:
        run_name = job.name or str(job.id)
        request = job.request if isinstance(job.request, dict) else {}
        parent_job_id = request.get("parent_job_id")
        company = company_for_job(job)
        addr_lower = (job.address or "").lower()
        job_chain_key = _coalesce_chain(_job_chain_name(job))
        contract = contracts_by_key.get((job_chain_key, addr_lower))
        entry: AnalysisListEntry = {
            "run_name": run_name,
            "job_id": str(job.id),
            "address": job.address,
            "chain": request.get("chain") or (contract.chain if contract else None),
            "company": company,
            "parent_job_id": parent_job_id,
            "rank_score": (float(contract.rank_score) if contract and contract.rank_score is not None else None),
            "is_proxy": bool(job.is_proxy),
            "proxy_type": contract.proxy_type if contract else None,
            "implementation_address": contract.implementation if contract else None,
            "proxy_address": request.get("proxy_address"),
            "available_artifacts": sorted(
                n for n in artifact_names_by_job.get(job.id, []) if not _is_internal_artifact_name(n)
            ),
        }

        # Hide proxies until the impl completes, or the card mutates when it lands.
        contract_name_source = contract
        if entry["is_proxy"] and entry["implementation_address"]:
            impl_addr_lower = entry["implementation_address"].lower()
            impl_job = jobs_by_key.get((job_chain_key, impl_addr_lower))
            if impl_job is None:
                continue
            # The impl's name ("WithdrawRequestNFT") over the proxy shell's ("UUPSProxy").
            impl_contract = contracts_by_key.get((job_chain_key, impl_addr_lower))
            if impl_contract is not None and impl_contract.contract_name:
                contract_name_source = impl_contract

        if contract_name_source and contract_name_source.contract_name:
            entry["contract_name"] = contract_name_source.contract_name
        results.append(entry)
    return _merge_proxy_impl_entries(results)


@router.get("/api/analyses/{run_name:path}/artifact/{artifact_name:path}")
def analysis_artifact(
    run_name: str,
    artifact_name: str,
    request: Request,
    chain: str | None = Query(default=None),
    x_psat_admin_key: str | None = Header(default=None),
):
    """Get one artifact for an analysis.

    Non-consumer-safe names need the admin key, checked before any lookup so there's no existence signal.

    The SPA renders absence as a fact about the contract, so three answers:

      200  present (including upgrade_history synthesized from UpgradeEvent rows).
      404  proven absent.
      503  not determined (``X-PSAT-Artifact-State: not_determined``).

    A 404 for storage outages once rendered as "no upgrades on this proxy".
    """
    lookup_name = artifact_name
    if artifact_name.endswith(".json"):
        lookup_name = artifact_name[:-5]
    elif artifact_name.endswith(".txt"):
        lookup_name = artifact_name[:-4]

    if lookup_name.lower() not in _CONSUMER_SAFE_ARTIFACTS:
        deps.require_admin_key(request, x_psat_admin_key)

    with deps.SessionLocal() as session:
        stmt = select(Job).where(Job.name == run_name).order_by(Job.updated_at.desc()).limit(1)
        job = session.execute(stmt).scalar_one_or_none()
        if job is None:
            try:
                job = session.get(Job, run_name)
            except Exception:
                session.rollback()
        if job is None:
            # Chain-qualify when a chain is supplied; without one keep the address-only lookup.
            stmt = (
                select(Job)
                .where(
                    Job.address == run_name,
                    Job.status == JobStatus.completed,
                    Job.request["effects_resume_work_id"].astext.is_(None),
                )
                .order_by(Job.updated_at.desc())
                .limit(1)
            )
            if chain is not None:
                try:
                    stmt = stmt.where(Job.chain_id == chain_by_name(chain).chain_id)
                except UnknownChainError:
                    raise HTTPException(status_code=400, detail=f"Unknown chain: {chain}") from None
            job = session.execute(stmt).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="Analysis not found")

        artifact: Any = None
        not_determined: str | None = None
        try:
            artifact = deps.get_artifact(session, job.id, lookup_name)
            if artifact is None:
                artifact = deps.get_artifact(session, job.id, artifact_name)
        except (StorageKeyMissing, StorageContentAbsent) as exc:
            logger.warning("artifact %s for job %s is absent: %s", lookup_name, job.id, exc)
        except StorageKeyAbsent as exc:
            # The row records no key, so the bucket was never asked: not-determined, not absent (see
            # ``db.storage.StorageKeyAbsent``).
            not_determined = "Artifact key not recorded"
            logger.error("artifact %s for job %s not determined: %s", lookup_name, job.id, exc)
        except Exception as exc:
            # We didn't find out; the synthesis fallback may still produce the body.
            not_determined = "Artifact read did not complete"
            logger.error("artifact %s for job %s not determined: %s", lookup_name, job.id, exc)

        # Reproducible from UpgradeEvent rows when the artifact is gone or storage is down.
        if artifact is None and lookup_name == "upgrade_history":
            from services.discovery.upgrade_history import synthesize_from_events

            contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
            if contract is not None:
                artifact = synthesize_from_events(session, contract)
            if artifact is None and not_determined is None:
                # No row is written both when the stage found no proxies and when it raised, and the SPA reads 404 as
                # proven absence. Falsified by the beacon proxy at ``0x3c55986c…``.
                not_determined = _upgrade_history_absence_reason(session, job, contract)

        if artifact is None and not_determined is not None:
            # 503, not 404: unknown. Retry-After because this state can change on its own.
            return JSONResponse(
                status_code=503,
                headers={"X-PSAT-Artifact-State": "not_determined", "Retry-After": "30"},
                content={
                    "detail": "Artifact state not determined",
                    "artifact": lookup_name,
                    "reason": not_determined,
                },
            )

        if artifact is None:
            raise HTTPException(status_code=404, detail="Artifact not found")

        if isinstance(artifact, (dict, list)):
            return JSONResponse(content=artifact)
        return PlainTextResponse(str(artifact))


@router.get("/api/analyses/{run_name:path}")
def analysis_detail(run_name: str) -> dict:
    with deps.SessionLocal() as session:
        payload = build_analysis_detail(session, run_name)
        if payload is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return payload
