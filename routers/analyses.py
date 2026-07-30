"""Analysis listing, detail, and artifact endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select

from db.models import Artifact, Contract, Job, JobStatus
from db.storage import StorageContentAbsent, StorageKeyAbsent, StorageKeyMissing
from services.aggregations import build_analysis_detail
from services.aggregations.company_overview import _coalesce_chain, _job_chain_name
from services.governance.proxies import _merge_proxy_impl_entries
from utils.chains import UnknownChainError, chain_by_name

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()

# Artifact names the consumer frontend fetches via ``/artifact/``. Any other
# name is operator/internal and gated behind a valid admin key. Compared
# against the requested name after extension-stripping and lower-casing.
_CONSUMER_SAFE_ARTIFACTS = frozenset({"upgrade_history", "dependencies", "dependency_graph_viz", "policy_state"})

# Internal/operator artifacts excluded from the public ``/api/analyses``
# listing so their existence isn't enumerable to anonymous callers.
_INTERNAL_ARTIFACT_NAMES = frozenset({"stage_errors", "stage_timings", "predicate_trees", "control_tracking_plan"})


def _is_internal_artifact_name(name: str) -> bool:
    n = name.lower()
    return n in _INTERNAL_ARTIFACT_NAMES or n.startswith("stage_timing_") or n.endswith("error") or n.endswith("plan")


# The sub-phase ``workers/static_worker`` records when the upgrade-history build
# raised and was swallowed (both the parallel and the finalize call sites).
_UPGRADE_HISTORY_PHASE = "dependency_upgrade_history"


def _upgrade_history_stage_raised(session: Any, job: Job) -> str | None:
    """Whether this job's upgrade-history sub-phase recorded a degraded failure.

    Returns a reason string when the answer is "yes, or we could not find out",
    and ``None`` only when the ``stage_errors`` record was read and carries no
    such entry. A job with no ``stage_errors`` artifact recorded no degraded
    errors at all, which IS an answer; a body the bucket could not produce is not.

    Realised on the local corpus: **0** jobs carry this phase — the honest
    lower-bound statement, not a firing proof. The mechanism is demonstrably live
    on the same 123 ``stage_errors`` artifacts through sibling phases
    (``controller_read`` 1,401 entries, ``dependency_dynamic`` 12), so what is
    unrealised is this phase's failure, not the read.
    """
    try:
        body = deps.get_artifact(session, job.id, "stage_errors")
    except (StorageKeyMissing, StorageContentAbsent):
        # The bucket was asked and says it holds no such object: no degraded
        # record exists for this job.
        return None
    except Exception as exc:  # storage down, undeserializable, key never recorded
        return f"stage_errors unreadable ({type(exc).__name__}): cannot rule out a failed upgrade-history stage"
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
    """Why a missing ``upgrade_history`` is NOT determined, or ``None`` if absence
    is proven.

    Absence is proven for exactly one shape: a Contract row that says
    self-consistently that the target is not a proxy, with the upgrade-history
    stage recording no failure. A non-proxy has no upgrade history by
    construction, so there is nothing the missing artifact could be hiding.

    Everything else keeps the question open:

    * **no Contract row** — nothing here knows whether the target is a proxy.
    * **``is_proxy`` true** — the artifact SHOULD have existed and does not.
    * **``is_proxy`` false while ``proxy_type`` or ``implementation`` is set** —
      the row contradicts itself, so its proxyhood is not evidence either way.
      A real counterexample: ``0x3c55986c…`` is ``is_proxy=False`` with
      ``proxy_type='beacon'`` yet has 14 ``Upgraded(address)`` logs at or before
      block 25619159, so reading it as a proven non-proxy denies a real history.

    What it cannot see, stated rather than implied: a real proxy the classifier
    missed entirely (``is_proxy`` false, ``proxy_type`` and ``implementation``
    both NULL) reads as a proven non-proxy here. Splitting that needs a
    proxy-detection verdict the ``contracts`` row does not carry.
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


@router.get("/api/analyses")
def analyses(response: Response) -> list[dict]:
    """List completed analyses with their available artifacts."""
    # Read-mostly listing — let the browser reuse it across navigations.
    # Short max-age + SWR keeps freshness while letting back/forward and
    # rapid re-renders avoid a network round-trip for the multi-MB payload.
    response.headers["Cache-Control"] = "private, max-age=15, stale-while-revalidate=60"
    with deps.SessionLocal() as session:
        stmt = select(Job).where(Job.status == JobStatus.completed).order_by(Job.updated_at.desc())
        jobs = session.execute(stmt).scalars().all()

        jobs_by_id = {str(job.id): job for job in jobs}
        # Keyed by (coalesced-chain, address) so a CREATE2 twin's per-chain
        # jobs stay distinct: the same address on ethereum and base
        # is two entities, and impl-hiding must find the impl on the proxy's
        # own chain — an impl completed only on the other chain must not
        # un-hide this chain's proxy.
        jobs_by_key: dict[tuple[str, str], Job] = {}
        for job in jobs:
            if job.address:
                jobs_by_key.setdefault((_coalesce_chain(_job_chain_name(job)), job.address.lower()), job)

        # Rank scores, chains, name, proxy_type, implementation come from
        # the ``contracts`` table. is_proxy comes from Job (denormalized via
        # store_artifact). Pulling all of these from columns lets us skip
        # the per-job ``contract_flags`` storage GET entirely — at 25ms
        # production RTT × N jobs, that GET batch was the dominant cost
        # of this endpoint after the parallel-fanout commit. Keyed by
        # (coalesced-chain, address) so each job pairs with its own chain's
        # Contract row rather than an arbitrary twin's.
        contracts_by_key: dict[tuple[str, str], Contract] = {}
        addresses_from_jobs = list({addr for (_chain, addr) in jobs_by_key})
        if addresses_from_jobs:
            for c in session.execute(select(Contract).where(Contract.address.in_(addresses_from_jobs))).scalars():
                addr_lower = (c.address or "").lower()
                if addr_lower:
                    contracts_by_key.setdefault((_coalesce_chain(c.chain), addr_lower), c)

        job_ids = [job.id for job in jobs]
        # Earlier code fetched every job's ``contract_analysis`` artifact body
        # from object storage just to read ``subject.name`` and ``summary``.
        # Both were redundant: ``contract_name`` is on the prefetched
        # ``Contract`` row and ``summary`` is never consumed by the frontend
        # listing (it's a detail-page field). Reading just artifact NAMES
        # (no body) keeps the available_artifacts list populated without
        # the per-job HTTP round-trip — the dominant cost of this endpoint
        # at production scale.
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

    results = []
    for job in jobs:
        run_name = job.name or str(job.id)
        request = job.request if isinstance(job.request, dict) else {}
        parent_job_id = request.get("parent_job_id")
        company = company_for_job(job)
        addr_lower = (job.address or "").lower()
        job_chain_key = _coalesce_chain(_job_chain_name(job))
        contract = contracts_by_key.get((job_chain_key, addr_lower))
        entry: dict[str, Any] = {
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
        }
        entry["available_artifacts"] = sorted(
            n for n in artifact_names_by_job.get(job.id, []) if not _is_internal_artifact_name(n)
        )

        # Hide proxy entries until the impl is completed — otherwise the
        # listing renders a half-populated card that mutates once the impl
        # lands. ``jobs_by_key`` only carries completed jobs.
        contract_name_source = contract
        if entry["is_proxy"] and entry["implementation_address"]:
            impl_addr_lower = entry["implementation_address"].lower()
            impl_job = jobs_by_key.get((job_chain_key, impl_addr_lower))
            if impl_job is None:
                continue
            # Always prefer the impl's name over the proxy shell's. Proxy
            # rows usually carry a generic name like "UUPSProxy" or
            # "TransparentUpgradeableProxy"; the impl's name is the one
            # the user actually recognises (e.g. "WithdrawRequestNFT").
            # Fall back to the proxy's name if the impl Contract row is
            # missing or unnamed.
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
    """Get a specific artifact for an analysis.

    Storage-backed artifacts are fetched from object storage transparently;
    inline (legacy) artifacts are served from Postgres. Either way, the body
    is returned directly to the client.

    Only the consumer-safe artifacts are public; any other name requires a
    valid admin key, enforced before any lookup so an unauthorized name yields
    no existence signal and no storage I/O.

    **Three answers, because this is the boundary the SPA reads.** This handler
    is the artifact path for ``EntityActivity`` (upgrade_history) and the
    dependency lane (dependency_graph_viz), and both render a body's absence as
    a statement about the contract:

      200  the body, proven present (including the upgrade_history synthesis
           below, which is a real payload rebuilt from UpgradeEvent rows).
      404  proven absent — no artifact row, the bucket answered "no object at
           any candidate", or the row records no key at all.
      503  not determined — storage was unreachable, unconfigured, or failed in
           a way we cannot interpret. ``X-PSAT-Artifact-State: not_determined``
           and a JSON body naming the artifact, so a caller need not parse prose.

    Returning 404 for the third case is the defect this endpoint had: a bucket
    outage and an artifact the job never produced were byte-identical answers,
    and the consumer turned that into "no upgrades on this proxy".
    """
    # Strip .json/.txt extension for artifact lookup.
    lookup_name = artifact_name
    if artifact_name.endswith(".json"):
        lookup_name = artifact_name[:-5]
    elif artifact_name.endswith(".txt"):
        lookup_name = artifact_name[:-4]

    if lookup_name.lower() not in _CONSUMER_SAFE_ARTIFACTS:
        deps.require_admin_key(request, x_psat_admin_key)

    with deps.SessionLocal() as session:
        # Find job by name or id or address
        stmt = select(Job).where(Job.name == run_name).order_by(Job.updated_at.desc()).limit(1)
        job = session.execute(stmt).scalar_one_or_none()
        if job is None:
            try:
                job = session.get(Job, run_name)
            except Exception:
                session.rollback()
        if job is None:
            # ``run_name`` is an address here. Two chains can share an address, so
            # chain-qualify by Job.chain_id when a chain is supplied;
            # absent a chain we keep the mainnet-preserving address-only lookup
            # (every prod row is chain 1 today, so output is unchanged).
            stmt = (
                select(Job)
                .where(Job.address == run_name, Job.status == JobStatus.completed)
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
            # The bucket was asked about every candidate key and answered "no
            # object here". Determined: this job has no body for that name.
            logger.warning("artifact %s for job %s is absent: %s", lookup_name, job.id, exc)
        except StorageKeyAbsent as exc:
            # The row records no key and holds no inline body, so the bucket was
            # never asked — the third state, not the second. Published as
            # not-determined for the same reason ``db.storage.StorageKeyAbsent``
            # names it separately: answering 404 here is byte-identical to a job
            # that never produced the artifact, and no consumer can tell them
            # apart from the response.
            not_determined = f"{type(exc).__name__}: {exc}"
            logger.error("artifact %s for job %s not determined: %s", lookup_name, job.id, exc)
        except Exception as exc:
            # Everything else — StorageUnavailable, StorageContentNotDetermined,
            # a deserialize failure, an unconfigured backend — means we did not
            # find out. Fall through to the synthesis fallback, which may still
            # produce the body from a different source; if it does not, this is
            # published as its own answer rather than as absence.
            not_determined = f"{type(exc).__name__}: {exc}"
            logger.error("artifact %s for job %s not determined: %s", lookup_name, job.id, exc)

        # upgrade_history is reproducible from UpgradeEvent rows. When the
        # stored artifact is gone or storage is down, regenerate from the
        # relational source so the per-proxy detail view stays usable.
        if artifact is None and lookup_name == "upgrade_history":
            from services.discovery.upgrade_history import synthesize_from_events

            contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
            if contract is not None:
                artifact = synthesize_from_events(session, contract)
            if artifact is None and not_determined is None:
                # The writer stores no upgrade_history row in two
                # indistinguishable cases — the stage found no proxies, and the
                # stage RAISED (``uh_pre = None``, logged via
                # ``record_degraded(phase="dependency_upgrade_history")``) — and a
                # 404 here is consumed by the SPA as proven absence ("No activity
                # before the line."). Falsified on real data: the beacon proxy at
                # ``0x3c55986c…`` has 0 rows, 0 UpgradeEvents, and 14
                # ``Upgraded(address)`` logs at or before block 25619159.
                not_determined = _upgrade_history_absence_reason(session, job, contract)

        if artifact is None and not_determined is not None:
            # 503, not 404: whether this job produced the artifact is unknown.
            # The header lets a consumer branch without parsing the body, and the
            # body names the artifact so the reason survives into a log or a UI
            # string. Retry-After is the honest hint — this is the one state that
            # can change on its own.
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
    """Get analysis detail by job name (run_name) or job_id."""
    with deps.SessionLocal() as session:
        payload = build_analysis_detail(session, run_name)
        if payload is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return payload
