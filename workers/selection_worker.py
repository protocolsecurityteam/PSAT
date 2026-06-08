"""Selection worker — ranks all discovered contracts for a protocol and queues the top N.

Runs after the three contract-discovery workers (``DiscoveryWorker``
company mode, ``DAppCrawlWorker``, ``DefiLlamaWorker``) have each
written their discoveries to the ``contracts`` table. Those workers no
longer create analysis child jobs themselves; that responsibility lives
here so a single ranked pass sees every source's contributions and the
``analyze_limit`` budget is spent on the top-scoring contracts across
inventory, DApp-crawl, and DefiLlama evidence together.

Readiness gating mirrors ``CoverageWorker``: a claim fires only when no
sibling ``dapp_crawl`` or ``defillama_scan`` job under the same root is
still queued or processing.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage, JobStatus
from db.queue import (
    complete_job,
    count_analysis_children,
    create_job,
    find_existing_job_for_address,
    is_known_proxy,
    store_artifact,
)
from services.artifacts import SELECTION_ARTIFACT, make_job_stage_context, make_stage_artifact
from services.discovery.ranking import (
    MIN_CONFIDENCE_THRESHOLD,
    effective_confidence,
    not_superseded_impl_clause,
    rank_contract_rows,
)
from utils.logging import log_timed_phase, record_stage_metric
from utils.rpc import require_supported_chain_id
from workers.base import BaseWorker, JobHandledDirectly

logger = logging.getLogger("workers.selection_worker")


def _existing_in_same_cascade(session: Session, addr: str, chain_id: int, root_job_id: str) -> bool:
    """True if a job for ``addr`` already exists with the same root_job_id; suppresses within-cascade proxy re-queueing
    under --force."""
    effective_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"selection cascade lookup for {addr}")
    stmt = select(Job.id).where(
        func.lower(Job.address) == addr.lower(),
        Job.chain_id == effective_chain_id,
        Job.request["root_job_id"].as_string() == root_job_id,
    )
    stmt = stmt.limit(1)
    return session.execute(stmt).scalar_one_or_none() is not None


class SelectionWorker(BaseWorker):
    """Drains the ``selection`` stage with a readiness-gated claim."""

    stage = JobStage.selection
    next_stage = JobStage.done
    poll_interval = 5.0

    # -- Claim ------------------------------------------------------------

    def _claim_job(self, session: Session) -> Job | None:
        """Claim only when DApp/DefiLlama sibling jobs have settled."""
        return self._claim_ready_job(session)

    def _claim_ready_job(self, session: Session) -> Job | None:
        """Claim a selection job whose DApp/DefiLlama siblings have settled (matched by ``request->>'root_job_id'``)."""
        claim_id = session.execute(
            text(
                """
                SELECT j.id
                FROM jobs j
                WHERE j.stage = 'selection' AND j.status = 'queued'
                  AND NOT EXISTS (
                    SELECT 1 FROM jobs sib
                    WHERE sib.stage IN ('dapp_crawl', 'defillama_scan')
                      AND sib.request->>'root_job_id' = j.id::text
                      AND sib.status IN ('queued', 'processing')
                  )
                ORDER BY j.updated_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """
            )
        ).scalar_one_or_none()
        if claim_id is None:
            return None
        job = session.get(Job, claim_id)
        if job is None:
            return None
        job.status = JobStatus.processing
        job.worker_id = self.worker_id
        session.commit()
        session.refresh(job)
        return job

    # -- Process ----------------------------------------------------------

    def process(self, session: Session, job: Job) -> None:
        """Rank all unanalyzed contracts for the protocol and queue the top N."""
        if job.protocol_id is None:
            raise ValueError(f"Selection job {job.id} has no protocol_id")

        request = job.request if isinstance(job.request, dict) else {}
        analyze_limit = int(request.get("analyze_limit", 5))
        root_job_id = request.get("root_job_id", str(job.id))

        self.update_detail(session, job, f"Preparing selection for {job.company or 'protocol'}")
        logger.info(
            "Selection started for job %s: protocol_id=%s, analyze_limit=%d",
            job.id,
            job.protocol_id,
            analyze_limit,
        )

        # Skip superseded historical impls (audit-coverage anchors only); the
        # current live impl of a proxy is kept (it carries the live marker).
        # Single source of truth for the anchor predicate: services/discovery/ranking.
        candidate_rows = (
            session.execute(
                select(Contract).where(
                    Contract.protocol_id == job.protocol_id,
                    not_superseded_impl_clause(Contract.discovery_sources),
                )
            )
            .scalars()
            .all()
        )
        candidates: list[Contract] = []
        for row in candidate_rows:
            chain_id = require_supported_chain_id(chain_id=row.chain_id, context=f"selection candidate {row.address}")
            existing = find_existing_job_for_address(session, row.address, chain_id=chain_id)
            if existing is not None and not is_known_proxy(session, row.address, chain_id=chain_id):
                continue
            candidates.append(row)

        if not candidates:
            logger.info("Selection job %s: no unanalyzed candidates", job.id)
            self._finish(session, job, ranked=[], child_ids=[])
            return

        self.update_detail(
            session,
            job,
            f"Ranking {len(candidates)} discovered contracts",
        )

        # Apply effective confidence up front so the threshold filter and the ranker see the same number.
        eligible_rows = [
            row
            for row in candidates
            if effective_confidence(
                float(row.confidence) if row.confidence is not None else None,
                list(row.discovery_sources or []),
            )
            >= MIN_CONFIDENCE_THRESHOLD
        ]
        if not eligible_rows:
            logger.info(
                "Selection job %s: %d candidates, none cleared confidence threshold %.2f",
                job.id,
                len(candidates),
                MIN_CONFIDENCE_THRESHOLD,
            )
            session.commit()
            self._finish(session, job, ranked=[], child_ids=[])
            return

        with log_timed_phase(logger, "ranking") as ph:
            ranked_dicts = rank_contract_rows(eligible_rows)
            ph["count"] = len(eligible_rows)

        # Persist rank_score onto the row so UI listings see the same ordering the selector picked.
        by_key: dict[tuple[str, int | None], dict] = {
            (d["__row_address"], d["__row_chain_id"]): d for d in ranked_dicts
        }
        for row in eligible_rows:
            entry = by_key.get((row.address, row.chain_id))
            if entry is None:
                continue
            rank = entry.get("rank_score")
            if rank is not None:
                row.rank_score = rank
        session.commit()

        child_ids = self._queue_top_n(
            session=session,
            job=job,
            ranked=ranked_dicts,
            analyze_limit=analyze_limit,
            root_job_id=root_job_id,
            request=request,
        )

        self._finish(session, job, ranked=ranked_dicts, child_ids=child_ids)

    def _queue_top_n(
        self,
        *,
        session: Session,
        job: Job,
        ranked: list[dict],
        analyze_limit: int,
        root_job_id: str,
        request: dict,
    ) -> list[dict]:
        """Create child analysis jobs for the top ``analyze_limit`` candidates."""
        already_used = count_analysis_children(session, root_job_id)
        remaining = max(0, analyze_limit - already_used)
        if remaining == 0:
            logger.info(
                "Selection job %s: analyze_limit %d already filled (%d existing children)",
                job.id,
                analyze_limit,
                already_used,
            )
            return []

        # Under --force, dedupe known-proxy re-queues within the same cascade so multiple discovery sources don't spawn
        # N copies.
        force = bool(request.get("force"))
        selected: list[dict] = []
        for entry in ranked:
            if len(selected) >= remaining:
                break
            addr = entry["__row_address"]
            chain_id = entry["__row_chain_id"]
            existing = find_existing_job_for_address(session, addr, chain_id=chain_id)
            if existing is not None:
                if not is_known_proxy(session, addr, chain_id=chain_id):
                    logger.info(
                        "Selection job %s: address %s already has job %s, skipping",
                        job.id,
                        addr,
                        existing.id,
                    )
                    continue
                if force and _existing_in_same_cascade(session, addr, chain_id, root_job_id):
                    logger.info(
                        "Selection job %s: proxy %s already has job %s in this cascade, "
                        "skipping (--force in-cascade dedupe)",
                        job.id,
                        addr,
                        existing.id,
                    )
                    continue
                logger.info(
                    "Selection job %s: proxy %s has existing job %s but re-queuing for upgrade check",
                    job.id,
                    addr,
                    existing.id,
                )
            selected.append(entry)

        child_ids: list[dict] = []
        company = job.company
        for entry in selected:
            addr = entry["__row_address"]
            chain_id = entry["__row_chain_id"]
            name = entry.get("name") or (f"{company}_{addr[2:10]}" if company else f"sel_{addr[2:10]}")
            sources = entry.get("discovery_sources") or []
            child_request = {
                "address": addr,
                "name": name,
                "chain_id": chain_id,
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "rank_score": entry.get("rank_score"),
                "confidence": entry.get("confidence"),
                "discovery_sources": list(sources),
                "protocol_id": job.protocol_id,
            }
            if company:
                child_request["company"] = company
            child_job = create_job(session, child_request)
            child_ids.append(
                {
                    "job_id": str(child_job.id),
                    "address": addr,
                    "chain_id": chain_id,
                    "name": name,
                    "rank_score": entry.get("rank_score"),
                    "discovery_sources": list(sources),
                }
            )
            logger.info(
                "Selection job %s: queued %s (%s, sources=%s, rank=%.4f)",
                job.id,
                addr,
                name,
                ",".join(sources) if sources else "unknown",
                entry.get("rank_score") or 0.0,
            )
        return child_ids

    def _finish(
        self,
        session: Session,
        job: Job,
        *,
        ranked: list[dict],
        child_ids: list[dict],
    ) -> None:
        summary_ranked = [
            {
                "address": entry["__row_address"],
                "chain_id": entry.get("__row_chain_id"),
                "name": entry.get("name"),
                "discovery_sources": entry.get("discovery_sources"),
                "confidence": entry.get("confidence"),
                "activity": entry.get("activity"),
                "rank_score": entry.get("rank_score"),
            }
            for entry in ranked
        ]
        store_artifact(
            session,
            job.id,
            SELECTION_ARTIFACT,
            data=make_stage_artifact(
                kind=SELECTION_ARTIFACT,
                stage=JobStage.selection.value,
                schema_version="1.0",
                context=make_job_stage_context(job, stage=JobStage.selection.value, schema_version="1.0"),
                data={
                    "company": job.company,
                    "ranked_count": len(ranked),
                    "analyzed_count": len(child_ids),
                    "ranked_contracts": summary_ranked,
                    "selected_contracts": child_ids,
                    "child_jobs": child_ids,
                    "summary": {
                        "ranked_count": len(ranked),
                        "analyzed_count": len(child_ids),
                    },
                },
            ),
        )
        record_stage_metric("ranked_candidates", len(ranked))
        record_stage_metric("queued", len(child_ids))
        if child_ids:
            detail = f"Selection complete: queued {len(child_ids)} of {len(ranked)} ranked candidates"
        elif ranked:
            detail = f"Selection complete: {len(ranked)} candidates, none queued (budget full or all deduped)"
        else:
            detail = "Selection complete: no eligible candidates"
        complete_job(session, job.id, detail)
        raise JobHandledDirectly()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    SelectionWorker().run_loop()


if __name__ == "__main__":
    main()
