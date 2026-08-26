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
still queued or processing. A stuck-sibling escape hatch unblocks the
job after a timeout so one wedged crawl can't strand the whole protocol.
"""

from __future__ import annotations

import logging
import os
import uuid

from sqlalchemy import select, text
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage, JobStatus
from db.queue import (
    DEFAULT_JOB_LEASE_TTL_S,
    complete_job,
    count_analysis_children,
    create_job,
    find_existing_job_for_address,
    is_known_proxy,
    store_artifact,
)
from services.discovery.ranking import (
    MIN_CONFIDENCE_THRESHOLD,
    effective_confidence,
    is_superseded_impl,
    rank_contract_rows,
)
from utils.chains import chain_enabled
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker, JobHandledDirectly
from workers.discovery import run_probe_pass

logger = logging.getLogger("workers.selection_worker")

# Bypass the sibling-readiness gate after this many seconds queued (default 30 min) so a wedged crawl doesn't strand the
# protocol.
_STUCK_SELECTION_TIMEOUT = int(os.getenv("PSAT_SELECTION_STUCK_TIMEOUT", "1800"))


def _existing_in_same_cascade(session: Session, addr: str, chain: str | None, root_job_id: str) -> bool:
    """True if a job for ``addr`` already exists with the same root_job_id; suppresses within-cascade proxy re-queueing
    under --force."""
    stmt = select(Job.id).where(
        Job.address == addr,
        Job.request["root_job_id"].as_string() == root_job_id,
    )
    if chain is not None:
        stmt = stmt.where(Job.request["chain"].as_string() == chain)
    stmt = stmt.limit(1)
    return session.execute(stmt).scalar_one_or_none() is not None


def _excluded_record(row: Contract, *, reason: str, effective_confidence: float | None = None) -> dict:
    """One ``pre_rank_excluded`` entry: a row removed BEFORE ranking, so it never
    competed for the budget and never appears in ``not_selected``."""
    record: dict = {
        "address": row.address,
        "chain": row.chain,
        "reason": reason,
    }
    if effective_confidence is not None:
        record["effective_confidence"] = effective_confidence
    logger.info("Selection candidate excluded before ranking", extra={**record, "site": "selection"})
    return record


class SelectionWorker(BaseWorker):
    """Drains the ``selection`` stage with a readiness-gated two-phase claim."""

    stage = JobStage.selection
    next_stage = JobStage.done
    poll_interval = 5.0

    # -- Claim ------------------------------------------------------------

    def _claim_job(self, session: Session) -> Job | None:
        """Primary readiness-gated claim OR stuck-sibling fallback."""
        return self._claim_ready_job(session) or self._claim_stuck_job(session)

    def _finalize_claim(self, session: Session, job: Job) -> Job:
        """Stamp status/worker plus a fresh lease, mirroring ``db.queue.claim_job``:
        without the lease, the stale-job sweep can requeue a live selection job and
        a sibling double-runs it."""
        job.status = JobStatus.processing
        job.worker_id = self.worker_id
        job.lease_id = uuid.uuid4()
        session.execute(
            sa_update(Job)
            .where(Job.id == job.id)
            .values(lease_expires_at=text(f"NOW() + INTERVAL '{int(DEFAULT_JOB_LEASE_TTL_S)} seconds'"))
        )
        session.commit()
        session.refresh(job)
        return job

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
        return self._finalize_claim(session, job)

    def _claim_stuck_job(self, session: Session) -> Job | None:
        """Bypass readiness and claim a job that's been queued too long."""
        claim_id = session.execute(
            text(
                """
                SELECT j.id
                FROM jobs j
                WHERE j.stage = 'selection' AND j.status = 'queued'
                  AND j.updated_at < (NOW() - (:timeout * INTERVAL '1 second'))
                ORDER BY j.updated_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """
            ),
            {"timeout": _STUCK_SELECTION_TIMEOUT},
        ).scalar_one_or_none()
        if claim_id is None:
            return None
        job = session.get(Job, claim_id)
        if job is None:
            return None
        logger.warning(
            "Claiming stuck selection job past timeout — DApp/DefiLlama sibling(s) did not settle",
            extra={"stuck_timeout_s": _STUCK_SELECTION_TIMEOUT},
        )
        return self._finalize_claim(session, job)

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
            "Selection started",
            extra={"protocol_id": job.protocol_id, "analyze_limit": analyze_limit},
        )

        # §3.4 event-1 sweep for the crawl writers: DApp/DefiLlama nominations
        # land AFTER the discovery stage's inline probe pass, and this claim
        # opens as soon as those siblings settle — without settling here, the
        # cascade's own crawl candidates are still unpromoted and the member
        # query below sees none of them (on a cold protocol: "no eligible
        # candidates" with a full nomination backlog). Selection is serialized
        # after every nomination writer, so this pass cannot race a sibling's
        # writes. Degrades: ranking proceeds on whatever membership the stored
        # evidence supports.
        try:
            with log_timed_phase(logger, "membership_probe_pass") as probe_ph:
                probe_result = run_probe_pass(session, job.protocol_id, heartbeat=lambda: self._heartbeat(session, job))
                probe_ph["targeted"] = len(probe_result.targeted_contract_ids)
                probe_ph["promoted"] = len(probe_result.promoted_contract_ids)
        except Exception as exc:
            session.rollback()
            record_degraded(
                phase="membership_probe_pass",
                exc=exc,
                context={"protocol_id": job.protocol_id, "site": "selection"},
                include_traceback=True,
            )

        # Every unanalysed row for the protocol, INCLUDING the ones the two
        # pre-rank filters remove. The superseded-impl anchors used to be
        # excluded in SQL and the sub-threshold rows used to survive only as a
        # count — so a candidate that never reached the ranking was
        # indistinguishable from one that never existed. Both are now
        # partitioned in Python and enumerated into ``pre_rank_excluded``:
        # without that, an empty ``not_selected`` would assert "nothing was
        # dropped" while two paths silently dropped rows upstream of it.
        # ``is_superseded_impl`` is the same predicate the SQL clause mirrored,
        # so the single source of truth is unchanged.
        all_rows = (
            session.execute(
                select(Contract).where(
                    Contract.protocol_id == job.protocol_id,
                    Contract.job_id.is_(None),
                )
            )
            .scalars()
            .all()
        )

        pre_rank_excluded: list[dict] = []
        candidates: list[Contract] = []
        for row in all_rows:
            # Skip superseded historical impls (audit-coverage anchors only); the
            # current live impl of a proxy is kept (it carries the live marker).
            if is_superseded_impl(list(row.discovery_sources or [])):
                pre_rank_excluded.append(
                    _excluded_record(row, reason="superseded_impl_anchor"),
                )
                continue
            candidates.append(row)
        record_stage_metric("candidates", len(candidates))

        if not candidates:
            logger.info("Selection found no unanalyzed candidates")
            self._finish(session, job, ranked=[], child_ids=[], not_selected=[], pre_rank_excluded=pre_rank_excluded)
            return

        self.update_detail(
            session,
            job,
            f"Ranking {len(candidates)} discovered contracts",
        )

        # Apply effective confidence up front so the threshold filter and the ranker see the same number.
        eligible_rows: list[Contract] = []
        for row in candidates:
            score = effective_confidence(
                float(row.confidence) if row.confidence is not None else None,
                list(row.discovery_sources or []),
            )
            if score >= MIN_CONFIDENCE_THRESHOLD:
                eligible_rows.append(row)
            else:
                pre_rank_excluded.append(
                    _excluded_record(row, reason="below_confidence_threshold", effective_confidence=score),
                )
        dropped = len(candidates) - len(eligible_rows)
        record_stage_metric("eligible", len(eligible_rows))
        record_stage_metric("dropped", dropped)
        if not eligible_rows:
            logger.info(
                "Selection: no candidates cleared confidence threshold",
                extra={
                    "candidates": len(candidates),
                    "dropped": dropped,
                    "threshold": MIN_CONFIDENCE_THRESHOLD,
                },
            )
            session.commit()
            self._finish(session, job, ranked=[], child_ids=[], not_selected=[], pre_rank_excluded=pre_rank_excluded)
            return

        with log_timed_phase(logger, "ranking") as ph:
            ranked_dicts = rank_contract_rows(eligible_rows)
            ph["count"] = len(eligible_rows)

        # On-chain activity is fetched per-contract during ranking; a row with no
        # last_active fell back to the neutral 0.5 (Etherscan unavailable /
        # unsupported chain). Splitting the count surfaces ranking made on neutral
        # data — otherwise indistinguishable from a legitimately-inactive contract.
        activity_fetched = sum(1 for d in ranked_dicts if (d.get("activity") or {}).get("last_active") is not None)
        record_stage_metric("activity_fetched", activity_fetched)
        record_stage_metric("activity_neutral", len(ranked_dicts) - activity_fetched)

        # Persist rank_score onto the row so UI listings see the same ordering the selector picked.
        by_key: dict[tuple[str, str | None], dict] = {(d["__row_address"], d["__row_chain"]): d for d in ranked_dicts}
        for row in eligible_rows:
            entry = by_key.get((row.address, row.chain))
            if entry is None:
                continue
            rank = entry.get("rank_score")
            if rank is not None:
                row.rank_score = rank
        session.commit()

        child_ids, not_selected = self._queue_top_n(
            session=session,
            job=job,
            ranked=ranked_dicts,
            analyze_limit=analyze_limit,
            root_job_id=root_job_id,
            request=request,
        )

        self._finish(
            session,
            job,
            ranked=ranked_dicts,
            child_ids=child_ids,
            not_selected=not_selected,
            pre_rank_excluded=pre_rank_excluded,
        )

    def _queue_top_n(
        self,
        *,
        session: Session,
        job: Job,
        ranked: list[dict],
        analyze_limit: int,
        root_job_id: str,
        request: dict,
    ) -> tuple[list[dict], list[dict]]:
        """Create child analysis jobs for the top ``analyze_limit`` candidates.

        Returns ``(child_ids, not_selected)``. Every ranked candidate that does
        not become a child appears in ``not_selected`` with its reason — a
        budget cut that leaves no record is the exact defect this ledger exists
        to prevent.
        """
        not_selected: list[dict] = []

        def _drop(entry: dict, reason: str, **extra: object) -> None:
            record = {
                "address": entry["__row_address"],
                "chain": entry["__row_chain"] or "ethereum",
                "rank_score": entry.get("rank_score"),
                "reason": reason,
            }
            not_selected.append(record)
            logger.info(
                "Selection candidate not selected",
                extra={**record, **extra, "site": "selection"},
            )

        already_used = count_analysis_children(session, root_job_id)
        remaining = max(0, analyze_limit - already_used)
        if remaining == 0:
            logger.info(
                "Selection budget already filled",
                extra={"analyze_limit": analyze_limit, "existing_children": already_used},
            )
            # Returning here without enumerating drops EVERY ranked candidate
            # silently — the same silent budget cut this ledger exists to
            # prevent, reproduced inside its own producer.
            for entry in ranked:
                _drop(entry, "budget_exhausted", analyze_limit=analyze_limit, existing_children=already_used)
            return [], not_selected

        # Under --force, dedupe known-proxy re-queues within the same cascade so multiple discovery sources don't spawn
        # N copies.
        force = bool(request.get("force"))
        selected: list[dict] = []
        for entry in ranked:
            addr = entry["__row_address"]
            # Coalesce NULL→"ethereum" (legacy convention): the dedup helpers
            # below skip chain filtering entirely for chain=None, so a legacy
            # NULL-chain row would dedup against a job on ANY chain at this
            # address. chain_enabled already coalesces None the same way.
            chain = entry["__row_chain"] or "ethereum"
            # Gate on the deployment allowlist (inv. 14): a company inventory can
            # carry addresses on chains the protocol declares (DeFiLlama membership
            # evidence) that this deployment has not enabled. Their discovered-stub
            # + Protocol.chains evidence is already written; we must not spawn
            # analysis children for them. Skip without consuming analyze budget;
            # widening PSAT_SUPPORTED_CHAIN_IDS lets a future scan pick them up.
            if not chain_enabled(chain):
                _drop(entry, "chain_not_enabled")
                continue
            existing = find_existing_job_for_address(session, addr, chain=chain)
            if existing is not None:
                if not is_known_proxy(session, addr, chain=chain):
                    _drop(entry, "existing_job", existing_job_id=str(existing.id))
                    continue
                if force and _existing_in_same_cascade(session, addr, chain, root_job_id):
                    _drop(entry, "in_cascade_dedupe", existing_job_id=str(existing.id))
                    continue
                logger.info(
                    "Re-queuing proxy for upgrade check",
                    extra={
                        "address": addr,
                        "chain": chain,
                        "existing_job_id": str(existing.id),
                        "reason": "proxy_upgrade_recheck",
                    },
                )
            # Budget LAST, so a candidate the chain gate or the dedup arm would
            # have rejected anyway is reported with the reason that actually
            # applies. Checking it first made every below-the-cut candidate read
            # `budget_exhausted` — no silent drop, but the wrong cause, and the
            # ledger's whole value is the cause. It also consumes no budget, for
            # the same reason the spawn walker spends its budget at create_job.
            if len(selected) >= remaining:
                _drop(entry, "budget_exhausted", analyze_limit=analyze_limit, existing_children=already_used)
                continue
            selected.append(entry)

        child_ids: list[dict] = []
        company = job.company
        for entry in selected:
            addr = entry["__row_address"]
            # Same NULL→"ethereum" coalesce as the dedup loop above, so the
            # child request never carries chain=None (inv. 6 — None must not
            # cascade into spawned jobs).
            chain = entry["__row_chain"] or "ethereum"
            name = entry.get("name") or (f"{company}_{addr[2:10]}" if company else f"sel_{addr[2:10]}")
            sources = entry.get("discovery_sources") or []
            child_request = {
                "address": addr,
                "name": name,
                "chain": chain,
                "rpc_url": request.get("rpc_url"),
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "rank_score": entry.get("rank_score"),
                "confidence": entry.get("confidence"),
                "discovery_sources": list(sources),
                "chains": entry.get("chains"),
                "protocol_id": job.protocol_id,
            }
            if company:
                child_request["company"] = company
            child_job = create_job(session, child_request)
            child_ids.append(
                {
                    "job_id": str(child_job.id),
                    "address": addr,
                    "chain": chain,
                    "name": name,
                    "rank_score": entry.get("rank_score"),
                    "discovery_sources": list(sources),
                }
            )
            logger.info(
                "Queued analysis child for candidate",
                extra={
                    "address": addr,
                    "chain": chain,
                    "contract_name": name,
                    "discovery_sources": list(sources),
                    "rank_score": entry.get("rank_score"),
                    "child_job_id": str(child_job.id),
                },
            )
        return child_ids, not_selected

    def _finish(
        self,
        session: Session,
        job: Job,
        *,
        ranked: list[dict],
        child_ids: list[dict],
        not_selected: list[dict],
        pre_rank_excluded: list[dict],
    ) -> None:
        summary_ranked = [
            {
                "address": entry["__row_address"],
                "chain": entry["__row_chain"],
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
            "selection_summary",
            data={
                "ranked_count": len(ranked),
                "analyzed_count": len(child_ids),
                "child_jobs": child_ids,
                # The two omission ledgers. ``not_selected`` covers the RANKED
                # population; ``pre_rank_excluded`` covers the rows removed
                # before ranking. Only both being empty proves nothing was
                # dropped — ``not_selected == []`` alone does not, because the
                # pre-rank filters run upstream of it.
                "not_selected": not_selected,
                "pre_rank_excluded": pre_rank_excluded,
                "ranked": summary_ranked,
            },
        )
        record_stage_metric("ranked_candidates", len(ranked))
        record_stage_metric("queued", len(child_ids))
        if child_ids:
            detail = f"Selection complete: queued {len(child_ids)} of {len(ranked)} ranked candidates"
            outcome = "queued"
        elif ranked:
            detail = f"Selection complete: {len(ranked)} candidates, none queued (budget full or all deduped)"
            outcome = "none_queued"
        else:
            detail = "Selection complete: no eligible candidates"
            outcome = "no_candidates"
        logger.info(
            "Selection complete",
            extra={
                "outcome": outcome,
                "ranked_count": len(ranked),
                "queued_count": len(child_ids),
                "selected": [{"address": c.get("address"), "rank_score": c.get("rank_score")} for c in child_ids],
            },
        )
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
