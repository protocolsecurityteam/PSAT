"""Ranks every discovered contract for a protocol and queues the top N.

One ranked pass sees inventory, DApp-crawl and DefiLlama contributions so ``analyze_limit`` goes to the best across all
sources. Claim waits for sibling ``dapp_crawl`` / ``defillama_scan`` jobs to settle, with a stuck-sibling timeout.
"""

from __future__ import annotations

import logging
import os
import uuid

from sqlalchemy import or_, select, text
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import Contract, ContractMembershipWitness, Job, JobStage, JobStatus
from db.queue import (
    DEFAULT_JOB_LEASE_TTL_S,
    advance_job,
    complete_job,
    count_analysis_children,
    create_job,
    find_existing_job_for_address,
    is_known_proxy,
    store_artifact,
)
from db.queue.static_cache import proven_analysis_schema_version
from services.clients.rpc_limits import RpcBackpressure, RpcBudgetExceeded
from services.discovery.membership_gate import resolve_membership_state
from services.discovery.ranking import (
    MIN_CONFIDENCE_THRESHOLD,
    effective_confidence,
    is_superseded_impl,
    rank_contract_rows,
)
from services.worker_workload import custom_claim_statement
from utils.chains import chain_enabled
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker, JobHandledDirectly
from workers.discovery import run_probe_pass

logger = logging.getLogger("workers.selection_worker")

_STUCK_SELECTION_TIMEOUT = int(os.getenv("PSAT_SELECTION_STUCK_TIMEOUT", "1800"))


def _existing_in_same_cascade(session: Session, addr: str, chain: str | None, root_job_id: str) -> bool:
    """Suppresses within-cascade proxy re-queues under --force."""
    stmt = select(Job.id).where(
        Job.address == addr,
        Job.request["root_job_id"].as_string() == root_job_id,
    )
    if chain is not None:
        stmt = stmt.where(Job.request["chain"].as_string() == chain)
    stmt = stmt.limit(1)
    return session.execute(stmt).scalar_one_or_none() is not None


def _excluded_record(row: Contract, *, reason: str, effective_confidence: float | None = None) -> dict:
    """A row removed before ranking; never competed and never appears in ``not_selected``."""
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
    stage = JobStage.selection
    next_stage = JobStage.done
    poll_interval = 5.0

    def _claim_job(self, session: Session) -> Job | None:
        return self._claim_ready_job(session) or self._claim_stuck_job(session)

    def _finalize_claim(self, session: Session, job: Job) -> Job:
        """Mirror ``db.queue.claim_job``'s lease, or the stale sweep requeues a live job and a sibling double-runs
        it.
        """
        from services.worker_lifecycle import note_claim

        note_claim(session)
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
        from services.worker_lifecycle import claim_allowed

        if not claim_allowed(session):
            return None
        claim_id = session.execute(
            custom_claim_statement("selection", stuck=False),
        ).scalar_one_or_none()
        if claim_id is None:
            return None
        job = session.get(Job, claim_id)
        if job is None:
            return None
        return self._finalize_claim(session, job)

    def _claim_stuck_job(self, session: Session) -> Job | None:
        from services.worker_lifecycle import claim_allowed

        if not claim_allowed(session):
            return None
        claim_id = session.execute(
            custom_claim_statement("selection", stuck=True),
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

    def process(self, session: Session, job: Job) -> None:
        if job.protocol_id is None:
            raise ValueError(f"Selection job {job.id} has no protocol_id")

        request = job.request if isinstance(job.request, dict) else {}
        analyze_limit = int(request.get("analyze_limit", 5))
        root_job_id = request.get("root_job_id", str(job.id))
        force = bool(request.get("force"))
        retryable_statuses = [JobStatus.failed, JobStatus.failed_terminal, JobStatus.completed]

        self.update_detail(session, job, f"Preparing selection for {job.company or 'protocol'}")
        logger.info(
            "Selection started",
            extra={"protocol_id": job.protocol_id, "analyze_limit": analyze_limit},
        )

        # Nomination sweep: crawl nominations land after discovery's inline probe, so without settling here the member
        # query sees none of them. Selection runs after every nomination writer, so this can't race. Degrades to
        # existing membership.
        try:
            with log_timed_phase(logger, "membership_probe_pass") as probe_ph:
                probe_result = run_probe_pass(
                    session,
                    job.protocol_id,
                    heartbeat=lambda: self._heartbeat(session, job),
                    skip_contract_ids=request.get("selection_probed_ids", []),
                )
                probe_ph["targeted"] = len(probe_result.targeted_contract_ids)
                probe_ph["promoted"] = len(probe_result.promoted_contract_ids)
                if getattr(probe_result, "deferred_contract_ids", ()):
                    seen = set(request.get("selection_probed_ids", []))
                    seen.update(probe_result.probed_contract_ids)
                    job.request = {**request, "selection_probed_ids": sorted(seen)}
                    advance_job(
                        session,
                        job.id,
                        JobStage.selection,
                        f"Membership probing continues: {len(probe_result.deferred_contract_ids)} candidates pending",
                        lease_id=job.lease_id,
                    )
                    raise JobHandledDirectly()
        except (JobHandledDirectly, RpcBackpressure, RpcBudgetExceeded):
            raise
        except Exception as exc:
            session.rollback()
            record_degraded(
                phase="membership_probe_pass",
                exc=exc,
                context={"protocol_id": job.protocol_id, "site": "selection"},
                include_traceback=True,
            )

        # Pre-rank filtered rows are partitioned here and listed in ``pre_rank_excluded``; otherwise an empty
        # ``not_selected`` would falsely claim nothing was dropped.
        all_rows = (
            session.execute(
                select(Contract).where(
                    or_(
                        Contract.protocol_id == job.protocol_id,
                        (Contract.protocol_id.is_(None)) & (Contract.nominated_protocol_id == job.protocol_id),
                    ),
                    or_(
                        Contract.job_id.is_(None),
                        Contract.job_id.in_(select(Job.id).where(Job.status.in_(retryable_statuses))),
                    ),
                )
            )
            .scalars()
            .all()
        )

        pre_rank_excluded: list[dict] = []
        candidates: list[Contract] = []
        code_proven = set(
            session.scalars(
                select(ContractMembershipWitness.contract_id).where(
                    ContractMembershipWitness.protocol_id == job.protocol_id,
                    ContractMembershipWitness.rule == "w1_code",
                    ContractMembershipWitness.revoked_at.is_(None),
                )
            )
        )
        for row in all_rows:
            prior = session.get(Job, row.job_id) if row.job_id is not None else None
            if (
                prior is not None
                and prior.status == JobStatus.completed
                and not force
                and not row.is_proxy
                and proven_analysis_schema_version(session, prior) == ANALYSIS_SCHEMA_VERSION
            ):
                pre_rank_excluded.append(_excluded_record(row, reason="current_analysis"))
                continue
            if row.protocol_id is None and (
                row.id not in code_proven or resolve_membership_state(session, row) == "pruned"
            ):
                pre_rank_excluded.append(_excluded_record(row, reason="candidate_code_not_proven"))
                continue
            # Superseded historical impls are audit-coverage anchors only; the live impl is kept.
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

        # Threshold filter and ranker must see the same effective confidence.
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

        # Rows without last_active ranked on the neutral 0.5; the split count surfaces that.
        activity_fetched = sum(1 for d in ranked_dicts if (d.get("activity") or {}).get("last_active") is not None)
        record_stage_metric("activity_fetched", activity_fetched)
        record_stage_metric("activity_neutral", len(ranked_dicts) - activity_fetched)

        by_key: dict[tuple[str, str | None], dict] = {(d["__row_address"], d["__row_chain"]): d for d in ranked_dicts}
        for row in eligible_rows:
            entry = by_key.get((row.address, row.chain))
            if entry is None:
                continue
            entry["analysis_membership_state"] = "member" if row.protocol_id is not None else "candidate"
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
        """Create child jobs for the top ``analyze_limit`` candidates.

        Returns ``(child_ids, not_selected)``; every ranked candidate not selected is recorded with its reason.
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
            # Returning without enumerating would silently drop every ranked candidate.
            for entry in ranked:
                _drop(entry, "budget_exhausted", analyze_limit=analyze_limit, existing_children=already_used)
            return [], not_selected

        force = bool(request.get("force"))
        selected: list[dict] = []
        for entry in ranked:
            addr = entry["__row_address"]
            # Dedup helpers skip chain filtering for None, so a NULL-chain row would match a job on any chain.
            chain = entry["__row_chain"] or "ethereum"
            # Deployment allowlist: no analysis children for disabled chains, and no budget consumed.
            if not chain_enabled(chain):
                _drop(entry, "chain_not_enabled")
                continue
            existing = find_existing_job_for_address(session, addr, chain=chain)
            if existing is not None:
                refresh = existing.status == JobStatus.completed and (
                    force or proven_analysis_schema_version(session, existing) != ANALYSIS_SCHEMA_VERSION
                )
                if not refresh and not is_known_proxy(session, addr, chain=chain):
                    _drop(entry, "existing_job", existing_job_id=str(existing.id))
                    continue
                if (force or refresh) and _existing_in_same_cascade(session, addr, chain, root_job_id):
                    _drop(entry, "in_cascade_dedupe", existing_job_id=str(existing.id))
                    continue
                logger.info(
                    "Re-queuing contract for analysis refresh",
                    extra={
                        "address": addr,
                        "chain": chain,
                        "existing_job_id": str(existing.id),
                        "reason": "analysis_refresh" if refresh else "proxy_upgrade_recheck",
                    },
                )
            # Budget last so each rejected candidate reports the reason that actually applies.
            if len(selected) >= remaining:
                _drop(entry, "budget_exhausted", analyze_limit=analyze_limit, existing_children=already_used)
                continue
            selected.append(entry)

        child_ids: list[dict] = []
        company = job.company
        for entry in selected:
            addr = entry["__row_address"]
            # Child requests must never carry chain=None.
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
                "analysis_membership_state": entry.get("analysis_membership_state", "member"),
            }
            if company:
                child_request["company"] = company
            if force:
                child_request["force"] = True
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
                # Only both ledgers empty proves nothing was dropped.
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
