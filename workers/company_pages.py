"""Single-flight overview/functions preparation on the workers VM, never web.

One replace-in-place row per protocol; failures back off and preserve the last
complete pair. Reads older than 60s fall back to live computation. The 30s sweep
covers balances/monitoring and any lost change hint. No web request writes here.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from threading import Event

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models import CompanyPageSnapshot as Page
from db.models import Protocol, SessionLocal
from db.queue import record_heartbeat
from services.aggregations.company_overview import build_company_overview, build_functions_for_protocol
from services.aggregations.company_overview.jobs import eligible_company_protocol_ids
from services.company_pages import MAX_AGE_SECONDS, enabled, encode, version
from utils.logging import configure_logging

logger = logging.getLogger(__name__)
REFRESH_SECONDS = 30


def refresh_one(session_factory=SessionLocal) -> str:
    with session_factory() as write:
        # Transaction-scoped, so safe behind a transaction-pooling proxy. One
        # preparer across all worker machines, without long-lived session locks.
        if not write.execute(text("SELECT pg_try_advisory_xact_lock(210031, 0)")).scalar():
            return "leased"
        candidates = select(Protocol.id).where(Protocol.id.in_(eligible_company_protocol_ids(write)))
        write.execute(pg_insert(Page).from_select(["protocol_id"], candidates).on_conflict_do_nothing())
        now = write.execute(select(func.clock_timestamp())).scalar_one()
        row = write.execute(
            select(Page.protocol_id, Protocol.name, Page.dirty_token, Page.attempts)
            .join(Protocol, Protocol.id == Page.protocol_id)
            .where(
                Page.protocol_id.in_(candidates),
                Page.next_attempt_at <= now,
                or_(
                    Page.version.is_distinct_from(version()),
                    Page.source_started_at.is_(None),
                    Page.source_started_at <= now - timedelta(seconds=REFRESH_SECONDS),
                    Page.dirty_token.is_distinct_from(Page.built_token),
                    Page.company_name.is_distinct_from(Protocol.name),
                ),
            )
            .order_by(Page.next_attempt_at, Page.protocol_id)
            .limit(1)
        ).first()
        if row is None:
            write.commit()
            return "idle"
        protocol_id, name, token, attempts = row
        try:
            with session_factory() as source:
                source.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                source.execute(text("SET LOCAL statement_timeout = '25s'"))
                started = source.execute(select(func.clock_timestamp())).scalar_one()
                snapshot = source.execute(text("SELECT pg_export_snapshot()")).scalar_one()
                source.info["company_page_snapshot"] = snapshot
                overview = encode(build_company_overview(source, name))
                functions = encode({"functions": build_functions_for_protocol(source, name)})
            finished = write.execute(select(func.clock_timestamp())).scalar_one()
            if (finished - started).total_seconds() >= MAX_AGE_SECONDS:
                raise ValueError("Company page build exceeded the freshness window")
            # Never update dirty_token: a mark arriving during the build must
            # survive publication and request another pass.
            write.execute(
                update(Page)
                .where(Page.protocol_id == protocol_id)
                .values(
                    company_name=name,
                    version=version(),
                    source_started_at=started,
                    published_at=finished,
                    overview_gzip=overview,
                    functions_gzip=functions,
                    built_token=token,
                    attempts=0,
                    next_attempt_at=finished + timedelta(seconds=5),
                )
            )
            write.commit()
            logger.info(
                "Prepared company page",
                extra={
                    "company": name,
                    "duration_ms": int((finished - started).total_seconds() * 1000),
                    "overview_bytes": len(overview),
                    "functions_bytes": len(functions),
                },
            )
            return "prepared"
        except Exception:
            # Builder sessions are separate: their rollback cannot poison this
            # metadata transaction. Do not replace either half after failure.
            logger.exception("Company page preparation failed", extra={"company": name})
            write.execute(
                update(Page)
                .where(Page.protocol_id == protocol_id)
                .values(
                    attempts=attempts + 1,
                    next_attempt_at=func.clock_timestamp() + timedelta(seconds=min(300, 5 * 2 ** min(attempts, 6))),
                )
            )
            write.commit()
            return "failed"


def run(stop: Event | None = None) -> None:
    stop = stop or Event()
    while not stop.is_set():
        try:
            outcome = refresh_one() if enabled() else "disabled"
            record_heartbeat(
                "company_pages", status="error" if outcome == "failed" else "running", detail={"outcome": outcome}
            )
        except Exception:
            outcome = "error"
            logger.exception("Company page worker pass failed")
            record_heartbeat("company_pages", status="error")
        # Drain due protocols immediately. A failed build has already advanced
        # its own retry deadline, so it must not delay other ready companies.
        # Idle/disabled/leased and unexpected errors still wait to avoid a spin.
        if outcome not in {"prepared", "failed"}:
            stop.wait(5)


if __name__ == "__main__":
    configure_logging()
    run()
