"""Bounded company preparation, independently supervised alongside the web API.

One replace-in-place row per company; unchanged revisions never rebuild.
Database triggers invalidate all source write paths transactionally. Failed
builds retain the previous sections, but origin reads refuse it while its inputs are dirty.
"""

from __future__ import annotations

import logging
import signal
from datetime import timedelta
from threading import Event

from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models import CompanyPageSnapshot as Page
from db.models import Protocol, SessionLocal
from db.queue import record_heartbeat
from services.aggregations.company_overview import build_company_overview as _build_overview
from services.aggregations.company_overview import build_functions_for_protocol
from services.aggregations.company_overview.jobs import eligible_company_names
from services.aggregations.company_overview.payload import build_company_summary
from services.company_page_purge import enqueue_purge, purge_one
from services.company_pages import (
    SECTIONS,
    dependencies_for,
    enabled,
    encode,
    revisions_current,
    section_columns,
    source_revisions,
    version,
)
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def build_company_overview(session, name):
    return _build_overview(session, name, include_summary=False)


def refresh_one(session_factory=SessionLocal) -> str:
    # Seed separately: contenders must not wait on another company's build
    # transaction while trying to insert already-existing primary keys.
    with session_factory() as seed:
        identities = eligible_company_names(seed)
        # A formerly legacy name can acquire real membership. Retire its old
        # cache identity without creating or changing any domain records.
        seed.execute(
            delete(Page).where(
                Page.protocol_id.is_(None), select(Protocol.id).where(Protocol.name == Page.company_name).exists()
            )
        )
        existing = set(seed.scalars(select(Page.cache_key)))
        missing = [
            {"cache_key": key, "company_name": name, "protocol_id": pid}
            for name, pid in identities.items()
            if (key := f"protocol:{pid}" if pid is not None else f"legacy:{name}") not in existing
        ]
        if missing:
            seed.execute(pg_insert(Page).values(missing).on_conflict_do_nothing())
        seed.commit()
    with session_factory() as write:
        due = []
        for section in SECTIONS:
            blob, _, source_at = section_columns(section)
            due.append(or_(blob.is_(None), source_at.is_(None), ~revisions_current(section)))
        row = write.execute(
            select(
                Page.cache_key,
                Page.protocol_id,
                func.coalesce(Protocol.name, Page.company_name),
                Page.company_name,
                Page.attempts,
                Page.version,
                *(predicate.label(section) for section, predicate in zip(SECTIONS, due)),
            )
            .outerjoin(Protocol, Protocol.id == Page.protocol_id)
            .where(
                func.coalesce(Protocol.name, Page.company_name).in_(identities),
                Page.next_attempt_at <= func.clock_timestamp(),
                or_(
                    Page.version.is_distinct_from(version()),
                    Page.company_name.is_distinct_from(func.coalesce(Protocol.name, Page.company_name)),
                    *due,
                ),
            )
            .order_by(Page.next_attempt_at, Page.company_name)
            .with_for_update(skip_locked=True, of=Page)
            .limit(1)
        ).first()
        if row is None:
            return "idle"
        cache_key, protocol_id, name, previous_name, attempts, previous_version, *dirty = row
        sections = [
            s
            for s, changed in zip(SECTIONS, dirty)
            if changed or previous_version != version() or previous_name != name
        ]
        try:
            # Preserve the row lease if publication SQL fails; rollback the
            # savepoint before recording backoff on the outer transaction.
            with write.begin_nested():
                values = {}
                with session_factory() as source:
                    source.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                    source.execute(text("SET LOCAL statement_timeout = '25s'"))
                    started = source.execute(select(func.clock_timestamp())).scalar_one()
                    snapshot = source.execute(text("SELECT pg_export_snapshot()")).scalar_one()
                    source.info["company_page_snapshot"] = snapshot
                    for section in sections:
                        source.info["company_page_section"] = section
                        source.info["company_page_dependencies"] = dependencies_for(protocol_id, section)
                        if section == "overview":
                            payload = build_company_overview(source, name)
                        elif section == "functions":
                            payload = {"functions": build_functions_for_protocol(source, name)}
                        else:
                            payload = build_company_summary(source, name)
                        blob, revisions, source_at = section_columns(section)
                        values[blob.key] = encode(payload)
                        del payload  # Never retain all decoded sections at once.
                        values[revisions.key] = source_revisions(source)
                        values[source_at.key] = started
                finished = write.execute(select(func.clock_timestamp())).scalar_one()
                # Publish only tokens seen in the read snapshot. A producer writing
                # during preparation leaves this result dirty for the next pass.
                write.execute(
                    update(Page)
                    .where(Page.cache_key == cache_key)
                    .values(
                        **values,
                        company_name=name,
                        version=version(),
                        published_at=finished,
                        attempts=0,
                        next_attempt_at=finished + timedelta(seconds=5),
                    )
                )
                enqueue_purge(write, name)
                if previous_name and previous_name != name:
                    enqueue_purge(write, previous_name)
            write.commit()
            logger.info(
                "Prepared company page",
                extra={
                    "company": name,
                    "sections": sections,
                    "duration_ms": int((finished - started).total_seconds() * 1000),
                    "prepared_bytes": sum(len(v) for k, v in values.items() if k.endswith("_gzip")),
                },
            )
            return "prepared"
        except Exception:
            logger.exception("Company page preparation failed", extra={"company": name, "sections": sections})
            write.execute(
                update(Page)
                .where(Page.cache_key == cache_key)
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
            # Builds take priority. Provider latency must not insert an HTTP
            # wait between every due company; drain purges when builds are idle.
            if outcome == "idle":
                purged = purge_one()
                if purged in {"purged", "failed"}:
                    outcome = "purged" if purged == "purged" else "purge_failed"
            record_heartbeat(
                "company_pages",
                status="error" if outcome in {"failed", "purge_failed"} else "running",
                detail={"outcome": outcome},
            )
        except Exception:
            outcome = "error"
            logger.exception("Company page worker pass failed")
            record_heartbeat("company_pages", status="error")
        # Drain due protocols immediately. A failed build has already advanced
        # its own retry deadline, so it must not delay other ready companies.
        # Idle/disabled/leased and unexpected errors still wait to avoid a spin.
        if outcome not in {"prepared", "failed", "purged", "purge_failed"}:
            stop.wait(5)


if __name__ == "__main__":
    configure_logging()
    stop = Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    run(stop)
