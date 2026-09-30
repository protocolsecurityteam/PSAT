"""Bounded company preparation, independently supervised alongside the web API.

One replace-in-place row per company; unchanged revisions never rebuild.
Database triggers invalidate all source write paths transactionally. Dirty
sections rebuild after a quiet period, no more often than a minimum interval,
and within a maximum wait. Summary and structural sections publish separately;
failed builds retain the previously published sections.
"""

from __future__ import annotations

import logging
import signal
from datetime import timedelta
from threading import Event

from sqlalchemy import and_, case, func, not_, or_, select, text, update
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
    PAYLOAD_SCHEMA,
    SECTIONS,
    SEMANTIC_EPOCH,
    builder_digest,
    chain_set,
    changed_within,
    dependencies_for,
    enabled,
    encode,
    revisions_current,
    section_columns,
    servable,
    source_revisions,
    timing,
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
        existing = set(seed.scalars(select(Page.cache_key)))
        missing = [
            {"cache_key": key, "company_name": name, "protocol_id": pid}
            for name, pid in identities.items()
            if (key := f"protocol:{pid}") not in existing
        ]
        if missing:
            seed.execute(pg_insert(Page).values(missing).on_conflict_do_nothing())
        seed.commit()
    with session_factory() as write:
        now = func.statement_timestamp()
        renamed = Page.company_name != Protocol.name
        missing, due, fresh = {}, {}, {}
        for section in SECTIONS:
            columns = section_columns(section)
            quiet, interval, wait = timing(section)
            interval_elapsed = columns.started <= now - timedelta(seconds=interval)
            missing[section] = or_(not_(servable(section)), renamed)
            due[section] = or_(
                missing[section],
                and_(
                    not_(revisions_current(section)),
                    interval_elapsed,
                    or_(not_(changed_within(section, quiet)), columns.started <= now - timedelta(seconds=wait)),
                ),
                and_(columns.digest.is_distinct_from(builder_digest()), interval_elapsed),
            )
            fresh[section] = and_(
                servable(section), ~renamed, columns.digest == builder_digest(), revisions_current(section)
            )
        row = write.execute(
            select(
                Page.cache_key,
                Page.protocol_id,
                Protocol.name,
                Page.company_name,
                Page.attempts,
                *(due[s].label("due_" + s) for s in SECTIONS),
                *(fresh[s].label("fresh_" + s) for s in SECTIONS),
            )
            .join(Protocol, Protocol.id == Page.protocol_id)
            .where(
                Protocol.name.in_(identities),
                Page.next_attempt_at <= func.clock_timestamp(),
                or_(*due.values()),
            )
            .order_by(
                case((or_(*missing.values()), 0), else_=1),
                func.least(*(case((due[s], section_columns(s).started)) for s in SECTIONS)),
                Page.company_name,
            )
            .with_for_update(skip_locked=True, of=Page)
            .limit(1)
        ).first()
        if row is None:
            return "idle"
        cache_key, protocol_id, name, previous_name, attempts = row[:5]
        flags = row._mapping
        units = []
        if flags["due_summary"]:
            units.append((False, ["summary"]))
        if flags["due_overview"] or flags["due_functions"]:
            units.append((True, [s for s in ("overview", "functions") if not flags["fresh_" + s]]))
        failed = False
        for structural, sections in units:
            try:
                # Preserve the row lease if publication SQL fails; rollback the
                # savepoint before recording backoff on the outer transaction.
                with write.begin_nested():
                    values, started = _build(session_factory, protocol_id, name, sections)
                    finished = write.execute(select(func.clock_timestamp())).scalar_one()
                    # Publish only tokens seen in the read snapshot. A producer writing
                    # during preparation leaves this result dirty for the next pass.
                    # A rename lands with the structural sections that carry the name.
                    write.execute(
                        update(Page)
                        .where(Page.cache_key == cache_key)
                        .values(
                            **values,
                            **({"company_name": name} if structural else {}),
                            published_at=finished,
                            attempts=0,
                            next_attempt_at=finished,
                        )
                    )
                    enqueue_purge(write, name)
                    if structural and previous_name and previous_name != name:
                        enqueue_purge(write, previous_name)
                logger.info(
                    "Prepared company page",
                    extra={
                        "company": name,
                        "sections": sections,
                        "duration_ms": int((finished - started).total_seconds() * 1000),
                        "prepared_bytes": sum(len(v) for k, v in values.items() if k.endswith("_gzip")),
                    },
                )
            except Exception:
                failed = True
                logger.exception("Company page preparation failed", extra={"company": name, "sections": sections})
        if failed:
            write.execute(
                update(Page)
                .where(Page.cache_key == cache_key)
                .values(
                    attempts=attempts + 1,
                    next_attempt_at=func.clock_timestamp() + timedelta(seconds=min(300, 5 * 2 ** min(attempts, 6))),
                )
            )
        write.commit()
        return "failed" if failed else "prepared"


def _build(session_factory, protocol_id, name, sections):
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
            columns = section_columns(section)
            values[columns.blob.key] = encode(payload)
            del payload  # Never retain all decoded sections at once.
            values[columns.revisions.key] = source_revisions(source)
            values[columns.started.key] = started
            values[columns.schema.key] = PAYLOAD_SCHEMA[section]
            values[columns.epoch.key] = SEMANTIC_EPOCH
            values[columns.chains.key] = chain_set()
            values[columns.digest.key] = builder_digest()
    return values, started


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
        # Drain due companies immediately. A failed build has already advanced
        # its own retry deadline, so it must not delay other ready companies.
        # Idle/disabled and unexpected errors still wait to avoid a spin.
        if outcome not in {"prepared", "failed", "purged", "purge_failed"}:
            stop.wait(5)


if __name__ == "__main__":
    configure_logging()
    stop = Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    run(stop)
