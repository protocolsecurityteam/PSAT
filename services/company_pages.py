"""Prepared response IO; no ORM graphs or unbounded in-process cache.

A section is servable while its schema, semantic epoch and chain set match,
and it is either fresh or younger than the stale limit. Every origin read
validates the revisions and builder digest and labels the response fresh or
stale; the edge gets at most 60s from that validation.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple

from fastapi import Request, Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy import String, and_, case, cast, exists, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from db.jsonb import jsonb_state
from db.models import CompanyPageRevision, CompanyPageSnapshot, Protocol
from utils.chains import supported_chain_ids
from utils.compression import accepts_gzip

logger = logging.getLogger(__name__)
MAX_AGE_SECONDS = 60
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_GZIP_BYTES = 4 * 1024 * 1024
# Bump a section when its response shape or field meaning changes; regenerate
# tests/fixtures/company_pages/schema_<section>.json alongside.
PAYLOAD_SCHEMA = {"overview": 1, "functions": 1, "summary": 1}
# Bump when a fix withdraws previously published facts: a hard cutover, never stale.
SEMANTIC_EPOCH = 1


def cache_tag(name: str) -> str:
    """One bounded ASCII tag for every cached URL/encoding of a company."""
    return "psat-company-" + hashlib.sha256(name.encode()).hexdigest()


def enabled() -> bool:
    return os.getenv("PSAT_PREPARED_COMPANY_PAGES", "0") == "1"


def timing(section: str) -> tuple[int, int, int]:
    """Rebuild pacing in seconds for the section's group: (quiet, min interval, max wait)."""
    if section == "summary":
        group, quiet, interval, wait = "SUMMARY", "0", "30", "60"
    else:
        group, quiet, interval, wait = "STRUCTURAL", "120", "300", "900"
    return (
        int(os.getenv(f"PSAT_COMPANY_{group}_QUIET_S", quiet)),
        int(os.getenv(f"PSAT_COMPANY_{group}_MIN_INTERVAL_S", interval)),
        int(os.getenv(f"PSAT_COMPANY_{group}_MAX_WAIT_S", wait)),
    )


def stale_max_seconds() -> int:
    return int(os.getenv("PSAT_COMPANY_STALE_MAX_S", "86400"))


def chain_set() -> str:
    return ",".join(str(chain_id) for chain_id in sorted(supported_chain_ids()))


@lru_cache(maxsize=1)
def _code_digest() -> str:
    # Hash the shared implementation and dependency lock once per interpreter.
    # Documentation/frontend/CI-only deployments can reuse existing responses.
    root = Path(__file__).resolve().parents[1]
    files = [root / "uv.lock", root / "workers/company_pages.py"]
    for directory in ("services", "db", "utils", "schemas"):
        files.extend((root / directory).rglob("*.py"))
        files.extend((root / directory).rglob("*.json"))
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def builder_digest() -> str:
    """Decides whether to rebuild, never whether to serve."""
    config = os.getenv("PSAT_SUPPORTED_CHAIN_IDS", "") + ":" + os.getenv("PSAT_COMPANY_BUILD_REVISION", "")
    return hashlib.sha256((_code_digest() + config).encode()).hexdigest()


def encode(payload: Any) -> bytes:
    raw = json.dumps(jsonable_encoder(payload), ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Company page exceeds prepared JSON size limit")
    body = gzip.compress(raw, compresslevel=6, mtime=0)
    if len(body) > MAX_GZIP_BYTES:
        raise ValueError("Company page exceeds prepared gzip size limit")
    return body


def _revision_value(key):
    # Only group fingerprints need a function call. Ordinary dependencies use
    # the indexed join below, not one SQL-function invocation per contract.
    return case(
        (key.contains("protocol:"), func.psat_page_revision(key)),
        else_=cast(CompanyPageRevision.token, String),
    )


def source_revisions(session: Session) -> dict[str, str | None]:
    """Capture the tokens in the SAME repeatable-read snapshot as both builds."""
    keys = sorted(session.info["company_page_dependencies"])
    dependencies = func.unnest(keys, type_=String).table_valued("dependency").render_derived()
    return {
        key: token
        for key, token in session.execute(
            select(dependencies.c.dependency, _revision_value(dependencies.c.dependency))
            .select_from(dependencies)
            .outerjoin(CompanyPageRevision, CompanyPageRevision.key == dependencies.c.dependency)
        )
    }


SECTIONS = ("overview", "functions", "summary")


class SectionColumns(NamedTuple):
    blob: Any
    revisions: Any
    started: Any
    schema: Any
    epoch: Any
    chains: Any
    digest: Any


def section_columns(section: str) -> SectionColumns:
    if section not in SECTIONS:
        raise ValueError("Unknown company section")
    page = CompanyPageSnapshot
    prefix = "" if section == "overview" else section + "_"
    return SectionColumns(
        getattr(page, section + "_gzip"),
        *(
            getattr(page, prefix + name)
            for name in (
                "source_revisions",
                "source_started_at",
                "schema_version",
                "semantic_epoch",
                "chain_set",
                "builder_digest",
            )
        ),
    )


def _markers_current(section: str):
    columns = section_columns(section)
    return and_(
        columns.blob.is_not(None),
        columns.schema == PAYLOAD_SCHEMA[section],
        columns.epoch == SEMANTIC_EPOCH,
        columns.chains == chain_set(),
        columns.started <= func.clock_timestamp(),
    )


def _within_stale_limit(section: str):
    started = section_columns(section).started
    return started >= func.statement_timestamp() - timedelta(seconds=stale_max_seconds())


def servable(section: str):
    """SQL predicate; unbuilt or pre-marker sections are never servable.

    The age limit bounds how long a stale build may stand in; a fresh build
    never expires.
    """
    fresh = and_(section_columns(section).digest == builder_digest(), revisions_current(section))
    return func.coalesce(and_(_markers_current(section), or_(fresh, _within_stale_limit(section))), False)


def dependencies_for(protocol_id: int, section: str) -> set[str]:
    if section == "summary":
        return {"summary:all", f"summary:protocol:{protocol_id}"}
    deps = {"all", f"protocol:{protocol_id}"}
    if section == "overview":
        deps.update({"overview:all", f"overview:protocol:{protocol_id}"})
    return deps


def _changed_dependencies(section: str):
    revision_column = section_columns(section).revisions
    revisions = case((jsonb_state(revision_column) == "object", revision_column), else_=literal({}, type_=JSONB))
    entries = func.jsonb_each_text(revisions).table_valued("key", "value")
    changed = (
        select(literal(1))
        .select_from(entries)
        .outerjoin(CompanyPageRevision, CompanyPageRevision.key == entries.c.key)
        .where(entries.c.value.is_distinct_from(_revision_value(entries.c.key)))
        .correlate(CompanyPageSnapshot)
    )
    return revisions, entries, changed


def changed_within(section: str, seconds: int):
    """SQL predicate: a recorded dependency whose revision moved changed in the last ``seconds``.

    Scheduling only. A late commit can carry an early change time, so this
    never decides freshness; the tokens do.
    """
    _, entries, changed = _changed_dependencies(section)
    window = func.statement_timestamp() - timedelta(seconds=seconds)
    return exists(changed.where(func.psat_page_changed_at(entries.c.key) > window))


def revisions_current(section: str = "overview"):
    """SQL predicate: every recorded dependency token is unchanged."""
    page = CompanyPageSnapshot
    revisions, _, changed = _changed_dependencies(section)
    prefix = "summary:" if section == "summary" else ""
    required = [
        revisions.has_key(prefix + "all"),
        revisions.has_key(literal(prefix + "protocol:") + cast(page.protocol_id, String)),
    ]
    if section == "overview":
        required += [
            revisions.has_key("overview:all"),
            revisions.has_key(literal("overview:protocol:") + cast(page.protocol_id, String)),
        ]
    return and_(*required, ~exists(changed))


def read_response(
    session: Session, request: Request, name: str, *, functions: bool = False, section: str | None = None
) -> Response | None:
    if not enabled():
        return None
    section = section or ("functions" if functions else "overview")
    columns = section_columns(section)
    row = session.execute(
        select(
            columns.blob,
            columns.started,
            func.statement_timestamp(),
            _within_stale_limit(section),
            columns.digest == builder_digest(),
            revisions_current(section),
        )
        .join(Protocol, Protocol.id == CompanyPageSnapshot.protocol_id)
        .where(
            Protocol.name == name,
            CompanyPageSnapshot.company_name == name,
            _markers_current(section),
        )
    ).first()
    if row is None:
        return None
    body, source_at, now, within_limit, same_code, same_data = row
    fresh = bool(same_code and same_data)
    if not (fresh or within_limit):
        logger.error(
            "Prepared company page exceeded stale limit",
            extra={"company": name, "section": section, "prepared_at": source_at.isoformat()},
        )
        return None
    if len(body) > MAX_GZIP_BYTES:
        return None
    headers = {
        "Cache-Tag": cache_tag(name),
        "Vary": "Accept-Encoding",
        "X-PSAT-Prepared-At": source_at.isoformat(),
        "X-PSAT-Payload-Schema": str(PAYLOAD_SCHEMA[section]),
        "X-PSAT-Validated-At": now.isoformat(),
        "X-PSAT-Response-Source": "prepared" if fresh else "prepared-stale",
        # Internal header consumed and stripped by the origin boundary.
        "X-PSAT-Fresh-Until": str(now.timestamp() + MAX_AGE_SECONDS),
    }
    if not fresh:
        headers["X-PSAT-Stale-Reason"] = "code" if same_data else "data"
    if accepts_gzip(request.headers.get("accept-encoding", "")):
        headers["Content-Encoding"] = "gzip"
    else:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
                body = compressed.read(MAX_JSON_BYTES + 1)
            if len(body) > MAX_JSON_BYTES:
                return None
        except (OSError, EOFError):
            logger.warning("Invalid prepared company gzip", extra={"company": name})
            return None
    return Response(body, media_type="application/json", headers=headers)


def prepared_or_pending(session: Session, request: Request, name: str, *, section: str = "overview") -> Response:
    """Same read contract for public/operator requests, including cache revalidation.

    No-cache means validate the saved revision, not rebuild unchanged data.
    Only an unservable section is refused; dirty or old-code snapshots are
    served labelled stale. The builder discovers due work without reader
    writes or locks on an in-progress preparation.
    """
    from fastapi import HTTPException
    from starlette.responses import JSONResponse

    response = read_response(session, request, name, section=section)
    if response is not None:
        return response
    from services.aggregations.company_overview.jobs import eligible_company_names

    if name not in eligible_company_names(session):
        raise HTTPException(404, "Company not found")
    return JSONResponse(
        {"detail": "Company data is being prepared. Please retry shortly.", "code": "company_preparing"},
        status_code=503,
        headers={"Retry-After": "2", "Cache-Control": "private, no-store", "X-PSAT-Response-Source": "preparing"},
    )
