"""Prepared response IO; no ORM graphs or unbounded in-process cache.

Unchanged source revisions permit reuse regardless of build age. Every origin
read validates the revisions; the edge gets at most 60s from that validation.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Request, Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy import String, and_, case, cast, exists, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from db.jsonb import jsonb_state
from db.models import CompanyPageRevision, CompanyPageSnapshot, Protocol
from utils.compression import accepts_gzip

logger = logging.getLogger(__name__)
MAX_AGE_SECONDS = 60
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_GZIP_BYTES = 4 * 1024 * 1024


def cache_tag(name: str) -> str:
    """One bounded ASCII tag for every cached URL/encoding of a company."""
    return "psat-company-" + hashlib.sha256(name.encode()).hexdigest()


def enabled() -> bool:
    return os.getenv("PSAT_PREPARED_COMPANY_PAGES", "0") == "1"


@lru_cache(maxsize=1)
def _builder_digest() -> str:
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


def version() -> str:
    config = os.getenv("PSAT_SUPPORTED_CHAIN_IDS", "") + ":" + os.getenv("PSAT_COMPANY_BUILD_REVISION", "")
    return "4:" + hashlib.sha256((_builder_digest() + config).encode()).hexdigest()


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
        (or_(key.contains("protocol:"), key == "legacy:jobs"), func.psat_page_revision(key)),
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


def section_columns(section: str):
    if section not in SECTIONS:
        raise ValueError("Unknown company section")
    page = CompanyPageSnapshot
    return (
        getattr(page, section + "_gzip"),
        getattr(page, "source_revisions" if section == "overview" else section + "_source_revisions"),
        getattr(page, "source_started_at" if section == "overview" else section + "_source_started_at"),
    )


def dependencies_for(protocol_id: int | None, section: str) -> set[str]:
    if protocol_id is None:
        return {"legacy:jobs", "summary:all"} if section == "summary" else {"legacy:jobs", "all", "overview:all"}
    if section == "summary":
        return {"summary:all", f"summary:protocol:{protocol_id}"}
    deps = {"all", f"protocol:{protocol_id}"}
    if section == "overview":
        deps.update({"overview:all", f"overview:protocol:{protocol_id}"})
    return deps


def revisions_current(section: str = "overview"):
    """SQL predicate: a dirty response must never receive another cache TTL."""
    page = CompanyPageSnapshot
    _, revision_column, _ = section_columns(section)
    revisions = case((jsonb_state(revision_column) == "object", revision_column), else_=literal({}, type_=JSONB))
    entries = func.jsonb_each_text(revisions).table_valued("key", "value")
    changed = (
        select(literal(1))
        .select_from(entries)
        .outerjoin(CompanyPageRevision, CompanyPageRevision.key == entries.c.key)
        .where(entries.c.value.is_distinct_from(_revision_value(entries.c.key)))
        .correlate(page)
    )
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
    legacy_required = and_(revisions.has_key(prefix + "all"), revisions.has_key("legacy:jobs"))
    return and_(case((page.protocol_id.is_(None), legacy_required), else_=and_(*required)), ~exists(changed))


def read_response(
    session: Session, request: Request, name: str, *, functions: bool = False, section: str | None = None
) -> Response | None:
    if not enabled():
        return None
    section = section or ("functions" if functions else "overview")
    blob, _, source_column = section_columns(section)
    row = session.execute(
        select(blob, source_column, func.statement_timestamp())
        .outerjoin(Protocol, Protocol.id == CompanyPageSnapshot.protocol_id)
        .where(
            or_(
                Protocol.name == name,
                and_(
                    CompanyPageSnapshot.protocol_id.is_(None),
                    ~select(Protocol.id).where(Protocol.name == name).correlate(None).exists(),
                ),
            ),
            CompanyPageSnapshot.company_name == name,
            CompanyPageSnapshot.version == version(),
            revisions_current(section),
            source_column <= func.clock_timestamp(),
            blob.is_not(None),
        )
    ).first()
    if row is None:
        return None
    body, source_at, now = row
    if len(body) > MAX_GZIP_BYTES:
        return None
    headers = {
        "Cache-Tag": cache_tag(name),
        "Vary": "Accept-Encoding",
        "X-PSAT-Prepared-At": source_at.isoformat(),
        "X-PSAT-Validated-At": now.isoformat(),
        "X-PSAT-Response-Source": "prepared",
        # Internal header consumed and stripped by the origin boundary.
        "X-PSAT-Fresh-Until": str(now.timestamp() + MAX_AGE_SECONDS),
    }
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
    Durable missing/dirty/version state is discovered by the builder without
    reader writes or locks on an in-progress preparation.
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
