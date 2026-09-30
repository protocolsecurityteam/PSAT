"""Solodit (Cyfrin) audit-report discovery client.

Solodit aggregates tens of thousands of findings across thousands of reports, so one query by protocol returns a
canonical list of reports with auditor, date and PDF URL.

There's no documented API; this wraps the web UI's unauthenticated tRPC endpoint
``https://solodit.cyfrin.io/api/trpc/findings.get``:

  - builds the devalue-encoded input (see ``LyuboslavLyubenov/search-solodit-mcp``);
  - decodes the response (a JS IIFE with ``BigInt`` and ``Date`` values) by piping it through ``node -e``;
  - paginates until pages run out or ``_STOP_AFTER_BARREN_PAGES`` pages add no new ``contest_link``;
  - dedups by ``contest_link``, one record per report.

The output shape matches ``audit_reports.search_audit_reports``; the LLM cluster pass handles cross-source dedup.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
import urllib.parse
from typing import Any

import requests

from utils.logging import record_degraded

logger = logging.getLogger(__name__)


_SOLODIT_TRPC_URL = "https://solodit.cyfrin.io/api/trpc/findings.get"

# Findings are by recency, so once audits are seen the rest are more findings on them.
_STOP_AFTER_BARREN_PAGES = 3

# Hard cap for generic queries that return thousands.
_MAX_PAGES = 40

# The backend is slow on popular queries (~5-10s).
_REQUEST_TIMEOUT = 30

_NODE_TIMEOUT = 10


def _build_input(keyword: str, page: int) -> str:
    """The tRPC input: string literals in a positional array referenced by index (reverse-engineered; see the MCP
    wrapper). Only ``keyword`` and ``page`` vary; every filter is maximally permissive.
    """
    safe_keyword = keyword.replace('"', '\\"')
    return (
        '{"0":"['
        '{\\"filters\\":1,\\"page\\":20},'
        '{\\"keywords\\":2,\\"firms\\":3,\\"tags\\":4,\\"forked\\":5,'
        '\\"impact\\":6,\\"user\\":-1,\\"protocol\\":-1,\\"reported\\":10,'
        '\\"reportedAfter\\":-1,\\"protocolCategory\\":13,\\"minFinders\\":14,'
        '\\"maxFinders\\":15,\\"rarityScore\\":16,\\"qualityScore\\":16,'
        '\\"bookmarked\\":17,\\"read\\":17,\\"unread\\":17,\\"sortField\\":18,'
        '\\"sortDirection\\":19},'
        f'\\"{safe_keyword}\\",[],[],[],'
        '[7,8,9],\\"HIGH\\",\\"MEDIUM\\",\\"LOW\\",'
        '{\\"label\\":11,\\"value\\":12},\\"All time\\",\\"alltime\\",'
        '[],\\"1\\",\\"100\\",1,true,\\"Recency\\",\\"Desc\\",'
        f'{int(page)}]"}}'
    )


# Eval the JS on stdin and print JSON, converting BigInt to string and Date to ISO 8601.
_NODE_DECODE_SCRIPT = (
    "process.stdin.resume(); let s=''; "
    "process.stdin.on('data', d => s+=d); "
    "process.stdin.on('end', () => { "
    "  try { "
    "    const obj = eval('('+s+')'); "
    "    console.log(JSON.stringify(obj, (k,v) => "
    "      typeof v === 'bigint' ? v.toString() : "
    "      v instanceof Date ? v.toISOString() : v)); "
    "  } catch (e) { "
    "    process.stderr.write('decode-error: '+e.message); "
    "    process.exit(1); "
    "  } "
    "});"
)


def _decode_response(js_payload: str) -> dict[str, Any] | None:
    """Decode the payload via node; ``None`` if node fails or the result isn't a dict (the page counts as empty)."""
    try:
        result = subprocess.run(
            ["node", "-e", _NODE_DECODE_SCRIPT],
            input=js_payload,
            capture_output=True,
            text=True,
            timeout=_NODE_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        record_degraded(phase="solodit_decode", exc=exc, context={"stage": "node_invoke"})
        logger.warning("Solodit node decode failed: %s", exc)
        return None
    if result.returncode != 0:
        logger.warning("Solodit node decode error: %s", result.stderr.strip())
        return None
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        record_degraded(phase="solodit_decode", exc=exc, context={"stage": "json_parse"})
        logger.warning("Solodit decode produced non-JSON: %s", exc)
        return None
    return parsed if isinstance(parsed, dict) else None


# The backend returns 500 under load (a soft rate limit) that succeeds on retry.
_MAX_RETRIES = 3
_BACKOFF_BASE = 1.5  # seconds — first retry waits 1.5s, then 3s, then 6s


def _fetch_page(keyword: str, page: int) -> dict[str, Any] | None:
    """One search page as ``{count, pages, findings}``, or ``None``.

    Retries 5xx and transport errors up to ``_MAX_RETRIES``; 4xx fails immediately (a bug in our input).
    """
    url = f"{_SOLODIT_TRPC_URL}?batch=1&input=" + urllib.parse.quote(_build_input(keyword, page))

    last_status: int | str = "no-attempt"
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                headers={
                    "User-Agent": "PSAT-audit-discovery/0.1",
                    "Accept": "*/*",
                    "Referer": "https://solodit.cyfrin.io/",
                },
                timeout=_REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            last_status = f"transport: {exc}"
            if attempt < _MAX_RETRIES:
                time.sleep(_BACKOFF_BASE * (2**attempt))
                continue
            break

        if resp.status_code == 200:
            try:
                body = resp.json()
            except ValueError as exc:
                record_degraded(
                    phase="solodit_fetch",
                    exc=exc,
                    context={"keyword": keyword, "page": page, "stage": "envelope_json"},
                )
                logger.warning(
                    "Solodit returned non-JSON envelope for keyword=%r page=%d",
                    keyword,
                    page,
                )
                return None
            if not isinstance(body, list) or not body:
                return None
            try:
                payload = body[0]["result"]["data"]
            except (KeyError, TypeError, IndexError) as exc:
                record_degraded(
                    phase="solodit_fetch",
                    exc=exc,
                    context={"keyword": keyword, "page": page, "stage": "envelope_shape"},
                )
                logger.warning(
                    "Solodit envelope missing result.data for keyword=%r page=%d",
                    keyword,
                    page,
                )
                return None
            if not isinstance(payload, str):
                return None
            return _decode_response(payload)

        last_status = resp.status_code
        if resp.status_code >= 500 or resp.status_code == 429:
            if attempt < _MAX_RETRIES:
                wait = _BACKOFF_BASE * (2**attempt)
                logger.info(
                    "Solodit %s for keyword=%r page=%d (attempt %d/%d), backing off %.1fs",
                    resp.status_code,
                    keyword,
                    page,
                    attempt + 1,
                    _MAX_RETRIES + 1,
                    wait,
                )
                time.sleep(wait)
                continue
        break

    logger.warning(
        "Solodit gave up after %d attempts for keyword=%r page=%d (last=%s)",
        _MAX_RETRIES + 1,
        keyword,
        page,
        last_status,
    )
    return None


_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]")


def _company_variants(company: str) -> list[str]:
    """Like ``audit_reports._company_name_variants``, kept local to avoid depending on the orchestrator."""
    base = company.strip().lower()
    if not base:
        return []
    variants = {base}
    stripped = _NON_ALPHANUMERIC.sub("", base)
    if stripped and stripped != base:
        variants.add(stripped)
    return [v for v in variants if v]


def _protocol_matches_company(protocol_name: str, company_variants: list[str]) -> bool:
    """Whether Solodit's resolved protocol matches the company.

    Keyword search matches content, so an "ether.fi" search also returns other protocols' findings that mention it.
    """
    if not company_variants:
        return True
    haystack = _NON_ALPHANUMERIC.sub("", (protocol_name or "").lower())
    if not haystack:
        return False
    return any(v in haystack or haystack in v for v in company_variants)


def search(
    company: str,
    *,
    max_pages: int = _MAX_PAGES,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Search Solodit for audit reports of ``company``, as records ready to merge with ``search_audit_reports``:

        {
          "url": str,             # canonical report URL
          "pdf_url": str | None,  # Solodit ``pdf_link``
          "auditor": str,
          "title": str,
          "date": str | None,     # YYYY-MM-DD
          "source_url": "https://solodit.cyfrin.io/",
          "confidence": float,    # high; human-curated
        }

    Stops when pages run out, at ``max_pages``, or after ``_STOP_AFTER_BARREN_PAGES`` barren pages. Returns ``[]`` on
    transport failure.
    """
    clean = (company or "").strip()
    if not clean:
        return []

    variants = _company_variants(clean)
    seen_urls: set[str] = set()
    out: list[dict[str, Any]] = []
    barren = 0
    total_pages_known: int | None = None

    if debug:
        logger.info("Solodit: searching for %r", clean)

    for page in range(1, max_pages + 1):
        if total_pages_known is not None and page > total_pages_known:
            break

        body = _fetch_page(clean, page)
        if body is None:
            # Stop early and keep what we have.
            break

        if total_pages_known is None:
            total_pages_known = body.get("pages")
            if debug:
                logger.info(
                    "Solodit: keyword=%r → %s findings across %s page(s)",
                    clean,
                    body.get("count"),
                    total_pages_known,
                )

        before = len(seen_urls)
        for finding in body.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            url = (finding.get("contest_link") or "").strip()
            if not url:
                url = (finding.get("source_link") or "").strip()
            if not url:
                continue
            if url in seen_urls:
                continue

            protocol_name = (finding.get("protocol_name") or "").strip()
            if variants and not _protocol_matches_company(protocol_name, variants):
                # Keyword matched content; the audit is for another protocol.
                continue

            seen_urls.add(url)

            firm_name = (finding.get("firm_name") or "").strip() or "Unknown"
            date_iso = (finding.get("report_date") or "").strip()
            date = date_iso[:10] if date_iso else None  # ISO → YYYY-MM-DD
            pdf_link = (finding.get("pdf_link") or "").strip() or None

            out.append(
                {
                    "url": url,
                    "pdf_url": pdf_link
                    if pdf_link and pdf_link.lower().endswith(".pdf")
                    else (url if url.lower().endswith(".pdf") else None),
                    "auditor": firm_name,
                    "title": _derive_title(firm_name, protocol_name or clean, finding),
                    "date": date,
                    "source_url": "https://solodit.cyfrin.io/",
                    "confidence": 0.95,
                }
            )

        added = len(seen_urls) - before
        if added == 0:
            barren += 1
            if barren >= _STOP_AFTER_BARREN_PAGES:
                if debug:
                    logger.info(
                        "Solodit: stopping after %d barren page(s) (have %d audit(s))",
                        barren,
                        len(out),
                    )
                break
        else:
            barren = 0

        # Pause between pages; sustained load triggers 500s.
        if total_pages_known and page < total_pages_known:
            time.sleep(0.75)

    if debug:
        logger.info("Solodit: %d unique audit(s) for %r", len(out), clean)
    return out


def _derive_title(firm: str, protocol: str, finding: dict[str, Any]) -> str:
    """Synthesize a report title: Solodit's ``title`` is the finding's, not the report's.

    Contest findings get "Foo Contest".
    """
    contest_id = (finding.get("contest_id") or "").strip()
    base = f"{firm} {protocol} Audit".strip()
    if contest_id:
        base = f"{firm} {protocol} Contest"
    return base
