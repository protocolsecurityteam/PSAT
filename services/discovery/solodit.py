"""Solodit (Cyfrin) audit-report discovery client.

Solodit aggregates ~50,000 findings across ~8,000 reports from every major
audit firm. For our purposes, it's the highest-leverage upstream source:
one query by protocol name returns a canonical list of audit reports for
that protocol, complete with auditor name, date, and the original PDF URL.

Solodit doesn't expose a documented public API, but the web UI's tRPC
backend at ``https://solodit.cyfrin.io/api/trpc/findings.get`` is reachable
without auth. This module is a thin client around that endpoint:

  - Builds the devalue-encoded input the backend expects (a structurally-
    shared array literal — see the MCP wrapper at
    ``LyuboslavLyubenov/search-solodit-mcp`` for prior art).
  - Decodes the response by piping the JS-eval'd payload through
    ``node -e`` (the response is a self-executing IIFE returning an object
    with ``BigInt`` ids and ``Date`` timestamps that no JSON parser handles).
  - Paginates until either ``pages`` is exhausted or no new ``contest_link``
    URLs have appeared for ``_STOP_AFTER_BARREN_PAGES`` consecutive pages.
  - Deduplicates by ``contest_link`` and returns one normalized record per
    audit report.

The output shape mirrors what ``audit_reports.search_audit_reports``
expects, so callers can drop Solodit's results straight into the same
report list that search/GitHub-crawled entries land in. The downstream
LLM validate-and-cluster pass handles cross-source mirror dedup.
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

logger = logging.getLogger(__name__)


_SOLODIT_TRPC_URL = "https://solodit.cyfrin.io/api/trpc/findings.get"

# Stop paginating once this many consecutive pages add zero new audit URLs.
# Findings are sorted by recency; once we've seen the audits, the remaining
# pages are just additional findings on the same already-collected audits.
_STOP_AFTER_BARREN_PAGES = 3

# Hard cap on pages even when new URLs keep appearing — protects against
# pathological queries (a generic word like "DeFi" returns thousands).
_MAX_PAGES = 40

# Per-request timeout for the Solodit HTTP call. The backend is slow on
# heavyweight queries (~5–10s for popular protocols).
_REQUEST_TIMEOUT = 30

# Per-request timeout for the node decoder. Even a 10K-finding response
# evals to JSON in well under a second on commodity hardware.
_NODE_TIMEOUT = 10


# --- Input/output -----------------------------------------------------------


def _build_input(keyword: str, page: int) -> str:
    """Build the structurally-shared input string the tRPC backend expects.

    The wire format inlines string literals into a positional array and
    references them by index — see the MCP wrapper repo for the original
    reverse-engineered template. Only ``keyword`` and ``page`` change per
    request; every other filter is fixed at "all-permissive" so we never
    accidentally drop a real audit.
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


# Node script that reads JS source on stdin, evals, and prints JSON. The
# replacer normalizes BigInt to string and Date to ISO 8601 — both appear
# in Solodit responses (id/auditfirm_id/protocol_id are BigInts, report_date
# is a Date) and would otherwise crash JSON.stringify.
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
    """Pipe the JS-eval'd payload through node and parse as JSON.

    Returns ``None`` if node fails or the output isn't a dict — callers
    treat the page as empty rather than blowing up the whole pagination.
    """
    try:
        result = subprocess.run(
            ["node", "-e", _NODE_DECODE_SCRIPT],
            input=js_payload,
            capture_output=True,
            text=True,
            timeout=_NODE_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("Solodit node decode failed: %s", exc)
        return None
    if result.returncode != 0:
        logger.warning("Solodit node decode error: %s", result.stderr.strip())
        return None
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Solodit decode produced non-JSON: %s", exc)
        return None
    return parsed if isinstance(parsed, dict) else None


# --- HTTP fetch -------------------------------------------------------------


# Retry config for 5xx + transport failures. Solodit's tRPC backend
# occasionally returns 500 under load (effectively a soft rate limit) and
# the same call succeeds on retry after a short backoff.
_MAX_RETRIES = 3
_BACKOFF_BASE = 1.5  # seconds — first retry waits 1.5s, then 3s, then 6s


def _fetch_page(keyword: str, page: int) -> dict[str, Any] | None:
    """Fetch one Solodit search page. Returns ``{count, pages, findings}`` or
    ``None`` on transport / decode failure.

    Retries up to ``_MAX_RETRIES`` times on 5xx and transient transport
    errors. 4xx errors fail immediately — those are programming bugs in
    the input we're sending, not infrastructure issues.
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
            except ValueError:
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
            except (KeyError, TypeError, IndexError):
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
        # Retry on 5xx (server-side / soft rate limit) and 429. Bail on 4xx.
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


# --- Filtering --------------------------------------------------------------


_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]")


def _company_variants(company: str) -> list[str]:
    """Same shape as ``audit_reports._company_name_variants`` — kept local
    so this module has no dependency on the orchestrator."""
    base = company.strip().lower()
    if not base:
        return []
    variants = {base}
    stripped = _NON_ALPHANUMERIC.sub("", base)
    if stripped and stripped != base:
        variants.add(stripped)
    return [v for v in variants if v]


def _protocol_matches_company(protocol_name: str, company_variants: list[str]) -> bool:
    """True when Solodit's resolved protocol_name matches the company we asked
    about. Solodit's keyword search returns hits whose CONTENT mentions the
    keyword, not whose protocol IS the keyword — so an "ether.fi" search
    would return Aave findings that happen to mention ether.fi in passing.
    Filter to entries where the resolved protocol matches what we asked for.
    """
    if not company_variants:
        return True
    haystack = _NON_ALPHANUMERIC.sub("", (protocol_name or "").lower())
    if not haystack:
        return False
    return any(v in haystack or haystack in v for v in company_variants)


# --- Public API -------------------------------------------------------------


def search(
    company: str,
    *,
    max_pages: int = _MAX_PAGES,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Search Solodit for audit reports of ``company``.

    Returns a list of normalized audit-report dicts ready to merge with
    the rest of ``search_audit_reports``'s output:

        {
          "url": str,             # canonical audit report URL
          "pdf_url": str | None,  # PDF when known (Solodit ``pdf_link``)
          "auditor": str,
          "title": str,
          "date": str | None,     # YYYY-MM-DD when available
          "source_url": "https://solodit.cyfrin.io/",
          "confidence": float,    # high — Solodit is human-curated
        }

    Iterates pages until either (a) Solodit's reported page count is
    exhausted, (b) ``max_pages`` is hit, or (c) ``_STOP_AFTER_BARREN_PAGES``
    consecutive pages add zero new ``contest_link`` URLs. Returns ``[]`` on
    transport failure — Solodit being down should never break the pipeline.
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
            # Transport / decode failure — stop early, don't fail the
            # whole pipeline. Whatever we have is still useful.
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
                # Some findings only have ``source_link`` — fall back.
                url = (finding.get("source_link") or "").strip()
            if not url:
                continue
            if url in seen_urls:
                continue

            protocol_name = (finding.get("protocol_name") or "").strip()
            if variants and not _protocol_matches_company(protocol_name, variants):
                # Solodit keyword-matched on content; the actual audit
                # is for a different protocol. Skip.
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

        # Be polite — Solodit's tRPC backend gets cranky under sustained
        # load and starts returning 500s. A short pause between successful
        # page fetches keeps us under whatever soft limit it enforces.
        if total_pages_known and page < total_pages_known:
            time.sleep(0.75)

    if debug:
        logger.info("Solodit: %d unique audit(s) for %r", len(out), clean)
    return out


def _derive_title(firm: str, protocol: str, finding: dict[str, Any]) -> str:
    """Synthesize an audit-report title.

    Solodit's ``title`` field is the FINDING title (about a specific bug),
    not the audit report title. Most callers want a coarse "Foo audited
    Bar" string for display + dedup matching, so we synthesize one. When
    the finding came from a contest platform (``contest_id``), prefer
    "Foo Contest" for clarity.
    """
    contest_id = (finding.get("contest_id") or "").strip()
    base = f"{firm} {protocol} Audit".strip()
    if contest_id:
        base = f"{firm} {protocol} Contest"
    return base


# --- CLI --------------------------------------------------------------------


def _cli() -> None:
    """``python -m services.discovery.solodit <company>``"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Search Solodit for audit reports")
    parser.add_argument("company", help="Protocol or company name")
    parser.add_argument("--max-pages", type=int, default=_MAX_PAGES)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    results = search(args.company, max_pages=args.max_pages, debug=args.debug)
    json.dump(results, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    _cli()
