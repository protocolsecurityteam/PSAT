"""LLM-based classification and extraction for audit report discovery.

Stage 1 — classify_search_results: given search results, determine which
are actual third-party audit reports and extract basic metadata.

Stage 2 — extract_report_details: given a fetched page's text, extract structured
audit metadata AND discover links to additional audit reports on the page.
"""

from __future__ import annotations

import json
import re
from typing import Any

from utils import llm

from .inventory_domain import _debug_log

_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_MARKDOWN_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)


def _parse_json_array(text: str) -> list[dict[str, Any]] | None:
    """Best-effort extraction of a JSON array from LLM output."""
    # Strip markdown fences first
    fence_match = _MARKDOWN_FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    # Try to extract the first [...] block
    match = _JSON_ARRAY_RE.search(text)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _parse_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort extraction of a JSON object from LLM output."""
    fence_match = _MARKDOWN_FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    match = _JSON_OBJECT_RE.search(text)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

    return None


_KNOWN_AUDITORS = (
    "Trail of Bits (often abbreviated ToB), OpenZeppelin (often OZ), Spearbit, "
    "Consensys Diligence, Halborn, Quantstamp, Sigma Prime, Sherlock, Code4rena (C4), "
    "Cantina, Zellic, Cyfrin, Hexens, MixBytes, Dedaub, "
    "Nethermind (their report IDs are formatted NM-#### or NM_####), ChainSecurity, "
    "Certora, PeckShield, SlowMist, Ackee, Omniscia, Solidified, Paladin, Decurity, "
    "Pashov, OtterSec, Statemind, Runtime Verification, Hats Finance, "
    "Pessimistic, Blackthorn, ABDK Consulting, CertiK, Lexfo, Securing, "
    "Immunefi, Zokyo, Kudelski Security, Secure3, Veridise, Chainlight, "
    "0xMacro, Guardian Audits, Three Sigma, Pragma, Certik, Solidprof, "
    "Sec3 (formerly Soteria), Fuzzland, Oak Security, Block Analitica"
)

_CLASSIFICATION_PROMPT = """\
You are analyzing web search results to identify third-party security audit reports \
specifically for the **{company}** smart contract protocol.

CRITICAL: Only classify a result as an audit if it is specifically about {company}. \
Audit reports for OTHER protocols (even if they appear in search results) must be \
marked is_audit: false. The title, URL, and snippet must reference {company} or its \
known contracts/products.

An audit report is a formal security review conducted by an independent auditing firm. \
Common firms: {auditors}. Use these names verbatim when you spot a match — including \
when only an abbreviation or report-ID prefix appears in the URL or filename.

For each search result below, determine:
- Is it an actual audit report for {company}, a page linking to {company} audit \
reports, or a page that lists/indexes multiple {company} audits?
- Pages that aggregate or list multiple audit reports for {company} (e.g. the \
protocol's security page, a GitHub audits directory) are valuable — mark them as \
is_audit: true with type "listing".

Do NOT classify as audits:
- Audit reports for OTHER protocols (even if the URL looks audit-related)
- Blog posts about security in general
- Bug bounty program pages
- Generic audit aggregator pages that list many protocols
- Marketing pages or protocol docs that merely mention security

Search results:
{results}

When extracting fields, look at ALL of: the title, the snippet, and the URL \
path/filename. Auditor names and dates are often embedded in the URL filename \
(e.g. ``Omniscia_Audit_EtherFi.pdf``, ``2024.06.25 - Halborn - EFIP.pdf``), or \
encoded as report IDs that follow a known auditor's convention. Use your \
knowledge of common auditor naming patterns to resolve those to a firm name \
when it is unambiguous.

Reply with ONLY a JSON array. Each element must have:
- "url": the exact URL from the search result
- "is_audit": true ONLY if this is an audit report or listing page \
specifically for {company}
- "type": "report" for a single audit report, "listing" for a page that \
links to multiple audits, "pdf" for a direct PDF link, null if not an audit
- "auditor": name of the auditing firm if identifiable from the title, \
snippet, OR url filename — null only when no signal is available
- "title": short clean human-readable title for the audit (drop \
boilerplate like "[PDF]" prefixes), null if not applicable
- "date": audit date as YYYY-MM-DD if visible in the title, snippet or \
URL (or YYYY-MM / YYYY), null if not present
- "confidence": 0.0 to 1.0 how confident you are this is a real \
{company} audit page"""

_EXTRACTION_PROMPT = """\
Identify third-party security audits of the **{company}** smart-contract protocol \
listed on the following page. We only need enough metadata to *identify* each \
audit — no findings, scope, or summary is required.

Page URL: {url}
Page content (truncated):
{page_text}

CRITICAL FILTER: Many pages are auditor publication directories or aggregator \
indexes that list audits for many DIFFERENT protocols. You must extract ONLY \
the audits that are clearly for {company}. Audits whose title or filename \
references a different protocol must be excluded — even if they are listed on \
the same page. When in doubt, exclude.

Return ONLY a JSON object with these fields:
- "reports": a list of audit report objects (audits of {company} only), each with:
  - "auditor": the auditing firm name (string)
  - "title": the audit report title (string) — should reference {company} or one of its products
  - "date": the audit date in ISO format YYYY-MM-DD if available, or YYYY-MM, or YYYY (string or null)
  - "pdf_url": direct URL to the PDF report if found on the page (string or null)
- "linked_urls": list of URLs found on this page that point to other audit reports, \
audit PDFs, or audit listing pages for {company} that are NOT already covered in the \
"reports" list above (list of strings, may be empty). Include direct PDF links, links \
to auditor blog posts, **GitHub repository URLs that belong to the protocol** (the \
downstream pipeline will explore them via the GitHub API to find audit folders), and \
links to other pages that list audits — but again, only links related to {company}, \
not to other protocols listed on the same page.

Return ONLY the JSON object, no other text."""


_FOLLOWUP_QUERY_PROMPT = """\
You have just searched the web for security audit reports for the {company} smart \
contract protocol. Below are the results from the initial search.

Based on what you see (and what's missing), suggest ONE follow-up search query that \
would find additional audit reports not already covered. Consider:
- Auditor firms mentioned in the results that might have their own blog posts
- The protocol might use a different name or have sub-protocols
- Audit contest platforms (Code4rena, Sherlock, Cantina) if not already found
- GitHub repositories where audit PDFs are often stored
- The protocol's official docs or security page if not already found

Initial results:
{results}

Reply with ONLY the search query string, nothing else. Keep it under 120 characters."""


def generate_followup_query(
    initial_results: list[dict[str, Any]],
    company: str,
    debug: bool = False,
) -> str | None:
    """Use the LLM to generate a targeted follow-up search query.

    Returns the query string, or ``None`` if the LLM call fails.
    """
    if not initial_results:
        return f'"{company}" security audit report findings'

    formatted = "\n".join(f"- {r.get('title', '(untitled)')}: {r.get('url', '')}" for r in initial_results[:15])

    prompt = _FOLLOWUP_QUERY_PROMPT.format(company=company, results=formatted)

    try:
        response = llm.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=128,
            temperature=0.0,
        )
        query = response.strip().strip('"').strip("'").strip()
        # Fix mismatched quotes (LLM sometimes produces 'word" or "word')
        if query.count('"') % 2 != 0:
            query = query.replace('"', "")
        if query and len(query) < 200:
            _debug_log(debug, f"LLM generated follow-up query: {query!r}")
            return query
        _debug_log(debug, f"LLM follow-up query unusable: {response!r}")
    except Exception as exc:
        _debug_log(debug, f"LLM follow-up query generation failed: {exc!r}")

    return None


def classify_search_results(
    results: list[dict[str, Any]],
    company: str,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Stage 1: Classify search results as audit/not-audit.

    Returns list of ``{url, is_audit, auditor, type, confidence}`` dicts for
    results classified as audits with confidence >= 0.5.
    """
    if not results:
        return []

    formatted = "\n".join(
        f"- Title: {r.get('title', '(untitled)')}\n"
        f"  URL: {r.get('url', '')}\n"
        f"  Snippet: {(r.get('content', '') or '')[:300]}"
        for r in results
    )

    prompt = _CLASSIFICATION_PROMPT.format(
        company=company,
        results=formatted,
        auditors=_KNOWN_AUDITORS,
    )

    try:
        response = llm.chat(
            [{"role": "user", "content": prompt}],
            # 20 search results × 7 fields each can run ~3k output tokens once
            # title and date are included; the previous 2k cap silently
            # truncated and made the JSON unparseable.
            max_tokens=4096,
            temperature=0.0,
        )
    except Exception as exc:
        _debug_log(debug, f"Audit classification LLM call failed: {exc!r}")
        return []

    parsed = _parse_json_array(response)
    if parsed is None:
        _debug_log(debug, "Audit classification: could not parse LLM response as JSON array")
        return []

    confirmed: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        if not item.get("is_audit"):
            continue
        confidence = float(item.get("confidence", 0))
        if confidence < 0.5:
            continue
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        confirmed.append(
            {
                "url": url,
                "auditor": item.get("auditor"),
                "title": item.get("title"),
                "date": item.get("date"),
                "type": item.get("type"),
                "confidence": confidence,
            }
        )

    _debug_log(debug, f"Audit classification: {len(confirmed)} confirmed from {len(results)} results")
    return confirmed


# Per-chunk window for chunked extraction. 15k chars ≈ 4k tokens of input —
# leaves room for the prompt + a sizeable JSON response on the same call.
_CHUNK_SIZE = 15000
# Cap how many chunks we send for one page so a 300k-char gitbook doesn't
# burn 20 LLM calls. 3 covers ~45k chars which is enough for nearly every
# real audit listing we've seen.
_MAX_CHUNKS = 3


def _chunked_text(text: str) -> list[str]:
    """Split page text into ``_MAX_CHUNKS`` overlapping windows of
    ``_CHUNK_SIZE`` chars each. Pages that fit in one window stay one chunk.
    """
    if len(text) <= _CHUNK_SIZE:
        return [text]
    chunks: list[str] = []
    overlap = 500  # carry a little context across boundaries
    start = 0
    while start < len(text) and len(chunks) < _MAX_CHUNKS:
        chunks.append(text[start : start + _CHUNK_SIZE])
        start += _CHUNK_SIZE - overlap
    return chunks


def _extract_one_chunk(
    url: str,
    chunk: str,
    company: str,
    debug: bool = False,
) -> dict[str, Any] | None:
    """Run the extraction prompt over a single text chunk and parse the
    JSON response. Returns ``None`` on LLM failure or unparseable output."""
    prompt = _EXTRACTION_PROMPT.format(company=company, url=url, page_text=chunk)
    try:
        response = llm.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=4096,
            temperature=0.0,
        )
    except Exception as exc:
        _debug_log(debug, f"Audit extraction LLM call failed for {url}: {exc!r}")
        return None

    parsed = _parse_json_object(response)
    if parsed is None:
        _debug_log(debug, f"Audit extraction: could not parse LLM response for {url}")
        return None
    return parsed


def extract_report_details(
    url: str,
    page_text: str,
    company: str,
    debug: bool = False,
) -> dict[str, Any] | None:
    """Stage 2: Extract structured audit data and discover links from page content.

    Returns a dict with ``reports`` (list of extracted report dicts) and
    ``linked_urls`` (list of URLs to follow), or ``None`` if extraction fails.

    Long pages are split into multiple windows so audit listings on heavyweight
    docs sites (gitbook, notion, SPAs) aren't truncated past the first ~15k
    characters.
    """
    chunks = _chunked_text(page_text)
    if len(chunks) > 1:
        _debug_log(debug, f"Extraction from {url}: splitting into {len(chunks)} chunks")

    raw_reports: list[Any] = []
    raw_links: list[Any] = []
    parsed_any = False
    for chunk in chunks:
        parsed = _extract_one_chunk(url, chunk, company, debug=debug)
        if parsed is None:
            continue
        parsed_any = True
        chunk_reports = parsed.get("reports")
        if isinstance(chunk_reports, list):
            raw_reports.extend(chunk_reports)
        elif parsed.get("auditor") and parsed.get("title"):
            # Backwards compat: a flat-field response is one report
            raw_reports.append(parsed)
        chunk_links = parsed.get("linked_urls")
        if isinstance(chunk_links, list):
            raw_links.extend(chunk_links)

    if not parsed_any:
        return None

    reports: list[dict[str, Any]] = []
    for raw in raw_reports:
        if not isinstance(raw, dict):
            continue
        auditor = str(raw.get("auditor") or "").strip()
        title = str(raw.get("title") or "").strip()
        if not auditor or not title:
            continue

        # Resolve pdf_url — may be relative
        pdf_url_raw = str(raw["pdf_url"]).strip() if raw.get("pdf_url") else None
        if pdf_url_raw and not pdf_url_raw.startswith(("http://", "https://")):
            from urllib.parse import urljoin

            pdf_url_raw = urljoin(url, pdf_url_raw)

        reports.append(
            {
                "auditor": auditor,
                "title": title,
                "date": str(raw["date"]).strip() if raw.get("date") else None,
                "pdf_url": pdf_url_raw,
            }
        )

    # Normalize linked URLs — resolve relative paths against the source page URL
    from urllib.parse import urljoin

    linked_urls: list[str] = []
    seen: set[str] = set()
    for link in raw_links:
        clean = str(link).strip() if link else ""
        if not clean:
            continue
        # Resolve relative URLs (e.g. "/audits" → "https://example.com/audits")
        if not clean.startswith(("http://", "https://")):
            clean = urljoin(url, clean)
        if clean.startswith(("http://", "https://")) and clean not in seen:
            seen.add(clean)
            linked_urls.append(clean)

    # When a page is split into multiple overlapping chunks the same audit can
    # be extracted from each chunk it falls inside. Dedup here so the caller
    # doesn't have to deal with within-page duplicates.
    if len(chunks) > 1:
        seen_keys: set[tuple[str, str, str]] = set()
        deduped_reports: list[dict[str, Any]] = []
        for r in reports:
            key = (
                (r.get("auditor") or "").strip().lower(),
                (r.get("title") or "").strip().lower(),
                (r.get("date") or "").strip(),
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_reports.append(r)
        reports = deduped_reports

    _debug_log(
        debug,
        f"Extraction from {url}: {len(reports)} report(s), {len(linked_urls)} linked URL(s)",
    )

    return {
        "reports": reports,
        "linked_urls": linked_urls,
    }
