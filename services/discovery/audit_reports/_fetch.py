"""HTTP page fetching + URL routing.

``_fetch_and_extract`` is the main dispatcher: GitHub URLs route to the
GitHub API for structured data; everything else goes through an HTML fetch
+ LLM extraction.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import requests as _requests

from utils.logging import record_degraded

from ..audit_reports_llm import extract_report_details
from ..inventory_domain import TAG_RE, _debug_log
from ._github import (
    _discover_repo_audit_folders,
    _expand_blob_to_directory,
    _fetch_github_org_as_reports,
    _fetch_github_raw,
    _fetch_github_tree_as_reports,
    _parse_github_url,
)
from ._urls import _is_pdf_url

logger = logging.getLogger(__name__)

_MAX_DOWNLOAD_BYTES = 512_000
_BINARY_CONTENT_TYPES = frozenset({"application/pdf", "application/octet-stream", "image/"})

_ANCHOR_RE = re.compile(r'(?is)<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>')
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style|noscript|svg)\b.*?</\1>")


def _page_to_text(page_html: str) -> str:
    """Convert HTML to LLM-friendly text, preserving anchor URLs.

    Anchor tags become ``link_text (href)`` so the LLM sees where links
    point — critical for GitHub directory pages where the PDF links ARE
    the content.
    """
    cleaned = _SCRIPT_STYLE_RE.sub(" ", page_html)
    cleaned = _ANCHOR_RE.sub(
        lambda m: f"{TAG_RE.sub(' ', m.group(2)).strip()} ({m.group(1)}) ",
        cleaned,
    )
    cleaned = TAG_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _fetch_html_page(url: str, debug: bool = False) -> str | None:
    """Fetch a page, reject binary content, cap at ``_MAX_DOWNLOAD_BYTES``."""
    try:
        resp = _requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "PSAT/0.1"},
            stream=True,
        )
        if resp.status_code != 200:
            _debug_log(debug, f"Fetch {url}: HTTP {resp.status_code}")
            return None

        content_type = (resp.headers.get("content-type") or "").lower()
        if any(ct in content_type for ct in _BINARY_CONTENT_TYPES):
            _debug_log(debug, f"Skipping binary content ({content_type}): {url}")
            resp.close()
            return None

        chunks: list[bytes] = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=64_000):
            chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded >= _MAX_DOWNLOAD_BYTES:
                _debug_log(debug, f"Truncated download at {downloaded} bytes: {url}")
                break
        resp.close()

        body = b"".join(chunks)
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = body.decode("latin-1", errors="replace")

        _debug_log(debug, f"Fetched {url} ({len(text)} chars)")
        return text

    except _requests.RequestException as exc:
        record_degraded(
            phase="audit_report_html_fetch",
            exc=exc,
            context={"url": url},
        )
        logger.warning(
            "Audit page fetch failed for %s; page contributes no reports",
            url,
            extra={"exc_type": type(exc).__name__, "url": url},
        )
        _debug_log(debug, f"Fetch {url} failed: {exc!r}")
        return None


def _fetch_and_extract(
    url: str,
    company: str,
    all_results: list[dict[str, Any]],
    debug: bool = False,
    *,
    enumerated_orgs: set[str] | None = None,
) -> dict[str, Any] | None:
    """Fetch a URL and run LLM extraction.

    GitHub tree/blob/repo/org URLs route to the GitHub API for clean
    structured data; everything else goes through an HTML fetch. When
    ``enumerated_orgs`` is provided, any org that gets fully enumerated
    here is recorded so the orchestrator can skip subsequent same-org
    URLs.
    """
    github = _parse_github_url(url)

    if github:
        if github["kind"] == "tree":
            return _fetch_github_tree_as_reports(
                github["owner"],
                github["repo"],
                github["path"],
                ref=github["ref"],
                company=company,
                url=url,
                debug=debug,
            )
        if github["kind"] == "org":
            extracted = _fetch_github_org_as_reports(
                github["owner"],
                company,
                url,
                debug=debug,
            )
            if extracted is not None and enumerated_orgs is not None:
                # Only record coverage when enumeration actually ran — an
                # empty list from a rate-limited call shouldn't suppress
                # per-URL fallback later.
                enumerated_orgs.add(github["owner"].lower())
            return extracted
        if github["kind"] == "repo":
            folders = _discover_repo_audit_folders(github["owner"], github["repo"], debug=debug)
            if not folders:
                _debug_log(debug, f"No audit folders found in repo {github['owner']}/{github['repo']}")
                return {"reports": [], "linked_urls": []}
            merged_reports: list[dict[str, Any]] = []
            merged_linked: list[str] = []
            for folder in folders:
                tree_url = (
                    f"https://github.com/{github['owner']}/{github['repo']}/tree/{folder['ref']}/{folder['path']}"
                )
                sub = _fetch_github_tree_as_reports(
                    github["owner"],
                    github["repo"],
                    folder["path"],
                    ref=folder["ref"],
                    company=company,
                    url=tree_url,
                    debug=debug,
                )
                if not sub:
                    continue
                merged_reports.extend(sub.get("reports", []))
                merged_linked.extend(sub.get("linked_urls", []))
            return {"reports": merged_reports, "linked_urls": merged_linked}
        # blob: PDF blobs expand to their parent directory; non-PDF blobs
        # fetch raw and run extraction.
        if _is_pdf_url(github["path"]):
            return _expand_blob_to_directory(
                github["owner"],
                github["repo"],
                github["ref"],
                github["path"],
                company,
                debug=debug,
            )
        page_text = _fetch_github_raw(
            github["owner"],
            github["repo"],
            github["ref"],
            github["path"],
            debug=debug,
        )
        if not page_text:
            return None
        return extract_report_details(url, page_text, company, debug=debug)

    # Non-GitHub: HTML fetch → text → LLM extract
    page_html = _fetch_html_page(url, debug=debug)
    if not page_html:
        return None
    page_text = _page_to_text(page_html)
    if not page_text:
        _debug_log(debug, f"Empty page after stripping HTML: {url}")
        return None
    return extract_report_details(url, page_text, company, debug=debug)
