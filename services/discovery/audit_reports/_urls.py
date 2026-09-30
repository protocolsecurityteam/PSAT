"""Dependency-free URL/filename utilities, a leaf module to avoid import cycles."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse


def _normalize_url(url: str) -> str:
    """Canonical form for dedup: lowercase scheme and host, no trailing slash."""
    try:
        parsed = urlparse(url)
        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=parsed.path.rstrip("/") or "/",
            fragment="",
        )
        return normalized.geturl()
    except Exception:
        return url.strip().rstrip("/")


def _dedupe_results_by_url(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for r in results:
        url = str(r.get("url", "")).strip()
        if not url:
            continue
        key = _normalize_url(url)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _is_pdf_url(url: str) -> bool:
    try:
        return urlparse(url).path.lower().endswith(".pdf")
    except Exception:
        return False


def _company_name_variants(company: str) -> list[str]:
    """Lowercase company-name variants (``EtherFi`` / ``ether.fi`` / ``ether_fi``) for filename matching."""
    base = company.strip().lower()
    if not base:
        return []
    variants = {base}
    stripped = re.sub(r"[^a-z0-9]", "", base)
    if stripped and stripped != base:
        variants.add(stripped)
    return [v for v in variants if v]


def _filename_mentions_company(name: str, company_variants: list[str]) -> bool:
    if not company_variants:
        return True
    haystack = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(v in haystack for v in company_variants)


def _extract_date_from_filename(name: str) -> str | None:
    """Best-effort ISO date from a filename (YYYY-MM-DD, YYYY_MM_DD, YYYY.MM.DD, YYYYMMDD, YYYY-MM, YYYY),
    calendar-validated within 2015-2099.
    """
    decoded = unquote(name or "")
    if not decoded:
        return None

    for pattern in (
        r"(?<!\d)(\d{4})[-_.](\d{2})[-_.](\d{2})(?!\d)",
        r"(?<!\d)(\d{4})(\d{2})(\d{2})(?!\d)",
    ):
        m = re.search(pattern, decoded)
        if m:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 2015 <= y <= 2099 and 1 <= mo <= 12 and 1 <= d <= 31:
                return f"{y:04d}-{mo:02d}-{d:02d}"

    m = re.search(r"(?<!\d)(\d{4})[-_.](\d{2})(?!\d)", decoded)
    if m:
        y, mo = int(m.group(1)), int(m.group(2))
        if 2015 <= y <= 2099 and 1 <= mo <= 12:
            return f"{y:04d}-{mo:02d}"

    m = re.search(r"(?<!\d)(20\d{2})(?!\d)", decoded)
    if m:
        return m.group(1)

    return None


def _augment_filename_metadata(name: str, meta: dict[str, Any] | None) -> dict[str, Any]:
    """Fill ``date`` when the LLM left it blank. Auditor is left to the LLM, which has sibling context."""
    out = dict(meta or {})
    date_val = out.get("date")
    date_str = str(date_val).strip() if date_val else ""
    if not date_str:
        deterministic_date = _extract_date_from_filename(name)
        if deterministic_date:
            out["date"] = deterministic_date
    return out
