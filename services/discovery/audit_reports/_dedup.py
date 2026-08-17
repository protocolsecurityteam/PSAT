"""Cross-source dedup + LLM validate-and-cluster.

Three passes in total:

    1. ``_collapse_by_filename`` — groups by normalized filename stem +
       year-month; keeps the richest entry per group.
    2. ``_llm_validate_and_cluster`` — single LLM call that validates
       entries, clusters mirrors, fills missing auditors, and fixes
       garbled titles. Replaces the heuristic pass when the LLM
       round-trip succeeds.
    3. ``_collapse_same_audit_mirrors`` — heuristic fallback when the
       LLM call fails. Same-date Unknown-auditor entries on unique
       hosts get dropped as cross-host mirrors; named-auditor +
       title-token matches collapse.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import unquote, urlparse

from utils import llm

from ..inventory_domain import _debug_log

logger = logging.getLogger(__name__)

_GENERIC_TITLE_TOKENS = frozenset(
    {
        "audit",
        "report",
        "review",
        "security",
        "smart",
        "contract",
        "assessment",
    }
)


def _title_tokens(title: str) -> set[str]:
    """Lowercase word-tokens with generic audit words removed.

    Single-character tokens stay so consecutive reports like ``V3.Prelude - 1``
    and ``V3.Prelude - 2`` remain distinguishable.
    """
    if not title:
        return set()
    raw = re.findall(r"[A-Za-z0-9.]+", title.lower())
    return {w for w in raw if w and w not in _GENERIC_TITLE_TOKENS}


def _richness_score(report: dict[str, Any]) -> int:
    return sum(1 for key in ("pdf_url", "date") if report.get(key))


def _collapse_by_filename(
    reports: list[dict[str, Any]],
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Collapse entries that share the same filename + year-month.

    Key: ``(normalized_filename_stem, YYYY-MM)`` — stem is URL-decoded,
    extension-stripped, lowercase, non-alphanumerics removed. Entries
    with no filename (org-root URLs, opaque UUIDs) never group. Within
    a group, keep the richest by ``(has_pdf, has_date, has_named_auditor,
    title_length)``; ties resolve to the first occurrence.
    """
    if len(reports) <= 1:
        return reports

    def _stem(url: str) -> str:
        if not url:
            return ""
        decoded = unquote(url.rsplit("/", 1)[-1])
        if not decoded or decoded.endswith("/"):
            return ""
        stem = decoded.rsplit(".", 1)[0] if "." in decoded else decoded
        return re.sub(r"[^a-z0-9]", "", stem.lower())

    def _year_month(date: Any) -> str:
        if not date:
            return ""
        m = re.match(r"(\d{4})-(\d{2})", str(date))
        return f"{m.group(1)}-{m.group(2)}" if m else ""

    def _richness(idx: int) -> tuple[int, int, int, int]:
        r = reports[idx]
        has_pdf = 1 if r.get("pdf_url") else 0
        has_date = 1 if r.get("date") else 0
        auditor = (r.get("auditor") or "").strip().lower()
        has_named = 0 if auditor in ("", "unknown") else 1
        title_len = len(r.get("title") or "")
        return (has_pdf, has_date, has_named, title_len)

    groups: dict[tuple[str, str], list[int]] = {}
    for i, r in enumerate(reports):
        url = r.get("pdf_url") or r.get("url") or ""
        stem = _stem(url)
        if not stem:
            continue
        groups.setdefault((stem, _year_month(r.get("date"))), []).append(i)

    drop: set[int] = set()
    for indices in groups.values():
        if len(indices) < 2:
            continue
        best = max(indices, key=lambda i: (_richness(i), -i))
        for i in indices:
            if i != best:
                drop.add(i)

    if drop:
        _debug_log(debug, f"Cross-source filename dedup: dropped {len(drop)} of {len(reports)} entry(ies)")
    return [r for i, r in enumerate(reports) if i not in drop]


# Prompt factored out so the function body stays scannable. Still inlined
# in one place — the validate+cluster call — so a stray edit can't drift.
_VALIDATE_CLUSTER_PROMPT = """\
You are reviewing {count} candidate audit reports discovered for the \
{company} smart-contract protocol.

For each entry, decide:

1. VALIDITY — is this a third-party smart-contract security audit OF \
{company} itself? Count as VALID only when the audit's scope is \
{company}'s own contracts (or a product/version shipped by {company}).
   Mark INVALID for:
   - docs landing pages, bug-bounty program pages, marketing pages
   - generic security blog posts
   - audits of an unrelated protocol that surfaced by accident
   - framework / base-layer audits whose scope is the framework itself \
(e.g. an EigenLayer audit isn't an audit of an LRT that happens to use \
EigenLayer; a BoringVault framework audit isn't an audit of a vault \
product that happens to deploy a BoringVault) — those belong to the \
framework's own protocol record, not here
   - DNS/infrastructure scans, frontend/UI-only audits — only \
smart-contract-level audits count
   When in doubt, keep as valid.

2. CLUSTERING — which entries are the SAME audit appearing under \
different URLs/repos/titles? Use the same integer ``cluster`` for every \
entry that's a mirror. Distinct audits get distinct clusters. Strong \
mirror signals: same auditor + same date (±2 weeks) + overlapping scope \
words; cross-host duplicates (gitbook PDF + github PDF); a Certora-of-X \
fork repo carrying the same files as the canonical X repo; a \
Cantina/Sherlock competition page that resolves to the same scope as a \
Spearbit/OZ review on the protocol's docs.
   Distinct audits to KEEP separate: same auditor on the same day for \
clearly different products (``v2.49`` vs ``Instant Withdrawal``); \
sequential bundles (``Bundle_9`` vs ``Bundle_11``); per-version \
reports; initial audit vs retest.

3. AUDITOR FIX — when ``auditor=Unknown`` but the auditor is obvious \
from neighbours, supply ``auditor`` in the response. Strong signals:
   - filename mentions an audit firm directly
   - folder is a single auditor's portfolio (``trailofbits/publications/...``)
   - sibling entries on the same date and same scope have a named auditor
   Don't guess randomly — fill only when you have at least one signal.

4. TITLE FIX — fix titles that are garbled page text, generic \
placeholders (``audits``, ``Final Report``), or just the protocol's name.
   IMPORTANT: when ``file`` is a meaningful audit filename (e.g. \
``2025.10.20 - WeETH withdrawal adapter.pdf``), DO NOT rewrite the title \
to a generic ``Auditor + Protocol`` form — the filename already contains \
scope detail. Only fix titles when the filename is opaque (UUID, \
drive.google.com, or absent).

Reply with ONLY a JSON object of this shape:
{{"entries": [
  {{"i": 0, "valid": true, "cluster": 1, "auditor": "Foo", "title": "Foo X Audit"}},
  {{"i": 1, "valid": false, "reason": "docs landing page"}},
  ...
]}}

Each entry MUST include "i" (original index) and "valid". Valid entries \
MUST include "cluster" (integer; reuse to mark mirrors). "auditor" and \
"title" overrides are optional — omit when the existing value is correct.

Entries:
{formatted}
"""


def _llm_validate_and_cluster(
    reports: list[dict[str, Any]],
    company: str,
    debug: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, int]] | None:
    """One-shot LLM pass to validate + cluster candidates.

    Returns ``(cleaned, stats)`` or ``None`` on LLM failure. The caller
    falls back to ``_collapse_same_audit_mirrors`` on ``None`` so a
    transient LLM failure never silently widens the output.
    """
    from ..audit_reports_llm import _parse_json_object

    if not reports:
        return reports, {
            "dropped_invalid": 0,
            "collapsed_mirrors": 0,
            "auditor_filled": 0,
            "title_fixed": 0,
        }

    def _filename_of(url: str) -> str:
        if not url:
            return ""
        return unquote(url.rsplit("/", 1)[-1])[:80]

    formatted = "\n".join(
        f"{i}: auditor={(r.get('auditor') or 'Unknown')!r} | "
        f"title={((r.get('title') or '')[:100])!r} | "
        f"date={r.get('date') or 'None'} | "
        f"file={_filename_of(r.get('pdf_url') or r.get('url') or '')!r} | "
        f"url={r.get('url') or ''}"
        for i, r in enumerate(reports)
    )

    prompt = _VALIDATE_CLUSTER_PROMPT.format(
        count=len(reports),
        company=company,
        formatted=formatted,
    )

    try:
        response = llm.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=16384,
            temperature=0.0,
        )
    except Exception as exc:
        # Returning None drops the run back to the heuristic mirror collapse —
        # a quieter, worse dedup that otherwise leaves no trace above DEBUG.
        logger.warning(
            "Validate+cluster LLM call failed for %s; falling back to heuristic dedup over %d report(s)",
            company,
            len(reports),
            extra={"exc_type": type(exc).__name__, "company": company, "reports": len(reports)},
        )
        _debug_log(debug, f"Validate+cluster LLM call failed: {exc!r}")
        return None

    parsed = _parse_json_object(response)
    if not parsed or not isinstance(parsed.get("entries"), list):
        _debug_log(debug, "Validate+cluster: unparseable LLM response")
        return None

    val_by_idx: dict[int, dict[str, Any]] = {}
    for item in parsed["entries"]:
        if not isinstance(item, dict):
            continue
        idx = item.get("i")
        if not isinstance(idx, int) or not (0 <= idx < len(reports)):
            continue
        val_by_idx[idx] = item

    if not val_by_idx:
        _debug_log(debug, "Validate+cluster: LLM returned no usable entries")
        return None

    # Partial responses must preserve untouched entries — drop only what
    # the LLM explicitly marked invalid.
    clusters: dict[int, list[int]] = {}
    standalone: list[int] = []
    dropped = 0
    for i in range(len(reports)):
        v = val_by_idx.get(i)
        if v is None:
            standalone.append(i)
            continue
        if not v.get("valid", True):
            dropped += 1
            continue
        cluster = v.get("cluster")
        if isinstance(cluster, int):
            clusters.setdefault(cluster, []).append(i)
        else:
            standalone.append(i)

    def richness(idx: int) -> int:
        return _richness_score(reports[idx])

    out: list[dict[str, Any]] = []
    auditor_filled = 0
    title_fixed = 0
    collapsed = 0

    for indices in clusters.values():
        if len(indices) > 1:
            collapsed += len(indices) - 1
        canonical = max(indices, key=lambda i: (richness(i), -i))
        r = dict(reports[canonical])
        v = val_by_idx[canonical]
        new_auditor = (v.get("auditor") or "").strip()
        if new_auditor and new_auditor.lower() != "unknown":
            old = (r.get("auditor") or "").strip().lower()
            if old in ("", "unknown") or old != new_auditor.lower():
                if old in ("", "unknown"):
                    auditor_filled += 1
                r["auditor"] = new_auditor
        new_title = (v.get("title") or "").strip()
        if new_title and new_title != (r.get("title") or "").strip():
            title_fixed += 1
            r["title"] = new_title
        out.append(r)

    for i in standalone:
        out.append(dict(reports[i]))

    stats = {
        "dropped_invalid": dropped,
        "collapsed_mirrors": collapsed,
        "auditor_filled": auditor_filled,
        "title_fixed": title_fixed,
    }
    _debug_log(
        debug,
        f"Validate+cluster: {len(reports)} → {len(out)} "
        f"(dropped={dropped}, collapsed={collapsed}, "
        f"auditor_filled={auditor_filled}, title_fixed={title_fixed})",
    )
    return out, stats


def _collapse_same_audit_mirrors(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Heuristic cross-host mirror dedup.

    Three passes, each designed not to merge genuinely distinct audits:

        1. Drop same-date Unknown-auditor entries on hosts no named
           same-date entry uses (cross-host mirror signature). Same-host
           Unknowns stay — they're sibling files whose auditor the LLM
           missed.
        2. For each (auditor, date) group spread across >1 host, keep
           the richest entry. All-on-one-host groups defer to pass 3,
           which has better title-token logic.
        3. Group by (auditor, date, non-generic title tokens); keep the
           richest per group. Distinct same-day audits by the same auditor
           still pass through because their title tokens differ.
    """
    # Pass 1: track named-auditor hosts per date.
    named_dates_hosts: dict[str, set[str]] = {}
    for r in reports:
        auditor = (r.get("auditor") or "").strip().lower()
        date = (r.get("date") or "").strip()
        if date and auditor and auditor != "unknown":
            host = urlparse(r.get("url") or "").netloc.lower()
            named_dates_hosts.setdefault(date, set()).add(host)

    pass1: list[dict[str, Any]] = []
    for r in reports:
        auditor = (r.get("auditor") or "").strip().lower()
        date = (r.get("date") or "").strip()
        if auditor in ("", "unknown") and date in named_dates_hosts:
            host = urlparse(r.get("url") or "").netloc.lower()
            if host and host not in named_dates_hosts[date]:
                continue
        pass1.append(r)

    # Pass 2: cross-host named-auditor mirrors.
    drop_cross_host: set[int] = set()
    cross_host_groups: dict[tuple[str, str], list[int]] = {}
    for i, r in enumerate(pass1):
        auditor = (r.get("auditor") or "").strip().lower()
        if not auditor or auditor == "unknown":
            continue
        date = (r.get("date") or "").strip()
        if not date:
            continue
        cross_host_groups.setdefault((auditor, date), []).append(i)

    for indices in cross_host_groups.values():
        if len(indices) < 2:
            continue
        hosts = {urlparse(pass1[i].get("url") or "").netloc.lower() for i in indices}
        if len(hosts) < 2:
            continue
        best = max(indices, key=lambda i: (_richness_score(pass1[i]), -i))
        for i in indices:
            if i != best:
                drop_cross_host.add(i)

    pass1 = [r for i, r in enumerate(pass1) if i not in drop_cross_host]

    # Pass 3: (auditor, date, title-tokens) collapse.
    drop: set[int] = set()
    groups: dict[tuple[str, str, frozenset[str]], list[int]] = {}
    for i, r in enumerate(pass1):
        auditor = (r.get("auditor") or "").strip().lower()
        if not auditor or auditor == "unknown":
            continue
        tokens = frozenset(_title_tokens(r.get("title") or ""))
        if not tokens:
            continue
        date = (r.get("date") or "").strip()
        groups.setdefault((auditor, date, tokens), []).append(i)

    for indices in groups.values():
        if len(indices) < 2:
            continue
        best = max(indices, key=lambda i: (_richness_score(pass1[i]), -i))
        for i in indices:
            if i != best:
                drop.add(i)

    return [r for i, r in enumerate(pass1) if i not in drop]
