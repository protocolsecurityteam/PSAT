"""Orchestrator for protocol audit report discovery.

Pipeline:

    Stage 0 — Solodit: seed canonical entries from Cyfrin's aggregator.
    Stage 1 — search backend broad query + LLM follow-up query + LLM classify.
    Stage 2 — fetch confirmed pages (GitHub API or HTML) + LLM extract.
    Stage 3 — follow links discovered in Stage 2 (one level).
    Stage 3.5 — curated auditor-portfolio crawl.
    Dedup — URL key, then filename, then LLM validate-and-cluster
    (heuristic mirror collapse fallback).

``search_audit_reports`` is the entry point. ``merge_audit_reports`` is
append-only across successive discovery runs: reports are never removed.

Submodules:
    _urls          — URL/filename utilities, no external deps
    _github        — all GitHub API calls + org/repo/tree enumeration
    _fetch         — HTML page fetch + ``_fetch_and_extract`` dispatcher
    _dedup         — filename collapse + LLM validate-and-cluster + mirror
                     heuristic fallback
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import requests as _requests

from .. import solodit as _solodit
from ..audit_reports_llm import classify_search_results, generate_followup_query
from ..inventory_domain import SearchFn, _debug_log
from ._dedup import (
    _collapse_by_filename,
    _collapse_same_audit_mirrors,
    _llm_validate_and_cluster,
    _richness_score,
    _title_tokens,
)
from ._fetch import _fetch_and_extract, _fetch_html_page, _page_to_text
from ._github import (
    _AUDIT_FOLDER_CANDIDATES,
    _AUDIT_FOLDER_LAST_SEGMENTS,
    _BRANCH_SHA_CACHE,
    _DEPENDENCY_LIBRARY_PATTERNS,
    _fetch_github_org_as_reports,
    _fetch_github_raw,
    _fetch_github_tree_as_reports,
    _github_api_headers,
    _is_dependency_library_repo,
    _is_vendored_dependency_path,
    _list_org_repos,
    _list_repo_root_for_company,
    _llm_extract_filename_metadata,
    _parse_github_url,
    _resolve_branch_commit,
    github_blob_to_raw,
)
from ._urls import (
    _augment_filename_metadata,
    _company_name_variants,
    _dedupe_results_by_url,
    _extract_date_from_filename,
    _filename_mentions_company,
    _is_pdf_url,
    _normalize_url,
)

# --- Stage budget caps ----------------------------------------------------

_MAX_STAGE2_PAGES = 5
_MAX_LINK_FOLLOWS = 5
_MAX_TOTAL_EXTRACTIONS = 8


# --- Auto-hop policy ------------------------------------------------------


def _should_auto_hop_org(url: str, company: str, auto_hopped: set[str]) -> bool:
    """Return True when the caller should fan out from ``url`` to the org.

    Three conditions: (1) URL parses as GitHub org/tree/blob/repo, (2) the
    owner substring-matches the company name (excludes third-party vendor
    orgs holding hundreds of unrelated repos), and (3) we haven't already
    hopped for this owner this run.
    """
    github = _parse_github_url(url)
    if not github:
        return False
    if github["kind"] not in ("tree", "blob", "repo", "org"):
        return False
    owner = github["owner"].lower()
    if owner in auto_hopped:
        return False
    variants = _company_name_variants(company)
    if not variants:
        return False
    owner_norm = re.sub(r"[^a-z0-9]", "", owner)
    return any(v in owner_norm for v in variants)


def _maybe_auto_hop_to_org(
    url: str,
    company: str,
    auto_hopped_orgs: set[str],
    confidence: float,
    now_iso: str,
    reports: list[dict[str, Any]],
    debug: bool = False,
) -> None:
    """Enumerate the whole org when ``url`` triggers an auto-hop.

    Mutates ``auto_hopped_orgs`` and ``reports`` in place. A no-op when
    the URL isn't eligible. ``auto_hopped_orgs`` is only updated when
    enumeration actually completed — a rate-limited call leaves the set
    untouched so per-URL fallback can still run.
    """
    if not _should_auto_hop_org(url, company, auto_hopped_orgs):
        return
    github = _parse_github_url(url)
    if github is None:
        return
    owner = github["owner"]
    org_url = f"https://github.com/{owner}"
    _debug_log(debug, f"Auto-hop to org {owner} (triggered by {url})")
    extracted_org = _fetch_github_org_as_reports(owner, company, org_url, debug=debug)
    if extracted_org is None:
        return
    auto_hopped_orgs.add(owner.lower())
    for report in extracted_org.get("reports", []):
        reports.append(_build_report_entry(report, org_url, confidence, now_iso))


# --- Report entry assembly ------------------------------------------------


def _build_report_entry(
    report: dict[str, Any],
    source_url: str,
    confidence: float,
    now_iso: str,
) -> dict[str, Any]:
    """Build a final report dict from extracted LLM data.

    ``source_commit`` / ``source_repo`` / ``source_path`` (when captured
    upstream) record exactly where the PDF lived at discovery time — a
    phase-2 linker uses them to verify the artifact hasn't moved.
    """
    pdf_url = github_blob_to_raw(str(report.get("pdf_url") or "").strip()) or None
    report_url = github_blob_to_raw(str(report.get("report_url") or "").strip()) or None
    entry = {
        "url": pdf_url or report_url or source_url,
        "pdf_url": pdf_url,
        "auditor": report["auditor"],
        "title": report["title"],
        "date": report.get("date"),
        "source_url": source_url,
        "confidence": round(confidence, 4),
        "discovered_at": now_iso,
    }
    for key in ("source_commit", "source_repo", "source_path"):
        val = report.get(key)
        if val:
            entry[key] = val
    return entry


def _build_fallback_entry(
    url: str,
    classification: dict[str, Any],
    company: str,
    all_results: list[dict[str, Any]],
    confidence: float,
    now_iso: str,
    pdf_url: str | None = None,
) -> dict[str, Any]:
    """Build a report entry from Stage 1 metadata when extraction fails."""
    search_match = next((r for r in all_results if r.get("url") == url), None)
    search_title = (search_match.get("title") or "").strip() if search_match else ""
    title = str(classification.get("title") or "").strip() or search_title or f"{company} Audit Report"
    normalized_url = github_blob_to_raw(url)
    normalized_pdf_url = github_blob_to_raw(pdf_url) if pdf_url else None
    return {
        "url": normalized_url,
        "pdf_url": normalized_pdf_url or (normalized_url if _is_pdf_url(normalized_url) else None),
        "auditor": str(classification.get("auditor") or "").strip() or "Unknown",
        "title": title,
        "date": classification.get("date") or None,
        "source_url": url,
        "confidence": round(confidence, 4),
        "discovered_at": now_iso,
    }


# --- Curated auditor-portfolio allowlist (Stage 3.5) ----------------------

# Every run crawls each portfolio and filters by company-name filename
# match. Unrelated files drop silently; cost is one recursive-tree call.
# Framework audits (EigenLayer-of-LRT etc.) belong to the framework's
# own protocol record and get joined separately.
_AUDITOR_PORTFOLIO_REPOS: tuple[tuple[str, str], ...] = (
    ("Zellic", "publications"),
    ("spearbit", "portfolio"),
    ("runtimeverification", "publications"),
    ("trailofbits", "publications"),
    ("Cyfrin", "cyfrin-audit-reports"),
    ("sherlock-protocol", "sherlock-reports"),
    ("ChainSecurity-Public", "audits"),
)


# --- Main orchestrator ----------------------------------------------------


def search_audit_reports(
    company: str,
    *,
    search_fn: SearchFn,
    seed_results: list[dict[str, Any]] | None = None,
    official_domain: str | None = None,
    max_queries: int = 2,
    debug: bool = False,
) -> dict[str, Any]:
    """Search the web for third-party audit reports for a protocol.

    Returns ``{reports, queries_used, errors, notes}``.
    """
    clean_company = company.strip()
    if not clean_company:
        raise ValueError("company must not be empty")

    errors: list[dict[str, Any]] = []
    notes: list[str] = []
    queries_used = [0]

    _debug_log(debug, f"Starting audit report discovery for: {clean_company}")

    now_iso = datetime.now(timezone.utc).isoformat()
    reports: list[dict[str, Any]] = []
    processed_urls: set[str] = set()
    auto_hopped_orgs: set[str] = set()
    extraction_count = 0

    # --- Stage 0: Solodit ---
    # Best-effort: outage / rate-limit → empty list, pipeline continues.
    solodit_results = _solodit.search(clean_company, debug=debug)
    for entry in solodit_results:
        url = entry.get("url", "")
        if not url:
            continue
        url_key = _normalize_url(url)
        if url_key in processed_urls:
            continue
        processed_urls.add(url_key)
        reports.append(
            {
                "url": url,
                "pdf_url": entry.get("pdf_url"),
                "auditor": entry.get("auditor") or "Unknown",
                "title": entry.get("title") or f"{clean_company} audit",
                "date": entry.get("date"),
                "source_url": entry.get("source_url") or "https://solodit.cyfrin.io/",
                "confidence": float(entry.get("confidence") or 0.95),
                "discovered_at": now_iso,
            }
        )
    if solodit_results:
        notes.append(f"Solodit: {len(solodit_results)} audit(s)")
        _debug_log(debug, f"Solodit seeded {len(solodit_results)} audit(s)")

    # --- Stage 1a: broad search + LLM follow-up query ---

    broad_results = search_fn(
        f'"{clean_company}" smart contract security audit report',
        max_results=10,
        queries_used=queries_used,
        max_queries=max_queries,
        errors=errors,
        debug=debug,
    )
    followup_query = generate_followup_query(broad_results, clean_company, debug=debug)
    followup_results: list[dict[str, Any]] = []
    if followup_query:
        followup_results = search_fn(
            followup_query,
            max_results=10,
            queries_used=queries_used,
            max_queries=max_queries,
            errors=errors,
            debug=debug,
        )

    all_results = _dedupe_results_by_url(broad_results + followup_results)
    notes.append(f"Search returned {len(all_results)} unique result(s)")
    if not all_results:
        notes.append("No search results found")

    # --- Stage 1b: LLM classification ---
    # Still runs on empty input (returns []); Solodit-seeded reports then
    # flow straight into validate+cluster at the end.
    classified = classify_search_results(all_results, clean_company, debug=debug)
    llm_classified_count = len(classified)
    seed_count = 0
    if seed_results:
        seen_seed_urls = {str(item.get("url") or "").strip() for item in classified}
        for seed in seed_results:
            url = str(seed.get("url") or "").strip()
            if not url or url in seen_seed_urls:
                continue
            classified.append(
                {
                    "url": url,
                    "title": seed.get("title"),
                    "auditor": None,
                    "date": None,
                    "type": None,
                    "confidence": 1.0,
                }
            )
            seen_seed_urls.add(url)
            seed_count += 1
    notes.append(f"LLM classified {llm_classified_count} result(s) as audit reports")
    if seed_count:
        notes.append(f"Deep Research audit seeds: {seed_count}")
    if not classified and all_results:
        notes.append("No results classified as audit reports")

    # Listing pages first (each expands into many reports); then confidence
    # descending. Without this an aggregator URL gets pushed below individual
    # PDF hits and misses the Stage-2 cap.
    classified.sort(key=lambda x: (x.get("type") != "listing", -x.get("confidence", 0)))

    discovered_links: list[dict[str, Any]] = []

    # --- Stage 2: fetch + LLM extract confirmed pages ---

    for item in classified[:_MAX_STAGE2_PAGES]:
        if extraction_count >= _MAX_TOTAL_EXTRACTIONS:
            break

        url = item["url"]
        url_key = _normalize_url(url)
        if url_key in processed_urls:
            continue
        processed_urls.add(url_key)

        stage1_confidence = item.get("confidence", 0.5)

        _maybe_auto_hop_to_org(
            url,
            clean_company,
            auto_hopped_orgs,
            stage1_confidence,
            now_iso,
            reports,
            debug=debug,
        )

        github = _parse_github_url(url)
        if github and github["owner"].lower() in auto_hopped_orgs:
            _debug_log(debug, f"Skipping {url} — org {github['owner']} already enumerated")
            continue

        # GitHub blob PDFs still route through _fetch_and_extract so the
        # parent directory gets expanded for auditor-portfolio repos.
        is_github_blob_pdf = github is not None and github["kind"] == "blob" and _is_pdf_url(github["path"])

        if _is_pdf_url(url) and not is_github_blob_pdf:
            reports.append(
                _build_fallback_entry(
                    url,
                    item,
                    clean_company,
                    all_results,
                    confidence=stage1_confidence,
                    now_iso=now_iso,
                    pdf_url=url,
                )
            )
            continue

        extracted = _fetch_and_extract(
            url,
            clean_company,
            all_results,
            debug=debug,
            enumerated_orgs=auto_hopped_orgs,
        )
        extraction_count += 1

        if extracted is None:
            reports.append(
                _build_fallback_entry(
                    url,
                    item,
                    clean_company,
                    all_results,
                    confidence=stage1_confidence,
                    now_iso=now_iso,
                )
            )
            continue

        for report in extracted.get("reports", []):
            reports.append(_build_report_entry(report, url, stage1_confidence, now_iso))

        for linked_url in extracted.get("linked_urls", []):
            linked_key = _normalize_url(linked_url)
            if linked_key not in processed_urls:
                discovered_links.append(
                    {
                        "url": linked_url,
                        "source_url": url,
                        "parent_confidence": stage1_confidence,
                    }
                )

    stage2_count = len(reports)
    _debug_log(debug, f"Stage 2 complete: {stage2_count} report(s) from {extraction_count} page(s)")

    # --- Stage 3: follow discovered links (one level only) ---

    links_followed = 0
    for link_item in discovered_links:
        if extraction_count >= _MAX_TOTAL_EXTRACTIONS:
            break
        if links_followed >= _MAX_LINK_FOLLOWS:
            break

        url = link_item["url"]
        url_key = _normalize_url(url)
        if url_key in processed_urls:
            continue
        processed_urls.add(url_key)

        parent_confidence = link_item.get("parent_confidence", 0.5)

        _maybe_auto_hop_to_org(
            url,
            clean_company,
            auto_hopped_orgs,
            parent_confidence,
            now_iso,
            reports,
            debug=debug,
        )

        github = _parse_github_url(url)
        if github and github["owner"].lower() in auto_hopped_orgs:
            continue

        is_github_blob_pdf = github is not None and github["kind"] == "blob" and _is_pdf_url(github["path"])

        if _is_pdf_url(url) and not is_github_blob_pdf:
            reports.append(
                _build_fallback_entry(
                    url,
                    {},
                    clean_company,
                    all_results,
                    confidence=parent_confidence,
                    now_iso=now_iso,
                    pdf_url=url,
                )
            )
            links_followed += 1
            continue

        extracted = _fetch_and_extract(
            url,
            clean_company,
            all_results,
            debug=debug,
            enumerated_orgs=auto_hopped_orgs,
        )
        extraction_count += 1
        links_followed += 1

        if extracted is None:
            continue

        for report in extracted.get("reports", []):
            reports.append(_build_report_entry(report, url, parent_confidence, now_iso))

        for linked_url in extracted.get("linked_urls", []):
            _maybe_auto_hop_to_org(
                linked_url,
                clean_company,
                auto_hopped_orgs,
                parent_confidence,
                now_iso,
                reports,
                debug=debug,
            )

    stage3_count = len(reports) - stage2_count
    if stage3_count:
        _debug_log(debug, f"Stage 3: {stage3_count} additional report(s) from {links_followed} linked page(s)")
        notes.append(f"Link following: {stage3_count} additional report(s) from {links_followed} linked page(s)")

    # --- Stage 3.5: curated auditor-portfolio crawl ---

    portfolio_yielded = 0
    portfolio_skipped = 0
    for owner, repo in _AUDITOR_PORTFOLIO_REPOS:
        if owner.lower() in auto_hopped_orgs:
            portfolio_skipped += 1
            continue
        extracted = _list_repo_root_for_company(owner, repo, clean_company, debug=debug)
        if not extracted:
            continue
        new_reports = extracted.get("reports", [])
        if not new_reports:
            continue
        portfolio_yielded += 1
        for report in new_reports:
            reports.append(
                _build_report_entry(
                    report,
                    f"https://github.com/{owner}/{repo}",
                    0.95,
                    now_iso,
                )
            )

    if portfolio_yielded or portfolio_skipped:
        _debug_log(
            debug,
            f"Portfolio crawl: {portfolio_yielded}/{len(_AUDITOR_PORTFOLIO_REPOS)} "
            f"portfolio(s) yielded reports ({portfolio_skipped} skipped — already enumerated)",
        )
        notes.append(
            f"Portfolio allowlist: {portfolio_yielded}/{len(_AUDITOR_PORTFOLIO_REPOS)} "
            f"portfolio(s) had {clean_company}-named report(s)"
        )

    # --- Dedup: URL → filename → LLM validate+cluster (+ heuristic fallback) ---

    seen_report_urls: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for report in reports:
        report_key = _normalize_url(report.get("pdf_url") or report["url"])
        if report_key not in seen_report_urls:
            seen_report_urls.add(report_key)
            deduped.append(report)
    reports = deduped

    pre_filename_dedup = len(reports)
    reports = _collapse_by_filename(reports, debug=debug)
    if len(reports) != pre_filename_dedup:
        notes.append(f"Cross-source dedup: collapsed {pre_filename_dedup - len(reports)} filename-duplicate(s)")

    pre_validate = len(reports)
    validate_result = _llm_validate_and_cluster(reports, clean_company, debug=debug)
    if validate_result is not None:
        reports, vstats = validate_result
        notes.append(
            f"LLM validate+cluster: {pre_validate} → {len(reports)} "
            f"(dropped={vstats['dropped_invalid']}, "
            f"collapsed={vstats['collapsed_mirrors']}, "
            f"auditor_filled={vstats['auditor_filled']}, "
            f"title_fixed={vstats['title_fixed']})"
        )
    else:
        # LLM unavailable — heuristic mirror dedup keeps cross-host mirrors
        # from surviving into the output.
        reports = _collapse_same_audit_mirrors(reports)
        if pre_validate != len(reports):
            notes.append(
                f"LLM validation unavailable; heuristic mirror dedup collapsed {pre_validate - len(reports)} entry(ies)"
            )

    notes.append(f"Extracted {len(reports)} audit report(s)")
    notes.append(f"Search queries used: {queries_used[0]}/{max_queries}")

    _debug_log(
        debug,
        f"Audit report discovery complete: {len(reports)} report(s), "
        f"extractions={extraction_count}, queries={queries_used[0]}/{max_queries}",
    )

    return {
        "company": clean_company,
        "official_domain": official_domain,
        "reports": reports,
        "queries_used": queries_used[0],
        "errors": errors[:12],
        "notes": notes[:12],
    }


def _empty_result(
    company: str,
    domain: str | None,
    queries_used: int,
    errors: list,
    notes: list,
) -> dict[str, Any]:
    return {
        "company": company,
        "official_domain": domain,
        "reports": [],
        "queries_used": queries_used,
        "errors": errors[:12],
        "notes": notes[:12],
    }


# --- Append-only merge ----------------------------------------------------


def _richness(report: dict[str, Any]) -> int:
    """Count non-null detail fields as a richness score."""
    return sum(1 for key in ("pdf_url", "date") if report.get(key))


def merge_audit_reports(prev: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Merge previous and new audit report results (append-only).

    URL-keyed: overlap keeps the richer entry (prefer new on tie). Prev-only
    reports survive unchanged; new-only reports get added.
    """
    prev_reports = {_normalize_url(r["url"]): r for r in prev.get("reports", []) if r.get("url")}
    new_reports = {_normalize_url(r["url"]): r for r in new.get("reports", []) if r.get("url")}

    merged: dict[str, dict[str, Any]] = {}
    for url_key, report in new_reports.items():
        if url_key in prev_reports:
            if _richness(prev_reports[url_key]) > _richness(report):
                merged[url_key] = prev_reports[url_key]
            else:
                merged[url_key] = report
        else:
            merged[url_key] = report

    for url_key, report in prev_reports.items():
        if url_key not in new_reports:
            merged[url_key] = report

    sorted_reports = sorted(
        merged.values(),
        key=lambda r: (r.get("date") or "", r.get("confidence") or 0),
        reverse=True,
    )

    return {
        "company": new.get("company", prev.get("company")),
        "official_domain": new.get("official_domain") or prev.get("official_domain"),
        "reports": sorted_reports,
        "queries_used": new.get("queries_used"),
        "errors": new.get("errors"),
        "notes": new.get("notes"),
    }


__all__ = [
    # Orchestration
    "search_audit_reports",
    "merge_audit_reports",
    # Report assembly
    "_build_report_entry",
    "_build_fallback_entry",
    # Auto-hop
    "_should_auto_hop_org",
    "_maybe_auto_hop_to_org",
    # URL helpers (re-exported for tests)
    "_normalize_url",
    "_dedupe_results_by_url",
    "_is_pdf_url",
    "_company_name_variants",
    "_filename_mentions_company",
    "_extract_date_from_filename",
    "_augment_filename_metadata",
    # Dedup (re-exported for tests)
    "_collapse_by_filename",
    "_collapse_same_audit_mirrors",
    "_llm_validate_and_cluster",
    "_title_tokens",
    "_richness_score",
    # GitHub (re-exported for tests)
    "_parse_github_url",
    "github_blob_to_raw",
    "_github_api_headers",
    "_resolve_branch_commit",
    "_BRANCH_SHA_CACHE",
    "_AUDIT_FOLDER_CANDIDATES",
    "_AUDIT_FOLDER_LAST_SEGMENTS",
    "_DEPENDENCY_LIBRARY_PATTERNS",
    "_is_dependency_library_repo",
    "_is_vendored_dependency_path",
    "_list_org_repos",
    "_list_repo_root_for_company",
    "_fetch_github_tree_as_reports",
    "_fetch_github_org_as_reports",
    "_fetch_github_raw",
    "_llm_extract_filename_metadata",
    # Fetch (re-exported for tests)
    "_fetch_html_page",
    "_page_to_text",
    "_fetch_and_extract",
    # Portfolio + caps
    "_AUDITOR_PORTFOLIO_REPOS",
    "_MAX_STAGE2_PAGES",
    "_MAX_LINK_FOLLOWS",
    "_MAX_TOTAL_EXTRACTIONS",
    # Request module re-exported so tests can monkeypatch
    "_requests",
]
