"""Post-process audit discovery rows with URL-derived metadata."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import requests

from services.discovery.audit_reports._fetch import _page_to_text
from services.discovery.audit_reports._github import (
    _discover_repo_audit_folders,
    _fetch_github_tree_as_reports,
    _github_api_headers,
    _parse_github_url,
    github_blob_to_raw,
)
from services.discovery.audit_reports._urls import _is_pdf_url
from services.discovery.inventory_domain import _debug_log

_HREF_RE = re.compile(r"""(?is)<a\b[^>]*href=["']([^"']+)["']""")
_PDF_URL_RE = re.compile(r"""https?://[^\s"'<>]+?\.pdf(?:[?#][^\s"'<>]*)?""", re.IGNORECASE)
_SHA_RE = re.compile(r"\b[0-9a-fA-F]{7,40}\b")
_GITHUB_URL_RE = re.compile(r"https?://github\.com/[^\s\"'<>)]+")
_GITHUB_REF_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/(commit|tree|blob|pull)/([^/#?]+)(?:/([^#?]+))?/?",
    re.IGNORECASE,
)
_SKIP_FETCH_HOST_SUFFIXES = (".example.com", ".example.org", ".example.net")


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _valid_sha(value: str) -> str | None:
    text = str(value or "").strip().lower()
    if not (7 <= len(text) <= 40):
        return None
    if not re.fullmatch(r"[0-9a-f]+", text):
        return None
    if not any(c in "abcdef" for c in text):
        return None
    if len(set(text)) < 3:
        return None
    return text


def _source_repo(value: Any) -> str | None:
    text = str(value or "").strip().strip("/")
    if not text:
        return None
    parsed = _parse_github_url(text)
    if parsed and parsed.get("repo"):
        return f"{parsed['owner']}/{parsed['repo']}"
    if re.fullmatch(r"[^/\s]+/[^/\s]+", text):
        return text
    return None


def _raw_github_metadata(value: Any) -> dict[str, str]:
    text = str(value or "").strip()
    if not text:
        return {}
    raw_url = github_blob_to_raw(text) or text
    parsed = urlparse(raw_url)
    if (parsed.hostname or "").lower() != "raw.githubusercontent.com":
        return {}
    parts = parsed.path.lstrip("/").split("/", 3)
    if len(parts) != 4:
        return {}
    owner, repo, ref, path = parts
    if not owner or not repo or not ref or not path:
        return {}

    metadata = {
        "source_repo": f"{owner}/{repo}",
        "source_path": unquote(path),
    }
    if len(ref) == 40 and (sha := _valid_sha(ref)):
        metadata["source_commit"] = sha
    return metadata


def _should_fetch_html(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        return False
    return not host.endswith(_SKIP_FETCH_HOST_SUFFIXES)


def _fetch_html(url: str, debug: bool = False) -> str | None:
    if not _should_fetch_html(url):
        return None
    try:
        resp = requests.get(url, timeout=8, headers={"User-Agent": "PSAT/0.1"})
    except requests.RequestException as exc:
        _debug_log(debug, f"Audit enrichment fetch failed for {url}: {exc!r}")
        return None
    if resp.status_code != 200:
        return None
    content_type = (resp.headers.get("content-type") or "").lower()
    if "text/html" not in content_type and "application/xhtml" not in content_type and content_type:
        return None
    return resp.text[:512_000]


def _extract_pdf_links(page_html: str, base_url: str) -> list[str]:
    links: list[str] = []
    for href in _HREF_RE.findall(page_html):
        resolved = urljoin(base_url, href.strip())
        if _is_pdf_url(resolved):
            links.append(resolved)
    for match in _PDF_URL_RE.findall(page_html):
        links.append(urljoin(base_url, match.strip()))
    return _dedupe([github_blob_to_raw(link) for link in links])


def _extract_github_refs(text: str) -> tuple[list[str], list[str]]:
    repos: list[str] = []
    commits: list[str] = []
    for raw_url in _GITHUB_URL_RE.findall(text or ""):
        url = raw_url.rstrip(".,;")
        parsed = _parse_github_url(url)
        if parsed and parsed.get("repo"):
            repos.append(f"{parsed['owner']}/{parsed['repo']}")
            if parsed["kind"] in {"tree", "blob"}:
                sha = _valid_sha(parsed.get("ref", ""))
                if sha:
                    commits.append(sha)
            continue
        match = _GITHUB_REF_RE.match(url)
        if not match:
            continue
        owner, repo, kind, ref, _path = match.groups()
        repo_ref = f"{owner}/{repo}"
        repos.append(repo_ref)
        if kind.lower() == "commit":
            sha = _valid_sha(ref)
            if sha:
                commits.append(sha)
        elif kind.lower() == "pull":
            commits.extend(_pull_commits(repo_ref, ref))
    return _dedupe(repos), _dedupe(commits)


def _commit_exists(repo: str, commit: str) -> bool:
    url = f"https://api.github.com/repos/{repo}/commits/{commit}"
    try:
        resp = requests.get(url, timeout=10, headers=_github_api_headers())
    except requests.RequestException:
        return False
    return resp.status_code == 200


def _pull_commits(repo: str, pull_number: str) -> list[str]:
    url = f"https://api.github.com/repos/{repo}/pulls/{pull_number}/commits"
    try:
        resp = requests.get(url, timeout=10, headers=_github_api_headers())
    except requests.RequestException:
        return []
    if resp.status_code != 200:
        return []
    try:
        payload = resp.json()
    except ValueError:
        return []
    commits: list[str] = []
    if isinstance(payload, list):
        for item in payload[:20]:
            sha = _valid_sha(str(item.get("sha") or "")) if isinstance(item, dict) else None
            if sha:
                commits.append(sha)
    return _dedupe(commits)


def _verified_commits(commits: list[str], repos: list[str]) -> list[str]:
    valid: list[str] = []
    for commit in _dedupe([sha for sha in (_valid_sha(c) for c in commits) if sha]):
        if any(_commit_exists(repo, commit) for repo in repos):
            valid.append(commit)
    return valid


def _append_classified_commit(report: dict[str, Any], sha: str, provenance: str) -> None:
    entries = list(report.get("classified_commits") or [])
    if any(str(entry.get("sha", "")).lower() == sha.lower() for entry in entries if isinstance(entry, dict)):
        return
    entries.append({"sha": sha, "label": "reviewed", "provenance": provenance})
    report["classified_commits"] = entries


def _normalize_text(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


# Vocabulary shared by nearly every audit filename; a title made only of these
# words identifies no particular document.
_GENERIC_TITLE_TOKENS = frozenset(
    {
        "audit",
        "audits",
        "report",
        "reports",
        "security",
        "assessment",
        "review",
        "final",
        "draft",
        "smart",
        "contract",
        "contracts",
        "protocol",
        "the",
        "of",
        "and",
        "for",
        "v",
    }
)

_UNKNOWN_AUDITORS = frozenset({"", "unknown", "n a", "na", "none", "anonymous", "unnamed", "tbd"})


def _auditor_key(value: Any) -> str:
    """Normalized auditor name, or ``""`` when the value is a not-determined
    sentinel rather than a firm."""
    text = _normalize_text(value)
    return "" if text in _UNKNOWN_AUDITORS else text


def _distinctive_title(value: Any) -> str:
    """Normalized title with the generic audit vocabulary removed.

    ``"Hats Finance Audit"`` -> ``"hats finance"``; ``"Audit Report"`` -> ``""``.
    An empty result carries no document identity and must never corroborate.
    """
    tokens = [t for t in _normalize_text(value).split() if t not in _GENERIC_TITLE_TOKENS]
    joined = " ".join(tokens)
    return joined if len(joined) >= 4 else ""


def _candidate_haystack(candidate: dict[str, Any]) -> str:
    filename = unquote(str(candidate.get("pdf_url") or "").rsplit("/", 1)[-1])
    parts = (candidate.get("title"), filename, candidate.get("source_path"), candidate.get("auditor"))
    return _normalize_text(" ".join(str(part or "") for part in parts))


def _contradicts_auditor(report_auditor: str, candidate: dict[str, Any], haystack: str) -> bool:
    """True when the candidate PDF is attributable to a *different* firm than
    the report names for itself."""
    if not report_auditor:
        return False
    candidate_auditor = _auditor_key(candidate.get("auditor"))
    if not candidate_auditor or candidate_auditor == report_auditor:
        return False
    return report_auditor not in haystack


def _corroborated_pdf_candidate(report: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the one candidate PDF that is evidently *this* report's document.

    Adoption must be earned by the report's own identity: its distinctive
    title, or the dependency component it was discovered for. Position in the
    folder listing, the protocol's name (which every file in the protocol's own
    repo carries), and the auditor's name alone (a firm can publish many
    reports in one folder) are not evidence of document identity. Ambiguity —
    two candidates corroborating equally — is not evidence either, so it
    adopts nothing.
    """
    report_auditor = _auditor_key(report.get("auditor"))
    title = _distinctive_title(report.get("title"))
    component = _normalize_text(report.get("dependency_component"))

    by_title: list[dict[str, Any]] = []
    by_component: list[dict[str, Any]] = []
    for candidate in candidates:
        haystack = _candidate_haystack(candidate)
        if _contradicts_auditor(report_auditor, candidate, haystack):
            continue
        if title and title in haystack:
            by_title.append(candidate)
        elif component and component in haystack:
            by_component.append(candidate)

    for tier in (by_title, by_component):
        if not tier:
            continue
        return tier[0] if len(tier) == 1 else None
    return None


def _prefer_repo_audit_pdf(report: dict[str, Any], repos: list[str], protocol: str, debug: bool = False) -> None:
    """Attach a repo-hosted PDF to a PDF-less report — only when the PDF is
    corroborated as this report's own document (see
    :func:`_corroborated_pdf_candidate`). An uncorroborated report keeps no
    ``pdf_url``: PDF-less is the honest state, and it also keeps the report's
    ``url`` unique, which the ``(protocol_id, url)`` audit-report upsert needs
    to persist it as its own row.
    """
    if report.get("pdf_url") and _is_pdf_url(str(report.get("pdf_url"))):
        return
    if not repos:
        return
    for repo_ref in repos[:3]:
        repo = _source_repo(repo_ref)
        if not repo:
            continue
        owner, name = repo.split("/", 1)
        for folder in _discover_repo_audit_folders(owner, name, debug=debug)[:3]:
            extracted = _fetch_github_tree_as_reports(
                owner,
                name,
                folder["path"],
                ref=folder["ref"],
                company=protocol,
                debug=debug,
            )
            if not extracted:
                continue
            candidates = [r for r in extracted.get("reports", []) if r.get("pdf_url")]
            if not candidates:
                continue
            preferred = _corroborated_pdf_candidate(report, candidates)
            if preferred is None:
                _debug_log(
                    debug,
                    f"Audit enrichment: no corroborated PDF for {report.get('title')!r} "
                    f"(auditor {report.get('auditor')!r}) among {len(candidates)} candidate(s) "
                    f"in {repo}/{folder['path']}; leaving it PDF-less",
                )
                continue
            report["pdf_url"] = preferred.get("pdf_url")
            report["url"] = preferred.get("pdf_url") or report.get("url")
            report.setdefault("source_repo", preferred.get("source_repo") or repo)
            for key in ("source_commit", "source_path"):
                if preferred.get(key):
                    report.setdefault(key, preferred[key])
            return


def enrich_audit_reports(audit_result: dict[str, Any], protocol: str, debug: bool = False) -> dict[str, Any]:
    """Mutate and return ``audit_result`` with PDF, repo, and commit metadata."""
    reports = audit_result.get("reports")
    if not isinstance(reports, list):
        return audit_result

    for report in reports:
        if not isinstance(report, dict):
            continue

        url = str(report.get("url") or "").strip()
        pdf_url = str(report.get("pdf_url") or "").strip()
        if pdf_url:
            report["pdf_url"] = github_blob_to_raw(pdf_url)
        elif _is_pdf_url(url):
            report["pdf_url"] = github_blob_to_raw(url)

        repos = [repo for repo in [_source_repo(report.get("source_repo"))] if repo]
        repos.extend(_source_repo(repo) or "" for repo in report.get("referenced_repos") or [])
        for candidate_url in (url, report.get("pdf_url")):
            github_meta = _raw_github_metadata(candidate_url)
            if not github_meta:
                continue
            if github_meta.get("source_repo"):
                repos.append(github_meta["source_repo"])
            for key in ("source_repo", "source_path", "source_commit"):
                if github_meta.get(key) and not report.get(key):
                    report[key] = github_meta[key]
        commits = [str(c) for c in report.get("reviewed_commits") or []]
        default_provenance = "ai_returned" if report.get("metadata_provenance") == "ai_returned" else "regex_extracted"
        provenance_by_commit = {(_valid_sha(c) or ""): default_provenance for c in commits}

        text_for_refs = url
        html = None
        if url and not _is_pdf_url(url):
            html = _fetch_html(url, debug=debug)
        if html:
            pdf_links = _extract_pdf_links(html, url)
            if pdf_links and not report.get("pdf_url"):
                report["pdf_url"] = pdf_links[0]
            page_text = _page_to_text(html)
            text_for_refs = f"{url} {page_text}"

        html_repos, html_commits = _extract_github_refs(text_for_refs)
        repos.extend(html_repos)
        for commit in html_commits:
            provenance_by_commit.setdefault(commit, "html_ref")
        commits.extend(html_commits)

        repos = _dedupe([repo for repo in repos if repo])
        if repos and not report.get("source_repo"):
            report["source_repo"] = repos[0]
        if repos:
            report["referenced_repos"] = repos

        if commits and repos:
            verified = _verified_commits(commits, repos)
            report["reviewed_commits"] = verified
            for sha in verified:
                _append_classified_commit(report, sha, provenance_by_commit.get(sha, "regex_extracted"))
        elif "reviewed_commits" in report:
            report["reviewed_commits"] = []

        _prefer_repo_audit_pdf(report, repos, protocol, debug=debug)

    return audit_result
