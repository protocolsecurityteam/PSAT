"""GitHub API integration: URL parsing, repo + org enumeration, tree fetch.

Every function that touches ``api.github.com`` or ``raw.githubusercontent.com``
lives here. Upstream submodules call into this one; this module imports only
from ``_urls`` so there are no cycles.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
import urllib.parse
from typing import Any

import requests as _requests

from utils import llm
from utils.github_urls import github_blob_to_raw
from utils.logging import record_degraded

from ..inventory_domain import _debug_log
from ._urls import (
    _augment_filename_metadata,
    _company_name_variants,
    _filename_mentions_company,
)

logger = logging.getLogger(__name__)

# --- URL parsing ----------------------------------------------------------

_GITHUB_TREE_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.+?)/?$")
_GITHUB_BLOB_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+?)/?$")
_GITHUB_REPO_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
_GITHUB_ORG_RE = re.compile(r"^https?://github\.com/([^/?#]+)/?$")

# Single-segment GitHub paths that look like orgs but aren't accounts.
_RESERVED_GITHUB_PATHS = frozenset(
    {
        "orgs",
        "users",
        "settings",
        "marketplace",
        "topics",
        "search",
        "sponsors",
        "explore",
        "about",
        "pricing",
        "enterprise",
        "trending",
        "collections",
        "events",
        "features",
        "customer-stories",
        "team",
        "contact",
        "site",
        "login",
        "join",
        "new",
        "organizations",
        "notifications",
        "issues",
        "pulls",
        "watching",
        "stars",
        "codespaces",
    }
)


def _parse_github_url(url: str) -> dict[str, str] | None:
    """Parse a GitHub URL into owner/repo (and ref/path for tree/blob)."""
    for pattern, kind in [(_GITHUB_TREE_RE, "tree"), (_GITHUB_BLOB_RE, "blob")]:
        m = pattern.match(url)
        if m:
            return {
                "kind": kind,
                "owner": m.group(1),
                "repo": m.group(2),
                "ref": m.group(3),
                "path": m.group(4),
            }
    m = _GITHUB_REPO_RE.match(url)
    if m:
        repo = m.group(2)
        if repo in _RESERVED_GITHUB_PATHS:
            return None
        return {"kind": "repo", "owner": m.group(1), "repo": repo, "ref": "", "path": ""}
    m = _GITHUB_ORG_RE.match(url)
    if m:
        owner = m.group(1)
        if owner in _RESERVED_GITHUB_PATHS:
            return None
        return {"kind": "org", "owner": owner, "repo": "", "ref": "", "path": ""}
    return None


def _github_api_headers() -> dict[str, str]:
    """Standard headers. GITHUB_TOKEN bumps rate limit 60→5000/hr."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "PSAT/0.1",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


# --- Branch → commit SHA cache --------------------------------------------

# Process-wide cache keyed on (owner, repo, branch). Values are
# ``(sha, monotonic_ts)``: a short TTL re-probes because HEAD advances on
# every push, and a size cap bounds the key count across repeated runs.
# Misses are not cached so a transient GitHub error retries next call.
_BRANCH_SHA_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}
_BRANCH_SHA_CACHE_LOCK = threading.Lock()
_BRANCH_SHA_CACHE_MAX = 4096
_BRANCH_SHA_CACHE_TTL_S = float(os.getenv("PSAT_BRANCH_SHA_CACHE_TTL_S", "300"))


def clear_branch_sha_cache() -> None:
    """Clear the process-wide branch→SHA cache. For tests + manual reset."""
    from utils.memory import reset_cache_pressure_state

    with _BRANCH_SHA_CACHE_LOCK:
        _BRANCH_SHA_CACHE.clear()
    reset_cache_pressure_state("branch_sha")


def _evict_branch_sha_if_needed() -> None:
    """Drop the oldest 25% of _BRANCH_SHA_CACHE entries when the bound is reached (caller holds the lock)."""
    if len(_BRANCH_SHA_CACHE) < _BRANCH_SHA_CACHE_MAX:
        return
    cutoff = sorted(_BRANCH_SHA_CACHE.values(), key=lambda v: v[1])[len(_BRANCH_SHA_CACHE) // 4][1]
    for k in [k for k, v in _BRANCH_SHA_CACHE.items() if v[1] <= cutoff]:
        _BRANCH_SHA_CACHE.pop(k, None)


def _log_branch_sha_pressure() -> None:
    """Log when _BRANCH_SHA_CACHE crosses 50/75/95% of its bound (caller holds the lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("branch_sha", len(_BRANCH_SHA_CACHE), _BRANCH_SHA_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _resolve_branch_commit(owner: str, repo: str, branch: str, debug: bool = False) -> str | None:
    """Return the HEAD commit SHA for a branch, or ``None`` on miss.

    Recorded on every GitHub-sourced audit so phase-2 linking can verify
    the PDF still lives at the same SHA and build stable permalinks.
    """
    key = (owner.lower(), repo.lower(), branch)
    now = time.monotonic()

    with _BRANCH_SHA_CACHE_LOCK:
        cached = _BRANCH_SHA_CACHE.get(key)
        if cached is not None:
            sha_cached, inserted_at = cached
            if now - inserted_at < _BRANCH_SHA_CACHE_TTL_S:
                return sha_cached
            del _BRANCH_SHA_CACHE[key]

    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}"
    sha: str | None = None
    try:
        resp = _requests.get(url, timeout=15, headers=_github_api_headers())
    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub ref lookup failed for {owner}/{repo}@{branch}: {exc!r}")
    else:
        if resp.status_code == 200:
            try:
                payload = resp.json() or {}
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                obj = payload.get("object") or {}
                if isinstance(obj, dict):
                    sha_val = obj.get("sha")
                    if isinstance(sha_val, str) and len(sha_val) == 40:
                        sha = sha_val
        else:
            _debug_log(debug, f"GitHub ref {resp.status_code} for {owner}/{repo}@{branch}")

    if sha is not None:
        with _BRANCH_SHA_CACHE_LOCK:
            _evict_branch_sha_if_needed()
            _BRANCH_SHA_CACHE[key] = (sha, now)
            _log_branch_sha_pressure()
    return sha


# --- Audit folder discovery config ----------------------------------------

# Probed in order via the contents API; first hit short-circuits.
_AUDIT_FOLDER_CANDIDATES: tuple[str, ...] = (
    "audits",
    "audit",
    "audit-reports",
    "security/audits",
    "docs/audits",
    "security",
    "reviews",
    "security-reviews",
    "external-audits",
    "code-audits",
    "formal-verification",
    "security-reports",
)

# Last-segment folder names we accept when scanning the recursive tree.
_AUDIT_FOLDER_LAST_SEGMENTS: frozenset[str] = frozenset(
    {
        "audit",
        "audits",
        "audit-reports",
        "security-audits",
        "reviews",
        "security-reviews",
        "external-audits",
        "code-audits",
        "formal-verification",
        "security-reports",
    }
)

# Cap per-org enumeration — sorted by pushed_at desc, so recent repos
# (where current audits live) probe first. morpho-org tops out ~40.
_MAX_ORG_REPOS = 100

# Library forks whose ``audits/`` folder belongs to the upstream library,
# not the protocol that vendored the fork.
_DEPENDENCY_LIBRARY_PATTERNS: tuple[str, ...] = (
    "openzeppelin-contracts",
    "openzeppelin-contracts-upgradeable",
    "forge-std",
    "solmate",
    "solady",
    "permit2",
    "uniswap-v2",
    "uniswap-v3",
    "uniswap-v4",
    "ds-test",
    "ds-math",
    "create2-helpers",
    "halmos-cheatcodes",
    "prb-math",
    "safe-contracts",
    "seaport",
)

# Path segments that mark a vendored-dep tree. An ``audits/`` under any of
# these belongs to the dep, not the protocol.
_VENDORED_DEP_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "lib",
        "libs",
        "node_modules",
        "vendor",
        "vendors",
        "third_party",
        "third-party",
        "submodules",
        "submodule",
        "deps",
        "dependencies",
        "packages",
        "externals",
        "external",
    }
)


def _is_dependency_library_repo(repo_name: str) -> bool:
    """True if the repo name matches a common vendored library fork."""
    lower = repo_name.lower()
    return any(pat in lower for pat in _DEPENDENCY_LIBRARY_PATTERNS)


def _is_vendored_dependency_path(path: str) -> bool:
    """True if path sits under ``lib/``/``vendor/``/etc."""
    parts = path.lower().split("/")
    return any(p in _VENDORED_DEP_PATH_SEGMENTS for p in parts[:-1])


# --- LLM-backed filename metadata extraction ------------------------------

_FILENAME_BATCH_SIZE = 12


def _llm_extract_filename_metadata(
    filenames: list[str],
    company: str,
    debug: bool = False,
    *,
    folder_context: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Ask the LLM for auditor / date / title per filename.

    Returns ``filename -> {auditor, date, title}``. Filenames the LLM can't
    classify are absent from the map. Every batch sees the full sibling
    list as context so the LLM can infer auditors for untagged files (e.g.
    a ``Final.pdf`` sitting next to Halborn-named siblings).
    """
    from ..audit_reports_llm import _KNOWN_AUDITORS, _parse_json_array

    if not filenames:
        return {}

    siblings_block = ""
    if len(filenames) > 1:
        siblings_block = (
            "\nFull file list in this folder (use as context for any file "
            "whose own name lacks a clear auditor):\n" + "\n".join(f"  - {n}" for n in filenames) + "\n"
        )

    folder_block = f"\nFolder path: {folder_context}\n" if folder_context else ""

    out: dict[str, dict[str, Any]] = {}
    for start in range(0, len(filenames), _FILENAME_BATCH_SIZE):
        batch = filenames[start : start + _FILENAME_BATCH_SIZE]
        file_list = "\n".join(f"- {name}" for name in batch)
        prompt = (
            f"Below are file names from a GitHub audit directory for the "
            f"{company} smart-contract protocol.{folder_block}"
            f"For each file, extract the auditing firm name, the audit date, "
            f"and a clean human-readable title. When a single file name is "
            f"ambiguous, look at the sibling files for context — protocols "
            f"often ship multiple reports from the same auditor in one "
            f"folder, and untagged files usually share that auditor.\n\n"
            f"Common auditing firms (use these names verbatim when you spot "
            f"a match — including from abbreviations or report-ID prefixes "
            f"like ``NM-####`` for Nethermind, ``ToB-`` for Trail of Bits, "
            f"``OZ-`` for OpenZeppelin): {_KNOWN_AUDITORS}.\n"
            f"{siblings_block}\n"
            f"Files to classify in this batch:\n{file_list}\n\n"
            f"Reply with ONLY a JSON array, one object per batched file, in "
            f"the same order. Each object MUST have these keys:\n"
            f'- "filename": the exact filename including extension\n'
            f'- "auditor": auditing firm name, or null if not identifiable\n'
            f'- "date": audit date as YYYY-MM-DD (or YYYY-MM / YYYY), or null\n'
            f'- "title": short human-readable title for the audit'
        )
        try:
            response = llm.chat(
                [{"role": "user", "content": prompt}],
                max_tokens=4096,
                temperature=0.0,
            )
        except Exception as exc:
            _debug_log(debug, f"GitHub tree LLM batch failed ({start}): {exc!r}")
            continue

        parsed = _parse_json_array(response)
        if not parsed:
            _debug_log(debug, f"GitHub tree LLM batch {start}: unparseable response")
            continue

        # Prefer LLM's ``filename`` key; fall back to positional match when
        # the LLM drops or rewrites the filename (common when models omit
        # extensions).
        for idx, item in enumerate(parsed):
            if not isinstance(item, dict):
                continue
            requested = batch[idx] if idx < len(batch) else None
            llm_name = str(item.get("filename") or "").strip()

            target = None
            if llm_name in batch:
                target = llm_name
            elif requested and (llm_name == requested.rsplit(".", 1)[0] or not llm_name):
                target = requested
            if target is None:
                continue
            out[target] = item

    _debug_log(debug, f"GitHub tree LLM: classified {len(out)}/{len(filenames)} filename(s)")
    return out


# --- Org / repo / tree enumeration ----------------------------------------


def _list_org_repos(owner: str, debug: bool = False) -> list[str]:
    """List public repo names for a GitHub org or user, by pushed_at desc.

    Tries ``/orgs/{owner}/repos`` first, falls back to ``/users/{owner}/repos``.
    Archived repos are included — protocol teams archive old versions (e.g.
    ``morpho-optimizers``) that still carry the authoritative audit files.
    """
    params = f"per_page={_MAX_ORG_REPOS}&sort=pushed&direction=desc&type=public"
    for endpoint in ("orgs", "users"):
        url = f"https://api.github.com/{endpoint}/{owner}/repos?{params}"
        try:
            resp = _requests.get(url, timeout=30, headers=_github_api_headers())
        except _requests.RequestException as exc:
            _debug_log(debug, f"GitHub {endpoint} list failed for {owner}: {exc!r}")
            continue
        if resp.status_code == 404:
            continue
        if resp.status_code != 200:
            _debug_log(debug, f"GitHub {endpoint} list {resp.status_code} for {owner}")
            return []
        data = resp.json()
        if not isinstance(data, list):
            return []
        names = [str(item.get("name")) for item in data if item.get("name")]
        _debug_log(debug, f"GitHub {endpoint} {owner}: {len(names)} repo(s)")
        return names[:_MAX_ORG_REPOS]
    _debug_log(debug, f"GitHub {owner}: neither orgs nor users endpoint returned data")
    return []


def _discover_repo_audit_folders(owner: str, repo: str, debug: bool = False) -> list[dict[str, str]]:
    """Probe a repo for audit folders. Returns ``[{ref, path}, ...]``.

    Costs one repo-metadata call + one recursive-tree call, with a
    contents-API fallback when the tree call misses.
    """
    meta_url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        resp = _requests.get(meta_url, timeout=15, headers=_github_api_headers())
    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub repo metadata failed for {owner}/{repo}: {exc!r}")
        return []
    if resp.status_code != 200:
        _debug_log(debug, f"GitHub repo metadata {resp.status_code} for {owner}/{repo}")
        return []
    default_branch = (resp.json() or {}).get("default_branch") or "main"

    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    try:
        tree_resp = _requests.get(tree_url, timeout=30, headers=_github_api_headers())
    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub tree call failed for {owner}/{repo}: {exc!r}")
        tree_resp = None

    found_paths: list[str] = []
    if tree_resp is not None and tree_resp.status_code == 200:
        data = tree_resp.json() or {}
        for item in data.get("tree", []):
            if item.get("type") != "tree":
                continue
            path = (item.get("path") or "").strip()
            if not path or _is_vendored_dependency_path(path):
                continue
            last_segment = path.rsplit("/", 1)[-1].lower()
            if last_segment in _AUDIT_FOLDER_LAST_SEGMENTS:
                found_paths.append(path)
        if data.get("truncated"):
            _debug_log(debug, f"GitHub tree truncated for {owner}/{repo}; some folders may be missed")

    if not found_paths:
        # Fallback: probe conventional paths via contents API.
        for candidate in _AUDIT_FOLDER_CANDIDATES:
            probe_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{candidate}?ref={default_branch}"
            try:
                pr = _requests.get(probe_url, timeout=15, headers=_github_api_headers())
            except _requests.RequestException:
                continue
            if pr.status_code == 200 and isinstance(pr.json(), list):
                found_paths.append(candidate)

    _debug_log(debug, f"GitHub repo {owner}/{repo}: {len(found_paths)} audit folder(s) {found_paths}")
    return [{"ref": default_branch, "path": p} for p in found_paths]


def _fetch_github_tree_as_reports(
    owner: str,
    repo: str,
    path: str,
    ref: str = "master",
    company: str = "",
    url: str = "",
    debug: bool = False,
) -> dict[str, Any] | None:
    """Fetch a directory via the contents API and build report entries.

    The API returns structured JSON so we don't need an LLM to parse HTML.
    A single batched LLM call extracts auditor / date / title per filename.
    For auditor-publication repos (owner doesn't match company), filenames
    are filtered to company-named files to avoid pulling in 400+ unrelated
    audits.
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    try:
        resp = _requests.get(api_url, timeout=15, headers=_github_api_headers())
        if resp.status_code != 200:
            _debug_log(debug, f"GitHub API {resp.status_code} for {api_url}")
            return None

        items = resp.json()
        if not isinstance(items, list):
            return None

        _debug_log(debug, f"GitHub API: {len(items)} items in {owner}/{repo}/{path}")

        audit_files: list[dict[str, str]] = []
        subdirs: list[str] = []
        for item in items:
            name = item.get("name", "")
            item_type = item.get("type", "")
            if item_type == "dir":
                subdirs.append(item.get("html_url") or "")
                continue
            if item_type != "file":
                continue
            lower = name.lower()
            if lower.endswith((".pdf", ".md")) and not lower.startswith((".gitkeep", "readme")):
                audit_files.append(
                    {
                        "name": name,
                        "download_url": item.get("download_url") or "",
                        "html_url": item.get("html_url") or "",
                    }
                )

        if not audit_files:
            _debug_log(debug, f"No audit files found in {owner}/{repo}/{path}")
            return {"reports": [], "linked_urls": subdirs}

        company_variants = _company_name_variants(company)
        owner_norm = re.sub(r"[^a-z0-9]", "", owner.lower())
        owner_matches_company = bool(company_variants) and any(v in owner_norm for v in company_variants)
        if not owner_matches_company and company_variants:
            before_count = len(audit_files)
            audit_files = [f for f in audit_files if _filename_mentions_company(f["name"], company_variants)]
            dropped = before_count - len(audit_files)
            if dropped:
                _debug_log(
                    debug,
                    f"GitHub tree {owner}/{repo}/{path}: company-name filter "
                    f"dropped {dropped} of {before_count} file(s)",
                )
            if not audit_files:
                return {"reports": [], "linked_urls": subdirs}

        file_metadata = _llm_extract_filename_metadata(
            [f["name"] for f in audit_files],
            company,
            debug=debug,
            folder_context=f"{owner}/{repo}/{path}",
        )
        source_commit = _resolve_branch_commit(owner, repo, ref, debug=debug)

        reports: list[dict[str, Any]] = []
        for f in audit_files:
            name = f["name"]
            meta = _augment_filename_metadata(name, file_metadata.get(name, {}))
            base_name = name.rsplit(".", 1)[0] if "." in name else name
            auditor = str(meta.get("auditor") or "").strip() or "Unknown"
            title = str(meta.get("title") or "").strip() or base_name
            date = str(meta.get("date") or "").strip() or None
            is_pdf = name.lower().endswith(".pdf")
            # ``report_url`` keeps each file's own GitHub link so multiple
            # .md files in the same directory don't collapse onto the tree
            # URL during URL-keyed dedup. For non-PDF files the html_url is
            # a /blob/ link that serves HTML — normalize to raw so the text
            # extraction worker gets the file body.
            report_url = f.get("html_url") or f.get("download_url")
            if not is_pdf and report_url:
                report_url = github_blob_to_raw(report_url)
            reports.append(
                {
                    "auditor": auditor,
                    "title": title,
                    "date": date,
                    "pdf_url": f["download_url"] if is_pdf else None,
                    "report_url": report_url,
                    "source_commit": source_commit,
                    "source_repo": f"{owner}/{repo}",
                    "source_path": f"{path}/{name}",
                }
            )

        _debug_log(debug, f"GitHub tree: built {len(reports)} report(s) from {len(audit_files)} file(s)")
        return {"reports": reports, "linked_urls": subdirs}

    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub API failed for {api_url}: {exc!r}")
        return None


def _fetch_github_org_as_reports(
    owner: str,
    company: str,
    url: str,
    debug: bool = False,
) -> dict[str, Any] | None:
    """Enumerate every non-library repo in an org and pull audit folders.

    Protocol teams shard across sibling repos with a shared ``audits/``
    pattern — a bare org URL has to fan out to catch everything.
    """
    repos = _list_org_repos(owner, debug=debug)
    if not repos:
        return None

    merged_reports: list[dict[str, Any]] = []
    merged_linked: list[str] = []
    probed_with_audits = 0

    for repo in repos:
        if _is_dependency_library_repo(repo):
            _debug_log(
                debug,
                f"GitHub org {owner}: skipping library fork {repo} (audits belong to the upstream library)",
            )
            continue
        folders = _discover_repo_audit_folders(owner, repo, debug=debug)
        if not folders:
            continue
        probed_with_audits += 1
        for folder in folders:
            tree_url = f"https://github.com/{owner}/{repo}/tree/{folder['ref']}/{folder['path']}"
            sub = _fetch_github_tree_as_reports(
                owner,
                repo,
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

    _debug_log(
        debug,
        f"GitHub org {owner}: {probed_with_audits}/{len(repos)} repo(s) had audit folder(s); "
        f"{len(merged_reports)} report(s) total",
    )
    return {"reports": merged_reports, "linked_urls": merged_linked}


def _expand_blob_to_directory(
    owner: str,
    repo: str,
    ref: str,
    blob_path: str,
    company: str,
    debug: bool = False,
) -> dict[str, Any] | None:
    """List a confirmed blob's parent directory and pull sibling audits.

    Handles the auditor-portfolio case: one confirmed blob expands into
    every same-company audit in the parent folder.
    """
    parent = blob_path.rsplit("/", 1)[0] if "/" in blob_path else ""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{parent}?ref={ref}"
    try:
        resp = _requests.get(api_url, timeout=15, headers=_github_api_headers())
    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub directory list failed for {owner}/{repo}/{parent}: {exc!r}")
        return None
    if resp.status_code != 200:
        _debug_log(debug, f"GitHub directory list {resp.status_code} for {owner}/{repo}/{parent}")
        return None
    items = resp.json()
    if not isinstance(items, list):
        return None

    variants = _company_name_variants(company)
    audit_files: list[dict[str, str]] = []
    for item in items:
        if item.get("type") != "file":
            continue
        name = item.get("name", "")
        lower = name.lower()
        if not (lower.endswith((".pdf", ".md")) and not lower.startswith((".gitkeep", "readme"))):
            continue
        if not _filename_mentions_company(name, variants):
            continue
        audit_files.append(
            {
                "name": name,
                "download_url": item.get("download_url") or "",
                "html_url": item.get("html_url") or "",
            }
        )

    if not audit_files:
        _debug_log(debug, f"No same-protocol siblings in {owner}/{repo}/{parent}")
        return None

    _debug_log(
        debug,
        f"Expanded blob → directory {owner}/{repo}/{parent}: {len(audit_files)} same-protocol file(s)",
    )

    file_metadata = _llm_extract_filename_metadata(
        [f["name"] for f in audit_files],
        company,
        debug=debug,
        folder_context=f"{owner}/{repo}/{parent}",
    )
    source_commit = _resolve_branch_commit(owner, repo, ref, debug=debug)

    reports: list[dict[str, Any]] = []
    for f in audit_files:
        name = f["name"]
        meta = _augment_filename_metadata(name, file_metadata.get(name, {}))
        base_name = name.rsplit(".", 1)[0] if "." in name else name
        auditor = str(meta.get("auditor") or "").strip() or "Unknown"
        title = str(meta.get("title") or "").strip() or base_name
        date = str(meta.get("date") or "").strip() or None
        is_pdf = name.lower().endswith(".pdf")
        report_url = f.get("html_url") or f.get("download_url")
        if not is_pdf and report_url:
            report_url = github_blob_to_raw(report_url)
        reports.append(
            {
                "auditor": auditor,
                "title": title,
                "date": date,
                "pdf_url": f["download_url"] if is_pdf else None,
                "report_url": report_url,
                "source_commit": source_commit,
                "source_repo": f"{owner}/{repo}",
                "source_path": f"{parent}/{name}" if parent else name,
            }
        )
    return {"reports": reports, "linked_urls": []}


def _list_repo_root_for_company(
    owner: str,
    repo: str,
    company: str,
    debug: bool = False,
) -> dict[str, Any] | None:
    """Recursive tree scan for company-named PDFs/MDs at any depth.

    Fallback for auditor publication repos (``Zellic/publications``,
    ``spearbit/portfolio``, etc.) that ship per-protocol reports at the
    root OR nested under category folders that aren't in our
    audit-folder allowlist. One recursive-tree call + filename filter.
    """
    meta_url = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        resp = _requests.get(meta_url, timeout=15, headers=_github_api_headers())
    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub repo metadata failed for {owner}/{repo}: {exc!r}")
        return None
    if resp.status_code != 200:
        _debug_log(debug, f"GitHub repo metadata {resp.status_code} for {owner}/{repo}")
        return None
    default_branch = (resp.json() or {}).get("default_branch") or "main"

    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    try:
        tree_resp = _requests.get(tree_url, timeout=30, headers=_github_api_headers())
    except _requests.RequestException as exc:
        _debug_log(debug, f"GitHub recursive-tree failed for {owner}/{repo}: {exc!r}")
        return None
    if tree_resp.status_code != 200:
        _debug_log(debug, f"GitHub recursive-tree {tree_resp.status_code} for {owner}/{repo}")
        return None
    data = tree_resp.json() or {}

    variants = _company_name_variants(company)
    if not variants:
        return None

    audit_files: list[dict[str, str]] = []
    for item in data.get("tree", []):
        if item.get("type") != "blob":
            continue
        path = (item.get("path") or "").strip()
        if not path or _is_vendored_dependency_path(path):
            continue
        lower = path.lower()
        if not lower.endswith((".pdf", ".md")):
            continue
        name = path.rsplit("/", 1)[-1]
        if name.lower().startswith((".gitkeep", "readme")):
            continue
        # Match on FILENAME, not path — ``ether-fi-fork/foo.pdf`` whose
        # filename doesn't mention the company would otherwise slip through.
        if not _filename_mentions_company(name, variants):
            continue
        encoded_path = "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/") if seg)
        audit_files.append(
            {
                "name": name,
                "path": path,
                "download_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{encoded_path}",
                "html_url": f"https://github.com/{owner}/{repo}/blob/{default_branch}/{encoded_path}",
            }
        )

    if data.get("truncated"):
        _debug_log(debug, f"GitHub tree truncated for {owner}/{repo} — recursive listing may be incomplete")

    if not audit_files:
        _debug_log(debug, f"No {company}-named files anywhere in {owner}/{repo}")
        return None

    _debug_log(debug, f"Recursive scan {owner}/{repo}: {len(audit_files)} {company}-named file(s)")

    file_metadata = _llm_extract_filename_metadata(
        [f["name"] for f in audit_files],
        company,
        debug=debug,
        folder_context=f"{owner}/{repo}",
    )
    source_commit = _resolve_branch_commit(owner, repo, default_branch, debug=debug)

    reports: list[dict[str, Any]] = []
    for f in audit_files:
        name = f["name"]
        meta = _augment_filename_metadata(name, file_metadata.get(name, {}))
        base_name = name.rsplit(".", 1)[0] if "." in name else name
        auditor = str(meta.get("auditor") or "").strip() or "Unknown"
        title = str(meta.get("title") or "").strip() or base_name
        date = str(meta.get("date") or "").strip() or None
        is_pdf = name.lower().endswith(".pdf")
        report_url = f.get("html_url") or f.get("download_url")
        if not is_pdf and report_url:
            report_url = github_blob_to_raw(report_url)
        reports.append(
            {
                "auditor": auditor,
                "title": title,
                "date": date,
                "pdf_url": f["download_url"] if is_pdf else None,
                "report_url": report_url,
                "source_commit": source_commit,
                "source_repo": f"{owner}/{repo}",
                "source_path": f["path"],
            }
        )
    return {"reports": reports, "linked_urls": []}


def _fetch_github_raw(owner: str, repo: str, ref: str, path: str, debug: bool = False) -> str | None:
    """Fetch raw file content from GitHub for markdown/text files."""
    from ._fetch import _BINARY_CONTENT_TYPES, _MAX_DOWNLOAD_BYTES
    from ._urls import _is_pdf_url

    if _is_pdf_url(path):
        _debug_log(debug, f"Skipping raw fetch for PDF: {path}")
        return None

    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    try:
        resp = _requests.get(raw_url, timeout=15, headers={"User-Agent": "PSAT/0.1"})
        if resp.status_code != 200:
            _debug_log(debug, f"GitHub raw {resp.status_code} for {raw_url}")
            return None

        content_type = (resp.headers.get("content-type") or "").lower()
        if any(ct in content_type for ct in _BINARY_CONTENT_TYPES):
            _debug_log(debug, f"Skipping binary GitHub file ({content_type}): {path}")
            return None

        text = resp.text[:_MAX_DOWNLOAD_BYTES]
        _debug_log(debug, f"GitHub raw: fetched {path} ({len(text)} chars)")
        return text

    except _requests.RequestException as exc:
        record_degraded(
            phase="audit_report_github_raw",
            exc=exc,
            context={"owner": owner, "repo": repo, "ref": ref, "path": path},
        )
        _debug_log(debug, f"GitHub raw fetch failed for {raw_url}: {exc!r}")
        return None
