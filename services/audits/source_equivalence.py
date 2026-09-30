"""Prove an audit reviewed the code deployed at an impl: if a reviewed commit's source file is byte-identical to the
verified source, coverage is proven. No compilation needed.

Impl source: DB ``SourceFile`` rows, else Etherscan. Audit source: GitHub raw. Outcomes distinguish each failure mode;
``TRANSIENT_STATUSES`` marks the retryable ones.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Final

import requests

logger = logging.getLogger(__name__)


# Retries run inside the fetch so the hash cache memoizes the post-retry outcome, not a flake; RST bursts from
# raw.githubusercontent.com were becoming permanent ``transport_error``.
_RETRY_ATTEMPTS: Final[int] = 3
_RETRY_INITIAL_BACKOFF: Final[float] = 0.5
_RETRY_BACKOFF_CAP: Final[float] = 10.0
# 404/403/410 stay terminal.
_TRANSIENT_HTTP_STATUS: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})


def _retry_sleep(seconds: float) -> None:
    """±50% jitter; separate so tests can stub the wait."""
    time.sleep(random.uniform(seconds * 0.5, seconds * 1.5))


# Keep in sync with the frontend badge mapping (ProtocolSurface.jsx).
EQUIVALENCE_STATUSES = frozenset(
    {
        "proven",  # ✓ files match byte-for-byte
        "hash_mismatch",  # ✗ files fetched on both sides, content differs
        "commit_not_found_in_repo",  # audit's commit doesn't exist in source_repo
        "candidate_path_missing",  # commit exists; our path guess missed (may be flattened source)
        "etherscan_unverified",  # deployed contract has no verified source
        "etherscan_fetch_failed",  # transient — Etherscan returned 5xx / timeout
        "github_fetch_failed",  # transient — GitHub returned 5xx / timeout
        "no_reviewed_commit",  # audit text had no commit SHA — cannot verify
        "no_source_repo",  # audit.source_repo is NULL — can't look it up
        "not_attempted",  # row predates verification rollout; needs backfill
        "row_vanished",  # concurrent coverage rebuild deleted the row mid-verify
        # Deferred-verification states owned by ``workers.coverage_verify``; stale ``verifying`` reverts to ``pending``.
        "pending",
        "verifying",
    }
)

# The rest are semantic and don't change without new code or re-extraction.
TRANSIENT_STATUSES = frozenset({"etherscan_fetch_failed", "github_fetch_failed"})


_HEX_TOKEN_RE = re.compile(r"\b([0-9a-f]{7,40})\b", re.IGNORECASE)


# Unanchored ``github.com/<owner>/<repo>`` scanner, stopping at the first path boundary.
_GITHUB_REPO_MENTION_RE = re.compile(
    r"github\.com/([A-Za-z0-9][A-Za-z0-9_.-]{0,38})/([A-Za-z0-9][A-Za-z0-9_.-]{0,99})",
    re.IGNORECASE,
)

# So ``github.com/etherfi-protocol/issues/42`` isn't read as repo ``issues``.
_GITHUB_NON_REPO_OWNERS = frozenset(
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
        "notifications",
        "issues",
        "pulls",
        "watching",
        "stars",
        "codespaces",
        "login",
        "join",
        "new",
        "organizations",
        "site",
        "team",
        "contact",
        "customer-stories",
    }
)

_GITHUB_NON_REPO_REPOS = frozenset(
    {
        "issues",
        "pulls",
        "wiki",
        "actions",
        "discussions",
        "releases",
        "tags",
        "commits",
        "blob",
        "tree",
        "raw",
        "compare",
        "branches",
    }
)


def extract_referenced_repos(text: str) -> list[str]:
    """Every ``owner/repo`` mentioned, deduped, lowercased, first-seen.

    Fallbacks for when ``source_repo`` is the auditor's publication repo.
    """
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _GITHUB_REPO_MENTION_RE.finditer(text):
        owner = m.group(1).lower()
        repo = m.group(2).lower()
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        if not repo:
            continue
        if owner in _GITHUB_NON_REPO_OWNERS:
            continue
        if repo in _GITHUB_NON_REPO_REPOS:
            continue
        key = f"{owner}/{repo}"
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def extract_reviewed_commits(text: str) -> list[str]:
    """SHA-like hex tokens, deduped, lowercased, first-seen. Rejects pure digits and all-same-char padding."""
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _HEX_TOKEN_RE.finditer(text):
        token = m.group(1).lower()
        if not any(c in "abcdef" for c in token):
            continue
        if len(set(token)) < 3:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


@dataclass(frozen=True)
class GithubFetch:
    """``content`` only on success; ``status`` separates transient from permanent failures."""

    content: str | None
    status: str
    detail: str


@dataclass(frozen=True)
class EtherscanFetch:
    source: VerifiedSource | None
    status: str
    detail: str


def _hash_source_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifiedSource:
    contract_name: str | None
    compiler_version: str | None
    files: dict[str, str]  # path -> sha256(content)


def fetch_etherscan_source_files(address: str, *, chain_id: int) -> EtherscanFetch:
    """Parsed verified source as path -> sha256 via the same parser discovery uses: ``ok``, ``unverified``, or
    ``fetch_failed``.
    """
    from services.clients.etherscan import get
    from services.discovery.fetch import parse_sources

    try:
        data = get("contract", "getsourcecode", address=address, chain_id=chain_id)
        result = data["result"][0]
    except Exception as exc:
        return EtherscanFetch(source=None, status="fetch_failed", detail=f"etherscan api error: {exc}")

    contract_name = (result.get("ContractName") or "").strip() or None
    compiler_version = (result.get("CompilerVersion") or "").strip() or None
    files = parse_sources(result)
    if not files:
        # Permanent until someone verifies the contract.
        return EtherscanFetch(
            source=None,
            status="unverified",
            detail=f"etherscan has no verified source for {address}",
        )
    hashed = {path: _hash_source_text(content) for path, content in files.items()}
    return EtherscanFetch(
        source=VerifiedSource(
            contract_name=contract_name,
            compiler_version=compiler_version,
            files=hashed,
        ),
        status="ok",
        detail="",
    )


def fetch_db_source_files(session: Any, contract_id: int) -> VerifiedSource | None:
    """Source from persisted ``SourceFile`` rows; ``None`` if not yet analyzed."""
    from db.models import Contract
    from db.queue import get_source_files

    contract = session.get(Contract, contract_id)
    if contract is None or contract.job_id is None:
        return None
    try:
        files = get_source_files(session, contract.job_id)
    except Exception as exc:
        # A clean miss (caller falls back), so no record_degraded.
        logger.warning(
            "DB source file fetch failed for contract %s: %s",
            contract_id,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return None
    if not files:
        return None
    hashed = {path: _hash_source_text(content) for path, content in files.items()}
    return VerifiedSource(
        contract_name=contract.contract_name,
        compiler_version=contract.compiler_version,
        files=hashed,
    )


def fetch_contract_source(session: Any, contract_id: int) -> EtherscanFetch:
    """DB-first, wrapped in the same ``EtherscanFetch`` envelope."""
    from db.models import Contract

    db_source = fetch_db_source_files(session, contract_id)
    if db_source is not None:
        return EtherscanFetch(source=db_source, status="ok", detail="")
    contract = session.get(Contract, contract_id)
    if contract is None or not contract.address:
        return EtherscanFetch(
            source=None,
            status="fetch_failed",
            detail=f"contract {contract_id} has no address",
        )
    from utils.chains import require_chain

    # NULL chain is legacy mainnet; an unknown named chain fails loud.
    return fetch_etherscan_source_files(
        contract.address,
        chain_id=require_chain(
            chain=contract.chain or "ethereum", context="source-equivalence etherscan fetch"
        ).chain_id,
    )


# Legacy shape; prefer ``fetch_contract_source``.
def fetch_contract_source_files(session: Any, contract_id: int) -> VerifiedSource | None:
    return fetch_contract_source(session, contract_id).source


def _fetch_github_raw(url: str, token: str | None) -> GithubFetch:
    """Fetch a raw URL with diagnostics, retrying transient failures before the hash cache memoizes the outcome, so
    one RST burst can't poison a URL for the process lifetime.
    """
    headers = {"User-Agent": "PSAT-source-equivalence/0.1"}
    if token:
        headers["Authorization"] = f"token {token}"

    backoff = _RETRY_INITIAL_BACKOFF
    last_transport_exc: requests.RequestException | None = None
    last_5xx_status: int | None = None

    for attempt in range(_RETRY_ATTEMPTS):
        last_attempt = attempt == _RETRY_ATTEMPTS - 1
        try:
            r = requests.get(url, headers=headers, timeout=15)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_transport_exc = exc
            if last_attempt:
                logger.warning("github raw fetch failed for %s: %s", url, exc)
                return GithubFetch(content=None, status="transport_error", detail=str(exc))
            logger.warning(
                "github raw fetch transient %s for %s, retrying in %.1fs (attempt %d/%d)",
                type(exc).__name__,
                url,
                backoff,
                attempt + 1,
                _RETRY_ATTEMPTS,
            )
            _retry_sleep(backoff)
            backoff = min(backoff * 2, _RETRY_BACKOFF_CAP)
            continue
        except requests.RequestException as exc:
            # Not a transport flake; retry won't help.
            logger.warning("github raw fetch failed for %s: %s", url, exc)
            return GithubFetch(content=None, status="transport_error", detail=str(exc))

        if r.status_code in _TRANSIENT_HTTP_STATUS and not last_attempt:
            last_5xx_status = r.status_code
            logger.warning(
                "github raw fetch HTTP %d for %s, retrying in %.1fs (attempt %d/%d)",
                r.status_code,
                url,
                backoff,
                attempt + 1,
                _RETRY_ATTEMPTS,
            )
            _retry_sleep(backoff)
            backoff = min(backoff * 2, _RETRY_BACKOFF_CAP)
            continue

        if r.status_code == 404:
            return GithubFetch(content=None, status="http_404", detail=f"{url}: 404")
        if 500 <= r.status_code < 600:
            return GithubFetch(content=None, status="http_5xx", detail=f"{url}: {r.status_code}")
        if r.status_code != 200:
            return GithubFetch(
                content=None,
                status="http_other",
                detail=f"{url}: {r.status_code}",
            )

        # Guards against a path colliding with a PDF or similar.
        ct = (r.headers.get("content-type") or "").lower()
        if ct and "text" not in ct and "application/octet-stream" not in ct:
            return GithubFetch(
                content=None,
                status="content_type_rejected",
                detail=f"{url}: content-type {ct!r} not source",
            )
        if len(r.content) > 5 * 1024 * 1024:
            return GithubFetch(
                content=None,
                status="size_cap_exceeded",
                detail=f"{url}: {len(r.content)} bytes > 5MB",
            )
        return GithubFetch(content=r.text, status="ok", detail="")

    if last_transport_exc is not None:
        return GithubFetch(content=None, status="transport_error", detail=str(last_transport_exc))
    assert last_5xx_status is not None  # one branch must have set this
    return GithubFetch(content=None, status="http_5xx", detail=f"{url}: {last_5xx_status}")


@dataclass(frozen=True)
class GithubHashResult:
    sha256: str | None
    status: str  # mirrors GithubFetch.status
    detail: str


def _coerce_github_hash_result(result: Any) -> GithubHashResult:
    if isinstance(result, GithubHashResult):
        return result
    if isinstance(result, str):
        return GithubHashResult(sha256=result, status="ok", detail="")
    if result is None:
        return GithubHashResult(sha256=None, status="http_404", detail="not found")
    status = getattr(result, "status", None)
    detail = getattr(result, "detail", "")
    sha256 = getattr(result, "sha256", None)
    if status is not None:
        return GithubHashResult(sha256=sha256, status=str(status), detail=str(detail))
    raise TypeError(f"unsupported github hash result type: {type(result).__name__}")


@functools.lru_cache(maxsize=4096)
def _fetch_github_raw_hash(url: str, token: str | None) -> GithubHashResult:
    """Process-global memoized hash, keyed by ``(url, token)``, capped at 4096.

    Stores only the sha256 and status so the cap is a real memory bound; terminal failures are cached too.
    """
    fetch = _fetch_github_raw(url, token)
    if fetch.content is None:
        return GithubHashResult(sha256=None, status=fetch.status, detail=fetch.detail)
    return GithubHashResult(sha256=_hash_source_text(fetch.content), status="ok", detail="")


def fetch_github_source_hash(repo: str, commit: str, path: str, *, token: str | None = None) -> GithubHashResult:
    """``http_404`` alone is ambiguous: the caller maps it to commit-not-found or path-missing."""
    if not (repo and commit and path):
        return GithubHashResult(
            sha256=None,
            status="invalid_input",
            detail=f"repo/commit/path required (got {repo!r},{commit!r},{path!r})",
        )
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
    return _fetch_github_raw_hash(url, token)


def _commit_exists_in_repo(repo: str, commit: str, *, token: str | None = None) -> GithubHashResult:
    """Whether a commit resolves in ``repo``, probing ``README.md`` at the ref, to tell a bad SHA from a path miss.

    A repo without a README degrades the diagnosis.
    """
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/README.md"
    return _fetch_github_raw_hash(url, token)


def _candidate_paths_for_name(name: str, etherscan_paths: list[str]) -> list[str]:
    """Etherscan paths verbatim (real layout), falling back to ``src/`` / ``contracts/`` for flattened verification."""
    name_lc = name.lower()
    matches = [p for p in etherscan_paths if p.rsplit("/", 1)[-1].lower() in (f"{name_lc}.sol", f"{name_lc}.vy")]
    if matches:
        return matches
    return [f"src/{name}.sol", f"contracts/{name}.sol"]


@dataclass(frozen=True)
class EquivalenceMatch:
    commit: str
    scope_name: str
    etherscan_path: str
    source_sha256: str


@dataclass(frozen=True)
class EquivalenceOutcome:
    status: str
    reason: str
    matches: tuple[EquivalenceMatch, ...] = field(default_factory=tuple)


def verify_audit_covers_impl(
    *,
    reviewed_commits: list[str],
    scope_name: str,
    impl_source: VerifiedSource,
    source_repo: str | None,
    github_token: str | None = None,
    specific_commit: str | None = None,
    fallback_repos: list[str] | None = None,
) -> EquivalenceOutcome:
    """Verify one audit reviewed one contract (``scope_name``), scoped so the reason describes this row.

    ``specific_commit`` narrows to the auditor-pinned SHA. ``fallback_repos`` are tried when ``source_repo`` lacks the
    commit (auditors often publish in a different repo).

    Statuses: ``proven``, ``hash_mismatch``, ``commit_not_found_in_repo``, ``candidate_path_missing``,
    ``github_fetch_failed``, ``no_reviewed_commit`` / ``no_source_repo``.
    """
    if specific_commit:
        reviewed_commits = [specific_commit]

    if not reviewed_commits:
        return EquivalenceOutcome(
            status="no_reviewed_commit",
            reason="audit has no parseable commit SHAs",
        )

    candidate_repos: list[str] = []
    seen_repos: set[str] = set()
    if source_repo:
        candidate_repos.append(source_repo)
        seen_repos.add(source_repo.lower())
    for repo in fallback_repos or []:
        key = repo.lower()
        if key in seen_repos:
            continue
        seen_repos.add(key)
        candidate_repos.append(repo)

    if not candidate_repos:
        return EquivalenceOutcome(
            status="no_source_repo",
            reason="audit has no source_repo or fallback repos",
        )

    # proven > hash_mismatch > candidate_path_missing > github_fetch_failed > commit_not_found_in_repo, so a real
    # mismatch isn't masked by another repo's 404.
    outcome_rank = {
        "proven": 5,
        "hash_mismatch": 4,
        "candidate_path_missing": 3,
        "github_fetch_failed": 2,
        "commit_not_found_in_repo": 1,
    }
    best: EquivalenceOutcome | None = None
    for repo in candidate_repos:
        outcome = _verify_single_repo(
            reviewed_commits=reviewed_commits,
            scope_name=scope_name,
            impl_source=impl_source,
            source_repo=repo,
            github_token=github_token,
        )
        if outcome.status == "proven":
            return outcome
        if best is None or outcome_rank.get(outcome.status, 0) > outcome_rank.get(best.status, 0):
            best = outcome
    assert best is not None
    return best


def _verify_single_repo(
    *,
    reviewed_commits: list[str],
    scope_name: str,
    impl_source: VerifiedSource,
    source_repo: str,
    github_token: str | None = None,
) -> EquivalenceOutcome:
    if not impl_source.files:
        return EquivalenceOutcome(
            status="etherscan_unverified",
            reason="impl source has no files",
        )
    if not scope_name:
        return EquivalenceOutcome(
            status="no_reviewed_commit",
            reason="no scope_name provided",
        )

    etherscan_paths = list(impl_source.files.keys())
    candidate_paths = _candidate_paths_for_name(scope_name, etherscan_paths)

    matches: list[EquivalenceMatch] = []
    any_commit_resolved = False  # at least one commit had *anything* resolve → not commit_not_found_overall
    any_hash_mismatch = False  # files on both sides, content differs
    any_transient = False  # saw a 5xx / transport err → retry later
    details: list[str] = []

    # Parallel over (commit × path): serial fetching cost ~100 round-trips per scope name. Pairs without an Etherscan
    # path are skipped so ``candidate_path_missing`` stays accurate.
    from services.concurrency import parallel_map

    fetch_pairs: list[tuple[str, str]] = []
    for commit in reviewed_commits:
        for path in candidate_paths:
            if not impl_source.files.get(path):
                continue
            fetch_pairs.append((commit, path))

    fetch_results: dict[tuple[str, str], object] = {}
    if fetch_pairs:
        results = parallel_map(
            lambda pair: fetch_github_source_hash(source_repo, pair[0], pair[1], token=github_token),
            fetch_pairs,
        )
        for pair, outcome in results:
            fetch_results[pair] = outcome

    # Replayed per commit so classification matches the serial version.
    for commit in reviewed_commits:
        commit_hit_anything = False
        commit_had_transient = False
        commit_had_404 = False
        for path in candidate_paths:
            etherscan_hash = impl_source.files.get(path)
            if not etherscan_hash:
                continue
            raw_outcome = fetch_results.get((commit, path))
            if isinstance(raw_outcome, BaseException):
                # Crashes count as transport errors, as the serial path did.
                commit_had_transient = True
                any_transient = True
                details.append(f"{commit[:8]} {path}: crash: {raw_outcome}")
                continue
            gh = _coerce_github_hash_result(raw_outcome)
            if gh.status == "ok" and gh.sha256 is not None:
                commit_hit_anything = True
                if gh.sha256 == etherscan_hash:
                    matches.append(
                        EquivalenceMatch(
                            commit=commit,
                            scope_name=scope_name,
                            etherscan_path=path,
                            source_sha256=etherscan_hash,
                        )
                    )
                else:
                    any_hash_mismatch = True
                    details.append(f"{commit[:8]} {path}: github={gh.sha256[:8]} etherscan={etherscan_hash[:8]}")
            elif gh.status == "http_404":
                commit_had_404 = True
            elif gh.status in ("http_5xx", "transport_error"):
                commit_had_transient = True
                any_transient = True
                details.append(f"{commit[:8]} {path}: {gh.detail}")

        if commit_hit_anything:
            any_commit_resolved = True
        elif commit_had_404 and not commit_had_transient:
            # Probe the repo root to tell a missing commit from a missing path.
            probe = _commit_exists_in_repo(source_repo, commit, token=github_token)
            if probe.status == "ok":
                any_commit_resolved = True

    if matches:
        return EquivalenceOutcome(
            status="proven",
            reason=f"{len(matches)} file(s) match across {len(set(m.commit for m in matches))} commit(s)",
            matches=tuple(matches),
        )

    if any_hash_mismatch:
        return EquivalenceOutcome(
            status="hash_mismatch",
            reason="; ".join(details[:3]) or f"files differ for {scope_name}",
        )

    if not any_commit_resolved:
        if any_transient:
            return EquivalenceOutcome(
                status="github_fetch_failed",
                reason="; ".join(details[:3]) or "GitHub transient failures during commit probe",
            )
        return EquivalenceOutcome(
            status="commit_not_found_in_repo",
            reason=f"none of {len(reviewed_commits)} commit(s) resolve in {source_repo}",
        )

    # Usually Etherscan's layout differs from GitHub's.
    return EquivalenceOutcome(
        status="candidate_path_missing",
        reason=f"commits exist; candidate paths ({candidate_paths}) not in repo",
    )
