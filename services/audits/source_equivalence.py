"""Prove an audit reviewed the code currently deployed at an impl address.

Forensic complement to temporal matching: if the audit PDF mentions commit
X and commit X's source is byte-identical to the impl's Etherscan-verified
source, the audit's coverage of that impl is proven. Source-text equality
is sufficient — no compilation step needed.

Impl source: DB ``SourceFile`` rows first (populated by the static worker),
Etherscan ``getsourcecode`` fallback. Audit source: GitHub raw, keyed on
``source_repo`` + ``reviewed_commits``.

Verification returns an ``EquivalenceOutcome`` that distinguishes
"proven" from each of several failure modes, so callers can persist a
specific status + reason rather than silently treating every failure as
"not verified". Status vocabulary lives in ``EQUIVALENCE_STATUSES``;
transient vs. permanent split in ``TRANSIENT_STATUSES`` so a retry sweep
knows what's worth re-running.
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


# ---------------------------------------------------------------------------
# Retry policy for transient GitHub raw fetches.
#
# Same shape as services.audits.text_extraction: prod observed bursts of
# ConnectionResetError(104) hammering raw.githubusercontent.com that turned
# every flake into a permanent ``transport_error``. Retry runs *inside* the
# fetch worker so its post-retry outcome — not a flake — is what the
# hash-level cache (``_fetch_github_raw_hash``) memoizes for the run.
# ---------------------------------------------------------------------------
_RETRY_ATTEMPTS: Final[int] = 3
_RETRY_INITIAL_BACKOFF: Final[float] = 0.5
_RETRY_BACKOFF_CAP: Final[float] = 10.0
# 408/429 are transient by spec; 5xx is the HTTP analogue of an RST.
# 404/403/410 stay terminal — refetching won't materialize a missing file.
_TRANSIENT_HTTP_STATUS: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})


def _retry_sleep(seconds: float) -> None:
    """Sleep ``seconds`` with ±50% jitter. Factored out so unit tests can
    stub the wall-clock wait without monkeypatching the whole ``time``
    module — tests under ``TestFetchGithubRawRetry`` rely on this.
    """
    time.sleep(random.uniform(seconds * 0.5, seconds * 1.5))


# ---------------------------------------------------------------------------
# Status vocabulary
# ---------------------------------------------------------------------------

# Every coverage row's ``equivalence_status`` is one of these. Keep in sync
# with the UI badge mapping in the frontend (ProtocolSurface.jsx).
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

        # Deferred-verification states owned by ``workers.coverage_verify``.
        # ``pending`` is the initial state coverage refresh writes for any
        # row that *could* be verified later (audit has reviewed_commits +
        # at least one repo). ``verifying`` is the in-flight sentinel the
        # worker stamps while running the HTTP probe — stale recovery
        # reverts it back to ``pending`` after a timeout.
        "pending",
        "verifying",
    }
)

# Subset of statuses where a retry might plausibly succeed (network /
# rate-limit failures). The rest are semantic — hash_mismatch stays
# hash_mismatch until code changes on one side, no_reviewed_commit stays
# until the PDF text is re-extracted, etc.
TRANSIENT_STATUSES = frozenset({"etherscan_fetch_failed", "github_fetch_failed"})


# ---------------------------------------------------------------------------
# Reviewed-commit extraction
# ---------------------------------------------------------------------------


# 7-40 char hex tokens: 7 is git's abbrev default, 40 is a full SHA.
_HEX_TOKEN_RE = re.compile(r"\b([0-9a-f]{7,40})\b", re.IGNORECASE)


# GitHub repo URL scanner for full-text PDF scraping (Phase D).
# Matches ``github.com/<owner>/<repo>`` with common surrounding punctuation.
# Non-anchored — scans body text for occurrences anywhere. Accepts optional
# trailing ``.git``, ``/tree/...``, ``/blob/...``, ``/pull/...`` etc. and
# stops at the first path boundary after owner/repo.
_GITHUB_REPO_MENTION_RE = re.compile(
    r"github\.com/([A-Za-z0-9][A-Za-z0-9_.-]{0,38})/([A-Za-z0-9][A-Za-z0-9_.-]{0,99})",
    re.IGNORECASE,
)

# Common GitHub paths under ``github.com/<owner>/`` that aren't protocol
# repos — profile pages, issue tracker, etc. Exclude to avoid false-matching
# a URL like ``github.com/etherfi-protocol/issues/42`` as repo ``issues``.
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
    """Pull every ``github.com/<owner>/<repo>`` reference from audit text.

    Returns deduped ``"owner/repo"`` strings, lowercased, first-seen order.
    Used by source-equivalence as fallback candidates when the primary
    ``AuditReport.source_repo`` doesn't contain the audit's reviewed commit
    — common when discovery recorded the auditor's publication repo instead
    of the protocol's own. Skips obvious GitHub-system paths (``issues``,
    ``pulls``, user profile URLs, etc.).
    """
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _GITHUB_REPO_MENTION_RE.finditer(text):
        owner = m.group(1).lower()
        repo = m.group(2).lower()
        # Strip trailing .git that the regex allowed through.
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
    """Pull commit-SHA-like hex tokens from audit PDF text.

    Deduped, lowercased, first-seen order. Pure-digit tokens (block
    numbers) and all-same-char tokens (``0000000``, ``ffffffff``) are
    rejected as noise. No GitHub validation — the caller decides.
    """
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _HEX_TOKEN_RE.finditer(text):
        token = m.group(1).lower()
        # Require at least one hex letter so we don't catch block numbers,
        # issue IDs, etc. that happen to be 7+ chars of digits.
        if not any(c in "abcdef" for c in token):
            continue
        # Reject all-same-char tokens (0000000, aaaaaaa, ffffffff) — common
        # padding / placeholder strings.
        if len(set(token)) < 3:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


# ---------------------------------------------------------------------------
# Fetch diagnostics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GithubFetch:
    """Outcome of a single GitHub raw fetch.

    ``content`` is non-None only on success. ``status`` + ``detail``
    distinguish transient transport failures (``http_5xx``,
    ``transport_error``) from permanent ones (``http_404``,
    ``content_type_rejected``, ``size_cap_exceeded``) so the orchestrator
    can emit the right EQUIVALENCE_STATUS.
    """

    content: str | None
    # "ok" | "http_404" | "http_5xx" | "http_other" | "transport_error"
    # | "content_type_rejected" | "size_cap_exceeded"
    status: str
    detail: str


@dataclass(frozen=True)
class EtherscanFetch:
    """Outcome of an Etherscan verified-source fetch.

    ``source`` is non-None only when ``status == 'ok'``. ``status`` is
    one of ``'ok'`` (verified source parsed), ``'unverified'`` (Etherscan
    returned the empty-source sentinel), ``'fetch_failed'`` (API error,
    transient).
    """

    source: VerifiedSource | None
    # "ok" | "unverified" | "fetch_failed"
    status: str
    detail: str


# ---------------------------------------------------------------------------
# Etherscan source fetch
# ---------------------------------------------------------------------------


def _hash_source_text(text: str) -> str:
    """Stable hash of a source file's content for equality comparison."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifiedSource:
    """Parsed Etherscan verified-source response for one address."""

    contract_name: str | None
    compiler_version: str | None
    files: dict[str, str]  # path -> sha256(content)


def fetch_etherscan_source_files(address: str) -> EtherscanFetch:
    """Return parsed verified-source for ``address`` as file-path→sha256.

    Delegates parsing to ``services.discovery.fetch.parse_sources`` — the
    same function the discovery worker uses when persisting source to the
    DB. Distinguishes three outcomes: parsed (``ok``), contract-not-verified
    (``unverified``), transport/API failure (``fetch_failed``).
    """
    from services.discovery.fetch import parse_sources
    from utils.etherscan import get

    try:
        data = get("contract", "getsourcecode", address=address)
        result = data["result"][0]
    except Exception as exc:
        return EtherscanFetch(source=None, status="fetch_failed", detail=f"etherscan api error: {exc}")

    contract_name = (result.get("ContractName") or "").strip() or None
    compiler_version = (result.get("CompilerVersion") or "").strip() or None
    files = parse_sources(result)
    if not files:
        # Etherscan returns empty SourceCode when the address has no verified
        # source. This is a permanent status until someone submits verification.
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
    """Return a Contract's verified source from ``SourceFile`` rows.

    Reuses what the discovery worker already persisted (keyed on
    ``Contract.job_id``) to avoid an Etherscan round-trip. Returns ``None``
    when the contract hasn't been analyzed yet — caller falls back to
    ``fetch_etherscan_source_files``.
    """
    from db.models import Contract
    from db.queue import get_source_files

    contract = session.get(Contract, contract_id)
    if contract is None or contract.job_id is None:
        return None
    try:
        files = get_source_files(session, contract.job_id)
    except Exception as exc:
        # Caller falls back to fetch_etherscan_source_files; the empty return is a
        # clean miss, not a degraded outcome — level audit only, no record_degraded.
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
    """DB-first resolver: try ``SourceFile`` rows, fall back to Etherscan.

    Wraps the DB result in the same ``EtherscanFetch`` envelope the
    Etherscan call returns so the orchestrator handles one shape. DB-hit
    becomes ``status='ok'`` with ``detail=''``.
    """
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
    return fetch_etherscan_source_files(contract.address)


# Kept for backwards compatibility with callers expecting the old
# VerifiedSource | None shape. Prefer ``fetch_contract_source`` in new code.
def fetch_contract_source_files(session: Any, contract_id: int) -> VerifiedSource | None:
    return fetch_contract_source(session, contract_id).source


# ---------------------------------------------------------------------------
# GitHub source fetch
# ---------------------------------------------------------------------------


def _fetch_github_raw(url: str, token: str | None) -> GithubFetch:
    """Fetch a GitHub raw URL, returning a diagnostic-rich outcome.

    The full body is returned here but not memoized; the process-global
    cache lives one level up in :func:`_fetch_github_raw_hash`, which keeps
    only the content hash. Retries transient transport flakes
    (``ConnectionError``, ``Timeout``) and transient HTTP statuses
    (408/429/5xx) with jittered exponential backoff *before* the hash-level
    cache memoizes the outcome — so a single RST burst can't poison a URL
    for the worker's process lifetime.
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
            # SSLError / InvalidURL / etc. — not transport flakes, retry won't help.
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

        # Reject likely binary or huge responses — source files are plain text
        # and shouldn't exceed a few hundred KB. This guards against a repo
        # path collision with a PDF or similar.
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

    # Loop fell through: every attempt was transient. Surface the most
    # recent failure shape so callers can distinguish transport vs 5xx.
    if last_transport_exc is not None:
        return GithubFetch(content=None, status="transport_error", detail=str(last_transport_exc))
    assert last_5xx_status is not None  # one branch must have set this
    return GithubFetch(content=None, status="http_5xx", detail=f"{url}: {last_5xx_status}")


@dataclass(frozen=True)
class GithubHashResult:
    """Hash of a file at a specific (repo, commit, path), or a failure detail."""

    sha256: str | None
    status: str  # mirrors GithubFetch.status
    detail: str


def _coerce_github_hash_result(result: Any) -> GithubHashResult:
    """Backward-compat for legacy test stubs that return bare hashes/None."""
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
    """Memoized content hash for ``url`` — the process-global GitHub cache.

    Keyed by ``(url, token)`` and capped at 4096 entries by ``lru_cache``.
    Stores only the sha256 (plus the fetch status/detail), never the body,
    so each row is a fixed ~100 bytes regardless of file size and the entry
    cap is a real memory bound. The full text from :func:`_fetch_github_raw`
    is hashed and discarded here. Terminal failures (404, content-type/size
    rejects, exhausted retries) cache their status too, so a known outcome
    is a single lookup per run.
    """
    fetch = _fetch_github_raw(url, token)
    if fetch.content is None:
        return GithubHashResult(sha256=None, status=fetch.status, detail=fetch.detail)
    return GithubHashResult(sha256=_hash_source_text(fetch.content), status="ok", detail="")


def fetch_github_source_hash(repo: str, commit: str, path: str, *, token: str | None = None) -> GithubHashResult:
    """Hash the file at ``github.com/<repo>/<commit>/<path>``.

    Returns a ``GithubHashResult``: ``sha256`` is set on ``status='ok'``,
    ``None`` otherwise. The caller maps the status to the appropriate
    ``EQUIVALENCE_STATUS`` (e.g. ``http_404`` alone is ambiguous — it
    could be ``commit_not_found_in_repo`` or ``candidate_path_missing``
    depending on whether the commit itself resolved).
    """
    if not (repo and commit and path):
        return GithubHashResult(
            sha256=None,
            status="invalid_input",
            detail=f"repo/commit/path required (got {repo!r},{commit!r},{path!r})",
        )
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
    return _fetch_github_raw_hash(url, token)


def _commit_exists_in_repo(repo: str, commit: str, *, token: str | None = None) -> GithubHashResult:
    """Probe whether a commit resolves in ``repo``.

    Fetches the repo's root tree at the commit ref — one URL, returns a
    success/failure diagnostic (``status == 'ok'`` ⇔ the commit resolves).
    Used to distinguish a real "commit not found" (bad SHA / force-push)
    from a "commit exists but this file isn't in it" (path miss).

    Hits ``raw.githubusercontent.com/<repo>/<commit>/README.md`` as a
    cheap probe. If the repo has no README (uncommon) this still reports
    ``http_404`` which degrades the diagnosis — acceptable edge case.
    """
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/README.md"
    return _fetch_github_raw_hash(url, token)


# ---------------------------------------------------------------------------
# Candidate path generation
# ---------------------------------------------------------------------------


def _candidate_paths_for_name(name: str, etherscan_paths: list[str]) -> list[str]:
    """Paths in Etherscan's source that plausibly correspond to ``name``.

    Prefers Etherscan paths verbatim (they carry the project's actual
    layout); falls back to conventional ``src/`` / ``contracts/`` when the
    bundle doesn't include a matching name (flattened verification).
    """
    name_lc = name.lower()
    matches = [p for p in etherscan_paths if p.rsplit("/", 1)[-1].lower() in (f"{name_lc}.sol", f"{name_lc}.vy")]
    if matches:
        return matches
    return [f"src/{name}.sol", f"contracts/{name}.sol"]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EquivalenceMatch:
    """Proof that audit at commit X reviewed the source file at path Y."""

    commit: str
    scope_name: str
    etherscan_path: str
    source_sha256: str


@dataclass(frozen=True)
class EquivalenceOutcome:
    """Verdict for one (audit, matched_name) verification attempt.

    ``status`` is one of ``EQUIVALENCE_STATUSES``. ``reason`` is a short
    human string. ``matches`` is non-empty only when ``status='proven'``.
    """

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
    """Verify one audit reviewed one specific contract (by ``scope_name``).

    Scoped per ``scope_name`` — NOT the full audit scope — so the returned
    reason describes what actually happened for the coverage row being
    verified (fixes a reviewer-flagged bug where mismatched Vault files
    could show up as the reason for a Pool row).

    ``specific_commit`` (Phase F) narrows verification to exactly that
    commit, ignoring the broader ``reviewed_commits`` list. Used when the
    audit's scope table pinned a specific reviewed commit to this contract
    — so ``hash_mismatch`` means "the auditor-declared commit's file
    differs" rather than "one of many SHAs in the PDF differs." Tighter
    signal, same verifier machinery.

    ``fallback_repos`` (Phase D) is a list of additional ``owner/repo``
    candidates to try when ``source_repo`` returns ``commit_not_found_in_repo``
    or ``no_source_repo``. The auditor often publishes in one repo
    (e.g. ``Cyfrin/cyfrin-audit-reports``) but reviewed code from a
    different repo (the protocol's own). The fallback list is typically
    the ``referenced_repos`` field on ``AuditReport`` — every repo the
    PDF text mentioned. First repo that produces a better outcome wins.

    Returns an ``EquivalenceOutcome``:
    - ``proven`` — at least one (commit, path) pair matched byte-for-byte
    - ``hash_mismatch`` — both sides returned content, hashes differ
    - ``commit_not_found_in_repo`` — every commit 404s in every tried repo
    - ``candidate_path_missing`` — commits exist; no candidate path found on GitHub
    - ``github_fetch_failed`` — 5xx / transport error on every attempted fetch
    - ``no_reviewed_commit`` / ``no_source_repo`` — fast-fails
    """
    # specific_commit overrides the list when provided — verify against
    # exactly that one SHA.
    if specific_commit:
        reviewed_commits = [specific_commit]

    if not reviewed_commits:
        return EquivalenceOutcome(
            status="no_reviewed_commit",
            reason="audit has no parseable commit SHAs",
        )

    # Assemble the candidate repo list: source_repo first (preserves
    # legacy call sites), then the referenced_repos fallback. Dedupe
    # while preserving order.
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

    # Try each repo. Outcome priority when no proof is found:
    #   proven > hash_mismatch > candidate_path_missing > github_fetch_failed
    #         > commit_not_found_in_repo
    # The first proven wins immediately; otherwise keep the strongest
    # negative signal for the final verdict. Avoids masking a real
    # hash_mismatch (found the code, it differs) behind a 404 from a
    # different repo we also happened to try.
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
    """Per-repo verification — the original single-repo logic extracted so
    the multi-repo wrapper can iterate. Returns the status describing what
    happened with THIS specific repo.
    """
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

    # Accumulate evidence across (commit, path) attempts. We can prove on
    # the first match and short-circuit; otherwise we need to summarize
    # the most diagnostic failure.
    matches: list[EquivalenceMatch] = []
    any_commit_resolved = False  # at least one commit had *anything* resolve → not commit_not_found_overall
    any_hash_mismatch = False  # files on both sides, content differs
    any_transient = False  # saw a 5xx / transport err → retry later
    details: list[str] = []

    # Flatten the (commit × path) cross-product into one parallel fetch.
    # Each ``fetch_github_source_hash`` is an independent HTTP call; the
    # prior nested loop walked the cross-product serially so a wide audit
    # paid one RTT per pair (5 commits × 20 paths = 100 sequential GitHub
    # round-trips per scope name). Skips pairs whose Etherscan path is
    # missing so ``candidate_path_missing`` stays accurate.
    from utils.concurrency import parallel_map

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

    # Replay the per-commit branching logic against the pre-fetched results.
    # ``commit_hit_anything`` / ``commit_had_404`` / ``commit_had_transient``
    # are still reasoned about per-commit so the negative-signal classification
    # below stays identical to the prior sequential implementation.
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
                # Treat fetch crashes the same as transport errors so the
                # parallel path can't escalate a failure mode the serial
                # path would have caught.
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
            # http_other / content_type_rejected / size_cap_exceeded: treat as 404-ish

        if commit_hit_anything:
            any_commit_resolved = True
        elif commit_had_404 and not commit_had_transient:
            # Every candidate path 404'd for this commit. Differentiate
            # "commit doesn't exist" from "commit exists but path missing"
            # by probing the repo root at the commit.
            probe = _commit_exists_in_repo(source_repo, commit, token=github_token)
            if probe.status == "ok":
                # Commit resolves — just our candidate paths didn't match.
                any_commit_resolved = True

    # Proof wins over everything.
    if matches:
        return EquivalenceOutcome(
            status="proven",
            reason=f"{len(matches)} file(s) match across {len(set(m.commit for m in matches))} commit(s)",
            matches=tuple(matches),
        )

    # No proof. Classify the strongest negative signal.
    if any_hash_mismatch:
        # Files exist on both sides but differ. Strong negative evidence.
        return EquivalenceOutcome(
            status="hash_mismatch",
            reason="; ".join(details[:3]) or f"files differ for {scope_name}",
        )

    if not any_commit_resolved:
        # Every commit's probe 404'd. Audit reference rot / wrong repo.
        if any_transient:
            return EquivalenceOutcome(
                status="github_fetch_failed",
                reason="; ".join(details[:3]) or "GitHub transient failures during commit probe",
            )
        return EquivalenceOutcome(
            status="commit_not_found_in_repo",
            reason=f"none of {len(reviewed_commits)} commit(s) resolve in {source_repo}",
        )

    # Commits resolve, but our candidate paths for ``scope_name`` never hit.
    # Most common cause: Etherscan's layout doesn't match GitHub's, or the
    # contract is in a subpath our heuristic doesn't guess.
    return EquivalenceOutcome(
        status="candidate_path_missing",
        reason=f"commits exist; candidate paths ({candidate_paths}) not in repo",
    )


def check_audit_covers_impl(
    *,
    reviewed_commits: list[str],
    scope_contracts: list[str],
    impl_source: VerifiedSource,
    source_repo: str | None,
    github_token: str | None = None,
) -> list[EquivalenceMatch]:
    """Legacy multi-scope wrapper: tries every scope name, returns all proven
    matches as a flat list.

    Kept for test and script callers that still iterate the whole audit
    scope. Prefer ``verify_audit_covers_impl`` (single-name, structured
    outcome) in new code — the row-level statuses on
    ``audit_contract_coverage`` need per-name scoping to be accurate.
    """
    if not scope_contracts:
        return []
    out: list[EquivalenceMatch] = []
    for name in scope_contracts:
        outcome = verify_audit_covers_impl(
            reviewed_commits=reviewed_commits,
            scope_name=name,
            impl_source=impl_source,
            source_repo=source_repo,
            github_token=github_token,
        )
        out.extend(outcome.matches)
    return out


def check_audit_row_covers_contract(
    session: Any,
    audit_id: int,
    contract_id: int,
    *,
    github_token: str | None = None,
) -> list[EquivalenceMatch]:
    """DB-bound wrapper returning proven matches as a flat list.

    Prefer ``verify_audit_row_covers_contract`` in new code — returns a
    structured outcome so the row-level status can be persisted.
    """
    outcome = verify_audit_row_covers_contract(session, audit_id, contract_id, github_token=github_token)
    return list(outcome.matches)


def verify_audit_row_covers_contract(
    session: Any,
    audit_id: int,
    contract_id: int,
    *,
    matched_name: str | None = None,
    github_token: str | None = None,
) -> EquivalenceOutcome:
    """DB-bound single-name verification: resolve inputs, delegate to
    ``verify_audit_covers_impl``.

    When ``matched_name`` is ``None``, falls back to "first scope entry"
    for backwards compatibility with callers that don't track matched_name.
    New coverage.py passes the ``CoverageMatch.matched_name`` explicitly
    so the returned status/reason actually pertains to the row being
    persisted.
    """
    from db.models import AuditReport, Contract

    audit = session.get(AuditReport, audit_id)
    contract = session.get(Contract, contract_id)
    if audit is None or contract is None:
        return EquivalenceOutcome(status="not_attempted", reason="audit or contract row missing")

    commits = list(audit.reviewed_commits or [])
    scope = list(audit.scope_contracts or [])
    repo = audit.source_repo
    fallback_repos = list(audit.referenced_repos or [])
    if not commits:
        return EquivalenceOutcome(status="no_reviewed_commit", reason="audit has no reviewed_commits")
    if not repo and not fallback_repos:
        return EquivalenceOutcome(status="no_source_repo", reason="audit has no source_repo or referenced_repos")
    if not contract.address:
        return EquivalenceOutcome(status="not_attempted", reason="contract has no address")

    name = matched_name or (scope[0] if scope else "")
    if not name:
        return EquivalenceOutcome(status="no_reviewed_commit", reason="no matched_name and empty scope")

    fetch = fetch_contract_source(session, contract_id)
    if fetch.status == "unverified":
        return EquivalenceOutcome(status="etherscan_unverified", reason=fetch.detail)
    if fetch.status == "fetch_failed":
        return EquivalenceOutcome(status="etherscan_fetch_failed", reason=fetch.detail)
    if fetch.source is None:
        # Belt-and-suspenders: ok status should always carry a source.
        return EquivalenceOutcome(status="etherscan_fetch_failed", reason="empty source")

    return verify_audit_covers_impl(
        reviewed_commits=commits,
        scope_name=name,
        impl_source=fetch.source,
        source_repo=repo,
        github_token=github_token,
        fallback_repos=fallback_repos,
    )
