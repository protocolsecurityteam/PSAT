"""Unit tests for ``services.audits.source_equivalence`` internals: Etherscan verified-source parsing, GitHub raw
fetch guards, candidate-path generation and the ``verify_audit_covers_impl`` statuses. DB-integrated coverage
behaviour is in ``test_audit_coverage.py``. No DB or network; ``requests.get`` and
``services.clients.etherscan.get`` are stubbed at module scope.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from services.audits import source_equivalence
from services.audits.source_equivalence import (
    VerifiedSource,
    _candidate_paths_for_name,
    _fetch_github_raw,
    _fetch_github_raw_hash,
    _hash_source_text,
    extract_reviewed_commits,
    fetch_db_source_files,
    fetch_etherscan_source_files,
    fetch_github_source_hash,
)


@pytest.fixture(autouse=True)
def _clear_lru_cache():
    """The process-global cache is ``_fetch_github_raw_hash`` (``_fetch_github_raw``
    itself is uncached). Stale hash hits would poison tests that stub
    ``requests.get`` / ``_fetch_github_raw`` for the same URL."""
    _fetch_github_raw_hash.cache_clear()
    yield
    _fetch_github_raw_hash.cache_clear()


# ---------------------------------------------------------------------------
# extract_reviewed_commits — filter rules beyond what test_audit_coverage covers
# ---------------------------------------------------------------------------


class TestExtractReviewedCommitsFilters:
    @pytest.mark.parametrize(
        "text, expected",
        [
            # Alternations like ``ababab`` pass the hex-letter check but are noise; covers the
            # ``len(set(token)) < 3`` guard.
            pytest.param("noise abababab more", [], id="rejects-token-with-fewer-than-three-unique-chars"),
            pytest.param(
                "noise abababab real 1a2b3c4d", ["1a2b3c4d"], id="rejects-low-entropy-token-but-keeps-real-sha"
            ),
            pytest.param(
                "commit 1a2b3c4d\nseen again 1a2b3c4d\nalso deadbeefcafe01",
                ["1a2b3c4d", "deadbeefcafe01"],
                id="dedupes-repeat-occurrences",
            ),
        ],
    )
    def test_filters(self, text, expected):
        assert extract_reviewed_commits(text) == expected


# ---------------------------------------------------------------------------
# fetch_etherscan_source_files — happy path, empty, and Etherscan failure
# ---------------------------------------------------------------------------


class TestFetchEtherscanSourceFiles:
    """``services.discovery`` re-exports ``fetch``, shadowing the submodule, so patch via the submodule object loaded
    through ``importlib``; ``etherscan.get`` is patched at the submodule level for consistency.
    """

    def test_returns_verified_source_for_successful_getsourcecode(self, monkeypatch):
        import importlib

        content = "contract LiquidityPool {}"
        captured = {
            "result": [
                {
                    "ContractName": "LiquidityPool",
                    "CompilerVersion": "v0.8.27+commit.40a35a09",
                    "SourceCode": content,
                }
            ]
        }
        fetch_module = importlib.import_module("services.discovery.fetch")
        etherscan_module = importlib.import_module("services.clients.etherscan")
        monkeypatch.setattr(etherscan_module, "get", lambda *_a, **_k: captured)
        monkeypatch.setattr(fetch_module, "parse_sources", lambda _res: {"LiquidityPool.sol": content})

        got = fetch_etherscan_source_files("0x" + "a" * 40, chain_id=1)
        assert got.status == "ok"
        assert got.source is not None
        assert got.source.contract_name == "LiquidityPool"
        assert got.source.compiler_version == "v0.8.27+commit.40a35a09"
        assert got.source.files == {"LiquidityPool.sol": _hash_source_text(content)}

    def test_returns_unverified_when_parse_sources_empty(self, monkeypatch):
        """Unverified contracts surface as status='unverified' so coverage can emit ``etherscan_unverified``."""
        import importlib

        fetch_module = importlib.import_module("services.discovery.fetch")
        etherscan_module = importlib.import_module("services.clients.etherscan")
        monkeypatch.setattr(
            etherscan_module,
            "get",
            lambda *_a, **_k: {"result": [{"ContractName": "", "CompilerVersion": "", "SourceCode": ""}]},
        )
        monkeypatch.setattr(fetch_module, "parse_sources", lambda _res: {})
        got = fetch_etherscan_source_files("0x" + "a" * 40, chain_id=1)
        assert got.source is None
        assert got.status == "unverified"

    def test_returns_fetch_failed_when_etherscan_raises(self, monkeypatch):
        """Any Etherscan exception (rate limit, network, malformed) becomes status='fetch_failed' so the retry sweep
        knows it's transient.
        """
        import importlib

        def boom(*_a, **_k):
            raise RuntimeError("etherscan down")

        etherscan_module = importlib.import_module("services.clients.etherscan")
        monkeypatch.setattr(etherscan_module, "get", boom)
        got = fetch_etherscan_source_files("0x" + "a" * 40, chain_id=1)
        assert got.source is None
        assert got.status == "fetch_failed"
        assert "etherscan down" in got.detail


# ---------------------------------------------------------------------------
# fetch_db_source_files — DB-lookup helper (no Etherscan call)
# ---------------------------------------------------------------------------


def _raises_db_gone(*_a, **_k):
    raise RuntimeError("DB gone")


class TestFetchDbSourceFilesShortCircuits:
    @pytest.mark.parametrize(
        "contract_exists, job_id, get_source_files",
        [
            # Session.get returning None: the contract doesn't exist, so no source lookup is attempted.
            pytest.param(False, None, None, id="contract-missing"),
            # Contract exists but was never analyzed (job_id NULL): caller falls back to Etherscan.
            pytest.param(True, None, None, id="contract-has-no-job-id"),
            # DB errors during source-file fetch must not bubble; degrade to the Etherscan fallback.
            pytest.param(True, "job-id", _raises_db_gone, id="get-source-files-raises"),
            # Job completed but no SourceFile rows: same as job_id=None.
            pytest.param(True, "job-id", lambda *_a, **_k: {}, id="no-source-files-rows"),
        ],
    )
    def test_returns_none(self, monkeypatch, contract_exists, job_id, get_source_files):
        import importlib

        session = MagicMock()
        session.get.return_value = MagicMock(job_id=job_id) if contract_exists else None
        if get_source_files is not None:
            monkeypatch.setattr(importlib.import_module("db.queue"), "get_source_files", get_source_files)
        assert fetch_db_source_files(session, 1) is None


# ---------------------------------------------------------------------------
# _fetch_github_raw — HTTP contract boundaries (uncached worker; the hash-level
# LRU it feeds is cleared per test by the autouse fixture)
# ---------------------------------------------------------------------------


def _resp(
    *,
    status_code: int = 200,
    text: str = "",
    content_type: str = "text/plain",
    content_bytes: bytes | None = None,
) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = content_bytes if content_bytes is not None else text.encode("utf-8")
    r.headers = {"content-type": content_type}
    return r


def _raising_get(exc):
    def raising(*_a, **_kw):
        raise exc

    return raising


class TestFetchGithubRaw:
    @pytest.mark.parametrize(
        "fake_get, expected_content, expected_status",
        [
            pytest.param(lambda *_a, **_k: _resp(status_code=404, text="Not Found"), None, "http_404", id="404"),
            # Distinguishes transient server errors from permanent 404s so the retry sweep retries it.
            pytest.param(lambda *_a, **_k: _resp(status_code=503, text="Unavailable"), None, "http_5xx", id="5xx"),
            pytest.param(_raising_get(requests.ConnectionError("timeout")), None, "transport_error", id="network"),
            # An image/pdf at the conventional path would poison hashes; rejected without parsing the body.
            pytest.param(
                lambda *_a, **_k: _resp(content_type="image/png", text="binary"),
                None,
                "content_type_rejected",
                id="binary-content-type-rejected",
            ),
            # Some raw-content CDNs serve source as octet-stream; the guard explicitly allows it.
            pytest.param(
                lambda *_a, **_k: _resp(content_type="application/octet-stream", text="contract X {}"),
                "contract X {}",
                "ok",
                id="octet-stream-accepted",
            ),
            # A 6MB response almost certainly isn't a single Solidity file.
            pytest.param(
                lambda *_a, **_k: _resp(
                    content_type="text/plain", content_bytes=b"x" * (6 * 1024 * 1024), text="x" * 10
                ),
                None,
                "size_cap_exceeded",
                id="oversized-body-rejected",
            ),
        ],
    )
    def test_response_handling(self, monkeypatch, fake_get, expected_content, expected_status):
        monkeypatch.setattr("services.audits.source_equivalence.requests.get", fake_get)
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content == expected_content
        assert got.status == expected_status

    def test_authorization_header_set_when_token_provided(self, monkeypatch):
        """Private repos require ``token ghp_...``. Verify the header
        actually reaches requests.get so rate-limit-evaders work."""
        captured = {}

        def capture(url, headers=None, timeout=None):
            captured.update({"url": url, "headers": headers or {}})
            return _resp(text="contract X {}")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", capture)
        _fetch_github_raw("https://example/file.sol", "secret-token")
        assert captured["headers"].get("Authorization") == "token secret-token"


# ---------------------------------------------------------------------------
# _fetch_github_raw — retry-with-backoff on transient transport failures.
#
# Same root-cause pattern as services.audits.text_extraction: prod observed
# bursts of ConnectionResetError(104) from raw.githubusercontent.com that
# turned every flake into a permanent ``transport_error``. Retry runs inside
# the worker so its outcome is settled *before* the hash-level cache memoizes
# it — otherwise a single flake would poison the URL for the worker's life.
# ---------------------------------------------------------------------------


class TestFetchGithubRawRetry:
    @pytest.mark.parametrize(
        "first_failure, body",
        [
            # First call RSTs (the prod failure mode), second succeeds: cache the success, not the flake.
            pytest.param(
                lambda: requests.exceptions.ConnectionError(
                    "Connection aborted.", ConnectionResetError(104, "Connection reset by peer")
                ),
                "contract X { function f() public {} }",
                id="connection-error",
            ),
            # 503 is transient: retry rather than memoize as ``http_5xx``.
            pytest.param(lambda: _resp(status_code=503, text="Unavailable"), "contract Y {}", id="5xx"),
            # Slow CDNs surface as ReadTimeout rather than ConnectionError; same treatment.
            pytest.param(lambda: requests.exceptions.ReadTimeout("read timed out"), "contract Z {}", id="read-timeout"),
        ],
    )
    def test_transient_failure_is_retried_to_success(self, monkeypatch, first_failure, body):
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def flaky(*_a, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                failure = first_failure()
                if isinstance(failure, Exception):
                    raise failure
                return failure
            return _resp(text=body, content_type="text/plain")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", flaky)

        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/Retry1.sol", None)
        assert got.status == "ok"
        assert got.content == body
        assert calls["n"] == 2

    def test_retries_exhausted_returns_transport_error(self, monkeypatch):
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def always_raises(*_a, **_kw):
            calls["n"] += 1
            raise requests.exceptions.ConnectionError(
                "Connection aborted.",
                ConnectionResetError(104, "Connection reset by peer"),
            )

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", always_raises)

        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/Retry2.sol", None)
        assert got.content is None
        assert got.status == "transport_error"
        assert calls["n"] == 3

    def test_404_does_not_retry(self, monkeypatch):
        """404 means the path is genuinely missing — retrying just wastes
        the budget. Stays terminal."""
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def always_404(*_a, **_kw):
            calls["n"] += 1
            return _resp(status_code=404, text="Not Found")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", always_404)

        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/Retry5.sol", None)
        assert got.status == "http_404"
        assert calls["n"] == 1

    def test_success_after_retry_is_memoized_not_the_flake(self, monkeypatch):
        """The retry is what makes the hash-level cache safe: without it a flake would be memoized as
        ``transport_error`` for
        the worker's life; with it the cache stores the successful content hash.
        """
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def flaky_then_ok(*_a, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.exceptions.ConnectionError(
                    "Connection aborted.",
                    ConnectionResetError(104, "Connection reset by peer"),
                )
            return _resp(text="contract M {}", content_type="text/plain")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", flaky_then_ok)

        url = "https://raw.githubusercontent.com/x/y/abc/Retry6.sol"
        first = _fetch_github_raw_hash(url, None)
        second = _fetch_github_raw_hash(url, None)

        assert first.status == "ok"
        assert second.status == "ok"
        assert first.sha256 == _hash_source_text("contract M {}")
        # Cache hit on the second call: the worker (and requests.get) is not
        # re-run — only the retried success was memoized, not the flake.
        assert calls["n"] == 2


# ---------------------------------------------------------------------------
# _fetch_github_raw_hash — the process-global cache. It memoizes the content
# hash (not the file body), so its 4096-entry lru_cache cap is a real memory
# bound: each row is fixed-size regardless of source-file size.
# ---------------------------------------------------------------------------


class TestFetchGithubRawHashCaching:
    def test_caches_content_hash_not_body(self, monkeypatch):
        """A large body must reduce to its 64-char sha256 in the cache — the
        raw text is never retained on the cached row (the ~1000× per-entry
        shrink that bounds the cache)."""
        body = "contract X { /* " + ("A" * 200_000) + " */ }"
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(text=body, content_type="text/plain"),
        )
        got = _fetch_github_raw_hash("https://raw.githubusercontent.com/x/y/abc/Big.sol", None)
        assert got.status == "ok"
        assert got.sha256 == _hash_source_text(body)
        assert got.sha256 is not None and len(got.sha256) == 64
        assert not hasattr(got, "content")


class TestFetchGithubSourceHash:
    _CONTENT = "contract Pool { function f() {} }"

    @pytest.mark.parametrize(
        "args, expected_sha, expected_status",
        [
            # Missing repo, commit or path short-circuits with invalid_input and no HTTP fetch.
            pytest.param(("", "abc", "file.sol"), None, "invalid_input", id="missing-repo"),
            pytest.param(("r/n", "", "file.sol"), None, "invalid_input", id="missing-commit"),
            pytest.param(("r/n", "abc", ""), None, "invalid_input", id="missing-path"),
            pytest.param(("r/n", "abc1234", "src/Pool.sol"), _hash_source_text(_CONTENT), "ok", id="content-fetched"),
        ],
    )
    def test_fetch_github_source_hash(self, monkeypatch, args, expected_sha, expected_status):
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(text=self._CONTENT, content_type="text/plain"),
        )
        got = fetch_github_source_hash(*args)
        assert got.sha256 == expected_sha
        assert got.status == expected_status


# ---------------------------------------------------------------------------
# _candidate_paths_for_name — Etherscan-first, conventional fallback
# ---------------------------------------------------------------------------


class TestCandidatePathsForName:
    @pytest.mark.parametrize(
        "name, paths, expected",
        [
            # A bundle containing the basename verbatim returns THOSE paths: they reflect the real layout.
            pytest.param(
                "MyPool",
                ["contracts/pool/MyPool.sol", "contracts/utils/Other.sol"],
                ["contracts/pool/MyPool.sol"],
                id="prefers-matching-etherscan-paths",
            ),
            # Flattened verifications don't carry the real tree; try ``src/`` and ``contracts/``.
            pytest.param("Vault", [], ["src/Vault.sol", "contracts/Vault.sol"], id="conventional-fallback"),
            # ``.vy`` is the other accepted extension (Curve-style repos).
            pytest.param("pool", ["src/pool.vy"], ["src/pool.vy"], id="matches-vyper-files"),
        ],
    )
    def test_candidate_paths(self, name, paths, expected):
        assert _candidate_paths_for_name(name, paths) == expected


# ---------------------------------------------------------------------------
# verify_audit_covers_impl — one test per EquivalenceOutcome.status value
# ---------------------------------------------------------------------------


class TestVerifyAuditCoversImplStatuses:
    """Each status in EQUIVALENCE_STATUSES maps to a specific failure mode
    ``_apply_equivalence_http`` will persist on the coverage row. Pin each
    so a refactor that loses a branch gets caught in CI."""

    def _src(self, files: dict[str, str]) -> VerifiedSource:
        return VerifiedSource(contract_name="X", compiler_version="v0.8", files=files)

    def test_proven_on_matching_hash(self, monkeypatch):
        monkeypatch.setattr(
            "services.audits.source_equivalence.fetch_github_source_hash",
            lambda *_a, **_k: source_equivalence.GithubHashResult(sha256="matching", status="ok", detail=""),
        )
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "matching"}),
            source_repo="r/n",
        )
        assert out.status == "proven"
        assert len(out.matches) == 1

    def test_candidate_path_absent_from_etherscan_bundle_never_fetches_github(self, monkeypatch):
        """``src/Pool.sol`` / ``contracts/Pool.sol`` are absent from a bundle rooted
        elsewhere: skip rather than false-positive, without a GitHub hash fetch."""

        def should_not_be_called(*_a, **_k):
            raise AssertionError("GitHub fetch must not run when path is absent from Etherscan")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", should_not_be_called)
        monkeypatch.setattr(
            "services.audits.source_equivalence._commit_exists_in_repo",
            lambda *_a, **_k: source_equivalence.GithubFetch(content="# readme", status="ok", detail=""),
        )
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"lib/other/File.sol": "hash"}),
            source_repo="r/n",
        )
        assert out.matches == ()
        assert out.status != "proven"

    def test_hash_mismatch_when_files_differ(self, monkeypatch):
        monkeypatch.setattr(
            "services.audits.source_equivalence.fetch_github_source_hash",
            lambda *_a, **_k: source_equivalence.GithubHashResult(sha256="different", status="ok", detail=""),
        )
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "etherscan_hash"}),
            source_repo="r/n",
        )
        assert out.status == "hash_mismatch"
        assert "abc1234"[:8] in out.reason or "src/Pool.sol" in out.reason

    def test_commit_not_found_in_repo(self, monkeypatch):
        """Every candidate path 404s AND the README probe 404s → commit
        doesn't exist in the repo (audit-reference rot)."""

        def fake_github(repo, commit, path, *, token=None):
            return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail=f"{path} 404")

        def fake_raw(url, token):
            return source_equivalence.GithubFetch(content=None, status="http_404", detail="no such commit")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", fake_github)
        monkeypatch.setattr("services.audits.source_equivalence._fetch_github_raw", fake_raw)
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "hash"}),
            source_repo="r/n",
        )
        assert out.status == "commit_not_found_in_repo"

    def test_candidate_path_missing_when_commit_resolves(self, monkeypatch):
        """File 404s but README probe succeeds → commit exists, our path
        heuristic just missed (likely Etherscan flattened the source)."""

        def fake_github(repo, commit, path, *, token=None):
            return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail=f"{path} 404")

        def fake_raw(url, token):
            return source_equivalence.GithubFetch(content="# readme", status="ok", detail="")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", fake_github)
        monkeypatch.setattr("services.audits.source_equivalence._fetch_github_raw", fake_raw)
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "hash"}),
            source_repo="r/n",
        )
        assert out.status == "candidate_path_missing"

    @pytest.mark.parametrize(
        "reviewed_commits, source_repo, files, expected_status",
        [
            pytest.param([], "r/n", {"src/Pool.sol": "hash"}, "no_reviewed_commit", id="no-reviewed-commit"),
            pytest.param(["abc1234"], None, {"src/Pool.sol": "hash"}, "no_source_repo", id="no-source-repo"),
            pytest.param(["abc1234"], "r/n", {}, "etherscan_unverified", id="etherscan-unverified-via-empty-files"),
        ],
    )
    def test_short_circuit_statuses(self, reviewed_commits, source_repo, files, expected_status):
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=reviewed_commits,
            scope_name="Pool",
            impl_source=self._src(files),
            source_repo=source_repo,
        )
        assert out.status == expected_status

    def test_github_fetch_failed_on_transient_errors(self, monkeypatch):
        """Every attempt returns 5xx / transport error → classify as
        github_fetch_failed so a retry sweep knows to re-run this row."""

        def fake_github(repo, commit, path, *, token=None):
            return source_equivalence.GithubHashResult(sha256=None, status="http_5xx", detail=f"{path} 503")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", fake_github)
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "hash"}),
            source_repo="r/n",
        )
        assert out.status == "github_fetch_failed"


# ---------------------------------------------------------------------------
# extract_referenced_repos (Phase D)
# ---------------------------------------------------------------------------


class TestExtractReferencedRepos:
    @pytest.mark.parametrize(
        "text, expected",
        [
            pytest.param(
                """
        The audit reviewed code at https://github.com/etherfi-protocol/smart-contracts
        with fixes applied at github.com/etherfi-protocol/smart-contracts/pull/42
        and also looked at https://github.com/etherfi-protocol/cash-v3
        """,
                ["etherfi-protocol/smart-contracts", "etherfi-protocol/cash-v3"],
                id="extracts-multiple-repos-dedupes",
            ),
            pytest.param(
                """
        See https://github.com/issues/42 and https://github.com/orgs/etherfi-protocol
        Real repo: github.com/etherfi-protocol/beHYPE
        """,
                ["etherfi-protocol/behype"],
                id="skips-github-system-paths",
            ),
            pytest.param(
                "Clone: https://github.com/owner/myrepo.git", ["owner/myrepo"], id="strips-trailing-git-suffix"
            ),
            pytest.param(
                """
        https://github.com/etherfi-protocol/smart-contracts/blob/master/src/WeETH.sol
        https://github.com/etherfi-protocol/smart-contracts/tree/abc1234/audits
        """,
                ["etherfi-protocol/smart-contracts"],
                id="handles-tree-blob-paths",
            ),
            pytest.param(
                """
        Bad: github.com/etherfi-protocol/issues/42
        Good: github.com/etherfi-protocol/smart-contracts/issues/42
        """,
                ["etherfi-protocol/smart-contracts"],
                id="skips-github-system-repo-names-in-repo-slot",
            ),
            pytest.param("", [], id="empty-text"),
            pytest.param(None, [], id="none-text"),
            pytest.param(
                "Audited at https://github.com/EtherFi-Protocol/Smart-Contracts",
                ["etherfi-protocol/smart-contracts"],
                id="lowercases-owner-and-repo",
            ),
        ],
    )
    def test_extract_referenced_repos(self, text, expected):
        assert source_equivalence.extract_referenced_repos(text) == expected


# ---------------------------------------------------------------------------
# verify_audit_covers_impl fallback_repos (Phase D)
# ---------------------------------------------------------------------------


class TestFallbackReposBehavior:
    def _src(self, files):
        return source_equivalence.VerifiedSource(contract_name="X", compiler_version="v0.8", files=files)

    def test_proven_in_fallback_repo_wins(self, monkeypatch):
        calls = []

        def fake_github(repo, commit, path, *, token=None):
            calls.append(repo)
            if repo == "etherfi-protocol/smart-contracts":
                return source_equivalence.GithubHashResult(sha256="matching", status="ok", detail="")
            return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="nope")

        def fake_raw(url, token):
            if "etherfi-protocol/smart-contracts" in url:
                return source_equivalence.GithubFetch(content="readme", status="ok", detail="")
            return source_equivalence.GithubFetch(content=None, status="http_404", detail="nope")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", fake_github)
        monkeypatch.setattr("services.audits.source_equivalence._fetch_github_raw", fake_raw)

        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "matching"}),
            source_repo="Cyfrin/cyfrin-audit-reports",  # wrong repo
            fallback_repos=["etherfi-protocol/smart-contracts"],
        )
        assert out.status == "proven"
        assert "Cyfrin/cyfrin-audit-reports" in calls
        assert "etherfi-protocol/smart-contracts" in calls

    def test_hash_mismatch_beats_commit_not_found(self, monkeypatch):
        """When one repo returns hash_mismatch and another commit_not_found,
        hash_mismatch wins (real signal about deployed-vs-audited divergence)."""

        def fake_github(repo, commit, path, *, token=None):
            if repo == "repo-with-code":
                return source_equivalence.GithubHashResult(sha256="different", status="ok", detail="")
            return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="nope")

        def fake_raw(url, token):
            if "repo-with-code" in url:
                return source_equivalence.GithubFetch(content="readme", status="ok", detail="")
            return source_equivalence.GithubFetch(content=None, status="http_404", detail="nope")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", fake_github)
        monkeypatch.setattr("services.audits.source_equivalence._fetch_github_raw", fake_raw)

        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "etherscan_hash"}),
            source_repo="empty-repo",  # 404s
            fallback_repos=["repo-with-code"],  # returns content that doesn't match
        )
        assert out.status == "hash_mismatch"

    def test_fallback_only_works_when_source_repo_is_none(self, monkeypatch):

        def fake_github(repo, commit, path, *, token=None):
            return source_equivalence.GithubHashResult(sha256="matching", status="ok", detail="")

        monkeypatch.setattr("services.audits.source_equivalence.fetch_github_source_hash", fake_github)

        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "matching"}),
            source_repo=None,
            fallback_repos=["only-repo"],
        )
        assert out.status == "proven"


def test_pinned_commit_overrides_reviewed_commits_in_verification(monkeypatch):
    """specific_commit narrows verify_audit_covers_impl to exactly that SHA;
    other commits in reviewed_commits are not attempted."""
    from services.audits import source_equivalence

    fetched_commits = []

    def fake_github(repo, commit, path, *, token=None):
        fetched_commits.append(commit)
        return source_equivalence.GithubHashResult(sha256="matching", status="ok", detail="")

    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    impl = source_equivalence.VerifiedSource(
        contract_name="Pool", compiler_version="v0.8", files={"src/Pool.sol": "matching"}
    )
    out = source_equivalence.verify_audit_covers_impl(
        reviewed_commits=["abc1234", "def5678", "fed9876"],
        scope_name="Pool",
        impl_source=impl,
        source_repo="r/n",
        specific_commit="def5678",  # narrow to this one
    )
    assert out.status == "proven"
    assert fetched_commits == ["def5678"]
