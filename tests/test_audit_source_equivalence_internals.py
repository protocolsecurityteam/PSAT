"""Unit tests for ``services.audits.source_equivalence`` internals.

The DB-integrated behaviours (coverage matcher upgrading via
``check_audit_row_covers_contract``) are covered in
``test_audit_coverage.py``. What lives here is the network-side contract
surface: Etherscan verified-source parsing, GitHub raw fetch guards,
candidate-path generation, and the zero-input short-circuits on the
``check_audit_row_covers_contract`` entry point. No DB, no network — we
stub ``requests.get`` and ``utils.etherscan.get`` at module scope.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.audits import source_equivalence  # noqa: E402
from services.audits.source_equivalence import (  # noqa: E402
    EquivalenceMatch,
    VerifiedSource,
    _candidate_paths_for_name,
    _fetch_github_raw,
    _fetch_github_raw_hash,
    _hash_source_text,
    check_audit_covers_impl,
    check_audit_row_covers_contract,
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
    def test_rejects_token_with_fewer_than_three_unique_chars(self):
        """Tokens like ``ababab`` (2 unique chars) or ``cdcdcdcd`` (2 unique)
        are noise — usually incidental 7+ char alternations that happen to
        pass the hex-letter check. Covers the ``len(set(token)) < 3`` guard
        that the all-digit test doesn't hit."""
        # "abababab" — 2 unique chars, passes the hex-letter check ('a','b').
        assert extract_reviewed_commits("noise abababab more") == []
        # Mix real + noisy so we prove only the noisy one gets rejected.
        assert extract_reviewed_commits("noise abababab real 1a2b3c4d") == ["1a2b3c4d"]

    def test_dedupes_repeat_occurrences(self):
        """A SHA mentioned twice in the text must appear once in the output,
        in first-seen position."""
        text = "commit 1a2b3c4d\nseen again 1a2b3c4d\nalso deadbeefcafe01"
        assert extract_reviewed_commits(text) == ["1a2b3c4d", "deadbeefcafe01"]


# ---------------------------------------------------------------------------
# fetch_etherscan_source_files — happy path, empty, and Etherscan failure
# ---------------------------------------------------------------------------


class TestFetchEtherscanSourceFiles:
    """The ``services.discovery`` package re-exports ``fetch`` (function)
    into its namespace, shadowing the submodule — so we patch via the
    submodule object loaded through ``importlib``. ``utils.etherscan.get``
    is similarly patched at the submodule level for consistency."""

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
        etherscan_module = importlib.import_module("utils.etherscan")
        monkeypatch.setattr(etherscan_module, "get", lambda *_a, **_k: captured)
        monkeypatch.setattr(fetch_module, "parse_sources", lambda _res: {"LiquidityPool.sol": content})

        got = fetch_etherscan_source_files("0x" + "a" * 40, chain_id=1)
        assert got.status == "ok"
        assert got.source is not None
        assert got.source.contract_name == "LiquidityPool"
        assert got.source.compiler_version == "v0.8.27+commit.40a35a09"
        assert got.source.files == {"LiquidityPool.sol": _hash_source_text(content)}

    def test_returns_unverified_when_parse_sources_empty(self, monkeypatch):
        """Unverified contracts come back with no parseable source — now
        surfaced as status='unverified' so the coverage layer can emit a
        specific ``etherscan_unverified`` equivalence status."""
        import importlib

        fetch_module = importlib.import_module("services.discovery.fetch")
        etherscan_module = importlib.import_module("utils.etherscan")
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
        """Rate limits, network errors, malformed responses — any exception
        from Etherscan is converted to status='fetch_failed' so the retry
        sweep knows it's transient."""
        import importlib

        def boom(*_a, **_k):
            raise RuntimeError("etherscan down")

        etherscan_module = importlib.import_module("utils.etherscan")
        monkeypatch.setattr(etherscan_module, "get", boom)
        got = fetch_etherscan_source_files("0x" + "a" * 40, chain_id=1)
        assert got.source is None
        assert got.status == "fetch_failed"
        assert "etherscan down" in got.detail

    def test_strips_blank_metadata_to_none(self, monkeypatch):
        """Whitespace-only ContractName/CompilerVersion fields are normalized
        to None so downstream checks (``if source.contract_name``) work."""
        import importlib

        fetch_module = importlib.import_module("services.discovery.fetch")
        etherscan_module = importlib.import_module("utils.etherscan")
        monkeypatch.setattr(
            etherscan_module,
            "get",
            lambda *_a, **_k: {
                "result": [
                    {
                        "ContractName": "   ",
                        "CompilerVersion": "",
                        "SourceCode": "contract X {}",
                    }
                ]
            },
        )
        monkeypatch.setattr(
            fetch_module,
            "parse_sources",
            lambda _res: {"X.sol": "contract X {}"},
        )
        got = fetch_etherscan_source_files("0x" + "a" * 40, chain_id=1)
        assert got.status == "ok"
        assert got.source is not None
        assert got.source.contract_name is None
        assert got.source.compiler_version is None


# ---------------------------------------------------------------------------
# fetch_db_source_files — DB-lookup helper (no Etherscan call)
# ---------------------------------------------------------------------------


class TestFetchDbSourceFilesShortCircuits:
    def test_returns_none_when_contract_missing(self):
        """Session.get returning None means the contract doesn't exist —
        the resolver must return None without attempting a source lookup."""
        session = MagicMock()
        session.get.return_value = None
        assert fetch_db_source_files(session, 999) is None

    def test_returns_none_when_contract_has_no_job_id(self):
        """Contract exists but was never analyzed (job_id is NULL) — no
        SourceFile rows to read, so the caller falls back to Etherscan."""
        session = MagicMock()
        contract = MagicMock()
        contract.job_id = None
        session.get.return_value = contract
        assert fetch_db_source_files(session, 1) is None

    def test_returns_none_when_get_source_files_raises(self, monkeypatch):
        """DB errors during source-file fetch must not bubble — the matcher
        should degrade gracefully to the Etherscan fallback."""
        import importlib

        session = MagicMock()
        contract = MagicMock()
        contract.job_id = "job-id"
        session.get.return_value = contract

        def boom(*_a, **_k):
            raise RuntimeError("DB gone")

        queue_module = importlib.import_module("db.queue")
        monkeypatch.setattr(queue_module, "get_source_files", boom)
        assert fetch_db_source_files(session, 1) is None

    def test_returns_none_when_no_source_files_rows(self, monkeypatch):
        """Job completed but somehow no SourceFile rows exist — same result
        as ``job_id=None``: punt to Etherscan."""
        import importlib

        session = MagicMock()
        contract = MagicMock()
        contract.job_id = "job-id"
        session.get.return_value = contract
        queue_module = importlib.import_module("db.queue")
        monkeypatch.setattr(queue_module, "get_source_files", lambda *_a, **_k: {})
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


class TestFetchGithubRaw:
    def test_404_returns_http_404_status(self, monkeypatch):
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(status_code=404, text="Not Found"),
        )
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content is None
        assert got.status == "http_404"

    def test_5xx_returns_http_5xx_status(self, monkeypatch):
        """Distinguishes transient server errors from permanent 404s — lets
        the retry sweep know this one is worth retrying."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(status_code=503, text="Unavailable"),
        )
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content is None
        assert got.status == "http_5xx"

    def test_network_exception_returns_transport_error(self, monkeypatch):
        def raising(*_a, **_kw):
            raise requests.ConnectionError("timeout")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", raising)
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content is None
        assert got.status == "transport_error"

    def test_binary_content_type_rejected(self, monkeypatch):
        """A repo that returned an image/pdf at the conventional path would
        poison hashes if we accepted it — the content-type check catches
        that without parsing the body."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(content_type="image/png", text="binary"),
        )
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content is None
        assert got.status == "content_type_rejected"

    def test_octet_stream_content_type_accepted(self, monkeypatch):
        """Some raw-content CDNs serve source as ``application/octet-stream``;
        the guard explicitly allows it so we don't false-negative on them."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(content_type="application/octet-stream", text="contract X {}"),
        )
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content == "contract X {}"
        assert got.status == "ok"

    def test_oversized_body_rejected(self, monkeypatch):
        """A 6MB response almost certainly isn't a single Solidity file —
        reject to keep the hot path from spending memory on junk."""
        big = b"x" * (6 * 1024 * 1024)
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(content_type="text/plain", content_bytes=big, text="x" * 10),
        )
        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/file.sol", None)
        assert got.content is None
        assert got.status == "size_cap_exceeded"

    def test_authorization_header_set_when_token_provided(self, monkeypatch):
        """Private repos require ``token ghp_...``. Verify the header
        actually reaches requests.get so rate-limit-evaders work."""
        captured = {}

        def capture(url, headers=None, timeout=None):  # noqa: ARG001
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
    def test_transient_connection_error_is_retried_to_success(self, monkeypatch):
        """First call RSTs (the prod failure mode), second succeeds — the
        cached outcome should be the success, not the flake."""
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def flaky(*_a, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.exceptions.ConnectionError(
                    "Connection aborted.",
                    ConnectionResetError(104, "Connection reset by peer"),
                )
            return _resp(text="contract X { function f() public {} }", content_type="text/plain")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", flaky)

        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/Retry1.sol", None)
        assert got.status == "ok"
        assert got.content == "contract X { function f() public {} }"
        assert calls["n"] == 2

    def test_retries_exhausted_returns_transport_error(self, monkeypatch):
        """If the upstream stays bad through every retry, the function should
        still surface the transport_error (not loop forever)."""
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

    def test_transient_5xx_is_retried_to_success(self, monkeypatch):
        """503 from raw.githubusercontent.com is transient — retry rather
        than memoize as ``http_5xx`` and starve the rest of the run."""
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def maybe_5xx(*_a, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return _resp(status_code=503, text="Unavailable")
            return _resp(text="contract Y {}", content_type="text/plain")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", maybe_5xx)

        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/Retry3.sol", None)
        assert got.status == "ok"
        assert got.content == "contract Y {}"
        assert calls["n"] == 2

    def test_read_timeout_is_retried_to_success(self, monkeypatch):
        """Slow CDNs surface as ReadTimeout rather than ConnectionError —
        same retry treatment."""
        monkeypatch.setattr("services.audits.source_equivalence._retry_sleep", lambda _s: None, raising=False)

        calls = {"n": 0}

        def maybe_timeout(*_a, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.exceptions.ReadTimeout("read timed out")
            return _resp(text="contract Z {}", content_type="text/plain")

        monkeypatch.setattr("services.audits.source_equivalence.requests.get", maybe_timeout)

        got = _fetch_github_raw("https://raw.githubusercontent.com/x/y/abc/Retry4.sol", None)
        assert got.status == "ok"
        assert calls["n"] == 2

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
        """The hash-level cache makes the retry strictly necessary: without
        it, a single transient flake gets memoized as ``transport_error``
        for the whole worker process, starving every later call to the same
        URL. With retry, the *successful* outcome is what the cache stores —
        and what it stores is the content hash, not the body."""
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
        # The body itself is not carried on the cached result — only its hash.
        assert not hasattr(got, "content")

    def test_lru_cap_is_bounded(self):
        """A finite 4096-entry ceiling (never ``maxsize=None``) keeps the
        process-global cache from growing without bound in a long-lived
        worker. Pin it so a refactor can't silently unbound the cache."""
        info = _fetch_github_raw_hash.cache_info()
        assert info.maxsize == 4096

    def test_failure_status_propagates_with_no_hash(self, monkeypatch):
        """A terminal failure caches its status with ``sha256=None`` — still a
        tiny row, and the caller can distinguish missing from mismatched."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(status_code=404, text="Not Found"),
        )
        got = _fetch_github_raw_hash("https://raw.githubusercontent.com/x/y/abc/Missing.sol", None)
        assert got.sha256 is None
        assert got.status == "http_404"


class TestFetchGithubSourceHash:
    def test_returns_invalid_input_on_missing_inputs(self):
        """The wrapper short-circuits without any HTTP call when any of repo,
        commit, or path is empty — status='invalid_input' makes that
        visible to callers."""
        for args in [("", "abc", "file.sol"), ("r/n", "", "file.sol"), ("r/n", "abc", "")]:
            got = fetch_github_source_hash(*args)
            assert got.sha256 is None
            assert got.status == "invalid_input"

    def test_returns_sha256_when_content_fetched(self, monkeypatch):
        content = "contract Pool { function f() {} }"
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(text=content, content_type="text/plain"),
        )
        got = fetch_github_source_hash("r/n", "abc1234", "src/Pool.sol")
        assert got.sha256 == _hash_source_text(content)
        assert got.status == "ok"

    def test_propagates_http_404_from_raw(self, monkeypatch):
        """404 on the raw fetch propagates as status='http_404' so the
        orchestrator can distinguish path-missing from hash-mismatch."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.requests.get",
            lambda *_a, **_k: _resp(status_code=404),
        )
        got = fetch_github_source_hash("r/n", "abc1234", "src/Pool.sol")
        assert got.sha256 is None
        assert got.status == "http_404"


# ---------------------------------------------------------------------------
# _candidate_paths_for_name — Etherscan-first, conventional fallback
# ---------------------------------------------------------------------------


class TestCandidatePathsForName:
    def test_prefers_matching_etherscan_paths(self):
        """When the bundle contains the basename verbatim, return THOSE
        paths — they reflect the project's actual layout and the GitHub
        fetch will succeed against them."""
        paths = ["contracts/pool/MyPool.sol", "contracts/utils/Other.sol"]
        assert _candidate_paths_for_name("MyPool", paths) == ["contracts/pool/MyPool.sol"]

    def test_falls_back_to_conventional_paths_when_no_etherscan_match(self):
        """Flattened verifications (Etherscan collapses everything into one
        ``Contract.sol`` file) don't carry the real tree — try ``src/``
        and ``contracts/`` which cover the vast majority of projects."""
        assert _candidate_paths_for_name("Vault", []) == ["src/Vault.sol", "contracts/Vault.sol"]

    def test_matches_vyper_files(self):
        """``.vy`` is the other accepted extension — covered so Curve-style
        repos don't false-negative."""
        paths = ["src/pool.vy"]
        assert _candidate_paths_for_name("pool", paths) == ["src/pool.vy"]


# ---------------------------------------------------------------------------
# check_audit_covers_impl — empty-input short-circuits
# ---------------------------------------------------------------------------


class TestCheckAuditCoversImplShortCircuits:
    def _src(self, files):
        return VerifiedSource(contract_name="X", compiler_version="v0.8", files=files)

    def test_empty_reviewed_commits_returns_empty(self):
        assert (
            check_audit_covers_impl(
                reviewed_commits=[],
                scope_contracts=["Pool"],
                impl_source=self._src({"src/Pool.sol": "abc"}),
                source_repo="r/n",
            )
            == []
        )

    def test_missing_source_repo_returns_empty(self):
        """No repo = no URL to fetch from = can't prove equivalence."""
        assert (
            check_audit_covers_impl(
                reviewed_commits=["abc1234"],
                scope_contracts=["Pool"],
                impl_source=self._src({"src/Pool.sol": "abc"}),
                source_repo=None,
            )
            == []
        )

    def test_impl_source_with_no_files_returns_empty(self):
        assert (
            check_audit_covers_impl(
                reviewed_commits=["abc1234"],
                scope_contracts=["Pool"],
                impl_source=self._src({}),
                source_repo="r/n",
            )
            == []
        )

    def test_empty_scope_contracts_returns_empty(self):
        assert (
            check_audit_covers_impl(
                reviewed_commits=["abc1234"],
                scope_contracts=[],
                impl_source=self._src({"src/Pool.sol": "abc"}),
                source_repo="r/n",
            )
            == []
        )

    def test_candidate_path_not_in_etherscan_bundle_skipped(self, monkeypatch):
        """The conventional-fallback path (``src/Pool.sol``) won't match
        bundles that use a deeper tree (``contracts/pool/Pool.sol``). Prove
        we skip rather than false-positive when the path is absent."""

        def should_not_be_called(*_a, **_k):
            raise AssertionError("GitHub fetch must not run when path is absent from Etherscan")

        monkeypatch.setattr(
            "services.audits.source_equivalence.fetch_github_source_hash",
            should_not_be_called,
        )
        assert (
            check_audit_covers_impl(
                reviewed_commits=["abc1234"],
                scope_contracts=["Pool"],  # falls back to src/Pool.sol, contracts/Pool.sol
                impl_source=self._src({"lib/other/File.sol": "hash"}),
                source_repo="r/n",
            )
            == []
        )

    def test_github_fetch_returning_404_skipped(self, monkeypatch):
        """GitHub 404 on a candidate path = file didn't exist at that commit.
        Don't record a match; the outer wrapper returns empty matches."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.fetch_github_source_hash",
            lambda *_a, **_k: source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="not found"),
        )
        # After every candidate path 404s, the verifier probes the repo root to
        # tell "commit missing" from "commit exists, path missing" — stub that
        # probe to "commit exists" so we exercise the path-missing branch (and
        # don't hit raw.githubusercontent.com).
        monkeypatch.setattr(
            "services.audits.source_equivalence._commit_exists_in_repo",
            lambda *_a, **_k: source_equivalence.GithubFetch(content="# readme", status="ok", detail=""),
        )
        assert (
            check_audit_covers_impl(
                reviewed_commits=["abc1234"],
                scope_contracts=["Pool"],
                impl_source=self._src({"src/Pool.sol": "hash"}),
                source_repo="r/n",
            )
            == []
        )

    def test_records_match_on_hash_equality(self, monkeypatch):
        """The one true-positive path. Preserved both as sanity and so we
        know the match's dataclass shape is actually constructable."""
        monkeypatch.setattr(
            "services.audits.source_equivalence.fetch_github_source_hash",
            lambda *_a, **_k: source_equivalence.GithubHashResult(sha256="matching-hash", status="ok", detail=""),
        )
        matches = check_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_contracts=["Pool"],
            impl_source=self._src({"src/Pool.sol": "matching-hash"}),
            source_repo="r/n",
        )
        assert matches == [
            EquivalenceMatch(
                commit="abc1234",
                scope_name="Pool",
                etherscan_path="src/Pool.sol",
                source_sha256="matching-hash",
            )
        ]


# ---------------------------------------------------------------------------
# check_audit_row_covers_contract — DB-wrapper short-circuits (mock sessions)
# ---------------------------------------------------------------------------


class TestCheckAuditRowCoversContractShortCircuits:
    """Cover every ``return []`` short-circuit so the matcher can be called
    from places where inputs aren't guaranteed to be complete (e.g. before
    scope extraction fills in ``reviewed_commits``)."""

    def test_returns_empty_when_audit_missing(self):
        session = MagicMock()
        session.get.return_value = None
        assert check_audit_row_covers_contract(session, 1, 2) == []

    def test_returns_empty_when_contract_missing(self):
        session = MagicMock()
        audit = MagicMock()
        # First session.get for AuditReport returns audit, second for Contract returns None
        session.get.side_effect = [audit, None]
        assert check_audit_row_covers_contract(session, 1, 2) == []

    def test_returns_empty_when_reviewed_commits_empty(self):
        session = MagicMock()
        audit = MagicMock()
        audit.reviewed_commits = []
        audit.scope_contracts = ["Pool"]
        audit.source_repo = "r/n"
        contract = MagicMock()
        contract.address = "0x" + "a" * 40
        session.get.side_effect = [audit, contract]
        assert check_audit_row_covers_contract(session, 1, 2) == []

    def test_returns_empty_when_source_repo_missing(self):
        session = MagicMock()
        audit = MagicMock()
        audit.reviewed_commits = ["abc1234"]
        audit.scope_contracts = ["Pool"]
        audit.source_repo = None
        contract = MagicMock()
        contract.address = "0x" + "a" * 40
        session.get.side_effect = [audit, contract]
        assert check_audit_row_covers_contract(session, 1, 2) == []

    def test_returns_empty_when_contract_has_no_address(self):
        """Can't reach Etherscan for a contract with no address — punt rather
        than pass an empty string down and get a useless API error."""
        session = MagicMock()
        audit = MagicMock()
        audit.reviewed_commits = ["abc1234"]
        audit.scope_contracts = ["Pool"]
        audit.source_repo = "r/n"
        contract = MagicMock()
        contract.address = ""
        session.get.side_effect = [audit, contract]
        assert check_audit_row_covers_contract(session, 1, 2) == []

    def test_returns_empty_when_impl_source_unavailable(self, monkeypatch):
        """DB + Etherscan both empty — no source to compare against. The
        underlying ``verify_audit_row_covers_contract`` reports the
        failure as ``etherscan_fetch_failed``; the legacy wrapper just
        returns an empty match list."""
        session = MagicMock()
        audit = MagicMock()
        audit.reviewed_commits = ["abc1234"]
        audit.scope_contracts = ["Pool"]
        audit.source_repo = "r/n"
        contract = MagicMock()
        contract.address = "0x" + "a" * 40
        contract.job_id = None
        session.get.side_effect = [audit, contract, contract]  # .get may be called again inside
        monkeypatch.setattr(
            source_equivalence,
            "fetch_contract_source",
            lambda *_a, **_k: source_equivalence.EtherscanFetch(source=None, status="fetch_failed", detail="no source"),
        )
        assert check_audit_row_covers_contract(session, 1, 2) == []

    def test_delegates_to_verify_on_full_inputs(self, monkeypatch):
        """All inputs present: delegate with the expected arguments and
        return the proven matches. This is the single happy-path shape
        the coverage matcher relies on."""
        session = MagicMock()
        audit = MagicMock()
        audit.reviewed_commits = ["abc1234", "def5678"]
        audit.scope_contracts = ["Pool", "Vault"]
        audit.source_repo = "r/n"
        contract = MagicMock()
        contract.address = "0x" + "a" * 40
        session.get.side_effect = [audit, contract]

        src = VerifiedSource(contract_name="X", compiler_version="v0.8", files={"src/Pool.sol": "h"})
        monkeypatch.setattr(
            source_equivalence,
            "fetch_contract_source",
            lambda *_a, **_k: source_equivalence.EtherscanFetch(source=src, status="ok", detail=""),
        )

        expected_matches = (
            EquivalenceMatch(commit="abc1234", scope_name="Pool", etherscan_path="src/Pool.sol", source_sha256="h"),
        )
        monkeypatch.setattr(
            source_equivalence,
            "verify_audit_covers_impl",
            lambda **_kw: source_equivalence.EquivalenceOutcome(
                status="proven", reason="test", matches=expected_matches
            ),
        )
        got = check_audit_row_covers_contract(session, 1, 2, github_token="tok")
        assert got == list(expected_matches)


# ---------------------------------------------------------------------------
# _hash_source_text — sanity: same text → same hash
# ---------------------------------------------------------------------------


def test_hash_source_text_is_sha256():
    content = "contract X {}"
    assert _hash_source_text(content) == hashlib.sha256(content.encode("utf-8")).hexdigest()


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
        """Happy path: sha matches → status='proven', matches non-empty."""
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

    def test_hash_mismatch_when_files_differ(self, monkeypatch):
        """Both sides fetched content; hashes don't match. Strong negative."""
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

        # Probe also 404s — commit doesn't exist.
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

        # Probe succeeds — commit resolves.
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

    def test_no_reviewed_commit(self):
        """Empty reviewed_commits[] → can't even start."""
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=[],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "hash"}),
            source_repo="r/n",
        )
        assert out.status == "no_reviewed_commit"

    def test_no_source_repo(self):
        """Audit never captured a GitHub repo — can't look anything up."""
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "hash"}),
            source_repo=None,
        )
        assert out.status == "no_source_repo"

    def test_etherscan_unverified_via_empty_files(self):
        """impl_source with no files → Etherscan has no verified source
        (happens when the deployed contract was never verified)."""
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({}),
            source_repo="r/n",
        )
        assert out.status == "etherscan_unverified"

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


def test_transient_statuses_is_correct():
    """``TRANSIENT_STATUSES`` must be a subset of ``EQUIVALENCE_STATUSES``.
    Guards a class of typo where a retry-sweep check silently fails to
    find its target status value."""
    assert source_equivalence.TRANSIENT_STATUSES <= source_equivalence.EQUIVALENCE_STATUSES
    # Permanent-only statuses must NOT be in the transient set.
    for permanent in ("proven", "hash_mismatch", "no_reviewed_commit", "no_source_repo"):
        assert permanent not in source_equivalence.TRANSIENT_STATUSES


# ---------------------------------------------------------------------------
# extract_referenced_repos (Phase D)
# ---------------------------------------------------------------------------


class TestExtractReferencedRepos:
    def test_extracts_multiple_repos_dedupes(self):
        text = """
        The audit reviewed code at https://github.com/etherfi-protocol/smart-contracts
        with fixes applied at github.com/etherfi-protocol/smart-contracts/pull/42
        and also looked at https://github.com/etherfi-protocol/cash-v3
        """
        got = source_equivalence.extract_referenced_repos(text)
        assert got == ["etherfi-protocol/smart-contracts", "etherfi-protocol/cash-v3"]

    def test_skips_github_system_paths(self):
        """GitHub profile paths like /issues, /orgs aren't repos."""
        text = """
        See https://github.com/issues/42 and https://github.com/orgs/etherfi-protocol
        Real repo: github.com/etherfi-protocol/beHYPE
        """
        got = source_equivalence.extract_referenced_repos(text)
        assert got == ["etherfi-protocol/behype"]

    def test_strips_trailing_git_suffix(self):
        text = "Clone: https://github.com/owner/myrepo.git"
        got = source_equivalence.extract_referenced_repos(text)
        assert got == ["owner/myrepo"]

    def test_handles_tree_blob_paths(self):
        """github.com/owner/repo/tree/branch/file should still extract owner/repo."""
        text = """
        https://github.com/etherfi-protocol/smart-contracts/blob/master/src/WeETH.sol
        https://github.com/etherfi-protocol/smart-contracts/tree/abc1234/audits
        """
        got = source_equivalence.extract_referenced_repos(text)
        # Single dedupe to one entry.
        assert got == ["etherfi-protocol/smart-contracts"]

    def test_skips_github_system_repo_names_in_repo_slot(self):
        text = """
        Bad: github.com/etherfi-protocol/issues/42
        Good: github.com/etherfi-protocol/smart-contracts/issues/42
        """
        got = source_equivalence.extract_referenced_repos(text)
        assert got == ["etherfi-protocol/smart-contracts"]

    def test_empty_and_none_text(self):
        assert source_equivalence.extract_referenced_repos("") == []
        assert source_equivalence.extract_referenced_repos(None) == []  # type: ignore[arg-type]

    def test_lowercases_owner_and_repo(self):
        """Normalize so fallback comparisons hit regardless of casing."""
        text = "Audited at https://github.com/EtherFi-Protocol/Smart-Contracts"
        got = source_equivalence.extract_referenced_repos(text)
        assert got == ["etherfi-protocol/smart-contracts"]


# ---------------------------------------------------------------------------
# verify_audit_covers_impl fallback_repos (Phase D)
# ---------------------------------------------------------------------------


class TestFallbackReposBehavior:
    """Multi-repo verification: try source_repo first, then fallback_repos."""

    def _src(self, files):
        return source_equivalence.VerifiedSource(contract_name="X", compiler_version="v0.8", files=files)

    def test_proven_in_fallback_repo_wins(self, monkeypatch):
        """source_repo 404s; one of the fallback repos has the matching file."""
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
        # Both repos were tried; source_repo first, fallback second.
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

    def test_no_source_repo_and_no_fallback_is_short_circuit(self):
        """Both repo fields empty → no_source_repo status, no fetches attempted."""
        out = source_equivalence.verify_audit_covers_impl(
            reviewed_commits=["abc1234"],
            scope_name="Pool",
            impl_source=self._src({"src/Pool.sol": "hash"}),
            source_repo=None,
            fallback_repos=None,
        )
        assert out.status == "no_source_repo"

    def test_fallback_only_works_when_source_repo_is_none(self, monkeypatch):
        """When source_repo is None but fallback_repos exist, verification proceeds."""

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
