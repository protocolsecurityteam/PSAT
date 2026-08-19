"""Error-path tests for ``services.audits.scope_extraction.process_audit_scope``.

The happy path is covered by
``test_audit_scope_extraction_integration.py`` against real storage and
the LLM stub. What lives here is every ``return ScopeExtractionOutcome(
status="failed", ...)`` branch the happy path doesn't hit:

    - storage client unavailable (ARTIFACT_STORAGE_* unset)
    - ``StorageUnavailable`` on ``client.get``
    - Unexpected exception on ``client.get``
    - UnicodeDecodeError on the stored bytes
    - Chunk-scan ``LLMUnavailableError`` after the primary path fails
    - Chunk-scan recovery — validated names + artifact written

All tests stub the storage client and LLM call; no MinIO, no OpenRouter.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.storage import StorageUnavailable  # noqa: E402
from services.audits import scope_extraction as scope_pkg  # noqa: E402
from services.audits.scope_extraction import (  # noqa: E402
    ScopeExtractionOutcome,
    process_audit_scope,
)
from services.audits.scope_extraction._errors import LLMUnavailableError  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Keep stray env vars out of these tests. ``process_audit_scope``
    doesn't read any itself but it imports modules that do."""
    for var in ("PSAT_LLM_STUB_DIR", "PSAT_SCOPE_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    yield


def _patch_storage(monkeypatch, client):
    """Swap the ``get_storage_client`` used inside the orchestrator."""
    monkeypatch.setattr(scope_pkg, "get_storage_client", lambda: client)


def _make_client(body: bytes | Exception) -> MagicMock:
    c = MagicMock()
    if isinstance(body, Exception):
        c.get.side_effect = body
    else:
        c.get.return_value = body
    return c


def _page_text(body: str) -> str:
    """Build pypdf-style page-marked text the chunk-scan walker understands."""
    return f"\f\n--- page 1 ---\n\f\n{body}"


class TestStorageFailurePaths:
    def test_missing_storage_client_returns_failed(self, monkeypatch):
        """ARTIFACT_STORAGE_* unset → ``get_storage_client`` returns None.
        The orchestrator must bail with a clear error rather than crashing
        on a NoneType ``.get``."""
        _patch_storage(monkeypatch, None)
        outcome = process_audit_scope(
            audit_report_id=1,
            text_storage_key="audits/text/1.txt",
            text_sha256="a" * 64,
            audit_title="Audit",
            auditor="Firm",
        )
        assert outcome.status == "failed"
        assert "storage not configured" in (outcome.error or "")

    def test_storage_unavailable_on_get_returns_failed(self, monkeypatch):
        """A MinIO/Tigris outage during fetch is transient — surface as
        failed so the worker's stale-recovery retry brings it back later."""
        _patch_storage(monkeypatch, _make_client(StorageUnavailable("connection refused")))
        outcome = process_audit_scope(
            audit_report_id=2,
            text_storage_key="audits/text/2.txt",
            text_sha256=None,
            audit_title="",
            auditor="",
        )
        assert outcome.status == "failed"
        assert "storage get failed" in (outcome.error or "")

    def test_unexpected_storage_error_returns_failed(self, monkeypatch):
        """Any non-StorageUnavailable exception from ``client.get`` still
        results in ``failed`` with the exception repr captured — prevents
        a weird boto3 edge case from looping forever."""
        _patch_storage(monkeypatch, _make_client(RuntimeError("broken pipe")))
        outcome = process_audit_scope(
            audit_report_id=3,
            text_storage_key="audits/text/3.txt",
            text_sha256=None,
            audit_title="",
            auditor="",
        )
        assert outcome.status == "failed"
        assert "storage" in (outcome.error or "")

    def test_unicode_decode_error_returns_failed(self, monkeypatch):
        """Binary bodies accidentally written to the text bucket must fail
        loudly, not corrupt ``scope_contracts`` with garbage."""
        _patch_storage(monkeypatch, _make_client(b"\xff\xfe\x00\x00not-utf-8"))
        outcome = process_audit_scope(
            audit_report_id=4,
            text_storage_key="audits/text/4.txt",
            text_sha256=None,
            audit_title="",
            auditor="",
        )
        assert outcome.status == "failed"
        assert "text decode" in (outcome.error or "")


class TestChunkScanPath:
    def test_chunk_scan_llm_unavailable_yields_skipped(self, monkeypatch):
        """No header found → chunk-scan runs → LLM unavailable. No crash,
        skipped outcome with a descriptive error. The chunk-scan fallback
        is the last-resort path; if IT fails, there's nothing else to try."""
        # Body with no ``scope``/``audited contracts`` header — forces the
        # locate_scope_section result to be empty, which routes through the
        # chunk-scan branch.
        body = " ".join(["filler"] * 300)
        _patch_storage(monkeypatch, _make_client(_page_text(body).encode("utf-8")))

        def boom(*_a, **_k):
            raise LLMUnavailableError("openrouter 429")

        monkeypatch.setattr(
            "services.audits.scope_extraction.extract_scope_via_chunk_scan",
            boom,
        )

        outcome = process_audit_scope(
            audit_report_id=5,
            text_storage_key="audits/text/5.txt",
            text_sha256=None,
            audit_title="Security Review",
            auditor="Firm",
        )
        # No sections AND chunk-scan failed → no valid contracts → skipped.
        assert outcome.status == "skipped"
        assert "no scope section" in (outcome.error or "")

    def test_chunk_scan_recovers_when_primary_returns_nothing(self, monkeypatch):
        """Primary path finds no scope → chunk-scan returns names → artifact
        is stored and the ``method`` field flips to ``llm_chunk_scan`` so
        the operator can tell where the names came from."""
        body = " ".join(["LiquidityPool Vault"] * 40) + " contract LiquidityPool {}"
        _patch_storage(monkeypatch, _make_client(_page_text(body).encode("utf-8")))

        from services.audits.scope_extraction._locate import ScopeSection

        fake_chunk = ScopeSection(
            start_page=1,
            end_page=1,
            header="test-chunk",
            text_slice=_page_text(body),
        )
        monkeypatch.setattr(
            "services.audits.scope_extraction.extract_scope_via_chunk_scan",
            lambda *_a, **_k: (
                ["LiquidityPool", "Vault"],
                [],
                [],
                '["LiquidityPool","Vault"]',
                "stub:m",
                1,
                fake_chunk,
            ),
        )
        # Intercept artifact write so we don't need a real bucket.
        stored: dict = {}

        def fake_store(aid, payload):
            stored["aid"] = aid
            stored["payload"] = payload
            return f"audits/scope/{aid}.json"

        monkeypatch.setattr("services.audits.scope_extraction._store_artifact", fake_store)

        outcome = process_audit_scope(
            audit_report_id=6,
            text_storage_key="audits/text/6.txt",
            text_sha256=None,
            audit_title="Spearbit Audit — Something",
            auditor="Spearbit",
        )
        assert outcome.status == "success"
        assert outcome.method == "llm_chunk_scan"
        # ``LiquidityPool`` must appear — the validator filters out names
        # that aren't in the raw text, and our body includes it.
        assert "LiquidityPool" in outcome.contracts
        assert outcome.storage_key == "audits/scope/6.json"
        assert stored["aid"] == 6
        # The stored payload carries the winning chunk's text slice.
        assert stored["payload"]["scope_section_text"] is not None
        assert stored["payload"]["method"] == "llm_chunk_scan"


class TestClassifiedCommitFiltering:
    def test_process_audit_scope_drops_classified_shas_missing_from_raw_text(self, monkeypatch):
        """Keep only classified commits whose 7-char prefix actually appears
        in the PDF text; this is the hallucination guard for commit labels."""
        body = _page_text("Scope\nPool.sol reviewed at commit abc1234 for this assessment.")
        _patch_storage(monkeypatch, _make_client(body.encode("utf-8")))

        monkeypatch.setattr(
            "services.audits.scope_extraction.extract_scope_with_llm",
            lambda *_a, **_k: (
                ["Pool"],
                [],
                [
                    {
                        "sha": "abc1234deadbeef",
                        "label": "reviewed",
                        "context": "audited at abc1234",
                    },
                    {
                        "sha": "def5678deadbeef",
                        "label": "fix",
                        "context": "fixed in def5678",
                    },
                ],
                '{"contracts":["Pool"]}',
                "stub:m",
            ),
        )

        stored: dict[str, object] = {}

        def fake_store(aid, payload):
            stored["aid"] = aid
            stored["payload"] = payload
            return f"audits/scope/{aid}.json"

        monkeypatch.setattr("services.audits.scope_extraction._store_artifact", fake_store)

        outcome = process_audit_scope(
            audit_report_id=7,
            text_storage_key="audits/text/7.txt",
            text_sha256=None,
            audit_title="Security Review",
            auditor="Firm",
        )
        assert outcome.status == "success"
        assert outcome.classified_commits == (
            {
                "sha": "abc1234deadbeef",
                "label": "reviewed",
                "context": "audited at abc1234",
            },
        )
        assert stored["aid"] == 7
        payload = cast(dict[str, Any], stored["payload"])
        assert payload["classified_commits"] == [
            {
                "sha": "abc1234deadbeef",
                "label": "reviewed",
                "context": "audited at abc1234",
            }
        ]


class TestOutcomeDefaults:
    def test_scope_extraction_outcome_defaults_preserve_none(self):
        """Constructing ``ScopeExtractionOutcome(status=...)`` alone keeps
        every optional field None — the worker relies on "unset" being
        distinguishable from "set to empty"."""
        oc = ScopeExtractionOutcome(status="failed", error="x")
        assert oc.contracts == ()
        assert oc.storage_key is None
        assert oc.extracted_date is None
        assert oc.reviewed_commits == ()
        assert oc.method == "llm"
        assert oc.raw_response is None
        assert oc.model is None


class TestArtifactPayloadShape:
    def test_build_artifact_payload_carries_required_fields(self):
        """The artifact JSON is the debugging source of truth for an audit
        row — every downstream viewer reads these keys."""
        from services.audits.scope_extraction._artifact import build_artifact_payload

        payload = build_artifact_payload(
            ["Pool", "Vault"],
            method="llm",
            model="google/gemini-2.0-flash-001",
            extracted_date="2024-06-01",
            raw_response='["Pool","Vault"]',
            scope_section_text="<scope>",
        )
        assert payload["contracts"] == ["Pool", "Vault"]
        assert payload["method"] == "llm"
        assert payload["model"] == "google/gemini-2.0-flash-001"
        assert payload["extracted_date"] == "2024-06-01"
        # Serializable — the worker hands this straight to json.dumps.
        json.dumps(payload)

    def test_build_artifact_payload_caps_scope_section_text(self):
        """Pathological PDFs can have 100k+ chars of scope prose. The 20k
        cap keeps the artifact readable in a debugger."""
        from services.audits.scope_extraction._artifact import build_artifact_payload

        long_text = "x" * 50_000
        payload = build_artifact_payload(
            [],
            method="llm",
            model=None,
            extracted_date=None,
            raw_response=None,
            scope_section_text=long_text,
        )
        sliced = payload["scope_section_text"]
        assert isinstance(sliced, str)
        assert len(sliced) == 20_000


class TestStoreArtifactFallbacks:
    def test_returns_none_when_storage_client_unavailable(self, monkeypatch):
        """Storage off → the artifact is just lost (debug-only data). The
        row-state update still proceeds; this branch must not raise."""
        from services.audits.scope_extraction import _artifact

        monkeypatch.setattr(_artifact, "get_storage_client", lambda: None)
        assert _artifact._store_artifact(42, {"contracts": []}) is None

    def test_returns_none_when_put_raises_storage_unavailable(self, monkeypatch):
        """Transient MinIO failure during artifact write → skip the key
        rather than fail the whole scope extraction."""
        from services.audits.scope_extraction import _artifact

        client = MagicMock()
        client.put.side_effect = StorageUnavailable("bucket offline")
        monkeypatch.setattr(_artifact, "get_storage_client", lambda: client)
        assert _artifact._store_artifact(42, {"contracts": []}) is None
