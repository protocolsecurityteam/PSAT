
from __future__ import annotations

from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from db.storage import StorageUnavailable
from services.audits import scope_extraction as scope_pkg
from services.audits.scope_extraction import (
    process_audit_scope,
)
from services.audits.scope_extraction._errors import LLMUnavailableError


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """``process_audit_scope`` imports modules that read env vars."""
    for var in ("PSAT_LLM_STUB_DIR", "PSAT_SCOPE_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    yield


def _patch_storage(monkeypatch, client):
    monkeypatch.setattr(scope_pkg, "get_storage_client", lambda: client)


def _make_client(body: bytes | Exception) -> MagicMock:
    c = MagicMock()
    if isinstance(body, Exception):
        c.get.side_effect = body
    else:
        c.get.return_value = body
    return c


def _page_text(body: str) -> str:
    return f"\f\n--- page 1 ---\n\f\n{body}"


class TestStorageFailurePaths:
    def test_missing_storage_client_returns_failed(self, monkeypatch):
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
        """Transient, so stale-recovery retries it later."""
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
        """A weird boto3 edge case must not loop forever."""
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
        """Binary bodies in the text bucket must not corrupt ``scope_contracts``."""
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
        assert outcome.status == "skipped"
        assert "no scope section" in (outcome.error or "")

    def test_chunk_scan_recovers_when_primary_returns_nothing(self, monkeypatch):
        """``method`` tells the operator where the names came from."""
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
        # The validator drops names absent from the raw text.
        assert "LiquidityPool" in outcome.contracts
        assert outcome.storage_key == "audits/scope/6.json"
        assert stored["aid"] == 6
        assert stored["payload"]["scope_section_text"] is not None
        assert stored["payload"]["method"] == "llm_chunk_scan"


class TestClassifiedCommitFiltering:
    def test_process_audit_scope_drops_classified_shas_missing_from_raw_text(self, monkeypatch):
        """The hallucination guard for commit labels."""
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


class TestArtifactPayloadShape:
    def test_build_artifact_payload_caps_scope_section_text(self):
        """Keeps the artifact readable in a debugger."""
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
        """The artifact is debug-only; the row-state update still proceeds."""
        from services.audits.scope_extraction import _artifact

        monkeypatch.setattr(_artifact, "get_storage_client", lambda: None)
        assert _artifact._store_artifact(42, {"contracts": []}) is None

    def test_returns_none_when_put_raises_storage_unavailable(self, monkeypatch):
        from services.audits.scope_extraction import _artifact

        client = MagicMock()
        client.put.side_effect = StorageUnavailable("bucket offline")
        monkeypatch.setattr(_artifact, "get_storage_client", lambda: client)
        assert _artifact._store_artifact(42, {"contracts": []}) is None
