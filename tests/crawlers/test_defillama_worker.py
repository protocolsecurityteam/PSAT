"""Tests for DefiLlamaWorker — process() paths and edge cases.

Child-job creation and ``analyze_limit`` enforcement moved out of the
worker in the move to a unified selection stage; tests that covered
those concerns now live next to the ``SelectionWorker`` and the
DApp-crawl integration suite. What's left here is the worker's direct
responsibilities: run the scan, persist artifacts, populate the
``contracts`` table, and mark the job complete.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.base import JobHandledDirectly
from workers.defillama_worker import DefiLlamaWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ADDR_1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PROTOCOL = "aave-v3"


def _job(**overrides: Any) -> SimpleNamespace:
    payload: dict[str, Any] = {
        "id": uuid.uuid4(),
        "address": None,
        "name": None,
        "company": None,
        "protocol_id": None,
        "request": {"defillama_protocol": PROTOCOL},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _scan_result(
    addresses: list[str] | None = None,
    address_details: list[dict] | None = None,
) -> dict:
    """Return a minimal scan_protocol result."""
    addrs = addresses or []
    return {
        "addresses": addrs,
        "scan_time": 1.23,
        "address_details": address_details or [],
    }


def _patch_worker_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Patch all external dependencies of DefiLlamaWorker.process() and return trackers."""
    store_calls: list[tuple[str, Any]] = []
    complete_calls: list[tuple] = []
    protocol_calls: list[tuple[str, str | None]] = []

    def fake_store(session, job_id, name, data=None, text_data=None):
        store_calls.append((name, data))

    def fake_complete(session, job_id, detail=""):
        complete_calls.append((job_id, detail))

    def fake_update_detail(session, job_id, detail):
        pass

    def fake_get_or_create_protocol(session, name, official_domain=None, canonical_slug=None, aliases=None):
        protocol_calls.append((name, official_domain))
        return SimpleNamespace(id=1, name=name, official_domain=official_domain, canonical_slug=canonical_slug)

    monkeypatch.setattr("workers.defillama_worker.store_artifact", fake_store)
    monkeypatch.setattr("workers.defillama_worker.complete_job", fake_complete)
    monkeypatch.setattr("workers.defillama_worker.get_or_create_protocol", fake_get_or_create_protocol)
    # Worker now resolves the name to a canonical DefiLlama slug before
    # upserting the Protocol row; stub the network call away.
    monkeypatch.setattr(
        "workers.defillama_worker.resolve_protocol",
        lambda name: {"slug": None, "url": None, "name": None, "chains": [], "all_slugs": [], "all_names": []},
    )
    monkeypatch.setattr("workers.base.update_job_detail", fake_update_detail)

    return {
        "store_calls": store_calls,
        "complete_calls": complete_calls,
        "protocol_calls": protocol_calls,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMissingProtocol:
    """process() raises ValueError when defillama_protocol is missing."""

    def test_missing_protocol_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        job = _job(request={})
        _patch_worker_deps(monkeypatch)

        with pytest.raises(ValueError, match="defillama_protocol"):
            worker.process(session, cast(Any, job))

    def test_none_request_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        job = _job(request=None)
        _patch_worker_deps(monkeypatch)

        with pytest.raises(ValueError, match="defillama_protocol"):
            worker.process(session, cast(Any, job))


class TestHappyPath:
    """Full successful scan writes artifacts and completes the job."""

    def test_stores_artifacts_and_completes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        trackers = _patch_worker_deps(monkeypatch)

        details = [
            {"address": ADDR_1, "chain": "ethereum"},
            {"address": ADDR_2, "chain": "polygon"},
        ]
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(
                addresses=[ADDR_1, ADDR_2],
                address_details=details,
            ),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        stored_names = [name for name, _ in trackers["store_calls"]]
        assert "defillama_full_scan" in stored_names
        assert "defillama_scan_results" in stored_names
        assert "discovery_summary" in stored_names
        assert len(trackers["complete_calls"]) == 1


class TestJobName:
    """Job name is set when missing, not overwritten when present."""

    def test_sets_name_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job(name=None)

        _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert job.name == f"DefiLlama: {PROTOCOL}"

    def test_preserves_existing_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        original_name = "My Custom Name"
        job = _job(name=original_name)

        _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert job.name == original_name


class TestNoCloneEnvVar:
    """DEFILLAMA_NO_CLONE env var is correctly passed through to scan_protocol."""

    def test_no_clone_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        _patch_worker_deps(monkeypatch)
        monkeypatch.setenv("DEFILLAMA_NO_CLONE", "true")

        captured_kwargs: list[dict] = []

        def spy_scan(**kwargs):
            captured_kwargs.append(kwargs)
            return _scan_result(addresses=[])

        monkeypatch.setattr("workers.defillama_worker.scan_protocol", spy_scan)

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert captured_kwargs[0]["no_clone"] is True

    def test_no_clone_false_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        _patch_worker_deps(monkeypatch)
        monkeypatch.delenv("DEFILLAMA_NO_CLONE", raising=False)

        captured_kwargs: list[dict] = []

        def spy_scan(**kwargs):
            captured_kwargs.append(kwargs)
            return _scan_result(addresses=[])

        monkeypatch.setattr("workers.defillama_worker.scan_protocol", spy_scan)

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert captured_kwargs[0]["no_clone"] is False


class TestScanResultArtifactContent:
    """Verify artifact data payloads contain correct information."""

    def test_full_scan_artifact_contents(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        trackers = _patch_worker_deps(monkeypatch)

        details = [{"address": ADDR_1, "chain": "ethereum"}]
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(
                addresses=[ADDR_1],
                address_details=details,
            ),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        full_scan = next(d for name, d in trackers["store_calls"] if name == "defillama_full_scan")
        assert full_scan["protocol"] == PROTOCOL
        assert full_scan["scan_time"] == 1.23
        assert full_scan["address_details"] == details

        scan_results = next(d for name, d in trackers["store_calls"] if name == "defillama_scan_results")
        assert scan_results["addresses_found"] == 1
        assert scan_results["addresses"] == [ADDR_1]

    def test_discovery_summary_artifact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        trackers = _patch_worker_deps(monkeypatch)

        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(
                addresses=[ADDR_1, ADDR_2],
                address_details=[
                    {"address": ADDR_1, "chain": "ethereum"},
                    {"address": ADDR_2, "chain": "polygon"},
                ],
            ),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        summary = next(d for name, d in trackers["store_calls"] if name == "discovery_summary")
        assert summary["mode"] == "defillama_scan"
        assert summary["protocol"] == PROTOCOL
        assert summary["discovered_count"] == 2
        # Ranking and child-job creation moved to SelectionWorker; the
        # DefiLlama summary no longer reports analyzed_count or child_jobs.
        assert "analyzed_count" not in summary
        assert "child_jobs" not in summary


class TestZeroAddressesFound:
    """Scan finds zero addresses — still completes with discovery_summary."""

    def test_no_addresses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        job = _job()

        trackers = _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert len(trackers["complete_calls"]) == 1

        summary = next(d for name, d in trackers["store_calls"] if name == "discovery_summary")
        assert summary["discovered_count"] == 0


class TestScanProtocolRaises:
    """If scan_protocol raises, the exception propagates (not caught by worker)."""

    def test_exception_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        job = _job()

        _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("clone failed")),
        )

        with pytest.raises(RuntimeError, match="clone failed"):
            worker.process(session, cast(Any, job))


class TestProtocolCreation:
    """Protocol row is created from defillama slug when company is absent."""

    def test_slug_becomes_protocol_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        trackers = _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert trackers["protocol_calls"] == [(PROTOCOL, None)]
        assert job.protocol_id == 1
        assert job.company == PROTOCOL

    def test_company_prefers_over_slug(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job(company="Aave")

        trackers = _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert trackers["protocol_calls"] == [("Aave", None)]
        assert job.company == "Aave"
