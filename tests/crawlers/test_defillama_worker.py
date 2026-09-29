"""Tests for DefiLlamaWorker.process() paths and edge cases.

Child-job creation and ``analyze_limit`` moved to ``SelectionWorker``; this file keeps the worker's direct duties:
run the scan, persist artifacts, populate ``contracts``, complete the job.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from workers.base import JobHandledDirectly
from workers.defillama_worker import DefiLlamaWorker

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
    addrs = addresses or []
    return {
        "addresses": addrs,
        "scan_time": 1.23,
        "address_details": address_details or [],
    }


def _patch_worker_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
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


class TestMissingProtocol:
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


class TestJobName:
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
        # Ranking/child jobs moved to SelectionWorker; the summary no longer reports analyzed_count or child_jobs.
        assert "analyzed_count" not in summary
        assert "child_jobs" not in summary


class TestZeroAddressesFound:
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


class TestListingAddressNomination:
    """The listing's own ``address`` field is nominated alongside the adapter
    scan's hits, under the same ``defillama`` tag and the same W6 seed path."""

    def _run(self, monkeypatch: pytest.MonkeyPatch, *, listing: list[dict], scanned: list[str]) -> list[dict]:
        worker = DefiLlamaWorker()
        session = MagicMock()
        job = _job()
        _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.resolve_protocol",
            lambda name: {
                "slug": None,
                "url": None,
                "name": None,
                "chains": [],
                "listing_addresses": listing,
                "all_slugs": [],
                "all_names": [],
            },
        )
        monkeypatch.setattr("workers.defillama_worker.scan_protocol", lambda **kwargs: _scan_result(addresses=scanned))
        captured: list[dict] = []

        def fake_bulk(session, *, protocol_id, entries, default_chain):
            captured.extend(entries)

        monkeypatch.setattr("workers.defillama_worker.bulk_upsert_discovered_contracts", fake_bulk)
        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))
        return captured

    def test_bare_listing_address_is_nominated_on_ethereum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        token = "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb"
        entries = self._run(
            monkeypatch, listing=[{"address": token, "chain": None, "slug": "ether.fi-liquid"}], scanned=[ADDR_1]
        )
        assert {"address": token, "chain": "ethereum", "new_sources": ["defillama"]} in entries
        assert {"address": ADDR_1, "chain": None, "new_sources": ["defillama"]} in entries

    def test_prefixed_listing_address_keeps_its_chain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        token = "0x60359a0d0bd9f2c6e3a8b1a9b4c5d6e7f8091a2b"
        entries = self._run(monkeypatch, listing=[{"address": token, "chain": "base", "slug": "x"}], scanned=[])
        assert entries == [{"address": token, "chain": "base", "new_sources": ["defillama"]}]

    def test_no_listing_address_changes_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entries = self._run(monkeypatch, listing=[], scanned=[ADDR_1])
        assert entries == [{"address": ADDR_1, "chain": None, "new_sources": ["defillama"]}]
