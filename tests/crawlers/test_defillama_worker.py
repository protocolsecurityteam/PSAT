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
_BARE_TOKEN = "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb"
_BASE_TOKEN = "0x60359a0d0bd9f2c6e3a8b1a9b4c5d6e7f8091a2b"


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
    @pytest.mark.parametrize(
        "request_payload", [pytest.param({}, id="missing-key"), pytest.param(None, id="none-request")]
    )
    def test_missing_protocol_raises(self, monkeypatch: pytest.MonkeyPatch, request_payload: Any) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        job = _job(request=request_payload)
        _patch_worker_deps(monkeypatch)

        with pytest.raises(ValueError, match="defillama_protocol"):
            worker.process(session, cast(Any, job))


class TestJobName:
    @pytest.mark.parametrize(
        ("initial_name", "expected"),
        [
            pytest.param(None, f"DefiLlama: {PROTOCOL}", id="sets-name-when-missing"),
            pytest.param("My Custom Name", "My Custom Name", id="preserves-existing-name"),
        ],
    )
    def test_job_name(self, monkeypatch: pytest.MonkeyPatch, initial_name: str | None, expected: str) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job(name=initial_name)

        _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert job.name == expected


class TestNoCloneEnvVar:
    @pytest.mark.parametrize(
        ("env", "expected"),
        [
            pytest.param({"DEFILLAMA_NO_CLONE": "true"}, True, id="true"),
            pytest.param({}, False, id="false-by-default"),
        ],
    )
    def test_no_clone(self, monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: bool) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        _patch_worker_deps(monkeypatch)
        monkeypatch.delenv("DEFILLAMA_NO_CLONE", raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        captured_kwargs: list[dict] = []

        def spy_scan(**kwargs):
            captured_kwargs.append(kwargs)
            return _scan_result(addresses=[])

        monkeypatch.setattr("workers.defillama_worker.scan_protocol", spy_scan)

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert captured_kwargs[0]["no_clone"] is expected


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
    @pytest.mark.parametrize(
        ("company", "expected_name"),
        [
            pytest.param(None, PROTOCOL, id="slug-becomes-protocol-name"),
            pytest.param("Aave", "Aave", id="company-preferred-over-slug"),
        ],
    )
    def test_protocol_name_derivation(
        self, monkeypatch: pytest.MonkeyPatch, company: str | None, expected_name: str
    ) -> None:
        worker = DefiLlamaWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job(company=company)

        trackers = _patch_worker_deps(monkeypatch)
        monkeypatch.setattr(
            "workers.defillama_worker.scan_protocol",
            lambda **kwargs: _scan_result(addresses=[]),
        )

        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert trackers["protocol_calls"] == [(expected_name, None)]
        assert job.protocol_id == 1
        assert job.company == expected_name


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

    @pytest.mark.parametrize(
        ("listing", "scanned", "expected"),
        [
            pytest.param(
                [{"address": _BARE_TOKEN, "chain": None, "slug": "ether.fi-liquid"}],
                [ADDR_1],
                [
                    {"address": _BARE_TOKEN, "chain": "ethereum", "new_sources": ["defillama"]},
                    {"address": ADDR_1, "chain": None, "new_sources": ["defillama"]},
                ],
                id="bare-listing-address-nominated-on-ethereum",
            ),
            pytest.param(
                [{"address": _BASE_TOKEN, "chain": "base", "slug": "x"}],
                [],
                [{"address": _BASE_TOKEN, "chain": "base", "new_sources": ["defillama"]}],
                id="prefixed-listing-address-keeps-its-chain",
            ),
            pytest.param(
                [],
                [ADDR_1],
                [{"address": ADDR_1, "chain": None, "new_sources": ["defillama"]}],
                id="no-listing-address-changes-nothing",
            ),
        ],
    )
    def test_listing_address_nomination(
        self, monkeypatch: pytest.MonkeyPatch, listing: list[dict], scanned: list[str], expected: list[dict]
    ) -> None:
        entries = self._run(monkeypatch, listing=listing, scanned=scanned)
        assert sorted(entries, key=lambda e: e["address"]) == sorted(expected, key=lambda e: e["address"])
