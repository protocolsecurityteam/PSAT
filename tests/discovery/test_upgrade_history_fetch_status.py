"""A failed upgrade-log fetch is recorded per proxy, never read as "no upgrades".

The fetch runs through the real Etherscan client with only the HTTP call stubbed; the DB consumers (upgrade counts,
implementation windows, scope resolution, the audit timeline) read the recorded status.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import requests

import services.clients.etherscan as etherscan
import services.discovery.upgrade_history as uh
from db.models import Contract, UpgradeEvent
from schemas.upgrade_history import UPGRADE_FETCH_COMPLETE, UPGRADE_FETCH_ERROR
from tests.conftest import requires_postgres
from tests.support.audit_coverage_builders import (
    _add_contract,
    _add_upgrade_event,
    _ts,
    seed_protocol,  # noqa: F401  (fixture, registered by import)
)
from workers.static_support.upgrade_history import _from_block_for_upgrade_history, _merge_upgrade_history


def _address(tag: str) -> str:
    return "0x" + (tag.encode().hex() + uuid.uuid4().hex + uuid.uuid4().hex)[:40]


def _topic(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


NO_RECORDS = {"status": "0", "message": "No records found", "result": []}
RATE_LIMITED = {"status": "0", "message": "NOTOK", "result": "Max calls per sec rate limit reached (10/sec)"}


@pytest.fixture
def wire(monkeypatch):
    """``{topic0: payload | exception}``; unlisted topics answer "No records found"."""
    answers: dict[str, Any] = {}
    calls: list[dict[str, Any]] = []

    def get(_url, params=None, timeout=None):
        calls.append(dict(params or {}))
        answer = answers.get(str((params or {}).get("topic0")), NO_RECORDS)
        if isinstance(answer, Exception):
            raise answer
        return _Response(answer)

    monkeypatch.setattr(etherscan.requests, "get", get)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    monkeypatch.setattr(etherscan, "_RATE_LIMIT_RETRIES", 0)
    return answers, calls


def _upgraded_log(proxy: str, impl: str, block: int) -> dict[str, Any]:
    return {
        "address": proxy,
        "topics": [uh.UPGRADED_TOPIC0, _topic(impl)],
        "data": "0x",
        "blockNumber": hex(block),
        "transactionHash": "0x" + f"{block:064x}",
        "logIndex": "0x0",
        "timeStamp": hex(1_700_000_000 + block),
    }


def _history(proxy: str, from_block: int = 0) -> dict[str, Any]:
    deps = {
        "address": proxy,
        "target_classification": {"type": "proxy", "proxy_type": "eip1967", "implementation": _address("cur")},
        "dependencies": {},
    }
    return dict(uh.build_upgrade_history(deps, enrich=False, from_block=from_block))


def test_no_records_on_every_topic_is_a_complete_empty_history(wire):
    proxy = _address("p")
    record = _history(proxy)["proxies"][proxy.lower()]
    assert record["fetch_status"] == UPGRADE_FETCH_COMPLETE
    assert record["events"] == [] and "fetch_errors" not in record


def test_found_logs_and_no_records_elsewhere_stay_complete(wire):
    answers, _ = wire
    proxy, impl = _address("p"), _address("i")
    answers[uh.UPGRADED_TOPIC0] = {"status": "1", "message": "OK", "result": [_upgraded_log(proxy, impl, 10)]}

    record = _history(proxy)["proxies"][proxy.lower()]
    assert record["fetch_status"] == UPGRADE_FETCH_COMPLETE
    assert [e["implementation"] for e in record["events"]] == [impl.lower()]


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(RATE_LIMITED, id="rate-limit-exhausted"),
        pytest.param({"status": "0", "message": "NOTOK", "result": "Invalid API Key"}, id="api-error"),
        pytest.param(requests.ConnectionError("reset by peer"), id="transport"),
    ],
)
def test_a_failed_topic_marks_the_proxy_errored_and_keeps_what_was_read(wire, failure):
    answers, _ = wire
    proxy, impl = _address("p"), _address("i")
    answers[uh.UPGRADED_TOPIC0] = {"status": "1", "message": "OK", "result": [_upgraded_log(proxy, impl, 10)]}
    answers[uh.ADMIN_CHANGED_TOPIC0] = failure

    record = _history(proxy, from_block=5)["proxies"][proxy.lower()]
    assert record["fetch_status"] == UPGRADE_FETCH_ERROR
    assert record["fetch_errors"] == ["admin_changed"]
    assert record["refetch_from_block"] == 5
    assert len(record["events"]) == 1


def _stored(proxy: str, blocks: list[int], **status: Any) -> dict[str, Any]:
    events = [
        {
            "event_type": "upgraded",
            "block_number": b,
            "tx_hash": f"0x{b:064x}",
            "log_index": 0,
            "implementation": f"0x{b:040x}",
        }
        for b in blocks
    ]
    return {
        "proxies": {
            proxy: {
                "proxy_address": proxy,
                "proxy_type": "eip1967",
                "current_implementation": None,
                "events": events,
                "upgrade_count": len(events),
                **status,
            }
        }
    }


def test_resume_block_is_the_failed_fetch_start_not_past_the_newest_event():
    proxy = _address("p").lower()
    complete = _stored(proxy, [10, 50], fetch_status=UPGRADE_FETCH_COMPLETE)
    assert _from_block_for_upgrade_history(complete) == 51

    # The refresh from 51 read an event at 70 on one topic and failed on another.
    errored = _stored(proxy, [70], fetch_status=UPGRADE_FETCH_ERROR, fetch_errors=["upgraded"], refetch_from_block=51)
    merged = _merge_upgrade_history(complete, errored)
    record = merged["proxies"][proxy]
    assert record["fetch_status"] == UPGRADE_FETCH_ERROR
    assert record["refetch_from_block"] == 51
    assert [e["block_number"] for e in record["events"]] == [10, 50, 70]
    assert _from_block_for_upgrade_history(merged) == 51

    # A second failure keeps the earliest unread block; a clean re-read from it settles the history.
    again = _merge_upgrade_history(
        merged,
        _stored(proxy, [], fetch_status=UPGRADE_FETCH_ERROR, fetch_errors=["admin_changed"], refetch_from_block=51),
    )
    assert again["proxies"][proxy]["refetch_from_block"] == 51
    assert again["proxies"][proxy]["fetch_errors"] == ["admin_changed", "upgraded"]
    settled = _merge_upgrade_history(again, _stored(proxy, [70, 80], fetch_status=UPGRADE_FETCH_COMPLETE))
    assert settled["proxies"][proxy]["fetch_status"] == UPGRADE_FETCH_COMPLETE
    assert "refetch_from_block" not in settled["proxies"][proxy]
    assert _from_block_for_upgrade_history(settled) == 81


def test_a_legacy_history_without_a_status_resumes_as_before():
    proxy = _address("p").lower()
    legacy = _stored(proxy, [10, 50])
    assert _from_block_for_upgrade_history(legacy) == 51
    merged = _merge_upgrade_history(legacy, _stored(proxy, [60]))
    assert "fetch_status" not in merged["proxies"][proxy]


def _proxy(session, protocol_id, *, status: str | None, implementation: str | None = None) -> Contract:
    proxy = _add_contract(
        session, protocol_id, address=_address("proxy"), name="Proxy", is_proxy=True, implementation=implementation
    )
    proxy.upgrade_history_status = status
    session.commit()
    return proxy


@requires_postgres
def test_projection_records_the_status_on_the_proxy_row(db_session, seed_protocol):
    protocol_id, _ = seed_protocol
    proxy = _proxy(db_session, protocol_id, status=None)
    artifact = _stored(
        proxy.address, [10], fetch_status=UPGRADE_FETCH_ERROR, fetch_errors=["upgraded"], refetch_from_block=0
    )
    uh.project_to_events(db_session, subject_contract_id=proxy.id, subject_chain="ethereum", artifact_data=artifact)
    db_session.commit()
    db_session.refresh(proxy)
    assert proxy.upgrade_history_status == UPGRADE_FETCH_ERROR
    assert db_session.query(UpgradeEvent).filter_by(contract_id=proxy.id).count() == 1


@requires_postgres
def test_upgrade_counts_are_not_determined_for_an_errored_proxy(db_session, seed_protocol):
    protocol_id, _ = seed_protocol
    complete = _proxy(db_session, protocol_id, status=UPGRADE_FETCH_COMPLETE)
    errored = _proxy(db_session, protocol_id, status=UPGRADE_FETCH_ERROR)
    errored_empty = _proxy(db_session, protocol_id, status=UPGRADE_FETCH_ERROR)
    legacy = _proxy(db_session, protocol_id, status=None)
    for proxy in (complete, errored, legacy):
        for block in (10, 20):
            _add_upgrade_event(
                db_session,
                contract_id=proxy.id,
                proxy_address=proxy.address,
                new_impl=_address("impl"),
                block_number=block,
                timestamp=_ts(2024, 1, block),
                tx_hash="0x" + uuid.uuid4().hex * 2,
            )

    counts = uh.upgrade_action_counts(db_session, [complete.id, errored.id, errored_empty.id, legacy.id])
    assert counts[complete.id]["count"] == 2
    assert counts[complete.id]["basis"]["history_fetch_status"] == UPGRADE_FETCH_COMPLETE
    assert counts[legacy.id]["count"] == 2
    assert counts[legacy.id]["basis"]["history_fetch_status"] == "not_determined"
    assert counts[errored.id]["count"] is None
    assert counts[errored.id]["basis"]["history_fetch_status"] == UPGRADE_FETCH_ERROR
    assert counts[errored.id]["basis"]["events_total"] == 2
    assert counts[errored_empty.id]["count"] is None
    assert counts[errored_empty.id]["basis"]["history_fetch_status"] == UPGRADE_FETCH_ERROR


@requires_postgres
@pytest.mark.parametrize(
    ("status", "successor", "bounds", "confidence"),
    [
        pytest.param(UPGRADE_FETCH_COMPLETE, "none", (10, None), "high", id="complete"),
        pytest.param(UPGRADE_FETCH_ERROR, "not_determined", (None, None), "low", id="errored"),
    ],
)
def test_impl_windows_of_an_errored_proxy_are_not_determined(
    db_session, seed_protocol, status, successor, bounds, confidence
):
    from services.audits.coverage import (
        _compute_impl_windows_batch,
        _confidence_for_impl_era,
        _publishable_block_bounds,
    )

    protocol_id, _ = seed_protocol
    proxy = _proxy(db_session, protocol_id, status=status)
    impl = _add_contract(db_session, protocol_id, address=_address("impl"), name="Impl")
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl.address,
        block_number=10,
        timestamp=_ts(2024, 1, 1),
    )

    (window,) = _compute_impl_windows_batch(db_session, [impl])[impl.id]
    assert window.successor == successor
    assert _publishable_block_bounds(window) == bounds
    assert _confidence_for_impl_era(_ts(2024, 3, 1), [window]) == (confidence, window)


@requires_postgres
@pytest.mark.parametrize(
    ("status", "resolves"),
    [pytest.param(UPGRADE_FETCH_COMPLETE, True, id="complete"), pytest.param(UPGRADE_FETCH_ERROR, False, id="errored")],
)
def test_an_errored_history_never_binds_an_audit_to_todays_impl(db_session, seed_protocol, status, resolves):
    from services.audits.coverage import _resolve_impl_for_address

    protocol_id, _ = seed_protocol
    impl = _add_contract(db_session, protocol_id, address=_address("impl"), name="Impl")
    proxy = _proxy(db_session, protocol_id, status=status, implementation=impl.address)
    target = _resolve_impl_for_address(
        db_session, protocol_id, proxy, audit_ts=_ts(2024, 3, 1), row_cache={}, proxy_events_cache={}
    )
    assert (target.id if target else None) == (impl.id if resolves else None)


@requires_postgres
def test_the_audit_timeline_marks_an_errored_proxys_windows_not_determined(db_session, seed_protocol):
    from services.aggregations import build_contract_audit_timeline

    protocol_id, _ = seed_protocol
    errored = _proxy(db_session, protocol_id, status=UPGRADE_FETCH_ERROR)
    complete = _proxy(db_session, protocol_id, status=UPGRADE_FETCH_COMPLETE)
    for proxy in (errored, complete):
        _add_upgrade_event(
            db_session,
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=_address("impl"),
            block_number=10,
            timestamp=_ts(2024, 1, 1),
        )

    unread = build_contract_audit_timeline(db_session, errored.id)
    read = build_contract_audit_timeline(db_session, complete.id)
    assert unread is not None and read is not None
    assert unread["contract"]["upgrade_history_status"] == UPGRADE_FETCH_ERROR
    assert [w["bounds"] for w in unread["impl_windows"]] == ["not_determined"]
    assert read["contract"]["upgrade_history_status"] == UPGRADE_FETCH_COMPLETE
    assert [w["bounds"] for w in read["impl_windows"]] == ["recorded"]
