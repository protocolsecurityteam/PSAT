"""An address with no code and no Etherscan creation record is asked about once, not on every probe.

Etherscan answers ``getcontractcreation`` for a code-less address with ``status 0 / "No data found" / null``. Paired
with this probe's own empty ``eth_getCode`` at a block, that answer is kept per ``(chain, address)``. A failed call is
no answer and is never kept. The wire is stubbed at HTTP (Etherscan) and ``rpc_request``; everything else is real.
"""

from __future__ import annotations

from typing import Any

import pytest
import requests

from db.models import Contract, ContractCreationWitness
from services.clients import etherscan
from services.clients.rpc import EthCallResult
from services.discovery import probes
from services.discovery.probes import CREATION_ABSENCE_REVALIDATE_S
from tests.conftest import requires_postgres
from tests.support.membership_builders import _protocol
from utils.chains import chain_by_id

pytestmark = [requires_postgres]

EMPTY = "0x" + "e0" * 20
CREATOR = "0x" + "4f" * 20
TX = "0x" + "b9" * 32
HEAD = 20_000_000

NO_DATA = {"status": "0", "message": "No data found", "result": None}
RATE_LIMITED = {"status": "0", "message": "NOTOK", "result": "Max calls per sec rate limit reached (5/sec)"}


class _Response:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Server Error")

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Wire:
    """Etherscan and RPC answers a test can change between probes."""

    def __init__(self) -> None:
        self.creation: Any = NO_DATA
        self.creation_calls = 0
        self.head = HEAD
        self.code = "0x"


@pytest.fixture()
def wire(monkeypatch) -> _Wire:
    state = _Wire()
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")

    def http_get(_url, params=None, timeout=None):
        assert (params or {}).get("action") == "getcontractcreation"
        state.creation_calls += 1
        answer = state.creation
        if isinstance(answer, requests.RequestException):
            raise answer
        if isinstance(answer, _Response):
            return answer
        return _Response(answer)

    def fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        if method == "eth_blockNumber":
            return hex(state.head)
        if method == "eth_getCode":
            return state.code
        raise AssertionError(f"unexpected rpc method {method}")

    monkeypatch.setattr(etherscan.requests, "get", http_get)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    monkeypatch.setattr(etherscan, "_RATE_LIMIT_RETRIES", 0)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", False)
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", False)
    monkeypatch.setattr(probes, "rpc_request", fake_rpc_request)
    monkeypatch.setattr(
        probes, "eth_call_batch", lambda *a, **kw: [EthCallResult(False, "0x", None, "reverted") for _ in a[1]]
    )
    monkeypatch.setattr(probes, "rpc_batch_request", lambda rpc_url, calls, *a, **kw: ["0x" + "0" * 64 for _ in calls])
    return state


@pytest.fixture()
def empty_row(db_session) -> Contract:
    protocol = _protocol(db_session)
    row = Contract(address=EMPTY, chain="ethereum", nominated_protocol_id=protocol.id)
    db_session.add(row)
    db_session.flush()
    return row


def _absence(session) -> int | None:
    witness = session.get(ContractCreationWitness, (1, EMPTY))
    return None if witness is None else witness.no_creation_record_block


def test_proven_absence_is_asked_once_across_jobs(db_session, wire, empty_row):
    for job in range(5):
        wire.head = HEAD + job
        result = probes.run_probe(db_session, empty_row)
        assert result.code_present is False
        assert (result.creation_tx_hash, result.deployer) == (None, None)

    assert wire.creation_calls == 1
    assert _absence(db_session) == HEAD


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(RATE_LIMITED, id="rate_limited"),
        pytest.param(_Response({"error": "upstream"}, status=502), id="http_error"),
        pytest.param(requests.ReadTimeout("timed out"), id="timeout"),
        pytest.param(_Response(ValueError("not json")), id="malformed_body"),
        pytest.param({"status": "0", "message": "No data found", "result": "No data found"}, id="no_data_not_null"),
        pytest.param({"status": "1", "message": "OK", "result": "unexpected"}, id="ok_not_a_list"),
    ],
)
def test_a_failed_call_is_never_kept_as_absence(db_session, wire, empty_row, failure):
    wire.creation = failure
    for _ in range(3):
        probes.run_probe(db_session, empty_row)

    assert wire.creation_calls == 3
    assert _absence(db_session) is None


def test_no_record_with_code_present_is_not_kept(db_session, wire, empty_row):
    wire.code = "0x6080"
    for _ in range(2):
        probes.run_probe(db_session, empty_row)

    assert wire.creation_calls == 2
    assert _absence(db_session) is None


def test_absence_is_revalidated_past_the_window(db_session, wire, empty_row):
    probes.run_probe(db_session, empty_row)
    window = int(CREATION_ABSENCE_REVALIDATE_S / chain_by_id(1).block_time_s)

    wire.head = HEAD + window
    probes.run_probe(db_session, empty_row)
    assert wire.creation_calls == 1

    wire.head = HEAD + window + 1
    probes.run_probe(db_session, empty_row)
    assert wire.creation_calls == 2
    assert _absence(db_session) == HEAD + window + 1


def test_code_appearing_drops_the_absence_and_asks_again(db_session, wire, empty_row):
    probes.run_probe(db_session, empty_row)
    assert _absence(db_session) == HEAD

    wire.head = HEAD + 10
    wire.code = "0x6080"
    wire.creation = {
        "status": "1",
        "message": "OK",
        "result": [{"contractAddress": EMPTY, "contractCreator": CREATOR, "txHash": TX, "blockNumber": str(HEAD + 5)}],
    }
    result = probes.run_probe(db_session, empty_row)

    assert wire.creation_calls == 2
    assert (result.deployer, result.creation_tx_hash) == (CREATOR, TX)
    assert _absence(db_session) is None
    witness = db_session.get(ContractCreationWitness, (1, EMPTY))
    assert witness is not None and (witness.code_absent_at_probe, witness.creation_tx_hash) == (False, TX)


def test_no_data_found_is_an_answer_only_for_creation_lookups(monkeypatch):
    monkeypatch.setattr(etherscan.requests, "get", lambda *a, **kw: _Response(NO_DATA))
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "k")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    monkeypatch.setattr(etherscan, "_RATE_LIMIT_RETRIES", 0)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", False)
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", False)

    assert (
        etherscan.get("contract", "getcontractcreation", chain_id=1, empty_result_ok=True, contractaddresses=EMPTY)
        == NO_DATA
    )
    with pytest.raises(RuntimeError):
        etherscan.get("contract", "getcontractcreation", chain_id=1, contractaddresses=EMPTY)
    with pytest.raises(RuntimeError):
        etherscan.get("logs", "getLogs", chain_id=1, empty_result_ok=True, address=EMPTY)
