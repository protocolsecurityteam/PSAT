"""Allowlist enforcement at user-facing chain-accepting edges.

14: work-spawning edges 400 a registered-but-unsupported chain before any job is created. The accept path is proven by
the handler reaching the mocked session's "not found".
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

_ADDR = "0x" + "ab" * 20
_BASE = "base"
_BASE_ID = 8453
_ENV = "PSAT_SUPPORTED_CHAIN_IDS"


def _client() -> TestClient:
    import api

    return TestClient(api.app)


def _mock_session_ctx(mock_session_cls, mock_session):
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)


def test_helper_accepts_supported_chain():
    from utils.chains import require_supported_chain

    info = require_supported_chain(chain="ethereum", context="t")
    assert info.chain_id == 1


def test_helper_rejects_registered_but_unsupported_chain(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)  # default allowlist = {1}
    from utils.chains import UnsupportedChainError, require_supported_chain

    with pytest.raises(UnsupportedChainError) as exc:
        require_supported_chain(chain=_BASE, context="t")
    msg = str(exc.value)
    assert _BASE in msg and str(_BASE_ID) in msg and _ENV in msg


def test_helper_accepts_when_allowlisted(monkeypatch):
    monkeypatch.setenv(_ENV, "1,8453")
    from utils.chains import require_supported_chain

    info = require_supported_chain(chain_id=_BASE_ID, context="t")
    assert info.chain_id == _BASE_ID


def test_helper_rejects_unknown_chain(monkeypatch):
    from utils.chains import UnsupportedChainError, require_supported_chain

    with pytest.raises(UnsupportedChainError):
        require_supported_chain(chain="nonexistent-chain", context="t")


@patch("routers.deps.create_job")
@patch("routers.deps.SessionLocal")
def test_analyze_rejects_unsupported_chain(mock_session_cls, mock_create_job, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    client = _client()

    resp = client.post("/api/analyze", json={"address": _ADDR, "name": "t", "chain": _BASE})

    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert _BASE in detail and _ENV in detail
    mock_create_job.assert_not_called()


@patch("routers.deps.create_job")
@patch("routers.deps.SessionLocal")
def test_analyze_accepts_unsupported_chain_when_allowlisted(mock_session_cls, mock_create_job, monkeypatch):
    monkeypatch.setenv(_ENV, "1,8453")
    client = _client()
    mock_create_job.return_value = _fake_job(address=_ADDR)
    _mock_session_ctx(mock_session_cls, MagicMock())

    resp = client.post("/api/analyze", json={"address": _ADDR, "name": "t", "chain": _BASE})

    assert resp.status_code == 200
    mock_create_job.assert_called_once()
    assert mock_create_job.call_args[0][1]["chain"] == _BASE


@patch("routers.deps.create_job")
@patch("routers.deps.SessionLocal")
def test_analyze_default_mainnet_unaffected(mock_session_cls, mock_create_job, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)  # mainnet-only deployment
    client = _client()
    mock_create_job.return_value = _fake_job(address=_ADDR)
    _mock_session_ctx(mock_session_cls, MagicMock())

    resp = client.post("/api/analyze", json={"address": _ADDR, "name": "t"})

    assert resp.status_code == 200
    mock_create_job.assert_called_once()


@patch("routers.deps.create_job")
@patch("routers.deps.SessionLocal")
def test_analyze_rejects_unregistered_chain_string(mock_session_cls, mock_create_job, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    client = _client()

    # A typo must not resolve to mainnet via derive_job_chain_id's internal fallback.
    resp = client.post("/api/analyze", json={"address": _ADDR, "name": "t", "chain": "arbtrum"})

    assert resp.status_code == 400
    assert "arbtrum" in resp.json()["detail"]
    mock_create_job.assert_not_called()


@patch("routers.deps.create_job")
@patch("routers.deps.SessionLocal")
def test_analyze_rejects_unknown_sentinel_chain(mock_session_cls, mock_create_job, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    client = _client()

    resp = client.post("/api/analyze", json={"address": _ADDR, "name": "t", "chain": "unknown"})

    assert resp.status_code == 400
    mock_create_job.assert_not_called()


@patch("routers.deps.create_job")
@patch("routers.deps.SessionLocal")
def test_analyze_chainless_company_submission_unaffected(mock_session_cls, mock_create_job, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    client = _client()
    mock_create_job.return_value = _fake_job(company="etherfi")
    _mock_session_ctx(mock_session_cls, MagicMock())

    resp = client.post("/api/analyze", json={"company": "etherfi"})

    assert resp.status_code == 200
    mock_create_job.assert_called_once()


@patch("routers.deps.SessionLocal")
def test_monitoring_enroll_rejects_unsupported_chain(mock_session_cls, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    client = _client()

    resp = client.post(
        "/api/protocols/1/monitoring",
        json={"address": _ADDR, "chain": _BASE, "contract_type": "proxy"},
    )

    assert resp.status_code == 400
    assert _BASE in resp.json()["detail"]
    mock_session_cls.assert_not_called()


@patch("routers.deps.SessionLocal")
def test_monitoring_enroll_passes_chain_gate_when_allowlisted(mock_session_cls, monkeypatch):
    monkeypatch.setenv(_ENV, "1,8453")
    client = _client()
    mock_session = MagicMock()
    mock_session.get.return_value = None  # Protocol not found → 404, past the chain gate
    _mock_session_ctx(mock_session_cls, mock_session)

    resp = client.post(
        "/api/protocols/1/monitoring",
        json={"address": _ADDR, "chain": _BASE, "contract_type": "proxy"},
    )

    assert resp.status_code == 404


@patch("routers.deps.SessionLocal")
def test_re_enroll_rejects_unsupported_chain(mock_session_cls, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    client = _client()

    resp = client.post("/api/protocols/1/re-enroll", params={"chain": _BASE})

    assert resp.status_code == 400
    assert _BASE in resp.json()["detail"]
    mock_session_cls.assert_not_called()


@patch("routers.deps.SessionLocal")
def test_re_enroll_passes_chain_gate_when_allowlisted(mock_session_cls, monkeypatch):
    monkeypatch.setenv(_ENV, "1,8453")
    client = _client()
    mock_session = MagicMock()
    mock_session.get.return_value = None  # Protocol not found → 404, past the chain gate
    _mock_session_ctx(mock_session_cls, mock_session)

    resp = client.post("/api/protocols/1/re-enroll", params={"chain": _BASE})

    assert resp.status_code == 404


@patch("routers.deps.SessionLocal")
def test_re_enroll_default_ethereum_passes_gate(mock_session_cls, monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)  # mainnet-only
    client = _client()
    mock_session = MagicMock()
    mock_session.get.return_value = None
    _mock_session_ctx(mock_session_cls, mock_session)

    resp = client.post("/api/protocols/1/re-enroll")

    assert resp.status_code == 404


def _fake_job(address: str | None = None, company: str | None = None):
    job = MagicMock()
    job.stage = MagicMock(value="discovery")
    job.id = "00000000-0000-0000-0000-000000000000"
    job.to_dict.return_value = {
        "job_id": job.id,
        "address": address,
        "company": company,
        "status": "queued",
        "stage": "discovery",
    }
    return job
