"""Tests for ``utils/secrets.py`` redaction helpers and the API
response surfaces that depend on them.

The endpoint-level checks exercise the serializers (``Job.to_dict``,
the stage_errors response, the protocol subscriptions response) via a
mocked SessionLocal rather than a live Postgres.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.secrets import sanitize_obj, sanitize_string, sanitize_url

_ALCHEMY = "https://eth-mainnet.g.alchemy.com/v2/FAKE_ALCHEMY_KEY_FOR_TESTS"
_INFURA = "https://mainnet.infura.io/v3/FAKE_INFURA_KEY_FOR_TESTS"
_ETHERSCAN = "https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&apikey=FAKE_ETHERSCAN_KEY"
_PUBLIC_RPC = "https://ethereum-rpc.publicnode.com"
_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/FAKE_DISCORD_TOKEN_FOR_TESTS"


class TestSanitizeUrl:
    def test_alchemy_path_key_is_masked(self):
        out = sanitize_url(_ALCHEMY)
        assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in out
        assert out.startswith("https://eth-mainnet.g.alchemy.com/")
        assert "<redacted>" in out

    def test_infura_path_key_is_masked(self):
        out = sanitize_url(_INFURA)
        assert "FAKE_INFURA_KEY_FOR_TESTS" not in out
        assert out.startswith("https://mainnet.infura.io/")

    def test_etherscan_apikey_query_param_is_masked(self):
        out = sanitize_url(_ETHERSCAN)
        assert "FAKE_ETHERSCAN_KEY" not in out
        assert "apikey=<redacted>" in out
        # Non-secret params survive.
        assert "module=account" in out
        assert "chainid=1" in out

    def test_discord_webhook_token_is_masked(self):
        out = sanitize_url(_DISCORD_WEBHOOK)
        assert "FAKE_DISCORD_TOKEN_FOR_TESTS" not in out
        # Webhook id (the public-ish part) survives so an admin can still
        # tell two webhooks apart in the UI.
        assert "123456789012345678" in out

    def test_public_rpc_pass_through(self):
        # No path-key, no query-key — nothing to redact.
        assert sanitize_url(_PUBLIC_RPC) == _PUBLIC_RPC

    def test_generic_path_key_segment_caught_by_shape(self):
        # An obscure provider not in the host suffix list — the
        # ``/v2/<longblob>`` shape still triggers redaction.
        out = sanitize_url("https://rpc.obscure-provider.example/v2/abc123XYZdef456GHI")
        assert "abc123XYZdef456GHI" not in out
        assert "/v2/<redacted>" in out

    def test_non_url_string_passes_through(self):
        assert sanitize_url("not a url") == "not a url"
        assert sanitize_url("") == ""

    def test_non_string_passes_through(self):
        # ``Job.error`` can be None; helper must not raise.
        assert sanitize_url(None) is None  # type: ignore[arg-type]


class TestSanitizeString:
    def test_url_embedded_in_traceback_is_scrubbed(self):
        msg = f"RuntimeError: RPC request failed for {_ALCHEMY}: timed out"
        out = sanitize_string(msg)
        assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in out
        assert "<redacted>" in out

    def test_multiple_urls_all_scrubbed(self):
        msg = f"first {_ALCHEMY} second {_ETHERSCAN}"
        out = sanitize_string(msg)
        assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in out
        assert "FAKE_ETHERSCAN_KEY" not in out

    def test_no_url_pass_through(self):
        assert sanitize_string("nothing to see") == "nothing to see"


class TestSanitizeObj:
    def test_nested_rpc_url_keyed_value_is_masked(self):
        body = {
            "address": "0xabc",
            "rpc_url": _ALCHEMY,
            "nested": {"dynamic_rpc": _ALCHEMY},
        }
        out = sanitize_obj(body)
        assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in str(out)
        assert out["address"] == "0xabc"

    def test_list_of_dicts_walked(self):
        body = [{"rpc_url": _ALCHEMY}, {"foo": "bar"}]
        out = sanitize_obj(body)
        assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in str(out)
        assert out[1]["foo"] == "bar"

    def test_url_in_arbitrary_string_field_still_caught(self):
        # A user pasted the URL into a free-text field. The recursive
        # sanitize_string() pass catches it even though the key name
        # isn't in the SECRET_VALUE_KEYS list.
        body = {"detail": f"trying to use {_ALCHEMY} for tracing"}
        out = sanitize_obj(body)
        assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in out["detail"]


# ---------------------------------------------------------------------------
# End-to-end: Job.to_dict + /api/jobs response
# ---------------------------------------------------------------------------


def _make_client():
    from fastapi.testclient import TestClient

    import api

    return TestClient(api.app)


def _mock_session_ctx(mock_session_cls, mock_session):
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)


def _build_real_job(request_body: dict, error: str | None = None):
    """Construct a real Job ORM instance so ``to_dict`` is exercised end-to-end."""
    from db.models import Job, JobStage, JobStatus

    job = Job(
        id=uuid.uuid4(),
        address=request_body.get("address"),
        company=None,
        name=request_body.get("name"),
        status=JobStatus.queued,
        stage=JobStage.discovery,
        detail="queued",
        request=request_body,
        error=error,
        worker_id=None,
        trace_id="trace-abc",
        is_proxy=False,
        retry_count=0,
        next_attempt_at=None,
        last_failure_kind=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    return job


def test_job_to_dict_redacts_rpc_url_in_request():
    job = _build_real_job({"address": "0xabc", "rpc_url": _ALCHEMY})
    out = job.to_dict()
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in str(out)
    assert "<redacted>" in out["request"]["rpc_url"]


def test_job_to_dict_redacts_url_inside_error_traceback():
    fake_tb = (
        "Traceback (most recent call last):\n"
        "  File rpc.py, line 252, in rpc_request\n"
        f"    raise RuntimeError('RPC request failed for {_ALCHEMY}: timed out')\n"
        "RuntimeError: RPC request failed\n"
    )
    job = _build_real_job({"address": "0xabc"}, error=fake_tb)
    out = job.to_dict()
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in str(out)
    assert "<redacted>" in out["error"]


@patch("routers.deps.SessionLocal")
def test_list_jobs_endpoint_never_returns_raw_alchemy_url(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    job = _build_real_job({"address": "0xabc", "rpc_url": _ALCHEMY})
    mock_session.execute.return_value.scalars.return_value.all.return_value = [job]

    resp = client.get("/api/jobs")
    assert resp.status_code == 200
    body = resp.json()
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in resp.text
    assert "<redacted>" in body[0]["request"]["rpc_url"]


@patch("routers.deps.SessionLocal")
def test_get_job_endpoint_never_returns_raw_alchemy_url(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    job = _build_real_job({"address": "0xabc", "rpc_url": _ALCHEMY})
    mock_session.get.return_value = job

    resp = client.get(f"/api/jobs/{job.id}")
    assert resp.status_code == 200
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in resp.text


# ---------------------------------------------------------------------------
# End-to-end: /api/jobs/{id}/errors sanitizes stage_errors body
# ---------------------------------------------------------------------------


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_job_errors_endpoint_redacts_stage_error_urls(mock_session_cls, mock_get_artifact):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    job = _build_real_job({"address": "0xabc"})
    mock_session.get.return_value = job

    mock_get_artifact.return_value = {
        "errors": [
            {
                "stage": "discovery",
                "severity": "error",
                "exc_type": "RuntimeError",
                "message": f"RPC request failed for {_ALCHEMY}: timeout",
                "traceback": f"...{_ALCHEMY}...",
                "phase": None,
                "trace_id": "trace-abc",
                "job_id": str(job.id),
                "worker_id": "worker-1",
                "failed_at": "2026-01-01T00:00:00+00:00",
                "retry_count": 0,
                "context": {"rpc_url": _ALCHEMY},
            }
        ]
    }

    resp = client.get(f"/api/jobs/{job.id}/errors")
    assert resp.status_code == 200
    assert "FAKE_ALCHEMY_KEY_FOR_TESTS" not in resp.text


# ---------------------------------------------------------------------------
# End-to-end: /api/protocols/{id}/subscriptions sanitizes Discord webhook URL
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
def test_list_protocol_subscriptions_masks_discord_webhook(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    sub = MagicMock()
    sub.id = uuid.uuid4()
    sub.protocol_id = 42
    sub.discord_webhook_url = _DISCORD_WEBHOOK
    sub.label = "test"
    sub.event_filter = None
    sub.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    mock_session.execute.return_value.scalars.return_value.all.return_value = [sub]

    resp = client.get("/api/protocols/42/subscriptions")
    assert resp.status_code == 200
    assert "FAKE_DISCORD_TOKEN_FOR_TESTS" not in resp.text
    body = resp.json()
    assert "<redacted>" in body[0]["discord_webhook_url"]


# ---------------------------------------------------------------------------
# End-to-end: dependency discovery artifacts do NOT carry rpc field
# ---------------------------------------------------------------------------


def test_static_dependencies_artifact_drops_rpc_field(monkeypatch):
    """find_dependencies() does not include the resolved RPC URL in its return body."""
    from services.discovery import static_dependencies as sd

    monkeypatch.setattr(sd, "load_dotenv", lambda _path: None)
    monkeypatch.setattr(sd, "discover_dependencies", lambda _rpc, _root, code_cache=None: ["0x" + "11" * 20])

    out = sd.find_dependencies("0x" + "aa" * 20, rpc_url=_ALCHEMY)
    assert "rpc" not in out
    assert out["dependencies"] == ["0x" + "11" * 20]


def test_dynamic_dependencies_artifact_drops_rpc_field(monkeypatch):
    from services.discovery import dynamic_dependencies as dd

    monkeypatch.setattr(dd, "load_dotenv", lambda _path: None)
    monkeypatch.setattr(dd, "resolve_trace_rpc", lambda url=None: _ALCHEMY)
    monkeypatch.setattr(
        dd,
        "_fetch_tx_metadata_from_rpc",
        lambda _rpc, _tx: {"tx_hash": "0xff", "block_number": 1, "method_selector": "0xabcd0000"},
    )

    def _fake_trace(_rpc, _tx):
        node = {"type": "CALL", "from": "0x" + "aa" * 20, "to": "0x" + "bb" * 20, "calls": []}
        return "debug_traceTransaction", node

    monkeypatch.setattr(dd, "trace_transaction", _fake_trace)
    monkeypatch.setattr(dd, "has_deployed_code", lambda _code: True)
    monkeypatch.setattr(dd, "get_code", lambda _rpc, _addr: "0xff")

    out = dd.find_dynamic_dependencies(
        "0x" + "aa" * 20,
        rpc_url=_ALCHEMY,
        tx_hashes=["0xff"],
    )
    assert "rpc" not in out, "dynamic_dependencies artifact must not embed the resolved RPC URL"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
