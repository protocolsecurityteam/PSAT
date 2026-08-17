"""Ingest-side input validation on the request models in ``schemas/api_requests``.

These assert the reject/accept boundary for hex addresses and outbound URLs so
a hostile payload cannot reach a downstream link, fetch, or scan filter.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas.api_requests import (  # noqa: E402
    AddAuditRequest,
    AnalyzeRequest,
    ProtocolSubscribeRequest,
)

_VALID_ADDR = "0x" + "ab" * 20


def test_analyze_request_rejects_non_hex_address():
    bad = "0x" + "zz" * 20  # 42 chars, not hex
    assert len(bad) == 42
    with pytest.raises(ValidationError):
        AnalyzeRequest(address=bad)


def test_analyze_request_accepts_valid_address():
    req = AnalyzeRequest(address="0x" + "AB" * 20)
    assert req.address == _VALID_ADDR  # lowercase-normalized


def test_analyze_request_dapp_urls_rejects_non_http():
    with pytest.raises(ValidationError):
        AnalyzeRequest(dapp_urls=["javascript:alert(1)"])


def test_analyze_request_dapp_urls_rejects_over_length():
    with pytest.raises(ValidationError):
        AnalyzeRequest(dapp_urls=[f"https://example.com/{i}" for i in range(51)])


def test_analyze_request_dapp_urls_accepts_http():
    req = AnalyzeRequest(dapp_urls=["https://example.com", "http://foo.test"])
    assert req.dapp_urls == ["https://example.com", "http://foo.test"]


@pytest.mark.parametrize("bad_url", ["javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd"])
def test_add_audit_request_rejects_dangerous_scheme(bad_url):
    with pytest.raises(ValidationError):
        AddAuditRequest(url=bad_url, auditor="a", title="t")


def test_add_audit_request_rejects_dangerous_pdf_url():
    with pytest.raises(ValidationError):
        AddAuditRequest(url="https://ok.test", pdf_url="javascript:alert(1)", auditor="a", title="t")


def test_add_audit_request_accepts_https():
    req = AddAuditRequest(url="https://audits.example/report.pdf", auditor="a", title="t")
    assert req.url == "https://audits.example/report.pdf"


def test_protocol_subscribe_rejects_non_discord_webhook():
    with pytest.raises(ValidationError):
        ProtocolSubscribeRequest(discord_webhook_url="https://evil.example/webhook")


def test_protocol_subscribe_rejects_http_discord():
    with pytest.raises(ValidationError):
        ProtocolSubscribeRequest(discord_webhook_url="http://discord.com/api/webhooks/1/abc")


def test_protocol_subscribe_accepts_discord_host():
    req = ProtocolSubscribeRequest(discord_webhook_url="https://discord.com/api/webhooks/1/abc")
    assert req.discord_webhook_url.startswith("https://discord.com/")
