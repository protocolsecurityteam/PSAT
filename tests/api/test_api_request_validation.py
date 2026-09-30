
from __future__ import annotations

import pytest
from pydantic import ValidationError

from schemas.api_requests import (
    AddAuditRequest,
    AnalyzeRequest,
    ProtocolSubscribeRequest,
)

_VALID_ADDR = "0x" + "ab" * 20


def test_analyze_request_accepts_valid_address():
    req = AnalyzeRequest(address="0x" + "AB" * 20)
    assert req.address == _VALID_ADDR  # lowercase-normalized


def test_analyze_request_dapp_urls_rejects_over_length():
    with pytest.raises(ValidationError):
        AnalyzeRequest(dapp_urls=[f"https://example.com/{i}" for i in range(51)])


@pytest.mark.parametrize(
    "bad_url",
    [
        "javascript:alert(1)",
        "data:text/html,<script>",
        "file:///etc/passwd",
        "JavaScript:alert(1)",  # scheme is case-insensitive
        " javascript:alert(1)",  # leading whitespace must not smuggle a scheme
        "java\nscript:alert(1)",  # embedded control char must not smuggle a scheme
    ],
)
def test_add_audit_request_rejects_dangerous_scheme(bad_url):
    with pytest.raises(ValidationError):
        AddAuditRequest(url=bad_url, auditor="a", title="t")


@pytest.mark.parametrize(
    ("model", "kwargs"),
    [
        pytest.param(AnalyzeRequest, {"address": "0x" + "zz" * 20}, id="address-non-hex"),
        # fullmatch anchoring: a trailing newline must not sneak past the hex check.
        pytest.param(AnalyzeRequest, {"address": "0x" + "ab" * 20 + "\n"}, id="address-trailing-newline"),
        pytest.param(AnalyzeRequest, {"dapp_urls": ["javascript:alert(1)"]}, id="dapp-urls-non-http"),
        pytest.param(
            AddAuditRequest,
            {"url": "https://ok.test", "pdf_url": "javascript:alert(1)", "auditor": "a", "title": "t"},
            id="audit-dangerous-pdf-url",
        ),
        pytest.param(
            ProtocolSubscribeRequest,
            {"discord_webhook_url": "https://evil.example/webhook"},
            id="webhook-non-discord",
        ),
        pytest.param(
            ProtocolSubscribeRequest,
            {"discord_webhook_url": "http://discord.com/api/webhooks/1/abc"},
            id="webhook-http-discord",
        ),
    ],
)
def test_request_models_reject_invalid_input(model, kwargs):
    with pytest.raises(ValidationError):
        model(**kwargs)


@pytest.mark.parametrize(
    "bypass_url",
    [
        "https://discord.com@evil.com/api/webhooks/1/abc",  # userinfo, real host is evil.com
        "https://discord.com.evil.com/api/webhooks/1/abc",  # subdomain-suffix, host ends in evil.com
        # urlparse reads discord.com but urllib3 dials the pre-backslash host; the gate reads the dialed host.
        "https://x\\@discord.com/api/webhooks/1/abc",
    ],
)
def test_protocol_subscribe_rejects_host_bypass(bypass_url):
    with pytest.raises(ValidationError):
        ProtocolSubscribeRequest(discord_webhook_url=bypass_url)


def test_protocol_subscribe_accepts_discord_host():
    req = ProtocolSubscribeRequest(discord_webhook_url="https://discord.com/api/webhooks/1/abc")
    assert req.discord_webhook_url.startswith("https://discord.com/")
