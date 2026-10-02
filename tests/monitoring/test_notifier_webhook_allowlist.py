from __future__ import annotations

from unittest.mock import patch

import pytest

from services.monitoring.notifier import _is_discord_webhook, _send_discord


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://discord.com/api/webhooks/1/abc", True),
        ("https://discordapp.com/api/webhooks/1/abc", True),
        ("https://canary.discord.com/api/webhooks/1/abc", True),
        ("https://ptb.discord.com/api/webhooks/1/abc", True),
        ("http://discord.com/api/webhooks/1/abc", False),  # not https
        ("https://evil.com/api/webhooks/1/abc", False),
        ("https://discord.com.evil.com/x", False),
        ("https://169.254.169.254/x", False),
        # urlparse reads discord.com but urllib3 dials elsewhere; the gate reads the dialed host.
        ("https://x\\@discord.com/api/webhooks/1/x", False),  # backslash-authority
        ("https://discord.com@evil.com/api/webhooks/1/x", False),  # userinfo, real host evil.com
    ],
)
def test_is_discord_webhook(url, ok):
    assert _is_discord_webhook(url) is ok


class _Resp:
    ok = True
    status_code = 204


@pytest.mark.parametrize(
    ("url", "posted"),
    [
        pytest.param("https://x\\@discord.com/api/webhooks/1/x", False, id="backslash_authority_bypass"),
        pytest.param("https://evil.example/webhook", False, id="non_discord_host"),
        pytest.param("https://discord.com/api/webhooks/1/abc", True, id="discord_host_posts"),
    ],
)
def test_send_discord_gate(url, posted):
    with patch("services.monitoring.notifier.requests.post", return_value=_Resp()) as mock_post:
        _send_discord(url, {"title": "x"})
    if posted:
        mock_post.assert_called_once()
    else:
        mock_post.assert_not_called()
