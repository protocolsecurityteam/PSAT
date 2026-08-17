"""The Discord notifier only POSTs to allowlisted Discord hosts over https."""

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
    ],
)
def test_is_discord_webhook(url, ok):
    assert _is_discord_webhook(url) is ok


def test_send_discord_skips_non_discord_host():
    with patch("services.monitoring.notifier.requests.post") as mock_post:
        _send_discord("https://evil.example/webhook", {"title": "x"})
    mock_post.assert_not_called()


def test_send_discord_posts_to_discord_host():
    class _Resp:
        ok = True
        status_code = 204

    with patch("services.monitoring.notifier.requests.post", return_value=_Resp()) as mock_post:
        _send_discord("https://discord.com/api/webhooks/1/abc", {"title": "x"})
    mock_post.assert_called_once()
