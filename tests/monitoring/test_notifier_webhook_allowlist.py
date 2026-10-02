from __future__ import annotations

import pytest

from services.monitoring.notifier import _is_discord_webhook


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
