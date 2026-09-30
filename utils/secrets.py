"""URL redaction for anything crossing an output boundary (logs, exceptions, responses, persisted state).

Dependency-free for cheap low-level import.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

# Substring match so every subdomain hits.
_SECRET_PATH_HOST_PARTS = (
    "alchemy.com",
    "alchemyapi.io",
    "infura.io",
    "quicknode.com",
    "quiknode.pro",
    "chainstack.com",
    "getblock.io",
    "ankr.com",
    "blockdaemon.com",
    "blastapi.io",
    "blockpi.network",
    "drpc.org",
    "dwellir.com",
    "nodereal.io",
    "nownodes.io",
    "tenderly.co",
    "pokt.network",
    "omniatech.io",
    "rpc.tatum.io",
    "moralis.io",
)

_SECRET_QUERY_KEYS = frozenset(
    {
        "apikey",
        "api-key",
        "api_key",
        "key",
        "token",
        "access_token",
        "auth",
        "authorization",
        "secret",
        "x-api-key",
    }
)

# Stops at whitespace/quotes so trailing prose isn't consumed.
_URL_RE = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+")

# Catches provider URLs whose host isn't listed.
_PATH_KEY_SEGMENT_RE = re.compile(r"/(v\d+)/[A-Za-z0-9_\-]{12,}")

_DISCORD_WEBHOOK_PATH_RE = re.compile(r"^/api(?:/v\d+)?/webhooks/")

_REDACTED = "<redacted>"


def _host_is_credentialed(host: str) -> bool:
    h = host.lower()
    return any(part in h for part in _SECRET_PATH_HOST_PARTS)


def sanitize_url(url: str) -> str:
    """Mask userinfo, known-provider paths, Discord webhook tokens, ``/vN/<opaque>`` segments and secret query
    values.

    Unparseable URLs become ``<redacted>``.
    """
    if not isinstance(url, str) or "://" not in url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return _REDACTED
    if not parts.scheme or not parts.netloc:
        return url

    new_path = parts.path
    if _host_is_credentialed(parts.hostname or ""):
        new_path = f"/{_REDACTED}"
    elif (parts.hostname or "").endswith(("discord.com", "discordapp.com")) and _DISCORD_WEBHOOK_PATH_RE.match(
        parts.path
    ):
        segments = parts.path.split("/")
        token_idx = 5 if len(segments) >= 3 and segments[2].startswith("v") else 4
        if len(segments) > token_idx:
            segments[token_idx] = _REDACTED
            new_path = "/".join(segments[: token_idx + 1])
    else:
        m = _PATH_KEY_SEGMENT_RE.search(parts.path)
        if m:
            new_path = parts.path.replace(m.group(0), f"/{m.group(1)}/{_REDACTED}", 1)

    new_query = parts.query
    if new_query:
        pairs = parse_qsl(new_query, keep_blank_values=True)
        rebuilt = []
        for k, v in pairs:
            if k.lower() in _SECRET_QUERY_KEYS and v:
                rebuilt.append(f"{k}={_REDACTED}")
            else:
                rebuilt.append(f"{k}={v}")
        new_query = "&".join(rebuilt)

    new_netloc = parts.netloc
    if parts.username is not None or parts.password is not None:
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        new_netloc = f"{host}:{parts.port}" if parts.port is not None else host

    return urlunsplit((parts.scheme, new_netloc, new_path, new_query, parts.fragment))


def sanitize_string(text: str) -> str:
    if not isinstance(text, str) or "://" not in text:
        return text
    return _URL_RE.sub(lambda m: sanitize_url(m.group(0)), text)


_SECRET_VALUE_KEYS = frozenset(
    {
        "rpc_url",
        "rpc",
        "eth_rpc",
        "dynamic_rpc",
        "discord_webhook_url",
        "webhook_url",
    }
)


def sanitize_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _SECRET_VALUE_KEYS and isinstance(v, str):
                out[k] = sanitize_url(v)
            else:
                out[k] = sanitize_obj(v)
        return out
    if isinstance(obj, list):
        return [sanitize_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(sanitize_obj(v) for v in obj)
    if isinstance(obj, str):
        return sanitize_string(obj)
    return obj


__all__ = ["sanitize_obj", "sanitize_string", "sanitize_url"]
