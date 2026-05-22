"""URL redaction helpers.

``sanitize_url`` normalizes a URL to its scheme + host with sensitive
path segments and query values replaced by ``<redacted>``. Use it on
any URL value that crosses an output boundary (logs, exception
messages, HTTP response bodies, persisted job state).

``sanitize_string`` runs the same scrub over every URL found inside a
free-form string. ``sanitize_obj`` walks a JSON-shaped value and
applies the scrub to every string leaf, plus replaces values under
known credential key names.

Kept dependency-free for cheap import from low-level call sites.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

# Host substrings whose URL path is treated as sensitive. The match is
# on substring containment so subdomains (``eth-mainnet.g.alchemy.com``,
# ``arb-mainnet.g.alchemy.com``) all hit the same suffix entry.
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
    "drpc.org",
    "nodereal.io",
    "tenderly.co",
    "pokt.network",
    "omniatech.io",
    "rpc.tatum.io",
    "moralis.io",
)

# Query-string parameter names whose values are masked. Matched
# case-insensitively.
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

# URL matcher for free-form strings. Stops at whitespace/quote/``>`` so
# trailing prose ("...: connection reset") is not consumed.
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# Generic ``/vN/<opaque>`` path-segment shape — catches provider URLs
# whose host isn't in the suffix list.
_PATH_KEY_SEGMENT_RE = re.compile(r"/(v[1-9])/[A-Za-z0-9_\-]{12,}")

_REDACTED = "<redacted>"


def _host_is_credentialed(host: str) -> bool:
    h = host.lower()
    return any(part in h for part in _SECRET_PATH_HOST_PARTS)


def sanitize_url(url: str) -> str:
    """Return *url* with sensitive path segments and query values masked.

    - Known provider hosts: path replaced with ``/<redacted>``.
    - Discord webhooks: trailing token segment masked, id retained.
    - ``/vN/<opaque>`` path segments: masked.
    - Query keys in ``_SECRET_QUERY_KEYS``: values masked.

    Non-URL strings pass through. Unparseable URLs are reduced to
    ``<redacted>``.
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
    elif (parts.hostname or "").endswith(("discord.com", "discordapp.com")) and parts.path.startswith("/api/webhooks/"):
        # /api/webhooks/<id>/<token>: retain id, mask token.
        segments = parts.path.split("/")
        if len(segments) >= 5:
            segments[4] = _REDACTED
            new_path = "/".join(segments[:5])
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

    return urlunsplit((parts.scheme, parts.netloc, new_path, new_query, parts.fragment))


def sanitize_string(text: str) -> str:
    """Apply :func:`sanitize_url` to every URL found inside *text*."""
    if not isinstance(text, str) or "://" not in text:
        return text
    return _URL_RE.sub(lambda m: sanitize_url(m.group(0)), text)


# Dict keys whose string values are routed through ``sanitize_url``
# regardless of shape. Case-insensitive.
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
    """Return a structural copy of *obj* with string leaves scrubbed."""
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
