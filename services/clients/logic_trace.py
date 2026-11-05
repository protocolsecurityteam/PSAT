"""Stream opcode traces and retain only locally verified hash preimages.

The provider need not support custom tracers. The response is parsed to EOF so a
truncated stream or late RPC error cannot masquerade as successful acquisition.
"""

from __future__ import annotations

from typing import Protocol

import ijson
import requests
import urllib3

from services.logic.model import BudgetExceeded, ReadError

from .logic_reads import hash_preimages
from .request_budget import charge_attempt
from .rpc import _assert_url_chain_id, _get_session, rpc_headers


class Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


def streamed_hash_preimages(stream: Readable, *, word_limit: int) -> dict[int, bytes]:
    seen_logs = False

    def checked_events():
        nonlocal seen_logs
        for prefix, event, value in ijson.parse(stream):
            if prefix == "error":
                raise ReadError("opcode trace RPC error")
            if prefix == "result.structLogs" and event == "start_array":
                seen_logs = True
            yield prefix, event, value

    result: dict[int, bytes] = {}
    words = 0
    try:
        for step in ijson.items(checked_events(), "result.structLogs.item"):
            if not isinstance(step, dict):
                raise ReadError("malformed opcode trace entry")
            if step.get("op") not in ("KECCAK256", "SHA3"):
                continue
            for key, raw in hash_preimages({"structLogs": (step,)}).items():
                if key in result:
                    continue
                words += max(1, (len(raw) + 31) // 32)
                if words > word_limit:
                    raise BudgetExceeded("trace preimage words")
                result[key] = raw
    except (ijson.JSONError, ValueError, TypeError, AttributeError) as exc:
        raise ReadError("malformed or truncated opcode trace") from exc
    if not seen_logs:
        raise ReadError("opcode trace unavailable")
    return result


def trace_hash_preimages(rpc_url: str, method: str, params: list, *, chain_id: int, word_limit: int):
    """One wire attempt, charged here; ChainReads owns retries and compact-result caching."""
    if method != "debug_traceTransaction":
        raise ValueError("streaming trace reader requires debug_traceTransaction")
    _assert_url_chain_id(rpc_url, chain_id)
    charge_attempt("rpc")
    try:
        with _get_session().post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            headers=rpc_headers(rpc_url),
            timeout=90,
            stream=True,
        ) as response:
            response.raise_for_status()
            response.raw.decode_content = True
            return streamed_hash_preimages(response.raw, word_limit=word_limit)
    except (requests.RequestException, urllib3.exceptions.HTTPError, OSError):
        # Do not include the authenticated URL in persisted exception text.
        raise ReadError("opcode trace transport failed") from None
