"""Read-only loopback gateway: Anvil fork reads share the Python workers' RPC limits."""

from __future__ import annotations

import contextvars
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping

from services.clients.rpc import _batch_size, _post_rpc
from services.clients.rpc_limits import RpcBackpressure, RpcBudgetExceeded

_READ_METHODS = frozenset(
    {
        "eth_call",
        "eth_getBalance",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getTransactionCount",
        "eth_chainId",
        "eth_blockNumber",
        "eth_gasPrice",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_getBlockReceipts",
        "eth_getAccountInfo",
        "eth_getProof",
        "eth_getBlockAccessList",
        "net_version",
        "web3_clientVersion",
    }
)


class ForkGateway:
    def __init__(self, upstream: str, headers: Mapping[str, str] | None = None):
        context = contextvars.copy_context()
        path = "/" + secrets.token_hex(24)
        slots = threading.BoundedSemaphore(2)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                if self.path != path:
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 1024 * 1024:
                        self.send_error(413)
                        return
                    payload = json.loads(self.rfile.read(length))
                    calls = payload if isinstance(payload, list) else [payload]
                    if (
                        not calls
                        or len(calls) > 500
                        or any(
                            not isinstance(call, dict) or call.get("method") not in _READ_METHODS or "id" not in call
                            for call in calls
                        )
                    ):
                        self.send_error(400, "Only bounded read-only RPC batches are accepted")
                        return
                    if not slots.acquire(timeout=1):
                        self.send_error(429)
                        return
                    try:

                        def forward():
                            replies = []
                            for start in range(0, len(calls), _batch_size()):
                                response = _post_rpc(
                                    upstream, calls[start : start + _batch_size()], timeout=15, extra_headers=headers
                                )
                                response.raise_for_status()
                                data = response.json()
                                replies.extend(data if isinstance(data, list) else [data])
                            return replies if isinstance(payload, list) else replies[0]

                        result = context.copy().run(forward)
                    finally:
                        slots.release()
                except (RpcBackpressure, RpcBudgetExceeded):
                    self.send_error(429, "RPC allowance or shared cooldown prevents this read")
                    return
                except Exception:
                    self.send_error(502, "Fork upstream read unavailable")
                    return
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False  # Close waits for bounded in-flight upstream reads.
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="fork-rpc-gateway")
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
