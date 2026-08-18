"""Browser integration test for the DApp crawler against a local fake DApp.

This test exercises the real browser crawler when Playwright and a Chromium
browser are installed. It is skipped automatically otherwise.
"""

from __future__ import annotations

import asyncio
import importlib
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _random_address() -> str:
    return "0x" + secrets.token_hex(20)


def _unique_addresses(count: int) -> list[str]:
    addresses: set[str] = set()
    while len(addresses) < count:
        addresses.add(_random_address())
    return sorted(addresses)


def _build_fake_site(addresses: dict[str, object]) -> dict[str, str]:
    root_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Fake DApp</title>
    <script src="/bundle.js"></script>
  </head>
  <body>
    <button id="connect-wallet">Connect Wallet</button>
    <div id="root-contract">Treasury: {addresses["root_page"]}</div>
    <a id="open-deposit" href="/deposit">Deposit Pool</a>
    <a id="open-stake" href="/stake">Stake Vault</a>
    <script>
      async function loadConfig() {{
        const resp = await fetch("/api/config");
        window.__CONFIG__ = await resp.json();
      }}

      document.getElementById("connect-wallet").addEventListener("click", async () => {{
        await window.ethereum.request({{ method: "eth_requestAccounts" }});
        await window.ethereum.request({{
          method: "wallet_switchEthereumChain",
          params: [{{ chainId: "0x89" }}],
        }});
        document.getElementById("connect-wallet").style.display = "none";
      }});

      loadConfig().catch(console.error);
    </script>
  </body>
</html>
"""

    deposit_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Deposit</title>
  </head>
  <body>
    <div id="vault-address">Vault: {addresses["deposit_page"]}</div>
    <input id="amount" placeholder="0.00" />
    <button id="deposit-button">Deposit Now</button>
    <script>
      const button = document.getElementById("deposit-button");
      button.addEventListener("click", async () => {{
        const accounts = await window.ethereum.request({{ method: "eth_accounts" }});
        await window.ethereum.request({{
          method: "personal_sign",
          params: ["Sign in to Fake DApp deposit", accounts[0]],
        }});
        await window.ethereum.request({{
          method: "eth_sendTransaction",
          params: [{{
            to: "{addresses["deposit_tx"]}",
            value: "0x0",
            data: "0xa9059cbb00000000000000000000000000000000000000000000000000000000",
          }}],
        }});
        button.disabled = true;
        button.textContent = "Deposited";
      }});
    </script>
  </body>
</html>
"""

    stake_html = f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Stake</title>
  </head>
  <body>
    <div id="staking-address">Staking vault: {addresses["stake_page"]}</div>
    <input id="amount" placeholder="0.00" />
    <button id="stake-button">Stake Now</button>
    <script>
      const button = document.getElementById("stake-button");
      button.addEventListener("click", async () => {{
        const accounts = await window.ethereum.request({{ method: "eth_accounts" }});
        await window.ethereum.request({{
          method: "personal_sign",
          params: ["Sign in to Fake DApp stake", accounts[0]],
        }});
        await window.ethereum.request({{
          method: "eth_sendTransaction",
          params: [{{
            to: "{addresses["stake_tx"]}",
            value: "0x0",
            data: "0x095ea7b300000000000000000000000000000000000000000000000000000000",
          }}],
        }});
        button.disabled = true;
        button.textContent = "Staked";
      }});
    </script>
  </body>
</html>
"""

    bundle_js = f"""\
window.__APP_DATA__ = {{
  factoryAddress: "{addresses["js_factory"]}",
  routerAddress: "{addresses["js_router"]}",
  label: "Fake DApp bundle config",
}};
"""

    api_config = f"""{{
  "contractAddress": "{addresses["api_contract"]}",
  "poolAddress": "{addresses["api_pool"]}"
}}"""

    return {
        "/": root_html,
        "/deposit": deposit_html,
        "/stake": stake_html,
        "/bundle.js": bundle_js,
        "/api/config": api_config,
    }


class _FakeDappHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        body = self.server.site_map.get(parsed.path)  # pyright: ignore[reportAttributeAccessIssue]
        if body is not None:
            content_type = "text/html; charset=utf-8"
            if parsed.path == "/bundle.js":
                content_type = "application/javascript; charset=utf-8"
            elif parsed.path == "/api/config":
                content_type = "application/json; charset=utf-8"
            self._send(200, content_type, body)
            return
        self._send(404, "text/plain; charset=utf-8", "not found")

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, status: int, content_type: str, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture()
def fake_dapp_site():
    generated = _unique_addresses(9)
    addresses = {
        "deposit_tx": generated[0],
        "deposit_page": generated[1],
        "stake_tx": generated[2],
        "stake_page": generated[3],
        "js_factory": generated[4],
        "js_router": generated[5],
        "api_contract": generated[6],
        "api_pool": generated[7],
        "root_page": generated[8],
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeDappHandler)
    server.site_map = _build_fake_site(addresses)  # pyright: ignore[reportArgumentType, reportAttributeAccessIssue]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"http://127.0.0.1:{server.server_port}/",
            "addresses": addresses,
        }
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _skip_if_playwright_unavailable(exc: Exception) -> None:
    message = str(exc)
    if "Executable doesn't exist" in message or "playwright install" in message:
        pytest.skip(f"Playwright browser unavailable: {message}")


def test_crawler_captures_interactions_and_addresses_from_fake_dapp(tmp_path, fake_dapp_site):
    pytest.importorskip("playwright.async_api", reason="Playwright is not installed")

    crawl_module = importlib.import_module("services.crawlers.dapp.crawl")
    fake_dapp_url = fake_dapp_site["url"]
    addresses = fake_dapp_site["addresses"]

    try:
        log = asyncio.run(
            crawl_module._crawl_async(
                [fake_dapp_url],
                chain_id=137,
                wait=1,
            )
        )
    except Exception as exc:
        _skip_if_playwright_unavailable(exc)
        raise

    expected_addresses = {
        addresses["deposit_tx"],
        addresses["deposit_page"],
        addresses["stake_tx"],
        addresses["stake_page"],
        addresses["js_factory"],
        addresses["js_router"],
        addresses["api_contract"],
        addresses["api_pool"],
        addresses["root_page"],
    }
    assert set(log.get_contract_addresses()) == expected_addresses

    interaction_types = {entry.type for entry in log.interactions}
    assert "switchChain" in interaction_types
    assert "personal_sign" in interaction_types
    assert "sendTransaction" in interaction_types
    assert "pageAddress" in interaction_types
    assert "apiResponse" in interaction_types
    assert "jsBundle" in interaction_types

    txs = [i for i in log.interactions if i.type == "sendTransaction"]
    assert len(txs) == 2
    assert {tx.to for tx in txs} == {addresses["deposit_tx"], addresses["stake_tx"]}
