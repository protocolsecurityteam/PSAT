"""
Core browser crawler using Playwright.

Launches a Chromium instance with the spoofed wallet provider injected,
visits target URLs, and captures all contract interactions.
"""

import asyncio
import json
import logging
import os
import time
from typing import Callable
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, async_playwright  # pyright: ignore[reportMissingImports]

from services.crawlers.dapp.inject import build_provider_script
from services.crawlers.dapp.interaction_log import InteractionLog
from services.crawlers.dapp.wallet import HoneypotWallet
from utils.rpc import require_supported_chain_id

logger = logging.getLogger(__name__)

# Concurrency cap for the per-URL crawl fan-out. Each URL holds a Page
# in the shared BrowserContext for the full wait window, so this caps
# memory + CPU. Default 3 keeps the shared-cpu-2x fleet happy.
_DAPP_PARALLEL = max(1, int(os.environ.get("PSAT_DAPP_PARALLEL", "3")))


class DAppCrawler:
    """
    Playwright-based crawler that impersonates a high-balance wallet
    and captures contract interactions from DApp frontends.
    """

    def __init__(
        self,
        wallet: HoneypotWallet,
        chain_id: int,
        eth_balance: str = "0x3635C9ADC5DEA00000",
        token_balance: str = "0x84595161401484A000000",
        headless: bool = True,
    ):
        chain_id = require_supported_chain_id(chain_id=chain_id, context="DApp crawler")
        self.wallet = wallet
        self.chain_id = chain_id
        self.eth_balance = eth_balance
        self.token_balance = token_balance
        self.headless = headless
        self.interaction_log = InteractionLog()
        self._provider_script = build_provider_script(wallet, chain_id, eth_balance, token_balance)

    # ------------------------------------------------------------------ #
    #  Page setup & message handling                                       #
    # ------------------------------------------------------------------ #

    # Regex to match Ethereum addresses in text
    _ADDR_RE = __import__("re").compile(r"0x[a-fA-F0-9]{40}")

    async def _setup_page(self, page: Page):
        """Inject the spoofed provider and network interceptors."""
        await page.add_init_script(self._provider_script)

        # Listen for captured interactions via postMessage
        await page.expose_function("_dappCrawlerCapture", self._handle_capture)
        await page.add_init_script("""
            window.addEventListener('message', (event) => {
                if (event.data?.source === 'dapp-crawler') {
                    window._dappCrawlerCapture(JSON.stringify(event.data.entry));
                }
            });
        """)

        # Handle signing requests from the injected provider
        await page.expose_function("_dappCrawlerSign", self._handle_sign_request)
        await page.add_init_script("""
            window.addEventListener('message', (event) => {
                if (event.data?.source === 'dapp-crawler-sign') {
                    window._dappCrawlerSign(JSON.stringify(event.data))
                        .then(sig => {
                            if (window.__dappCrawlerPendingSign &&
                                window.__dappCrawlerPendingSign.id === event.data.id) {
                                window.__dappCrawlerPendingSign.resolve(sig);
                                window.__dappCrawlerPendingSign = null;
                            }
                        });
                }
            });
        """)

        # Intercept API responses and JS bundles for contract addresses
        page.on("response", lambda resp: asyncio.ensure_future(self._sniff_response(resp, page.url)))

        # Also sniff JS bundles for hardcoded addresses
        page.on("response", lambda resp: asyncio.ensure_future(self._sniff_js_bundle(resp, page.url)))

    # URL patterns that return user/wallet data, not contract addresses
    _USER_DATA_PATTERNS = [
        "leaderboard",
        "ranking",
        "referral",
        "profile",
        "user",
        "account",
        "history",
        "trades",
        "orders",
        "position",
        "notification",
        "activity",
        "analytics",
        "stats/user",
    ]

    # URL patterns likely to contain contract/protocol config
    _CONTRACT_DATA_PATTERNS = [
        "config",
        "contract",
        "address",
        "market",
        "pool",
        "vault",
        "token",
        "asset",
        "reserve",
        "collateral",
        "protocol",
        "registry",
        "factory",
        "deploy",
        "pair",
        "farm",
    ]

    async def _sniff_response(self, response, page_url: str):
        """
        Inspect JSON API responses for Ethereum addresses.
        Skips user-data endpoints (leaderboards, profiles, trade history)
        to avoid capturing EOA wallets instead of contracts.
        """
        try:
            url = response.url
            content_type = response.headers.get("content-type", "")

            if "json" not in content_type:
                return

            url_lower = url.lower()

            # Skip endpoints that return user/wallet data
            if any(p in url_lower for p in self._USER_DATA_PATTERNS):
                return

            body = await response.text()
            if len(body) > 500_000:
                return

            addrs = set(a.lower() for a in self._ADDR_RE.findall(body))

            addrs.discard(self.wallet.address.lower())
            addrs.discard("0x" + "0" * 40)
            addrs.discard("0x" + "f" * 40)
            addrs.discard("0x000000000000000000000000000000000000dead")

            if not addrs:
                return

            # If the endpoint looks like it has contract data, take all addresses.
            # Otherwise, only take addresses that appear as JSON values next to
            # contract-related keys (heuristic to filter out user wallets).
            is_contract_endpoint = any(p in url_lower for p in self._CONTRACT_DATA_PATTERNS)

            if not is_contract_endpoint:
                import re

                contract_context = re.findall(
                    r"(?:address|contract|token|pool|vault|market|factory|proxy|implementation)"
                    r'["\s:]+["\'](0x[a-fA-F0-9]{40})',
                    body,
                    re.IGNORECASE,
                )
                if contract_context:
                    addrs = set(a.lower() for a in contract_context)
                else:
                    return

            already_seen = {i.to for i in self.interaction_log.interactions if i.to}
            new_addrs = addrs - already_seen

            if new_addrs:
                logger.info(
                    "Sniffed %d new addresses from API: %s",
                    len(new_addrs),
                    url[:100],
                )
                for addr in new_addrs:
                    self.interaction_log.add(
                        {
                            "type": "apiResponse",
                            "url": page_url,
                            "timestamp": int(time.time() * 1000),
                            "to": addr,
                            "data": f"api:{url[:200]}",
                        }
                    )
        except Exception:
            pass

    async def _sniff_js_bundle(self, response, page_url: str):
        """
        Scan loaded JavaScript bundles for hardcoded contract addresses.
        Many DApps compile contract addresses directly into their JS bundles.
        Only looks at JS files from the same origin.
        """
        try:
            url = response.url
            content_type = response.headers.get("content-type", "")

            if "javascript" not in content_type and not url.endswith(".js"):
                return

            # Only scan same-origin JS files
            from urllib.parse import urlparse

            page_origin = urlparse(page_url).netloc
            js_origin = urlparse(url).netloc
            if page_origin and js_origin and page_origin != js_origin:
                return

            body = await response.text()
            if len(body) > 2_000_000:  # skip huge bundles
                return

            import re

            contract_context = re.findall(
                r"(?:address|contract|token|vault|pool|diamond|proxy|factory|router|collateral|market|gToken|lending|borrowing)"
                r".{0,80}?(0x[a-fA-F0-9]{40})",
                body,
                re.IGNORECASE,
            )
            contract_context2 = re.findall(
                r"(0x[a-fA-F0-9]{40})"
                r".{0,80}?(?:address|contract|token|vault|pool|diamond|proxy|factory|router|collateral|market|gToken|lending|borrowing)",
                body,
                re.IGNORECASE,
            )

            addrs = set(a.lower() for a in contract_context + contract_context2)
            addrs.discard(self.wallet.address.lower())
            addrs.discard("0x" + "0" * 40)
            addrs.discard("0x" + "f" * 40)
            addrs -= {f"0x{'f' * i}{'0' * (40 - i)}" for i in range(1, 40)}  # mask patterns

            if not addrs:
                return

            already_seen = {i.to for i in self.interaction_log.interactions if i.to}
            new_addrs = addrs - already_seen

            if new_addrs:
                logger.info(
                    "Sniffed %d addresses from JS bundle: %s",
                    len(new_addrs),
                    url.split("/")[-1][:60],
                )
                for addr in new_addrs:
                    self.interaction_log.add(
                        {
                            "type": "jsBundle",
                            "url": page_url,
                            "timestamp": int(time.time() * 1000),
                            "to": addr,
                            "data": f"js:{url.split('/')[-1][:100]}",
                        }
                    )
        except Exception:
            pass

    async def _handle_capture(self, entry_json: str):
        """Process a captured interaction from the browser."""
        try:
            entry = json.loads(entry_json)
            self.interaction_log.add(entry)
            logger.info(
                "Captured %s interaction on %s -> %s",
                entry.get("type"),
                entry.get("url", "?"),
                entry.get("to", "N/A"),
            )
        except json.JSONDecodeError:
            logger.warning("Failed to parse captured interaction: %s", entry_json)

    async def _handle_sign_request(self, request_json: str) -> str:
        """Sign auth messages with the honeypot wallet's real key."""
        try:
            request = json.loads(request_json)
            method = request.get("method", "")
            params = request.get("params", [])

            if method in ("personal_sign", "eth_sign"):
                message = params[0] if method == "personal_sign" else params[1]
                sig = self.wallet.sign_message(message)
                logger.info("Auto-signed auth message: %s...", message[:40])
                return sig

            if method.startswith("eth_signTypedData"):
                typed_data = params[1]
                sig = self.wallet.sign_typed_data(typed_data)
                logger.info("Auto-signed typed data (%s)", method)
                return sig

        except Exception as e:
            # Returns a dummy signature; no exception propagates. WARNING per the
            # level contract for swallowed-and-fallback paths.
            logger.warning("Signing failed: %s", e, extra={"exc_type": type(e).__name__})

        return "0x" + "00" * 65

    # ------------------------------------------------------------------ #
    #  Selector banks                                                      #
    # ------------------------------------------------------------------ #

    CONNECT_WALLET_SELECTORS = [
        'xpath=//a[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "connect a wallet")]',
        'xpath=//a[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "connect wallet")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "connect wallet")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "connect")]',
        'xpath=//div[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "connect wallet") and @role="button"]',
        '[data-testid*="connect" i]',
        '[data-testid*="wallet" i]',
        '[class*="connectWallet" i]',
        '[class*="connect-wallet" i]',
        '[class*="iekbcc0"]',
        "w3m-connect-button",
        'button:has-text("Connect")',
    ]

    WALLET_OPTION_SELECTORS = [
        'xpath=//*[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "metamask") and (self::button or self::div[@role="button"] or self::wui-list-wallet or self::li)]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "metamask")]',
        'xpath=//div[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "metamask") and @role="button"]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "injected")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "browser wallet")]',
        '[data-testid*="metamask" i]',
        '[data-testid*="injected" i]',
        '[data-testid="rk-wallet-option-metaMask"]',
        '[data-testid="rk-wallet-option-injected"]',
        'w3m-wallet-button[name="MetaMask"]',
        'w3m-wallet-button[name="Injected"]',
        "text=MetaMask",
    ]

    COOKIE_DISMISS_SELECTORS = [
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "i understand")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "accept the risk")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "accept risk")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "switch network")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "switch chain")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "accept all")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "accept cookies")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "got it")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "i agree")]',
        '[data-testid="cookie-accept"]',
    ]

    SIGN_IN_SELECTORS = [
        'xpath=//a[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "sign in")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "sign in")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "get started")]',
        'xpath=//button[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "launch app")]',
        'xpath=//a[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "launch app")]',
    ]

    BROWSER_TAB_SELECTORS = [
        "text=Browser",
        'xpath=//*[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "browser") and (self::button or self::div[@role="tab"] or self::span)]',
        '[data-testid="tab-browser"]',
    ]

    ACTION_KEYWORDS = [
        "deposit",
        "stake",
        "swap",
        "approve",
        "supply",
        "mint",
        "bridge",
        "borrow",
        "lend",
        "withdraw",
        "claim",
        "redeem",
    ]

    # ------------------------------------------------------------------ #
    #  Overlay / connect helpers                                           #
    # ------------------------------------------------------------------ #

    async def _dismiss_overlays(self, page: Page):
        """Dismiss cookie banners and other overlays."""
        for selector in self.COOKIE_DISMISS_SELECTORS:
            try:
                el = page.locator(selector).first
                if await el.is_visible(timeout=500):
                    logger.info("Dismissing overlay: %s", selector)
                    await el.click()
                    await page.wait_for_timeout(500)
                    return
            except Exception:
                continue

    async def _try_connect_wallet(self, page: Page, max_rounds: int = 5):
        """Multi-step wallet connection: dismiss -> sign-in -> connect -> pick wallet."""
        all_selectors = [
            ("browser-tab", self.BROWSER_TAB_SELECTORS),
            ("wallet-option", self.WALLET_OPTION_SELECTORS),
            ("connect", self.CONNECT_WALLET_SELECTORS),
            ("sign-in", self.SIGN_IN_SELECTORS),
        ]

        for round_num in range(max_rounds):
            logger.info("Connect wallet round %d (url: %s)", round_num + 1, page.url)
            await self._dismiss_overlays(page)

            clicked = False
            for category, selectors in all_selectors:
                for selector in selectors:
                    try:
                        el = page.locator(selector).first
                        if await el.is_visible(timeout=1000):
                            logger.info("Round %d: clicking %s: %s", round_num + 1, category, selector)
                            await el.click()
                            await page.wait_for_timeout(3000)
                            clicked = True
                            break
                    except Exception:
                        continue
                if clicked:
                    break

            if not clicked:
                logger.info("Round %d: no more buttons to click", round_num + 1)
                break

    # ------------------------------------------------------------------ #
    #  Action link discovery                                               #
    # ------------------------------------------------------------------ #

    async def _discover_action_links(self, page: Page) -> list[dict]:
        """
        Find all same-origin action links on the current page that could lead
        to pages with contract interactions (deposit, stake, swap, etc.).
        """
        keywords_js = json.dumps(self.ACTION_KEYWORDS)
        results = await page.evaluate(f"""
            () => {{
                const keywords = {keywords_js};
                const found = [];
                const seen = new Set();
                const currentOrigin = window.location.origin;

                document.querySelectorAll('a[href]').forEach(el => {{
                    if (el.offsetParent === null) return;
                    const text = el.textContent?.trim().toLowerCase() || '';
                    const href = el.href;
                    if (seen.has(href)) return;

                    // Only follow same-origin links
                    try {{
                        const linkOrigin = new URL(href).origin;
                        if (linkOrigin !== currentOrigin) return;
                    }} catch {{ return; }}

                    // Match by action keyword in text
                    for (const kw of keywords) {{
                        if (text.includes(kw)) {{
                            seen.add(href);
                            found.push({{
                                text: el.textContent?.trim().substring(0, 80),
                                href: href,
                                keyword: kw,
                                isLink: true,
                            }});
                            return;
                        }}
                    }}

                    // Match links with contract addresses in the URL
                    if (href.match(/0x[a-fA-F0-9]{{40}}/)) {{
                        seen.add(href);
                        found.push({{
                            text: el.textContent?.trim().substring(0, 80),
                            href: href,
                            keyword: 'contract-link',
                            isLink: true,
                        }});
                    }}
                }});

                return found;
            }}
        """)
        logger.info("Discovered %d action links on %s", len(results), page.url)
        for r in results:
            logger.info("  [%s] %s -> %s", r["keyword"], r["text"], r["href"])
        return results

    # ------------------------------------------------------------------ #
    #  Form interaction                                                    #
    # ------------------------------------------------------------------ #

    async def _click_all_tabs(self, page: Page):
        """Click through all visible tab-like buttons to reveal hidden content."""
        tab_keywords = [
            "stake",
            "deposit",
            "supply",
            "lend",
            "borrow",
            "swap",
            "withdraw",
            "redeem",
            "claim",
            "editor",
            "payoff",
            "managed",
            "wallet",
            "positions",
            "overview",
            "details",
        ]
        clicked_tabs = []
        for kw in tab_keywords:
            for selector in [
                f'xpath=//button[translate(normalize-space(.), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{kw}"]',
                f'xpath=//*[@role="tab" and contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "{kw}")]',
            ]:
                try:
                    el = page.locator(selector).first
                    if await el.is_visible(timeout=300):
                        if await el.is_disabled(timeout=200):
                            continue
                        logger.info("Clicking tab: %s", kw)
                        await el.click(timeout=2000)
                        await page.wait_for_timeout(1500)
                        clicked_tabs.append(kw)

                        await self._scrape_page_addresses(page)
                        break
                except Exception:
                    continue
        return clicked_tabs

    async def _try_fill_and_submit(self, page: Page):
        """
        On a deposit/stake/swap page:
        1. Dismiss overlays (switch network, risk modals)
        2. Click through all tabs to reveal content and scrape addresses
        3. Try filling amount inputs
        4. Click submit buttons to trigger transactions
        """
        await self._dismiss_overlays(page)
        await page.wait_for_timeout(1000)

        await self._click_all_tabs(page)

        input_selectors = [
            'input[placeholder="0.00"]',
            'input[placeholder="0"]',
            'input[placeholder="0.0"]',
            'input[inputmode="decimal"]',
            'input[inputmode="numeric"]',
            'input[type="number"]',
            'xpath=//input[contains(@placeholder, "amount")]',
            'xpath=//input[contains(@placeholder, "Amount")]',
            'xpath=//input[contains(@placeholder, "Enter")]',
        ]

        for selector in input_selectors:
            try:
                inp = page.locator(selector).first
                if await inp.is_visible(timeout=500):
                    if await inp.is_disabled(timeout=300):
                        continue
                    await inp.click()
                    await inp.fill("1")
                    logger.info("Filled amount input: %s", selector)
                    await page.wait_for_timeout(2000)
                    break
            except Exception:
                continue

        submit_patterns = [
            "stake now",
            "deposit now",
            "swap now",
            "open position",
            "confirm",
            "approve",
            "deposit",
            "stake",
            "swap",
            "supply",
            "submit",
            "send",
            "mint",
            "bridge",
            "lend",
            "borrow",
        ]
        for kw in submit_patterns:
            for tag in ["button", "a"]:
                selector = f'xpath=//{tag}[contains(translate(., "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "{kw}")]'
                try:
                    el = page.locator(selector).first
                    if await el.is_visible(timeout=300):
                        if await el.is_disabled(timeout=200):
                            continue
                        logger.info("Clicking submit: '%s' (%s)", kw, tag)
                        await el.click(timeout=3000)
                        await page.wait_for_timeout(3000)
                        return
                except Exception:
                    continue

        logger.info("No enabled submit button found on %s", page.url)

    # ------------------------------------------------------------------ #
    #  Page address scraping                                               #
    # ------------------------------------------------------------------ #

    async def _scrape_page_addresses(self, page: Page):
        """
        Scrape Ethereum contract addresses visible on the page -- from text
        content, links to block explorers, and data attributes.
        """
        try:
            results = await page.evaluate("""
                () => {
                    const found = {};

                    // 1. Full addresses in page text
                    const textAddrs = document.body.innerText.match(/0x[a-fA-F0-9]{40}/g) || [];
                    textAddrs.forEach(a => { found[a.toLowerCase()] = 'page-text'; });

                    // 2. Block explorer links (address, token, contract pages)
                    const explorers = ['etherscan', 'scrollscan', 'arbiscan', 'basescan',
                                       'polygonscan', 'bscscan', 'optimistic.etherscan'];
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href;
                        if (explorers.some(e => href.includes(e))) {
                            const match = href.match(/\\/(?:address|token|contract)\\/(0x[a-fA-F0-9]{40})/);
                            if (match) found[match[1].toLowerCase()] = href;
                        }
                    });

                    // 3. Addresses in same-origin link hrefs and element attributes
                    const currentOrigin = window.location.origin;
                    document.querySelectorAll('*').forEach(el => {
                        for (const attr of el.attributes || []) {
                            if (attr.name === 'href') {
                                try {
                                    const linkOrigin = new URL(attr.value, currentOrigin).origin;
                                    const explorers = ['etherscan', 'scrollscan', 'arbiscan',
                                                       'basescan', 'polygonscan', 'bscscan'];
                                    const isExplorer = explorers.some(e => attr.value.includes(e));
                                    if (linkOrigin !== currentOrigin && !isExplorer) continue;
                                } catch {}
                            }
                            const matches = attr.value.match(/0x[a-fA-F0-9]{40}/g) || [];
                            matches.forEach(addr => {
                                const key = addr.toLowerCase();
                                if (!found[key]) {
                                    found[key] = attr.name + ':' + attr.value.substring(0, 120);
                                }
                            });
                        }
                    });

                    // 4. Addresses from JS runtime state
                    function deepScan(obj, depth, visited) {
                        if (depth > 4 || !obj || visited.has(obj)) return;
                        visited.add(obj);
                        try {
                            if (typeof obj === 'string') {
                                const m = obj.match(/^0x[a-fA-F0-9]{40}$/);
                                if (m) found[obj.toLowerCase()] = 'js-runtime';
                                return;
                            }
                            if (typeof obj !== 'object') return;
                            if (Array.isArray(obj)) {
                                obj.slice(0, 200).forEach(v => deepScan(v, depth + 1, visited));
                            } else {
                                const keys = Object.keys(obj).slice(0, 100);
                                for (const k of keys) {
                                    const kl = k.toLowerCase();
                                    if (kl.includes('address') || kl.includes('contract') ||
                                        kl.includes('token') || kl.includes('vault') ||
                                        kl.includes('pool') || kl.includes('market') ||
                                        kl.includes('diamond') || kl.includes('proxy') ||
                                        kl.includes('factory') || kl.includes('router') ||
                                        kl.includes('collateral')) {
                                        try { deepScan(obj[k], depth + 1, visited); } catch {}
                                    }
                                }
                            }
                        } catch {}
                    }
                    const visited = new WeakSet();
                    try { deepScan(window.__NEXT_DATA__?.props, 0, visited); } catch {}
                    try { deepScan(window.__APP_DATA__, 0, visited); } catch {}
                    try { deepScan(window.__CONFIG__, 0, visited); } catch {}
                    for (const key of Object.keys(window)) {
                        const kl = key.toLowerCase();
                        if (kl.includes('config') || kl.includes('contract') ||
                            kl.includes('address') || kl.includes('constant')) {
                            try { deepScan(window[key], 0, visited); } catch {}
                        }
                    }

                    return found;
                }
            """)

            already_seen = {i.to for i in self.interaction_log.interactions if i.to}
            for addr, source in results.items():
                if addr.lower() == self.wallet.address.lower():
                    continue
                if addr.lower() in already_seen:
                    continue
                logger.info("Scraped address from page: %s (source: %s)", addr, source)
                self.interaction_log.add(
                    {
                        "type": "pageAddress",
                        "url": page.url,
                        "timestamp": int(time.time() * 1000),
                        "to": addr,
                        "data": source,
                    }
                )
        except Exception as e:
            logger.warning("Page address scraping failed: %s", e)

    # ------------------------------------------------------------------ #
    #  Main crawl orchestration                                            #
    # ------------------------------------------------------------------ #

    async def _explore_page(
        self, page: Page, context: BrowserContext, depth: int = 0, max_depth: int = 1, visited: set | None = None
    ):
        """
        Explore a page: scrape addresses, discover action links to follow,
        then on leaf pages try to fill forms and trigger transactions.
        """
        if visited is None:
            visited = set()

        current_url = page.url
        if current_url in visited:
            return
        visited.add(current_url)

        logger.info("Exploring (depth=%d): %s", depth, current_url)

        await self._dismiss_overlays(page)
        await page.wait_for_timeout(500)

        await self._scrape_page_addresses(page)

        action_links = []
        if depth < max_depth:
            action_links = await self._discover_action_links(page)

        await self._try_fill_and_submit(page)
        await self._scrape_page_addresses(page)

        for link_info in action_links:
            href = link_info["href"]
            if href in visited:
                continue

            logger.info("Following action link: %s -> %s", link_info["text"], href)
            child_page = await context.new_page()
            await self._setup_page(child_page)

            try:
                await child_page.goto(href, wait_until="domcontentloaded", timeout=30000)
                await child_page.wait_for_timeout(5000)
                await self._dismiss_overlays(child_page)
                await child_page.wait_for_timeout(1000)
                await self._explore_page(child_page, context, depth + 1, max_depth, visited)
            except Exception as e:
                logger.warning("Error exploring %s: %s", href, e)
            finally:
                await child_page.close()

    async def crawl(self, urls: list[str], wait_seconds: int = 10, progress: Callable[[str], None] | None = None):
        """
        Visit URLs, connect wallet, then deeply explore each site for
        contract interactions.

        URLs run concurrently up to ``PSAT_DAPP_PARALLEL`` (default 3) — each
        gets its own Page in the shared BrowserContext. The interaction_log
        is mutated cooperatively from a single asyncio thread so per-URL
        capture order is preserved within a URL but interleaves across URLs.
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )

            sem = asyncio.Semaphore(_DAPP_PARALLEL)

            async def _visit(url: str) -> None:
                site_label = urlparse(url).netloc or url
                async with sem:
                    page = await context.new_page()
                    await self._setup_page(page)
                    logger.info("Visiting %s", url)
                    try:
                        if progress:
                            progress(f"Opening {site_label}")
                        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                        await page.wait_for_timeout(3000)

                        if progress:
                            progress(f"Connecting wallet on {site_label}")
                        await self._try_connect_wallet(page)
                        await page.wait_for_timeout(2000)

                        if progress:
                            progress(f"Exploring {site_label} for contract interactions")
                        await self._explore_page(page, context, depth=0, max_depth=1)

                        if progress:
                            progress(f"Watching {site_label} for {wait_seconds}s")
                        await page.wait_for_timeout(wait_seconds * 1000)
                    except Exception as e:
                        logger.warning("Error visiting %s: %s", url, e)
                    finally:
                        await page.close()

            await asyncio.gather(*[_visit(url) for url in urls], return_exceptions=False)

            await browser.close()

        return self.interaction_log
