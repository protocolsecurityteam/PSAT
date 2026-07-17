"""Callable entry point for DApp crawling; used by workers.dapp_crawl_worker."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import asdict
from typing import Callable

from services.crawlers.dapp.browser import DAppCrawler
from services.crawlers.dapp.interaction_log import InteractionLog
from services.crawlers.dapp.wallet import HoneypotWallet

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None]

# Hard cap: a hung wallet-connect flow used to wedge the worker past the stale-job sweep
# because the blocked asyncio.run never released playwright. Timeout lets us fail cleanly.
_DAPP_CRAWL_TIMEOUT_SECONDS = int(os.environ.get("PSAT_DAPP_CRAWL_TIMEOUT", "300"))


async def _crawl_async(
    urls: list[str],
    *,
    chain_id: int,
    eth_balance: str = "0x3635C9ADC5DEA00000",
    token_balance: str = "0x84595161401484A000000",
    wait: int = 10,
    progress: ProgressCallback | None = None,
) -> InteractionLog:
    wallet = HoneypotWallet()
    logger.info("Honeypot wallet: %s", wallet.address)
    if progress:
        progress(f"Launching browser with wallet {wallet.address[:8]}...")

    crawler = DAppCrawler(
        wallet=wallet,
        chain_id=chain_id,
        eth_balance=eth_balance,
        token_balance=token_balance,
        headless=True,
    )

    logger.info("Crawling %d URLs...", len(urls))
    interaction_log = await crawler.crawl(urls, wait_seconds=wait, progress=progress)
    return interaction_log


def crawl_dapp(
    urls: list[str],
    *,
    chain_id: int,
    wait: int = 10,
    progress: ProgressCallback | None = None,
) -> dict:
    """Crawl DApp URLs and return discovered contract addresses."""

    async def _bounded() -> InteractionLog:
        return await asyncio.wait_for(
            _crawl_async(
                urls,
                chain_id=chain_id,
                wait=wait,
                progress=progress,
            ),
            timeout=_DAPP_CRAWL_TIMEOUT_SECONDS,
        )

    try:
        interaction_log = asyncio.run(_bounded())
    except asyncio.TimeoutError as exc:
        logger.error(
            "DApp crawl exceeded %ds limit — aborting so the worker can mark the job failed",
            _DAPP_CRAWL_TIMEOUT_SECONDS,
        )
        raise RuntimeError(
            f"DApp crawl exceeded {_DAPP_CRAWL_TIMEOUT_SECONDS}s — likely a hung wallet-connect "
            f"or stalled page load on {urls!r}"
        ) from exc

    addresses = interaction_log.get_contract_addresses()
    logger.info("Discovered %d unique contract addresses", len(addresses))

    return {
        "addresses": addresses,
        "address_details": interaction_log.get_address_details(),
        "interactions": [asdict(i) for i in interaction_log.interactions],
        "interaction_count": len(interaction_log.interactions),
        "session_start": interaction_log.session_start,
    }
