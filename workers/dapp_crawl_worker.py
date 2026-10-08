"""Discovers contract addresses by crawling DApp frontends with a spoofed wallet.

Writes every address to ``contracts`` (``discovery_source='dapp_crawl'``); ``SelectionWorker`` creates analysis jobs so
all sources compete for ``analyze_limit`` equally.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from db.models import DAppInteraction, Job, JobStage
from db.queue import (
    bulk_upsert_discovered_contracts,
    complete_job,
    get_or_create_protocol,
    store_artifact,
)
from services.crawlers.dapp.crawl import crawl_dapp
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from utils.chains import UnknownChainError, chain_by_id
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker, JobHandledDirectly

logger = logging.getLogger("workers.dapp_crawl")


class DAppCrawlWorker(BaseWorker):
    stage = JobStage.dapp_crawl
    next_stage = JobStage.done

    def process(self, session: Session, job: Job) -> None:
        request = job.request if isinstance(job.request, dict) else {}
        urls = request.get("dapp_urls", [])
        if not urls:
            raise ValueError("dapp_crawl job missing dapp_urls in request")

        chain_id = request.get("chain_id") or 1
        wait = request.get("wait") or 10

        first_host = (urlparse(urls[0]).hostname or "").lstrip(".")
        if first_host.startswith("www."):
            first_host = first_host[4:]
        protocol_name = job.company or first_host or f"dapp_{str(job.id)[:8]}"
        official_domain = first_host or None
        # Resolver collapses hostname spellings ("ether.fi") onto the same row as github-org spellings ("etherfi"). None
        # for unknown hosts; the name lookup handles those.
        resolved = resolve_protocol(protocol_name)
        canonical_slug = pick_family_slug(resolved)
        protocol_row = get_or_create_protocol(
            session,
            protocol_name,
            official_domain=official_domain,
            canonical_slug=canonical_slug,
            aliases=resolved.get("all_names") or [],
        )
        job.protocol_id = protocol_row.id
        if not job.company:
            job.company = protocol_row.name
        session.commit()

        self.update_detail(session, job, f"Preparing crawl for {len(urls)} DApp URL(s)")
        logger.info("DApp crawl started for job %s: %d URLs", job.id, len(urls))

        def report(detail: str) -> None:
            self.update_detail(session, job, detail)

        with log_timed_phase(logger, "dapp_crawl") as ph:
            result = crawl_dapp(
                urls,
                chain_id=chain_id,
                wait=wait,
                progress=report,
            )
            ph["count"] = len(result["addresses"])

        addresses = result["addresses"]
        logger.info("DApp crawl found %d addresses for job %s", len(addresses), job.id)
        url_outcomes = list(result.get("url_outcomes") or [])
        crawl_status = _crawl_status(urls, url_outcomes)
        for outcome in url_outcomes:
            if outcome.get("outcome") == "loaded":
                continue
            # A page that never loaded (bot challenge, error status, crash) captured nothing: its share of the dApp's
            # contracts is not determined, never "none".
            record_degraded(
                phase="dapp_page_load",
                exc=RuntimeError(f"{outcome.get('outcome')}: {outcome.get('reason')}"),
                context={"url": outcome.get("url"), "status": outcome.get("status")},
            )
        record_stage_metric("dapp_urls_not_loaded", sum(1 for o in url_outcomes if o.get("outcome") != "loaded"))

        store_artifact(
            session,
            job.id,
            "dapp_crawl_results",
            data={
                "urls_crawled": urls,
                "crawl_status": crawl_status,
                "url_outcomes": url_outcomes,
                "addresses_found": len(addresses),
                "addresses": addresses,
                "interaction_count": result.get("interaction_count", 0),
            },
        )

        for entry in result.get("interactions", []):
            to_raw = entry.get("to") or ""
            session.add(
                DAppInteraction(
                    job_id=job.id,
                    protocol_id=protocol_row.id,
                    type=str(entry.get("type") or "unknown"),
                    page_url=entry.get("url"),
                    to_address=to_raw.lower() if to_raw else None,
                    value=entry.get("value"),
                    data=entry.get("data"),
                    method_selector=entry.get("method_selector"),
                    typed_data=entry.get("typed_data"),
                    is_permit=bool(entry.get("is_permit")),
                    message=entry.get("message"),
                    captured_at=entry.get("timestamp"),
                )
            )
        session.commit()

        protocol_id = protocol_row.id
        try:
            chain_name = chain_by_id(chain_id).name
        except UnknownChainError:
            chain_name = None
        default_chain = request.get("chain") or chain_name
        detail_by_addr: dict[str, dict] = {}
        for detail in result.get("address_details", []):
            addr = detail.get("address", "").lower()
            if addr:
                detail_by_addr[addr] = detail

        # Unattributed addresses inherit the job chain rather than chain=NULL, which would duplicate a sibling's
        # 'ethereum' stub.
        bulk_entries: list[dict] = []
        for addr in addresses:
            normalized = addr.lower()
            info = detail_by_addr.get(normalized, {})
            source_urls = info.get("source_urls", [])
            bulk_entries.append(
                {
                    "address": normalized,
                    "chain": info.get("chain"),
                    "new_sources": ["dapp_crawl"],
                    "discovery_url": source_urls[0] if source_urls else None,
                }
            )
        bulk_upsert_discovered_contracts(
            session, protocol_id=protocol_id, entries=bulk_entries, default_chain=default_chain
        )
        session.commit()
        record_stage_metric("contracts_found", len(addresses))

        store_artifact(
            session,
            job.id,
            "discovery_summary",
            data={
                "mode": "dapp_crawl",
                "urls": urls,
                "crawl_status": crawl_status,
                "discovered_count": len(addresses),
            },
        )

        if not job.name:
            job.name = f"DApp crawl ({len(urls)} URLs)"
            session.commit()

        if crawl_status == "complete":
            detail = f"DApp crawl complete: {len(addresses)} addresses written to contracts table"
        else:
            loaded = sum(1 for o in url_outcomes if o.get("outcome") == "loaded")
            detail = (
                f"DApp crawl {crawl_status}: {loaded} of {len(urls)} URL(s) loaded; {len(addresses)} addresses written "
                "to contracts table, not a complete list"
            )
        complete_job(session, job.id, detail)
        raise JobHandledDirectly()


def _crawl_status(urls: list[str], url_outcomes: list[dict]) -> str:
    """``complete`` only when every URL's page loaded; ``partial`` when some did; ``not_loaded`` when none did."""
    loaded = {o.get("url") for o in url_outcomes if o.get("outcome") == "loaded"}
    if all(url in loaded for url in urls):
        return "complete"
    return "partial" if loaded else "not_loaded"


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    DAppCrawlWorker().run_loop()


if __name__ == "__main__":
    main()
