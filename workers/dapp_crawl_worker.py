"""DApp Crawl worker — discovers contract addresses by crawling DApp frontends.

Calls the integrated dapp crawler directly (no subprocess) to visit DApp
URLs with a spoofed wallet, captures contract interactions, and writes
every discovered address into the ``contracts`` table tagged
``discovery_source='dapp_crawl'``. Analysis child jobs are created
later by the ``SelectionWorker`` so this crawl's discoveries can
compete with inventory and DefiLlama hits for the shared
``analyze_limit`` budget on equal footing.
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
from services.artifacts import CRAWLER_ARTIFACT, make_job_stage_context, make_stage_artifact
from services.crawlers.dapp.crawl import crawl_dapp
from services.discovery.chain_resolver import expand_entries_by_resolved_chains
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from utils.logging import log_timed_phase, record_stage_metric
from utils.rpc import require_supported_chain_id
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

        chain_id = require_supported_chain_id(chain_id=job.chain_id, context=f"dapp_crawl job {job.id}")
        wait = request.get("wait") or 10

        # Derive / create Protocol row from URL hostname if no company context exists
        first_host = (urlparse(urls[0]).hostname or "").lstrip(".")
        if first_host.startswith("www."):
            first_host = first_host[4:]
        protocol_name = job.company or first_host or f"dapp_{str(job.id)[:8]}"
        official_domain = first_host or None
        # Route through the resolver so dapp-crawl jobs that started from a
        # hostname spelling ("ether.fi") collapse onto the same canonical
        # row as discovery jobs that started from the github-org spelling
        # ("etherfi"). Returns None for unknown hostnames; the name-keyed
        # lookup handles those.
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

        # Call crawler directly — no subprocess
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

        # Persist full interaction log for later audit / analytics
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

        # Write ALL discovered addresses to contracts table
        protocol_id = protocol_row.id
        # Build per-address context from address_details
        detail_by_addr: dict[str, dict] = {}
        for detail in result.get("address_details", []):
            addr = detail.get("address", "").lower()
            if addr:
                detail_by_addr[addr] = detail

        bulk_entries: list[dict] = []
        for addr in addresses:
            normalized = addr.lower()
            info = detail_by_addr.get(normalized, {})
            source_urls = info.get("source_urls", [])
            bulk_entries.append(
                {
                    "address": normalized,
                    "chain_id": chain_id,
                    "new_sources": ["dapp_crawl"],
                    "discovery_url": source_urls[0] if source_urls else None,
                }
            )
        bulk_entries = expand_entries_by_resolved_chains(bulk_entries)
        bulk_upsert_discovered_contracts(session, protocol_id=protocol_id, entries=bulk_entries)
        session.commit()
        record_stage_metric("contracts_found", len(addresses))

        summary = {
            "mode": "dapp_crawl",
            "urls": urls,
            "urls_crawled": urls,
            "addresses_found": len(addresses),
            "discovered_count": len(addresses),
            "interaction_count": result.get("interaction_count", 0),
        }
        store_artifact(
            session,
            job.id,
            CRAWLER_ARTIFACT,
            data=make_stage_artifact(
                kind=CRAWLER_ARTIFACT,
                stage=JobStage.dapp_crawl.value,
                schema_version="1.0",
                context=make_job_stage_context(job, stage=JobStage.dapp_crawl.value, schema_version="1.0"),
                data={
                    "source": "dapp_crawl",
                    "discovered_contracts": addresses,
                    "address_details": result.get("address_details", []),
                    "interactions": result.get("interactions", []),
                    "summary": summary,
                },
            ),
        )

        if not job.name:
            job.name = f"DApp crawl ({len(urls)} URLs)"
            session.commit()

        complete_job(
            session,
            job.id,
            f"DApp crawl complete: {len(addresses)} addresses written to contracts table",
        )
        raise JobHandledDirectly()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    DAppCrawlWorker().run_loop()


if __name__ == "__main__":
    main()
