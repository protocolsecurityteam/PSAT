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
from services.crawlers.dapp.crawl import crawl_dapp
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from utils.chains import canonical_chain
from utils.logging import log_timed_phase, record_stage_metric
from utils.rpc import chain_name_for_chain_id
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

        # Derive / create Protocol row from URL hostname if no company context exists
        first_host = (urlparse(urls[0]).hostname or "").lstrip(".")
        if first_host.startswith("www."):
            first_host = first_host[4:]
        protocol_name = job.company or first_host or f"dapp_{str(job.id)[:8]}"
        official_domain = first_host or None
        # Route through the resolver so dapp-crawl jobs that started from a
        # hostname spelling ("ether.fi") collapse onto the same canonical
        # row as discovery jobs that started from the github-org spelling
        # ("etherfi"). Returns None for unknown hostnames; the fallback
        # name-keyed lookup handles those.
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

        # Store raw results
        store_artifact(
            session,
            job.id,
            "dapp_crawl_results",
            data={
                "urls_crawled": urls,
                "addresses_found": len(addresses),
                "addresses": addresses,
                "interaction_count": result.get("interaction_count", 0),
            },
        )

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
        default_chain = canonical_chain(request.get("chain")) or chain_name_for_chain_id(chain_id) or "ethereum"
        # A single crawl can surface the same address on different chains
        # (different contracts). Key the per-address detail map by
        # (address, chain) so two chains' deployments survive to the
        # (address, chain)-keyed DB upsert instead of collapsing here.
        # Addresses with at least one explorer-pinned chain keep only those
        # chains; addresses with no chain context fall back to the job chain.
        detail_by_key: dict[tuple[str, str], dict] = {}
        chains_by_addr: dict[str, set[str]] = {}
        for detail in result.get("address_details", []):
            addr = detail.get("address", "").lower()
            if not addr:
                continue
            addr_chain = canonical_chain(detail.get("chain")) or default_chain
            detail_by_key[(addr, addr_chain)] = detail
            chains_by_addr.setdefault(addr, set()).add(addr_chain)

        bulk_entries: list[dict] = []
        seen_keys: set[tuple[str, str]] = set(detail_by_key.keys())
        # Discovered addresses with no detail row fall back to the job chain.
        for addr in addresses:
            normalized = addr.lower()
            if normalized not in chains_by_addr:
                seen_keys.add((normalized, default_chain))
        for normalized, addr_chain in sorted(seen_keys):
            info = detail_by_key.get((normalized, addr_chain), {})
            source_urls = info.get("source_urls", [])
            bulk_entries.append(
                {
                    "address": normalized,
                    "chain": addr_chain,
                    "new_sources": ["dapp_crawl"],
                    "discovery_url": source_urls[0] if source_urls else None,
                }
            )
        bulk_upsert_discovered_contracts(session, protocol_id=protocol_id, entries=bulk_entries)
        session.commit()
        record_stage_metric("contracts_found", len(addresses))

        store_artifact(
            session,
            job.id,
            "discovery_summary",
            data={
                "mode": "dapp_crawl",
                "urls": urls,
                "discovered_count": len(addresses),
            },
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
