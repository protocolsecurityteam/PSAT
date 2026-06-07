"""DefiLlama worker — discovers contract addresses from DefiLlama adapter source code.

Calls the integrated defillama crawler directly (no subprocess) to scan
adapter source for contract addresses and writes every discovered
address into the ``contracts`` table tagged
``discovery_source='defillama'``. Analysis child jobs are created
later by the ``SelectionWorker`` so this scan's discoveries can
compete with inventory and DApp-crawl hits for the shared
``analyze_limit`` budget on equal footing.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from sqlalchemy.orm import Session

from db.models import Job, JobStage
from db.queue import (
    bulk_upsert_discovered_contracts,
    complete_job,
    get_or_create_protocol,
    store_artifact,
)
from services.artifacts import CRAWLER_ARTIFACT, make_job_stage_context, make_stage_artifact
from services.crawlers.defillama.scan import scan_protocol
from services.discovery.chain_resolver import expand_entries_by_resolved_chains
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from utils.logging import log_timed_phase, record_stage_metric
from workers.base import BaseWorker, JobHandledDirectly

logger = logging.getLogger("workers.defillama")

DEFAULT_REPO_PATH = Path(tempfile.gettempdir()) / "defillama-adapters"
REPO_PATH = Path(os.getenv("DEFILLAMA_REPO_PATH", str(DEFAULT_REPO_PATH)))


class DefiLlamaWorker(BaseWorker):
    stage = JobStage.defillama_scan
    next_stage = JobStage.done

    def process(self, session: Session, job: Job) -> None:
        request = job.request if isinstance(job.request, dict) else {}
        protocol = request.get("defillama_protocol")
        if not protocol:
            raise ValueError("defillama_scan job missing defillama_protocol in request")

        no_clone = os.getenv("DEFILLAMA_NO_CLONE", "").lower() in ("1", "true", "yes")

        # Derive / create Protocol row from company or slug. Route the
        # name through the resolver so the row is keyed on the same family
        # slug the discovery worker used — without this the per-sibling
        # DefiLlama scan would create a separate row keyed on the sibling's
        # slug instead of attaching to the parent protocol.
        protocol_name = job.company or str(protocol)
        resolved = resolve_protocol(protocol_name)
        canonical_slug = pick_family_slug(resolved)
        protocol_row = get_or_create_protocol(
            session,
            protocol_name,
            canonical_slug=canonical_slug,
            aliases=resolved.get("all_names") or [],
        )
        job.protocol_id = protocol_row.id
        if not job.company:
            job.company = protocol_row.name
        session.commit()

        self.update_detail(session, job, f"Preparing DefiLlama scan for {protocol}")
        logger.info("DefiLlama scan started for job %s: protocol=%s", job.id, protocol)

        def report(detail: str) -> None:
            self.update_detail(session, job, detail)

        # Call crawler directly — no subprocess
        with log_timed_phase(logger, "defillama_scan") as ph:
            result = scan_protocol(
                protocol_name=protocol,
                repo_path=REPO_PATH,
                no_clone=no_clone,
                progress=report,
            )
            ph["count"] = len(result["addresses"])

        addresses = result["addresses"]
        logger.info("DefiLlama scan found %d addresses for job %s", len(addresses), job.id)

        # Build chain lookup from detailed results
        chain_by_address: dict[str, str | None] = {}
        for entry in result.get("address_details", []):
            addr = entry.get("address", "").lower()
            chain = entry.get("chain")
            if addr and chain:
                chain_by_address[addr] = chain

        # Write ALL discovered addresses to contracts table
        protocol_id = protocol_row.id
        bulk_entries: list[dict] = []
        for addr in addresses:
            normalized = addr.lower()
            chain = chain_by_address.get(normalized)
            bulk_entries.append(
                {
                    "address": normalized,
                    "chain": chain,
                    "new_sources": ["defillama"],
                }
            )
        bulk_entries = expand_entries_by_resolved_chains(bulk_entries)
        bulk_upsert_discovered_contracts(session, protocol_id=protocol_id, entries=bulk_entries)
        session.commit()
        record_stage_metric("contracts_found", len(addresses))

        summary = {
            "mode": "defillama_scan",
            "protocol": protocol,
            "scan_time": result["scan_time"],
            "addresses_found": len(addresses),
            "discovered_count": len(addresses),
        }
        store_artifact(
            session,
            job.id,
            CRAWLER_ARTIFACT,
            data=make_stage_artifact(
                kind=CRAWLER_ARTIFACT,
                stage=JobStage.defillama_scan.value,
                schema_version="1.0",
                context=make_job_stage_context(job, stage=JobStage.defillama_scan.value, schema_version="1.0"),
                data={
                    "source": "defillama_scan",
                    "discovered_contracts": addresses,
                    "address_details": result["address_details"],
                    "summary": summary,
                },
            ),
        )

        if not job.name:
            job.name = f"DefiLlama: {protocol}"
            session.commit()

        complete_job(
            session,
            job.id,
            f"DefiLlama scan complete for {protocol}: {len(addresses)} addresses written to contracts table",
        )
        raise JobHandledDirectly()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    DefiLlamaWorker().run_loop()


if __name__ == "__main__":
    main()
