"""Discovery worker — fetches verified source and stores it in DB.

For address-mode jobs: fetches source, stores files + metadata, advances to static.
For company-mode jobs: discovers contracts via protocol inventory, writes them
to the ``contracts`` table, spawns DApp / DefiLlama sibling jobs, then advances
to the ``selection`` stage. The ``SelectionWorker`` ranks the unified contract
set and creates the top-N analysis child jobs once the siblings settle.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, null, select
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage
from db.queue import (
    advance_job,
    bulk_upsert_discovered_contracts,
    create_job,
    get_or_create_protocol,
    store_artifact,
    store_source_files,
)
from schemas.common import Contract as ContractSchema
from schemas.common import make_contract
from services.artifacts import (
    DISCOVERY_ARTIFACT,
    make_job_contract,
    make_job_stage_context,
    make_stage_artifact,
)
from services.discovery.chain_resolver import expand_entries_by_resolved_chains
from services.discovery.fetch import fetch, is_vyper_result, parse_remappings, parse_sources
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from utils.rpc import require_supported_chain_id, supported_chain_ids
from workers.base import BaseWorker, JobHandledDirectly

logger = logging.getLogger("workers.discovery")


def _resolve_job_chain_id(job: Job) -> int:
    return require_supported_chain_id(
        chain_id=job.chain_id,
        context=f"discovery job {job.id}",
    )


def _chain_id_for_company_job(job: Job) -> int | None:
    if job.chain_id is None:
        return None
    return require_supported_chain_id(chain_id=job.chain_id, context=f"company discovery job {job.id}")


def _dapp_crawl_chain_ids_for_company_job(job: Job) -> list[int]:
    if job.chain_id is not None:
        chain_id = _chain_id_for_company_job(job)
        if chain_id is None:
            message = f"company discovery job {job.id} has no DApp crawl chain_id"
            logger.error("%s", message)
            raise RuntimeError(message)
        return [chain_id]
    try:
        chain_ids = sorted(supported_chain_ids())
    except RuntimeError as exc:
        logger.error("company discovery job %s could not load supported DApp crawl chain ids: %s", job.id, exc)
        raise
    if not chain_ids:
        message = f"company discovery job {job.id} has no supported DApp crawl chain ids"
        logger.error("%s", message)
        raise RuntimeError(message)
    return chain_ids


def _contract_from_inventory_entry(entry: dict) -> ContractSchema:
    address = entry.get("address")
    if not isinstance(address, str) or not address:
        raise ValueError(f"inventory artifact entry missing address: {entry!r}")
    try:
        chain_id = require_supported_chain_id(
            chain_id=entry.get("chain_id"),
            context=f"inventory artifact entry for {address}",
        )
    except RuntimeError as exc:
        raise ValueError(f"inventory artifact entry requires supported chain_id: {entry!r}") from exc
    name_value = entry.get("name") or entry.get("contract_name")
    name = name_value if isinstance(name_value, str) else None
    return make_contract(
        address=address,
        chain_id=chain_id,
        name=name,
        label=name,
    )


def _contracts_from_inventory(inventory: dict) -> list[ContractSchema]:
    contracts: list[ContractSchema] = []
    for entry in inventory.get("contracts", []):
        if not isinstance(entry, dict):
            continue
        contracts.append(_contract_from_inventory_entry(entry))
    return contracts


def _store_address_discovery_artifact(
    session: Session,
    job: Job,
    contract_row: Contract | None,
    *,
    summary: dict,
    metadata: dict | None = None,
) -> None:
    contract = make_job_contract(session, job, contract_row)
    data = {
        "contracts": [contract],
        "summary": summary,
    }
    if metadata is not None:
        data["metadata"] = metadata
    store_artifact(
        session,
        job.id,
        DISCOVERY_ARTIFACT,
        data=make_stage_artifact(
            kind=DISCOVERY_ARTIFACT,
            stage=JobStage.discovery.value,
            schema_version="1.0",
            context=make_job_stage_context(job, stage=JobStage.discovery.value, schema_version="1.0"),
            data=data,
            contract=contract,
        ),
    )


def _sync_audit_reports_to_db(session: Session, protocol_id: int, reports: list[dict]) -> None:
    """Upsert audit report rows into the relational table."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from db.models import AuditReport

    for report in reports:
        auditor = str(report.get("auditor") or "").strip()
        title = str(report.get("title") or "").strip()
        url = str(report.get("url") or "").strip()
        if not url or not auditor or not title:
            continue
        classified_commits = report.get("classified_commits") or None

        stmt = pg_insert(AuditReport).values(
            protocol_id=protocol_id,
            url=url,
            pdf_url=report.get("pdf_url"),
            auditor=auditor,
            title=title,
            date=report.get("date"),
            confidence=report.get("confidence"),
            source_url=report.get("source_url"),
            # Needed by services/audits/source_equivalence for GitHub lookup.
            source_repo=report.get("source_repo"),
            reviewed_commits=report.get("reviewed_commits") or None,
            referenced_repos=report.get("referenced_repos") or None,
            classified_commits=classified_commits if classified_commits is not None else null(),
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_audit_report_protocol_url",
            set_={
                "pdf_url": stmt.excluded.pdf_url,
                "auditor": stmt.excluded.auditor,
                "title": stmt.excluded.title,
                "date": stmt.excluded.date,
                "confidence": stmt.excluded.confidence,
                "source_url": stmt.excluded.source_url,
                "source_repo": func.coalesce(stmt.excluded.source_repo, AuditReport.source_repo),
                "reviewed_commits": func.coalesce(stmt.excluded.reviewed_commits, AuditReport.reviewed_commits),
                "referenced_repos": func.coalesce(stmt.excluded.referenced_repos, AuditReport.referenced_repos),
                "classified_commits": func.coalesce(stmt.excluded.classified_commits, AuditReport.classified_commits),
            },
        )
        session.execute(stmt)
    session.commit()
    # Core upserts do not synchronize SQLAlchemy's identity map. Keep the
    # worker/test session consistent for callers that read audit rows next.
    session.expire_all()


def _deployer_cascade_protocol_id(session: Session, deployer: str | None) -> int | None:
    """Return a ``protocol_id`` to inherit when *deployer* also deployed
    a HIGH-sourced contract attributed to a protocol.

    This is the fifth ownership branch (after the four direct-source +
    structural-edge branches in ``asserts_ownership``): a same-deployer
    match. It exists because the dependency-cascade spawn at
    ``workers/resolution_worker.py:499-513`` only propagates
    ``discovery_relationship`` for impl / beacon edges. Contracts pulled
    in by a plain function-call dependency edge land here with NULL
    ``discovery_sources`` and no structural signal — even when their
    source-provider-recorded deployer is one of the protocol's known
    qualified deployer EOAs.

    The HIGH-sourced sibling requirement keeps shared-infrastructure
    contracts (WETH9, USDC, OZ libs) out: their deployers never wrote
    a HIGH-source contract attributed to the calling protocol.

    Returns the protocol with the most HIGH-sourced sibling contracts
    sharing this deployer (defensive against the unlikely case where a
    single EOA has HIGH-sourced contracts split across two protocols).
    """
    if not deployer:
        return None
    from services.discovery.source_confidence import HIGH_CONFIDENCE_SOURCES

    row = session.execute(
        select(Contract.protocol_id, func.count(Contract.id).label("n"))
        .where(
            func.lower(Contract.deployer) == deployer.lower(),
            Contract.protocol_id.is_not(None),
            Contract.discovery_sources.op("&&")(list(HIGH_CONFIDENCE_SOURCES)),
        )
        .group_by(Contract.protocol_id)
        .order_by(func.count(Contract.id).desc())
        .limit(1)
    ).first()
    return row[0] if row else None


class DiscoveryWorker(BaseWorker):
    stage = JobStage.discovery
    next_stage = JobStage.static

    def process(self, session: Session, job: Job) -> None:
        if job.company and not job.address:
            self._process_company(session, job)
        elif job.address:
            self._process_address(session, job)
        else:
            raise ValueError("Job has neither address nor company")

    def _process_company(self, session: Session, job: Job) -> None:
        """Discover contracts for a company and advance to the selection stage.

        All three discovery sources (this inventory pass, plus the DApp
        and DefiLlama siblings spawned below) write into ``contracts``
        without queuing analysis jobs. The ``SelectionWorker`` ranks the
        unified set and spends the ``analyze_limit`` budget in one pass.
        """
        company = job.company
        if company is None:
            raise ValueError("Company job missing company name")
        request = job.request if isinstance(job.request, dict) else {}
        chain_id = _chain_id_for_company_job(job)
        root_job_id = str(job.id)

        self.update_detail(session, job, f"Discovering contracts + audits for {company}")
        logger.info("Discovery started for job %s: company=%s, chain_id=%s", job.id, company, chain_id)

        # Premium+Deps unified discovery (see services/discovery/run_discovery.py).
        # Runs audit + address pipelines in one call, including Deep Research seeds,
        # dependency two-pass for BoringVault-class components, and SPA-bait overrides.
        from services.discovery.run_discovery import run_discovery

        with log_timed_phase(logger, "unified_discovery") as ph:
            unified = run_discovery(company)
            inventory = unified["addresses"]
            audit_result_raw: dict = unified["audits"]
            discovery_meta = unified["meta"]
            ph["contracts"] = len(inventory) if hasattr(inventory, "__len__") else None
            ph["audits"] = len(audit_result_raw) if isinstance(audit_result_raw, (list, dict)) else None

        # Resolve to a DefiLlama family slug FIRST so the Protocol upsert is
        # keyed on a stable canonical id. Without this, the same protocol
        # discovered via different free-text spellings (e.g. "ether fi" vs
        # "etherfi") splits into duplicate rows. The resolved struct is
        # reused below for the parallel-discovery sibling spawns.
        resolved = resolve_protocol(company)
        canonical_slug = pick_family_slug(resolved)

        protocol_row = get_or_create_protocol(
            session,
            company,
            official_domain=inventory.get("official_domain"),
            canonical_slug=canonical_slug,
            aliases=resolved.get("all_names") or [],
        )
        job.protocol_id = protocol_row.id
        session.commit()

        # --- Audit report discovery ---
        self.update_detail(session, job, f"Persisting audit reports for {company}")
        audit_result: dict | None = None
        try:
            audit_result = audit_result_raw
            _sync_audit_reports_to_db(session, protocol_row.id, audit_result.get("reports", []))
            audit_count = len(audit_result.get("reports", []))
            record_stage_metric("audit_reports", audit_count)
            if audit_count:
                logger.info("Job %s: found %d audit report(s) for %s", job.id, audit_count, company)
        except Exception as exc:
            session.rollback()
            record_degraded(
                phase="audit_discovery",
                exc=exc,
                context={"company": company},
                include_traceback=True,
            )
            logger.error("Job %s: audit report persistence failed: %s", job.id, exc)
            raise RuntimeError(f"audit report persistence failed for {company}") from exc

        discovered = [e for e in inventory.get("contracts", []) if isinstance(e, dict)]

        # Write ALL discovered addresses to contracts table. Ranking and
        # job creation happen later in the selection stage, once DApp
        # crawl and DefiLlama results are also in the table — that way
        # every source competes for the analyze_limit budget on equal
        # footing instead of the first-to-arrive claiming everything.
        # The upsert unions ``discovery_sources`` so a contract that's
        # already in the table from a prior source gains this one as
        # corroboration rather than being dropped.
        # Build the bulk payload in one pass. Inventory entries carry their
        # own ``source`` list (e.g. ``["ai_inventory", "deployer_expansion"]``)
        # when multiple inventory signals agreed; preserve that granularity
        # so ranking sees the richer corroboration story.
        bulk_entries: list[dict] = []
        for entry in discovered:
            entry_sources = entry.get("source")
            if not isinstance(entry_sources, list) or not entry_sources:
                raise ValueError(f"Discovered contract entry missing explicit source: {entry!r}")
            base_entry = {
                "new_sources": entry_sources,
                "contract_name": entry.get("name"),
                "confidence": entry.get("confidence"),
            }
            deployments = entry.get("deployments")
            if isinstance(deployments, list) and deployments:
                deployment_entries = deployments
            elif entry.get("address"):
                deployment_entries = [entry]
            else:
                raise ValueError(f"Discovered contract entry missing address/deployments: {entry!r}")

            for deployment in deployment_entries:
                if not isinstance(deployment, dict) or not deployment.get("address"):
                    raise ValueError(f"Discovered deployment entry missing address: {deployment!r}")
                bulk_entries.append(
                    {
                        **base_entry,
                        "address": str(deployment["address"]),
                    }
                )
        record_stage_metric("contracts_discovered", len(bulk_entries))
        # One SELECT for all existing rows + a single bulk add for new ones —
        # collapses 100-300 sequential SELECTs that delayed the cascade kickoff
        # into roughly one round-trip.
        bulk_entries = expand_entries_by_resolved_chains(bulk_entries)
        bulk_upsert_discovered_contracts(session, protocol_id=protocol_row.id, entries=bulk_entries)
        session.commit()

        summary = {
            "mode": "company",
            "company": company,
            "official_domain": inventory.get("official_domain"),
            "discovered_count": len(bulk_entries),
        }
        artifact_data = {
            "contracts": _contracts_from_inventory({"contracts": bulk_entries}),
            "inventory": inventory,
            "metadata": discovery_meta,
            "summary": summary,
        }
        if audit_result is not None:
            artifact_data["audit_reports"] = audit_result
        store_artifact(
            session,
            job.id,
            DISCOVERY_ARTIFACT,
            data=make_stage_artifact(
                kind=DISCOVERY_ARTIFACT,
                stage=JobStage.discovery.value,
                schema_version="1.0",
                context=make_job_stage_context(job, stage=JobStage.discovery.value, schema_version="1.0"),
                data=artifact_data,
            ),
        )

        if not job.name:
            job.name = company
            session.commit()

        # Run unconditionally: DApp crawl + DefiLlama scans are independent
        # sources, and empty primary inventory is the case that most needs them.
        self._spawn_parallel_discovery(session, job, company, request, root_job_id, resolved=resolved)

        self.update_detail(
            session,
            job,
            f"Discovered {len(bulk_entries)} contracts; awaiting parallel discovery before ranking",
        )

        # Hand off to the selection stage. The SelectionWorker waits for
        # DApp/DefiLlama siblings to settle, then ranks the full set of
        # unanalyzed contracts for this protocol and creates the top-N
        # analysis child jobs under the shared analyze_limit budget.
        advance_job(
            session,
            job.id,
            JobStage.selection,
            f"Discovery complete for {company}: {len(bulk_entries)} contracts; ranking pending",
        )
        raise JobHandledDirectly()

    def _spawn_parallel_discovery(
        self,
        session: Session,
        job: Job,
        company: str,
        request: dict,
        root_job_id: str,
        resolved: dict | None = None,
    ) -> None:
        """Spawn DApp crawl and DefiLlama scan jobs if we can resolve the protocol."""
        protocol = resolved if resolved is not None else resolve_protocol(company)
        if not protocol.get("slug") and not protocol.get("url"):
            logger.info("Job %s: no DefiLlama match for '%s', skipping parallel discovery", job.id, company)
            return

        logger.info(
            "Job %s: resolved '%s' → slug=%s url=%s",
            job.id,
            company,
            protocol.get("slug"),
            protocol.get("url"),
        )

        # Spawn DefiLlama adapter scans — one per sub-protocol
        all_slugs = protocol.get("all_slugs", [])
        if not all_slugs and protocol.get("slug"):
            all_slugs = [protocol["slug"]]
        for slug in all_slugs:
            defillama_request = {
                "defillama_protocol": slug,
                "name": f"{company}_defillama_{slug}",
                "company": company,
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "analyze_limit": request.get("analyze_limit", 5),
                "protocol_id": job.protocol_id,
            }
            dl_job = create_job(session, defillama_request, initial_stage=JobStage.defillama_scan)
            logger.info("Job %s: spawned DefiLlama scan job %s (slug=%s)", job.id, dl_job.id, slug)

        # Spawn DApp crawl
        dapp_url = protocol.get("url")
        if dapp_url:
            dapp_chain_ids = _dapp_crawl_chain_ids_for_company_job(job)
            crawl_jobs: list[str] = []
            for dapp_chain_id in dapp_chain_ids:
                dapp_request = {
                    "dapp_urls": [dapp_url],
                    "name": f"{company}_dapp_crawl_chain_{dapp_chain_id}",
                    "company": company,
                    "parent_job_id": str(job.id),
                    "root_job_id": root_job_id,
                    "analyze_limit": request.get("analyze_limit", 5),
                    "chain_id": dapp_chain_id,
                    "wait": request.get("wait", 10),
                    "protocol_id": job.protocol_id,
                }
                crawl_job = create_job(session, dapp_request, initial_stage=JobStage.dapp_crawl)
                crawl_jobs.append(str(crawl_job.id))
                logger.info(
                    "Job %s: spawned DApp crawl job %s (url=%s chain_id=%s)",
                    job.id,
                    crawl_job.id,
                    dapp_url,
                    dapp_chain_id,
                )
            logger.info(
                "Job %s: spawned %d DApp crawl job(s) for %s across chain_ids=%s",
                job.id,
                len(crawl_jobs),
                company,
                dapp_chain_ids,
            )
    def _process_address(self, session: Session, job: Job) -> None:
        """Fetch verified source for a single address."""
        address = job.address
        if address is None:
            raise ValueError("Address job missing address")

        request = job.request if isinstance(job.request, dict) else {}
        chain_id = _resolve_job_chain_id(job)
        if job.chain_id != chain_id:
            job.chain_id = chain_id
            session.commit()

        self.update_detail(session, job, f"Fetching verified source for {address}")
        with log_timed_phase(logger, "source_fetch"):
            result = fetch(address, chain_id=chain_id)

        contract_name = result.get("ContractName", "Contract")

        sources = parse_sources(result)
        remappings = parse_remappings(result)

        self.update_detail(session, job, "Storing source files")
        store_source_files(session, job.id, sources)

        raw_evm = result.get("EVMVersion", "") or ""
        evm_version = raw_evm if raw_evm.lower() not in ("", "default") else "shanghai"

        deployer = None

        # Write to contracts table — upsert to handle pre-existing discovered rows
        request = job.request if isinstance(job.request, dict) else {}
        existing = session.execute(
            select(Contract).where(
                Contract.address == address.lower(),
                Contract.chain_id == chain_id,
            )
        ).scalar_one_or_none()

        # Ownership gate: an analysis job inherits ``protocol_id`` from
        # its parent (selection or resolution-dependency), but that
        # alone doesn't prove the contract belongs to the protocol.
        # WETH9 pulled in as a dependency of a confirmed etherfi
        # contract is still WETH9, not an etherfi contract.
        # ``asserts_ownership`` grants ``protocol_id`` via either
        # direct evidence (a HIGH source in the discovery_sources list)
        # or structural evidence (same-protocol relationship — impl /
        # proxy / beacon — to a confirmed parent). The cascade-spawn
        # sites (workers/resolution_worker.py, workers/static_worker.py
        # proxy-impl cascade) populate ``discovery_relationship`` +
        # ``parent_owns_high`` for the structural branch.
        # See services/discovery/source_confidence.py.
        from services.discovery.source_confidence import asserts_ownership

        request_sources = request.get("discovery_sources") or []
        parent_owns_high = bool(request.get("parent_owns_high"))
        discovery_relationship = request.get("discovery_relationship")
        structural_ownership = asserts_ownership(
            None,
            parent_owns=parent_owns_high,
            parent_relationship=discovery_relationship,
        )

        contract_row: Contract | None
        if existing:
            existing.contract_name = contract_name
            existing.compiler_version = result.get("CompilerVersion", "")
            existing.language = "vyper" if is_vyper_result(result) else "solidity"
            existing.evm_version = evm_version
            existing.optimization = result.get("OptimizationUsed", "1") == "1"
            existing.optimization_runs = int(result.get("Runs", "200") or 200)
            existing.source_format = "standard_json" if "sources" in str(result.get("SourceCode", ""))[:10] else "flat"
            existing.source_file_count = len(sources)
            existing.license = result.get("LicenseType", "")
            existing.deployer = deployer
            existing.remappings = remappings or []
            existing.source_verified = True
            should_adopt = (
                not existing.protocol_id
                and job.protocol_id
                and (asserts_ownership(existing.discovery_sources) or structural_ownership)
            )
            if should_adopt:
                existing.protocol_id = job.protocol_id
                # Audit trail: when ownership comes from the structural
                # branch (no HIGH source in discovery_sources), record
                # how it was earned so future readers can tell direct
                # from inherited adoption.
                if structural_ownership and not asserts_ownership(existing.discovery_sources):
                    merged = list(existing.discovery_sources or [])
                    if "structural_adoption" not in merged:
                        merged.append("structural_adoption")
                    existing.discovery_sources = merged
            # Deployer-cascade adoption — fifth branch, fires when neither
            # direct nor structural-edge evidence applies but the deployer
            # EOA is shared with a HIGH-sourced sibling. See
            # ``_deployer_cascade_protocol_id`` for the rationale. Tags the
            # row with ``structural_adoption`` to match the audit
            # convention used by the structural-edge branch above; this is
            # also the sentinel the companion migration reverts under.
            if not existing.protocol_id:
                cascade_pid = _deployer_cascade_protocol_id(session, existing.deployer)
                if cascade_pid:
                    existing.protocol_id = cascade_pid
                    merged = list(existing.discovery_sources or [])
                    if "structural_adoption" not in merged:
                        merged.append("structural_adoption")
                    existing.discovery_sources = merged
            contract_row = existing
        else:
            owning_protocol_id = None
            if job.protocol_id and (asserts_ownership(request_sources) or structural_ownership):
                owning_protocol_id = job.protocol_id
            sources_for_row = list(request_sources)
            if structural_ownership and not asserts_ownership(request_sources):
                sources_for_row.append("structural_adoption")
            # Deployer-cascade adoption — fifth branch (mirrors the
            # ``if existing`` arm above). When the dependency-cascade
            # spawn didn't propagate ``discovery_relationship``, the
            # shared-deployer signal is what saves these from going to
            # the contracts table as orphans.
            if not owning_protocol_id:
                cascade_pid = _deployer_cascade_protocol_id(session, deployer)
                if cascade_pid:
                    owning_protocol_id = cascade_pid
                    if "structural_adoption" not in sources_for_row:
                        sources_for_row.append("structural_adoption")
            contract = Contract(
                job_id=job.id,
                address=address.lower(),
                chain_id=chain_id,
                protocol_id=owning_protocol_id,
                contract_name=contract_name,
                compiler_version=result.get("CompilerVersion", ""),
                language="vyper" if is_vyper_result(result) else "solidity",
                evm_version=evm_version,
                optimization=result.get("OptimizationUsed", "1") == "1",
                optimization_runs=int(result.get("Runs", "200") or 200),
                source_format="standard_json" if "sources" in str(result.get("SourceCode", ""))[:10] else "flat",
                source_file_count=len(sources),
                license=result.get("LicenseType", ""),
                deployer=deployer,
                remappings=remappings or [],
                rank_score=request.get("rank_score"),
                confidence=request.get("confidence"),
                discovery_sources=sources_for_row or None,
                source_verified=True,
            )
            session.add(contract)
            contract_row = contract
        session.commit()

        if not job.name:
            job.name = f"{contract_name}_{address[2:10]}"
            session.commit()

        record_stage_metric("source_files", len(sources))
        _store_address_discovery_artifact(
            session,
            job,
            contract_row,
            summary={
                "mode": "address",
                "address": address.lower(),
                "contract_name": contract_name,
                "source_file_count": len(sources),
                "source_verified": True,
                "cached": False,
            },
            metadata={
                "compiler_version": result.get("CompilerVersion", ""),
                "language": "vyper" if is_vyper_result(result) else "solidity",
                "evm_version": evm_version,
            },
        )
        self.update_detail(session, job, f"Discovery complete: {contract_name} ({len(sources)} source files)")
        logger.info("Discovery complete for %s (%s)", address, contract_name)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    DiscoveryWorker().run_loop()


if __name__ == "__main__":
    main()
