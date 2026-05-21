"""Discovery worker — fetches verified source from Etherscan and stores in DB.

For address-mode jobs: fetches source, stores files + metadata, advances to static.
For company-mode jobs: discovers contracts via protocol inventory, writes them
to the ``contracts`` table, spawns DApp / DefiLlama sibling jobs, then advances
to the ``selection`` stage. The ``SelectionWorker`` ranks the unified contract
set and creates the top-N analysis child jobs once the siblings settle.
"""

from __future__ import annotations

import logging
from typing import cast

from sqlalchemy import func, null, select
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage
from db.queue import (
    advance_job,
    bulk_upsert_discovered_contracts,
    copy_static_cache,
    create_job,
    find_completed_static_cache,
    find_previous_company_inventory,
    get_artifact,
    get_or_create_protocol,
    store_artifact,
    store_source_files,
)
from services.discovery.audit_reports import merge_audit_reports, search_audit_reports
from services.discovery.deployer import _batch_get_creators
from services.discovery.fetch import fetch, is_vyper_result, parse_remappings, parse_sources
from services.discovery.inventory import merge_inventory, search_protocol_inventory
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from utils import etherscan
from utils.logging import record_degraded
from workers.base import BaseWorker, JobHandledDirectly

logger = logging.getLogger("workers.discovery")


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
    Etherscan-recorded deployer is one of the protocol's known
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
        chain = request.get("chain")
        root_job_id = str(job.id)

        # Load previous inventory from a prior completed company job (same chain)
        prev_inventory: dict | None = None
        prev_job = find_previous_company_inventory(session, company, exclude_job_id=job.id, chain=chain)
        if prev_job:
            _raw = get_artifact(session, prev_job.id, "contract_inventory")
            if isinstance(_raw, dict):
                prev_inventory = _raw

        self.update_detail(session, job, f"Discovering contracts + audits for {company}")
        logger.info("Discovery started for job %s: company=%s, chain=%s", job.id, company, chain)

        # Premium+Deps unified discovery (see services/discovery/run_discovery.py).
        # Runs audit + address pipelines in one call, including Deep Research seeds,
        # dependency two-pass for BoringVault-class components, and SPA-bait overrides.
        from services.discovery.run_discovery import run_discovery

        try:
            unified = run_discovery(company, chain=chain)
            inventory = unified["addresses"]
            audit_result_raw: dict | None = unified["audits"]
            discovery_meta = unified["meta"]
        except Exception as exc:
            record_degraded(
                phase="unified_discovery",
                exc=exc,
                context={"company": company, "chain": chain},
                include_traceback=True,
            )
            logger.warning("Job %s: unified discovery failed, falling back to legacy search: %s", job.id, exc)
            inventory = search_protocol_inventory(company, chain=chain)
            audit_result_raw = None
            discovery_meta = {"fallback": True, "error": str(exc)}

        # Merge with previous inventory if available
        if prev_inventory and isinstance(prev_inventory, dict):
            inventory = merge_inventory(prev_inventory, inventory)

        store_artifact(session, job.id, "contract_inventory", data=inventory)
        store_artifact(session, job.id, "discovery_meta", data=discovery_meta)

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
        prev_audits: dict | None = None
        if prev_job:
            _raw_audits = get_artifact(session, prev_job.id, "audit_reports")
            if isinstance(_raw_audits, dict):
                prev_audits = _raw_audits

        try:
            if audit_result_raw is None:
                # Legacy fallback path (unified discovery failed above)
                audit_result_raw = search_audit_reports(
                    company,
                    official_domain=inventory.get("official_domain"),
                )
            audit_result = audit_result_raw
            if prev_audits:
                audit_result = merge_audit_reports(prev_audits, audit_result)
            store_artifact(session, job.id, "audit_reports", data=audit_result)
            _sync_audit_reports_to_db(session, protocol_row.id, audit_result.get("reports", []))
            audit_count = len(audit_result.get("reports", []))
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
            logger.warning("Job %s: audit report persistence failed: %s", job.id, exc)

        discovered = [e for e in inventory.get("contracts", []) if e.get("address")]

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
            entry_chains = entry.get("chains")
            entry_chain = entry_chains[0] if isinstance(entry_chains, list) and entry_chains else entry.get("chain")
            entry_sources = entry.get("source") or ["inventory"]
            if not isinstance(entry_sources, list):
                entry_sources = [str(entry_sources)]
            bulk_entries.append(
                {
                    "address": str(entry["address"]),
                    "chain": entry_chain,
                    "new_sources": entry_sources,
                    "contract_name": entry.get("name"),
                    "confidence": entry.get("confidence"),
                    "chains": entry.get("chains"),
                }
            )
        # One SELECT for all existing rows + a single bulk add for new ones —
        # collapses 100-300 sequential SELECTs that delayed the cascade kickoff
        # into roughly one round-trip.
        bulk_upsert_discovered_contracts(session, protocol_id=protocol_row.id, entries=bulk_entries)
        session.commit()

        store_artifact(
            session,
            job.id,
            "discovery_summary",
            data={
                "mode": "company",
                "company": company,
                "official_domain": inventory.get("official_domain"),
                "discovered_count": len(discovered),
            },
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
            f"Discovered {len(discovered)} contracts; awaiting parallel discovery before ranking",
        )

        # Hand off to the selection stage. The SelectionWorker waits for
        # DApp/DefiLlama siblings to settle, then ranks the full set of
        # unanalyzed contracts for this protocol and creates the top-N
        # analysis child jobs under the shared analyze_limit budget.
        advance_job(
            session,
            job.id,
            JobStage.selection,
            f"Discovery complete for {company}: {len(discovered)} contracts; ranking pending",
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
                "rpc_url": request.get("rpc_url"),
                "protocol_id": job.protocol_id,
            }
            dl_job = create_job(session, defillama_request, initial_stage=JobStage.defillama_scan)
            logger.info("Job %s: spawned DefiLlama scan job %s (slug=%s)", job.id, dl_job.id, slug)

        # Spawn DApp crawl
        dapp_url = protocol.get("url")
        if dapp_url:
            dapp_request = {
                "dapp_urls": [dapp_url],
                "name": f"{company}_dapp_crawl",
                "company": company,
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "analyze_limit": request.get("analyze_limit", 5),
                "chain_id": request.get("chain_id") or 1,
                "wait": request.get("wait", 10),
                "rpc_url": request.get("rpc_url"),
                "protocol_id": job.protocol_id,
            }
            crawl_job = create_job(session, dapp_request, initial_stage=JobStage.dapp_crawl)
            logger.info("Job %s: spawned DApp crawl job %s (url=%s)", job.id, crawl_job.id, dapp_url)

    def _process_address(self, session: Session, job: Job) -> None:
        """Fetch verified source for a single address."""
        address = job.address
        if address is None:
            raise ValueError("Address job missing address")

        # Check for cached static data from a previously completed job (same chain).
        # `force` is the bench-mode escape hatch — see AnalyzeRequest.force in api.py.
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("force"):
            cached_job = None
            logger.info("Discovery: force=True, skipping static cache lookup for %s", address)
        else:
            cached_job = find_completed_static_cache(session, address, chain=request.get("chain"))
        if cached_job is not None:
            self.update_detail(session, job, f"Reusing cached static data for {address}")
            new_contract_id = copy_static_cache(session, cached_job.id, job.id)
            if new_contract_id is not None:
                # Mark the job so downstream workers know static data was cached
                req = job.request if isinstance(job.request, dict) else {}
                job.request = {**req, "static_cached": True, "cache_source_job_id": str(cached_job.id)}
                session.commit()

                # Set job name from the cached contract if not already set
                if not job.name:
                    from sqlalchemy import select as sa_select

                    contract_row = session.execute(
                        sa_select(Contract).where(Contract.job_id == job.id).limit(1)
                    ).scalar_one_or_none()
                    if contract_row and contract_row.contract_name:
                        job.name = f"{contract_row.contract_name}_{address[2:10]}"
                        session.commit()

                logger.info(
                    "Discovery cache hit for %s — reused data from job %s",
                    address,
                    cached_job.id,
                )
                self.update_detail(session, job, f"Discovery complete (cached): {address}")
                return

            logger.warning(
                "Discovery cache copy failed for %s from job %s — falling back to fetch",
                address,
                cached_job.id,
            )

        self.update_detail(session, job, f"Fetching verified source for {address}")
        # Both calls hit Etherscan. parallel_get routes each thunk through
        # _wait_rate_limit, so the 5/sec global limit is preserved while the
        # serial RTT between them goes away.
        fan_out = etherscan.parallel_get(
            {
                "fetch": lambda a=address: fetch(a),
                "creators": lambda a=address: _batch_get_creators([a]),
            }
        )
        result_or_exc = fan_out["fetch"]
        if isinstance(result_or_exc, BaseException):
            raise result_or_exc
        result = cast(dict, result_or_exc)

        contract_name = result.get("ContractName", "Contract")

        sources = parse_sources(result)
        remappings = parse_remappings(result)

        self.update_detail(session, job, "Storing source files")
        store_source_files(session, job.id, sources)

        raw_evm = result.get("EVMVersion", "") or ""
        evm_version = raw_evm if raw_evm.lower() not in ("", "default") else "shanghai"

        # Look up deployer wallet via Etherscan
        deployer = None
        creators_or_exc = fan_out.get("creators")
        if isinstance(creators_or_exc, dict):
            deployer = creators_or_exc.get(address.lower())
        elif isinstance(creators_or_exc, BaseException):
            logger.debug("Could not fetch deployer for %s: %s", address, creators_or_exc)

        # Write to contracts table — upsert to handle pre-existing discovered rows
        request = job.request if isinstance(job.request, dict) else {}
        existing = session.execute(
            select(Contract).where(
                Contract.address == address.lower(),
                Contract.chain == request.get("chain"),
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

        if existing:
            existing.job_id = job.id
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
                chain=request.get("chain"),
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
                chains=request.get("chains"),
                source_verified=True,
            )
            session.add(contract)
        session.commit()

        if not job.name:
            job.name = f"{contract_name}_{address[2:10]}"
            session.commit()

        self.update_detail(session, job, f"Discovery complete: {contract_name}")
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
