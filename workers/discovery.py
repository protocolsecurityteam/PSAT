"""Discovery worker — fetches verified source from Etherscan and stores in DB.

For address-mode jobs: fetches source, stores files + metadata, advances to static.
For company-mode jobs: discovers contracts via protocol inventory, writes them
to the ``contracts`` table, spawns DApp / DefiLlama sibling jobs, then advances
to the ``selection`` stage. The ``SelectionWorker`` ranks the unified contract
set and creates the top-N analysis child jobs once the siblings settle.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Callable, Collection, Sequence, cast

from sqlalchemy import func, null, select
from sqlalchemy.orm import Session

from db.models import (
    WITNESS_RULE_W4_DEPLOYER,
    Contract,
    ContractCreationWitness,
    Job,
    JobStage,
    OpsKv,
    Protocol,
    ProtocolDeployer,
    SessionLocal,
)
from db.queue import (
    advance_job,
    bulk_upsert_discovered_contracts,
    copy_static_cache,
    copy_static_cache_cross_chain,
    create_job,
    find_completed_static_cache,
    find_previous_company_inventory,
    get_artifact,
    get_or_create_protocol,
    store_artifact,
    store_source_files,
)
from services.clients import etherscan
from services.clients.rpc import chain_id_for_chain_name
from services.discovery import membership_gate as gate
from services.discovery.audit_reports import merge_audit_reports, search_audit_reports
from services.discovery.deployer import _batch_get_creators
from services.discovery.deployer_enumeration import (
    creation_factories,
    enumerate_with_coverage,
    session_deployer_enumerator,
)
from services.discovery.fetch import fetch, is_vyper_result, parse_remappings, parse_sources, source_content_hash
from services.discovery.inventory import merge_inventory, search_protocol_inventory
from services.discovery.perimeter import (
    needs_probe,
    probe_predates_revocation,
    produce_structural_witness,
    record_code_witness,
)
from services.discovery.probes import fetch_creations
from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol
from services.discovery.selection_enqueue import enqueue_selection_for_promotions, enqueue_selection_pass
from utils.chains import (
    UnknownChainError,
    canonical_chain,
    canonical_chain_list,
    chain_by_id,
    chain_by_name,
    require_chain,
    supported_chain_ids,
)
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker, JobHandledDirectly

logger = logging.getLogger("workers.discovery")


def _sync_audit_reports_to_db(session: Session, protocol_id: int, reports: list[dict]) -> None:
    """Upsert audit report rows into the relational table.

    Two shapes make an artifact entry produce no row of its own: a missing
    identity field, and a ``url`` another entry in the same batch already
    claimed (the upsert is keyed on ``(protocol_id, url)``, so the later entry
    overwrites the earlier one). Both are reported — the artifact's entry count
    and the table's row count disagreeing is otherwise invisible.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from db.models import AuditReport

    incomplete: list[dict[str, str]] = []
    collisions: list[dict[str, str]] = []
    claimed_by: dict[str, str] = {}

    for report in reports:
        auditor = str(report.get("auditor") or "").strip()
        title = str(report.get("title") or "").strip()
        url = str(report.get("url") or "").strip()
        if not url or not auditor or not title:
            incomplete.append(
                {
                    "missing": ",".join(
                        field for field, value in (("url", url), ("auditor", auditor), ("title", title)) if not value
                    ),
                    "url": url or "",
                    "auditor": auditor or "",
                    "title": title or "",
                }
            )
            continue
        overwritten = claimed_by.get(url)
        if overwritten is not None:
            collisions.append({"url": url, "overwritten_title": overwritten, "kept_title": title})
        claimed_by[url] = title
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

    if incomplete or collisions:
        lost = len(incomplete) + len(collisions)
        logger.warning(
            "Audit sync for protocol %s: %d of %d artifact entries produced no row "
            "(%d missing url/auditor/title, %d url collisions): %s",
            protocol_id,
            lost,
            len(reports),
            len(incomplete),
            len(collisions),
            {"incomplete": incomplete[:10], "collisions": collisions[:10]},
        )
        record_degraded(
            phase="audit_report_sync",
            exc=RuntimeError(f"{lost} of {len(reports)} audit entries produced no row"),
            context={
                "protocol_id": protocol_id,
                "entries": len(reports),
                "distinct_urls_upserted": len(claimed_by),
                "incomplete": incomplete[:10],
                "collisions": collisions[:10],
            },
        )


#: ``ops_kv`` key for the chain-enable boot sweep (spec §3.4 event 4).
ENABLED_CHAINS_SEEN_KEY = "enabled_chains_seen"


#: Class C verdict reasons that are COUNTEREVIDENCE against an existing A/B
#: registry row (not mere absence of proof) — they revoke it (invariant 8).
_DEPLOYER_COUNTEREVIDENCE_REASONS = frozenset(
    {"cross_protocol_collision", "foreign_or_unknown_creations", "enumeration_coverage_gap"}
)


def _snapshot_covers(row: ProtocolDeployer, contract_address: str) -> bool:
    """Whether the registry row's recorded enumeration snapshot already names
    *contract_address* as one of the EOA's creations."""
    evidence = row.evidence if isinstance(row.evidence, dict) else {}
    enumeration = evidence.get("enumeration")
    addresses = enumeration.get("addresses") if isinstance(enumeration, dict) else None
    return isinstance(addresses, list) and contract_address.lower() in addresses


def _register_protocol_deployer(
    session: Session,
    *,
    protocol_id: int,
    deployer: str,
    contract_address: str | None = None,
    reprobe_sink: set[int] | None = None,
) -> ProtocolDeployer | None:
    """§3.3 ladder wire: classify the EOA; register A/B; Class C registers
    nothing. An unrevoked Class B row whose recorded enumeration snapshot
    already covers *contract_address* is reused without re-enumerating; any
    other path re-classifies, and a Class C verdict carrying counterevidence
    revokes the stale row (``gate.demote``). The Etherscan enumeration is paid
    only when Class B is reachable (≥2 member rows already claim the deployer,
    or a registry row exists to re-verify) — a recall-only pre-check; the
    verdict is ``classify_deployer``'s alone."""
    addr = deployer.lower()
    existing = session.execute(
        select(ProtocolDeployer).where(
            ProtocolDeployer.protocol_id == protocol_id,
            ProtocolDeployer.address == addr,
            ProtocolDeployer.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None and contract_address is not None and _snapshot_covers(existing, contract_address):
        return existing

    verdict = gate.classify_deployer(session, protocol_id=protocol_id, address=addr)
    history: list[str] = []
    factories: dict[str, str] = {}
    scope: list[int] = []
    coverage_gap: str | None = None
    if verdict.trust_class is None and verdict.evidence.get("reason") == "no_complete_enumeration":
        sibling_count = session.execute(
            select(func.count(Contract.id)).where(
                func.lower(Contract.deployer) == addr,
                Contract.protocol_id == protocol_id,
            )
        ).scalar_one()
        if existing is not None or sibling_count >= 2:
            creations, scope, complete, coverage_gap = enumerate_with_coverage(session, addr)
            history = sorted({c.address for c in creations})
            factories = creation_factories(creations)
            verdict = gate.classify_deployer(
                session,
                protocol_id=protocol_id,
                address=addr,
                creation_history=history,
                history_complete=complete,
                creation_factories=factories,
            )
    if verdict.trust_class is None:
        reason = verdict.evidence.get("reason")
        # F3: a coverage gap on a standing Class-B row is positive
        # counterevidence — budget/cap incompleteness is not.
        if reason == "no_complete_enumeration" and coverage_gap is not None and existing is not None:
            if existing.trust_class == "B":
                reason = "enumeration_coverage_gap"
        if existing is not None and reason in _DEPLOYER_COUNTEREVIDENCE_REASONS:
            demotion = gate.demote(session, deployer_row=existing, reason=str(reason))
            if reprobe_sink is not None:
                reprobe_sink.update(demotion.reprobe_contract_ids)
        return None

    evidence = dict(verdict.evidence)
    if verdict.trust_class == "B":
        enumeration = dict(evidence.get("enumeration") or {})
        enumeration["chain_ids"] = scope
        enumeration["addresses"] = history
        if factories:
            enumeration["factories"] = factories
        evidence["enumeration"] = enumeration
    classification = gate.DeployerClassification(trust_class=verdict.trust_class, evidence=evidence)
    return gate.register_deployer(session, protocol_id=protocol_id, address=addr, classification=classification)


def _write_deployer_witness(session: Session, *, contract: Contract, registry_row: ProtocolDeployer) -> bool:
    """W4 for one deployed contract: the persisted creation tx + the registry
    row it rests on. No creation tx on record → no witness (invariant 2)."""
    if (contract.deployer or "").lower() != registry_row.address:
        return False
    chain_id = chain_id_for_chain_name(contract.chain)
    address = (contract.address or "").lower()
    if chain_id is None or not address:
        return False
    row = session.get(ContractCreationWitness, (chain_id, address))
    if row is None or not row.creation_tx_hash:
        try:
            fetch_creations(session, [address], chain_id=chain_id)
        except Exception as exc:
            logger.warning(
                "creation fetch for W4 failed",
                extra={"address": address, "chain_id": chain_id, "exc_type": type(exc).__name__},
            )
            record_degraded(
                phase="deployer_witness_creation_fetch",
                exc=exc,
                context={"address": address, "chain_id": chain_id},
            )
        row = session.get(ContractCreationWitness, (chain_id, address))
    if row is None or not row.creation_tx_hash:
        return False
    gate.write_witness(
        session,
        contract_id=contract.id,
        protocol_id=registry_row.protocol_id,
        rule=WITNESS_RULE_W4_DEPLOYER,
        evidence=gate.w4_evidence(
            deployer_address=registry_row.address,
            deployer_registry_id=registry_row.id,
            creation_tx_hash=row.creation_tx_hash,
            creation_block=row.creation_block,
        ),
        via_address=registry_row.address,
    )
    return True


#: Bound on one reprobe pass. The tail is never lost state: reprobe ids are
#: re-derived from stored evidence at every evaluate, and the probe pass's
#: revocation-staleness targeting re-finds demoted members at the next event.
_REPROBE_PASS_CAP = 25


def _consume_reprobes(
    session: Session,
    contract_ids: Sequence[int],
    *,
    context: str,
    exclude: Collection[int] = (),
) -> None:
    """Invariant-8 consumer for the gate's ``reprobe_contract_ids``: probe the
    re-queued candidates (bounded), then evaluate once with the fresh probe
    facts. One round only — a still-blocked candidate settles at a later
    event. Degrades; never raises into the caller."""
    ids = [cid for cid in dict.fromkeys(contract_ids) if cid not in set(exclude)][:_REPROBE_PASS_CAP]
    if not ids:
        return
    probed: list[int] = []
    resolved: set[str] = set()
    try:
        for contract_id in ids:
            contract = session.get(Contract, contract_id)
            if contract is None or contract.protocol_id is not None:
                continue
            protocol_id = contract.nominated_protocol_id
            if protocol_id is None:
                continue
            result = gate.probe(session, contract)
            probed.append(contract_id)
            record_code_witness(session, contract=contract, protocol_id=protocol_id, probe_result=result)
            gate.seed_llama_witness(session, contract=contract)
            resolved.update(result.resolved_addresses)
        session.commit()
    except Exception as exc:
        session.rollback()
        record_degraded(
            phase="membership_reprobe",
            exc=exc,
            context={"context": context, "contract_ids": ids},
        )
        logger.warning(
            "membership reprobe pass failed",
            extra={"context": context, "exc_type": type(exc).__name__, "error": str(exc)[:300]},
        )
        return
    if not probed:
        return
    gate.evaluate_committed(
        session,
        gate.FactsDelta(new_edge_addresses=tuple(sorted(resolved)), recheck_contract_ids=tuple(probed)),
        context=f"reprobe:{context}",
        deployer_enumerator=session_deployer_enumerator(session),
    )


def run_probe_pass(
    session: Session,
    protocol_id: int,
    *,
    heartbeat: Callable[[], None] | None = None,
) -> gate.PromotionResult:
    """§3.4 event 1: settle the protocol's fresh candidates near-line. Bounded
    to the current protocol's candidates AND to ``PSAT_PROBE_PASS_MAX`` wire
    probes per pass (lowest ids first); commits before evaluating. The pass is
    idempotent — ``needs_probe`` re-selects the deferred tail on the next pass,
    and the deferral is recorded, never silent. *heartbeat*, when given, is
    called after each wire probe so a long pass stays visibly leased."""
    probe_budget = int(os.getenv("PSAT_PROBE_PASS_MAX", "200"))
    candidates = list(
        session.execute(
            select(Contract)
            .where(
                Contract.protocol_id.is_(None),
                Contract.nominated_protocol_id == protocol_id,
            )
            .order_by(Contract.id)
        ).scalars()
    )
    probed: list[Contract] = []
    seeded: list[Contract] = []
    resolved: set[str] = set()
    deferred = 0
    for contract in candidates:
        # Revocation staleness re-targets demoted members whose completed
        # attempt ``needs_probe`` would skip (invariant 8 pickup for
        # request/queue-context demotions, e.g. the protocol-merge cascade).
        if needs_probe(session, contract) or probe_predates_revocation(session, contract):
            if len(probed) >= probe_budget:
                deferred += 1
                continue
            result = gate.probe(session, contract)
            probed.append(contract)
            record_code_witness(session, contract=contract, protocol_id=protocol_id, probe_result=result)
            resolved.update(result.resolved_addresses)
            if heartbeat is not None:
                heartbeat()
        # W6 rides on the persisted code fact, so an already-probed candidate
        # a fresh defillama nomination just tagged is seeded here too.
        if gate.seed_llama_witness(session, contract=contract):
            seeded.append(contract)
    if deferred:
        record_degraded(
            phase="membership_probe_pass_budget",
            exc=RuntimeError(f"{deferred} unprobed candidates deferred past the probe-pass budget"),
            context={"protocol_id": protocol_id, "budget": probe_budget, "deferred": deferred},
        )
        logger.warning(
            "probe pass budget exhausted — tail deferred to the next pass",
            extra={"protocol_id": protocol_id, "budget": probe_budget, "deferred": deferred},
        )
    promoted: list[int] = []
    for contract in probed:
        if gate.promote(session, contract=contract, protocol_id=protocol_id):
            promoted.append(contract.id)
    session.commit()
    # Seeded-but-unprobed rows carry no W1 witness row yet; the fixpoint's
    # admission binds W1 from the persisted code probe on recheck.
    delta = gate.FactsDelta(
        new_member_contract_ids=tuple(promoted),
        new_edge_addresses=tuple(sorted(resolved)),
        recheck_contract_ids=tuple(sorted({c.id for c in seeded if c.protocol_id is None})),
    )
    cascade = gate.evaluate(session, delta, deployer_enumerator=session_deployer_enumerator(session))
    session.commit()
    # After the gate's commit: create_job commits, so enqueuing first would
    # land the cascade durably ahead of its own commit point. Residual: a crash
    # in between delays the pass to the next event, never loses it — selection
    # ranks the full unanalyzed set, so a later pass covers these members.
    enqueue_selection_for_promotions(
        session, tuple(promoted) + cascade.promoted_contract_ids, reason="membership_promotion"
    )
    _consume_reprobes(
        session,
        cascade.reprobe_contract_ids,
        context=f"probe_pass:{protocol_id}",
        exclude={contract.id for contract in probed},
    )
    return gate.PromotionResult(
        targeted_contract_ids=cascade.targeted_contract_ids,
        promoted_contract_ids=tuple(promoted) + cascade.promoted_contract_ids,
        demoted_contract_ids=cascade.demoted_contract_ids,
        reprobe_contract_ids=cascade.reprobe_contract_ids,
    )


def _structural_intake(session: Session, job: Job, contract: Contract, request: dict) -> bool:
    """W2 from the cascade-spawn edge hint: the request only says WHERE to
    look — the witness is earned by re-verifying the stored resolution on the
    parent's own row (``produce_structural_witness``), never by the flag."""
    relationship = request.get("discovery_relationship")
    if relationship not in ("implementation", "proxy", "beacon"):
        return False
    parent_job_id = request.get("parent_job_id")
    if not isinstance(parent_job_id, str):
        return False
    try:
        parent_uuid = uuid.UUID(parent_job_id)
    except ValueError:
        return False
    parent = session.execute(select(Contract).where(Contract.job_id == parent_uuid).limit(1)).scalar_one_or_none()
    if parent is None:
        return False
    edge = produce_structural_witness(
        session,
        candidate=contract,
        parent=parent,
        protocol_id=job.protocol_id,
        relationship=relationship,
    )
    return edge is not None


def _gate_intake(session: Session, job: Job, contract: Contract | None, request: dict) -> None:
    """Route one fetched/cached Contract row through the membership gate:
    nomination, W2/W4 witnesses, the event-1 probe, then a promotion attempt.
    Commits; never stamps ``protocol_id`` itself (invariant 1)."""
    protocol_id = job.protocol_id
    if not protocol_id or contract is None:
        return

    human_assertion = gate.human_assertion_from_request(job.request)

    tags = [t for t in (request.get("discovery_sources") or []) if isinstance(t, str) and t]
    if not tags:
        discovered_by = request.get("discovered_by")
        tags = [discovered_by] if isinstance(discovered_by, str) and discovered_by else [""]
    for tag in tags:
        # The gate consumes the W5 assertion at nomination (invariant 14);
        # the witness upsert is idempotent across tags.
        gate.nominate(
            session, contract=contract, protocol_id=protocol_id, source_tag=tag, human_assertion=human_assertion
        )

    _structural_intake(session, job, contract, request)

    registry_row: ProtocolDeployer | None = None
    reprobe_sink: set[int] = set()
    deployer = (contract.deployer or "").lower() or None
    if deployer:
        registry_row = _register_protocol_deployer(
            session,
            protocol_id=protocol_id,
            deployer=deployer,
            contract_address=(contract.address or "").lower() or None,
            reprobe_sink=reprobe_sink,
        )
        if registry_row is not None:
            _write_deployer_witness(session, contract=contract, registry_row=registry_row)

    if needs_probe(session, contract):
        result = gate.probe(session, contract)
        record_code_witness(session, contract=contract, protocol_id=protocol_id, probe_result=result)
    seeded = gate.seed_llama_witness(session, contract=contract)

    promoted = gate.promote(session, contract=contract, protocol_id=protocol_id)
    session.commit()

    # A demote-only registration (registry_row None, sink non-empty) is still
    # a deployer fact change the cascade must see. A W6 seeded onto an
    # already-probed row has no W1 witness row yet; the fixpoint's admission
    # binds W1 from the persisted code probe on recheck.
    deployer_changed = deployer is not None and (registry_row is not None or bool(reprobe_sink))
    delta = gate.FactsDelta(
        new_member_contract_ids=(contract.id,) if promoted else (),
        changed_deployer_addresses=(deployer,) if deployer_changed and deployer else (),
        recheck_contract_ids=(contract.id,) if seeded and not promoted else (),
    )
    if delta != gate.FactsDelta():
        cascade = gate.evaluate(session, delta, deployer_enumerator=session_deployer_enumerator(session))
        session.commit()
        # Enqueue after the commit (create_job commits). Residual: a crash in
        # between delays the pass to the next event, never loses it — selection
        # ranks the full unanalyzed set.
        enqueue_selection_for_promotions(
            session,
            ((contract.id,) if promoted else ()) + cascade.promoted_contract_ids,
            reason="membership_promotion",
        )
        reprobe_sink.update(cascade.reprobe_contract_ids)
    _consume_reprobes(session, sorted(reprobe_sink), context=f"gate_intake:{job.id}", exclude={contract.id})


def _sweep_candidates(session: Session, chain_id: int) -> list[Contract]:
    """Parked / probe-pending candidates on one chain. Pruned rows are
    excluded — only re-nomination re-runs W1 (§3.4 event 1)."""
    try:
        info = chain_by_id(chain_id)
    except UnknownChainError:
        return []
    names = sorted({info.name.lower(), *(alias.lower() for alias in info.aliases)})
    rows = list(
        session.execute(
            select(Contract).where(
                Contract.protocol_id.is_(None),
                Contract.nominated_protocol_id.is_not(None),
                func.lower(func.coalesce(Contract.chain, "ethereum")).in_(names),
            )
        ).scalars()
    )
    swept: list[Contract] = []
    for row in rows:
        witness = session.get(ContractCreationWitness, (chain_id, (row.address or "").lower()))
        if witness is not None and witness.code_absent_at_probe is True:
            continue
        swept.append(row)
    return swept


def _enqueue_selection_pass(session: Session, protocol_id: int) -> None:
    """Chain-enable sweep's own enqueue (§3.4 event 4). Shares the dedupe with
    the promotion-triggered path so a sweep and a promotion never double-fire."""
    enqueue_selection_pass(session, protocol_id, reason="chain_enable")


def run_chain_enable_sweep(session: Session) -> None:
    """§3.4 event 4: compare ``PSAT_SUPPORTED_CHAIN_IDS`` against the persisted
    ``enabled_chains_seen`` marker; for each newly enabled chain, probe-sweep
    its parked/probe-pending candidates and enqueue a selection pass for every
    protocol that gained promoted members. The marker tracks the CURRENT
    enabled set, so a chain disabled and later re-enabled sweeps again."""
    enabled = sorted(supported_chain_ids())
    marker = session.get(OpsKv, ENABLED_CHAINS_SEEN_KEY)
    if marker is None:
        # Race-safe first-boot seed: a concurrent boot's insert wins and this
        # one no-ops (a doubled sweep is the accepted residual, an
        # IntegrityError crash is not).
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        session.execute(
            pg_insert(OpsKv)
            .values(key=ENABLED_CHAINS_SEEN_KEY, value=enabled)
            .on_conflict_do_nothing(index_elements=["key"])
        )
        session.commit()
        logger.info("enabled-chains marker seeded", extra={"chains": enabled})
        return
    seen = {int(c) for c in marker.value if isinstance(c, int)} if isinstance(marker.value, list) else set()
    new_ids = [chain_id for chain_id in enabled if chain_id not in seen]
    if not new_ids:
        if seen != set(enabled):
            marker.value = enabled
            session.commit()
        return

    logger.info("chain-enable sweep starting", extra={"new_chain_ids": new_ids})
    promoted_by_protocol: dict[int, list[int]] = {}
    resolved: set[str] = set()
    swept_ids: set[int] = set()
    for chain_id in new_ids:
        for contract in _sweep_candidates(session, chain_id):
            protocol_id = contract.nominated_protocol_id
            if protocol_id is None:
                continue
            result = gate.probe(session, contract)
            swept_ids.add(contract.id)
            record_code_witness(session, contract=contract, protocol_id=protocol_id, probe_result=result)
            resolved.update(result.resolved_addresses)
            if gate.promote(session, contract=contract, protocol_id=protocol_id):
                promoted_by_protocol.setdefault(protocol_id, []).append(contract.id)
    session.commit()

    all_promoted = tuple(cid for ids in promoted_by_protocol.values() for cid in ids)
    eval_result = gate.evaluate(
        session,
        gate.FactsDelta(new_member_contract_ids=all_promoted, new_edge_addresses=tuple(sorted(resolved))),
        deployer_enumerator=session_deployer_enumerator(session),
    )
    session.commit()
    _consume_reprobes(session, eval_result.reprobe_contract_ids, context="chain_enable_sweep", exclude=swept_ids)

    gained = set(promoted_by_protocol)
    for contract_id in eval_result.promoted_contract_ids:
        row = session.get(Contract, contract_id)
        if row is not None and row.protocol_id is not None:
            gained.add(row.protocol_id)
    for protocol_id in sorted(gained):
        _enqueue_selection_pass(session, protocol_id)

    marker.value = enabled
    session.commit()


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

        # Evidence-based chain membership (invariant 3): the declared chain set
        # narrows discovery's ``eth_getCode`` probe so it CONFIRMS membership on
        # chains the protocol is known to use rather than ORIGINATING it on any
        # chain an address happens to have code on. Sourced from the requested
        # chain plus the persisted ``Protocol.chains`` of a prior run (read here,
        # written back below). Always a list — never ``None`` — so the pipeline
        # is always narrowed; ``None`` would re-enable the legacy all-chain probe.
        declared_chains: list[str] = []
        seen_declared: set[str] = set()
        requested = canonical_chain(chain) if chain else None
        if requested and requested != "unknown":
            declared_chains.append(requested)
            seen_declared.add(requested)
        if prev_job and prev_job.protocol_id:
            prev_protocol = session.get(Protocol, prev_job.protocol_id)
            for existing_chain in (prev_protocol.chains or []) if prev_protocol else []:
                canon = canonical_chain(existing_chain)
                if canon and canon != "unknown" and canon not in seen_declared:
                    declared_chains.append(canon)
                    seen_declared.add(canon)

        self.update_detail(session, job, f"Discovering contracts + audits for {company}")
        logger.info("Discovery started for job %s: company=%s, chain=%s", job.id, company, chain)

        # Premium+Deps unified discovery (see services/discovery/run_discovery.py).
        # Runs audit + address pipelines in one call, including Deep Research seeds,
        # dependency two-pass for BoringVault-class components, and SPA-bait overrides.
        from services.discovery.run_discovery import run_discovery

        try:
            with log_timed_phase(logger, "unified_discovery") as ph:
                unified = run_discovery(company, chain=chain, declared_chains=declared_chains)
                inventory = unified["addresses"]
                audit_result_raw: dict | None = unified["audits"]
                discovery_meta = unified["meta"]
                ph["contracts"] = len(inventory) if hasattr(inventory, "__len__") else None
                ph["audits"] = len(audit_result_raw) if isinstance(audit_result_raw, (list, dict)) else None
        except Exception as exc:
            record_degraded(
                phase="unified_discovery",
                exc=exc,
                context={"company": company, "chain": chain},
                include_traceback=True,
            )
            logger.warning("Job %s: unified discovery failed, falling back to legacy search: %s", job.id, exc)
            inventory = search_protocol_inventory(company, chain=chain, declared_chains=declared_chains)
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

        # Persist the protocol's declared chain set (invariant 3): the union of
        # what a prior run already recorded, the requested chain, and every
        # chain a discovered contract is now confirmed on (candidates excluded —
        # they carry no corroborating evidence). Written here so the next run
        # reads it back above and narrows its probe accordingly. Never shrinks:
        # a chain proven once stays declared.
        proven_chains: set[str] = set(declared_chains)
        for entry in inventory.get("contracts", []):
            for ch in canonical_chain_list(entry.get("chains")) or []:
                if ch and ch != "unknown":
                    proven_chains.add(ch)
        existing_chains: set[str] = set(protocol_row.chains or [])
        merged_chains: list[str] = sorted(proven_chains | existing_chains)
        if merged_chains != sorted(existing_chains):
            protocol_row.chains = merged_chains
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
            logger.warning("Job %s: audit report persistence failed: %s", job.id, exc)

        discovered = [e for e in inventory.get("contracts", []) if e.get("address")]
        record_stage_metric("contracts_discovered", len(discovered))

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
        # into roughly one round-trip. Inventory entries without their own chain
        # inherit the company discovery's chain (inv. 6, mainnet edge default)
        # rather than persisting chain=NULL and duplicating against sibling
        # writers' 'ethereum' stubs.
        inventory_default_chain = canonical_chain(chain) or "ethereum"
        bulk_upsert_discovered_contracts(
            session,
            protocol_id=protocol_row.id,
            entries=bulk_entries,
            default_chain=inventory_default_chain,
        )
        session.commit()

        # §3.4 event 1: settle this protocol's fresh nominations near-line —
        # probe, then let probe-derived facts promote. Degrades, never blocks
        # discovery: candidates stay explainably parked until the next event.
        try:
            with log_timed_phase(logger, "membership_probe_pass") as probe_ph:
                probe_result = run_probe_pass(session, protocol_row.id)
                probe_ph["targeted"] = len(probe_result.targeted_contract_ids)
                probe_ph["promoted"] = len(probe_result.promoted_contract_ids)
        except Exception as exc:
            session.rollback()
            record_degraded(
                phase="membership_probe_pass",
                exc=exc,
                context={"protocol_id": protocol_row.id},
                include_traceback=True,
            )

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

        # Seed both sibling scans with the discovery job's chain (inv. 6): derive
        # chain_id from the request's chain string via the registry rather than a
        # bare ``or 1``. A company discovery with no chain defaults to mainnet —
        # an explicit, documented choice. Each scan still attributes each address's
        # own chain from its own results; this is only the per-address fallback, so
        # a non-mainnet company's addresses inherit its chain instead of mainnet.
        spawn_chain = request.get("chain")
        spawn_chain_id = request.get("chain_id")
        if not spawn_chain_id:
            try:
                spawn_chain_id = chain_by_name(spawn_chain).chain_id if spawn_chain else 1
            except UnknownChainError:
                spawn_chain_id = 1

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
                "chain": spawn_chain,
                "chain_id": spawn_chain_id,
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
                "chain": spawn_chain,
                "chain_id": spawn_chain_id,
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

                # Membership gate — the cache hit reuses ANALYSIS, not protocol
                # membership. The row is nominated and evaluated here so an
                # explicit address+company submit of an already-analyzed
                # contract still enters the gate (promotion marks the dirty
                # queues internally).
                cached_row = session.get(Contract, new_contract_id)
                _gate_intake(session, job, cached_row, request)

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
        # Address-scoped discovery jobs always carry a chain (Phase-0 dual-write
        # + backfill); one that can't resolve is a data bug — fail loud (inv. 6).
        fetch_chain = require_chain(
            getattr(job, "chain_id", None),
            chain=request.get("chain") if isinstance(request, dict) else None,
            context=f"discovery source fetch for {address}",
        )
        fetch_chain_id = fetch_chain.chain_id
        with log_timed_phase(logger, "source_fetch"):
            fan_out = etherscan.parallel_get(
                {
                    "fetch": lambda a=address: fetch(a, chain_id=fetch_chain_id),
                    "creators": lambda a=address: _batch_get_creators([a], chain_id=fetch_chain_id),
                }
            )
        result_or_exc = fan_out["fetch"]
        if isinstance(result_or_exc, BaseException):
            raise result_or_exc
        result = cast(dict, result_or_exc)

        contract_name = result.get("ContractName", "Contract")

        sources = parse_sources(result)
        remappings = parse_remappings(result)

        # Stamp the source content hash + analyzer version so a later same-source
        # deployment on another chain can reuse this job's code-plane analysis
        # (invariant 1). Written unconditionally here: a cache-hit job returned
        # before ever reaching this fetch, so every hashed job did real analysis.
        from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

        this_source_hash = source_content_hash(result)
        job.source_content_hash = this_source_hash
        job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION

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

        # Write to contracts table — upsert to handle pre-existing discovered rows.
        # Chain identity comes from the job's first-class chain_id (resolved above
        # via the registry), never the request payload: a chainless /api/analyze
        # submission would otherwise write chain=NULL and, because NULL ≠ NULL
        # defeats uq_contract_address_chain, duplicate against 'ethereum' stubs
        # (inv. 1/6/12).
        request = job.request if isinstance(job.request, dict) else {}
        chain_name = fetch_chain.name
        existing = session.execute(
            select(Contract).where(
                Contract.address == address.lower(),
                # Legacy NULL-chain rows are mainnet by convention; coalescing lets
                # a mainnet write dedup against them instead of minting a duplicate,
                # while a non-mainnet write (coalesce → 'ethereum' ≠ its own name)
                # correctly never matches a NULL/mainnet row at the same address.
                func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name,
            )
        ).scalar_one_or_none()

        # Membership gate (invariant 1): a job's ``protocol_id`` — inherited
        # from its parent selection/cascade job — is a NOMINATION, never a
        # stamp. WETH9 pulled in as a dependency of a confirmed etherfi
        # contract is still WETH9; membership is earned through witnesses in
        # ``_gate_intake`` after the row is committed.
        request_sources = [s for s in (request.get("discovery_sources") or []) if isinstance(s, str)]

        gate_row: Contract | None = existing
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
            # None means the creators fetch answered nothing for this chain,
            # never that the contract has no deployer — keep prior evidence.
            if deployer:
                existing.deployer = deployer
            existing.remappings = remappings or []
            existing.source_verified = True
        else:
            contract = Contract(
                job_id=job.id,
                address=address.lower(),
                chain=chain_name,
                protocol_id=None,
                # Nomination recorded at write so a terminal intake failure
                # cannot strand an unclaimed row (spec §3.1 orphan amnesia).
                nominated_protocol_id=job.protocol_id,
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
                discovery_sources=request_sources or None,
                chains=request.get("chains"),
                source_verified=True,
            )
            session.add(contract)
            gate_row = contract
        session.commit()

        # Membership gate intake for the row this fetch touched: nominate,
        # earn witnesses, probe (event 1), attempt promotion. Promotion and
        # demotion mark the enrollment + scoring dirty queues inside the gate.
        _gate_intake(session, job, gate_row, request)

        if not job.name:
            job.name = f"{contract_name}_{address[2:10]}"
            session.commit()

        # Cross-chain code-plane reuse (invariant 1): the exact (address, chain)
        # cache missed above (else we'd have returned), but if a completed job
        # analyzed this same verified source on another chain, reuse its analysis
        # onto this deployment's own Contract row instead of re-running the static
        # forge+Slither pass. State (proxy impl, controllers, balances, events) is
        # still resolved per (chain, address) downstream — reuse is code-plane only.
        if not request.get("force"):
            donor = find_completed_static_cache(
                session, address, chain=request.get("chain"), source_content_hash=this_source_hash
            )
            if donor is not None and donor.id != job.id:
                copied = copy_static_cache_cross_chain(session, donor.id, job.id, target_address=address)
                if copied is not None:
                    # ``static_cached`` skips the static worker's forge+Slither pass,
                    # but deliberately WITHOUT ``cache_source_job_id`` — that key
                    # drives ``_check_proxy_cache`` to validate the donor's
                    # implementation address, which is per-chain state. Proxy
                    # classification must re-resolve on this chain, so we leave it
                    # unset and record provenance under a distinct key.
                    job.request = {
                        **request,
                        "static_cached": True,
                        "cross_chain_cache_source_job_id": str(donor.id),
                    }
                    session.commit()
                    logger.info(
                        "Discovery cross-chain code-plane reuse for %s from job %s (source_hash=%s)",
                        address,
                        donor.id,
                        this_source_hash[:12],
                    )

        record_stage_metric("source_files", len(sources))
        self.update_detail(session, job, f"Discovery complete: {contract_name} ({len(sources)} source files)")
        logger.info("Discovery complete for %s (%s)", address, contract_name)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    worker = DiscoveryWorker()
    # §3.4 event 4 fires at boot; a sweep failure leaves the marker unchanged
    # (the next boot retries) and must not crash-loop the worker.
    session = SessionLocal()
    try:
        run_chain_enable_sweep(session)
    except Exception:
        logger.exception("chain-enable boot sweep failed")
    finally:
        session.close()
    worker.run_loop()


if __name__ == "__main__":
    main()
