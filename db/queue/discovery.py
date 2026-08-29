"""Contract and protocol discovery upserts."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import Contract, ContractMembershipWitness, Protocol, ProtocolDeployer
from services.discovery.membership_gate import MEMBERSHIP_DIRTY_REASON, nominate
from services.discovery.membership_gate import demote as gate_demote_deployer
from utils.chains import canonical_chain, canonical_chain_list

from ._chains import _mainnet_coalesced_chain

logger = logging.getLogger(__name__)


def bulk_upsert_discovered_contracts(
    session: Session,
    *,
    protocol_id: int | None,
    entries: list[dict[str, Any]],
    default_chain: str | None = None,
) -> list[Contract]:
    """Bulk variant of :func:`upsert_discovered_contract` with identical first-writer-wins semantics.

    Each *entries* item is a dict with keys: ``address`` (required),
    ``chain``, ``new_sources`` (list[str]), ``contract_name``, ``confidence``,
    ``chains``, ``discovery_url``. The single-row helper does one SELECT per
    address, which dominates wall time when discovery surfaces 100-300
    contracts at once. This collapses every SELECT into one ``IN (...)`` and
    keeps the merge logic identical so semantics don't drift.

    *default_chain* is the job's chain (derived from ``Job.chain_id`` via the
    registry): an entry that carries no evidence chain of its own inherits it
    so no writer persists ``chain=NULL`` and mints a duplicate against a sibling
    writer's ``'ethereum'`` stub (NULL ≠ NULL defeats ``uq_contract_address_chain``).
    The ``'unknown'`` resolve-later sentinel is a real chain bucket, not absent
    evidence, so it is preserved, never coerced.

    Commit is the caller's responsibility — typical use is one bulk call
    per discovery source followed by a single commit.
    """
    if not entries:
        return []

    resolved_default = canonical_chain(default_chain)

    # Normalize once so the lookup map and the merge loop see identical keys.
    norm_entries: list[tuple[str, str | None, dict[str, Any]]] = []
    for entry in entries:
        address = str(entry["address"]).lower()
        chain = canonical_chain(entry.get("chain")) or resolved_default
        clean_entry = dict(entry)
        clean_entry["chain"] = chain
        clean_entry["chains"] = canonical_chain_list(entry.get("chains"))
        norm_entries.append((address, chain, clean_entry))

    # One round-trip for every existing row across the requested (address, chain) tuples.
    # We can't use a single tuple-IN against a composite key efficiently in SQLAlchemy
    # core without raw SQL, so query by address set and filter chain in Python — the
    # set is small (typically 100-300 addresses) and the chain comparison is O(1).
    # The chain half of the key is mainnet-coalesced so a mainnet writer dedups
    # against legacy NULL-chain rows instead of minting a duplicate.
    addresses = list({a for a, _c, _e in norm_entries})
    existing_rows = session.execute(select(Contract).where(Contract.address.in_(addresses))).scalars().all()
    existing_by_key: dict[tuple[str, str], Contract] = {
        (row.address, _mainnet_coalesced_chain(row.chain)): row for row in existing_rows
    }

    out: list[Contract] = []
    for address, chain, entry in norm_entries:
        key = (address, _mainnet_coalesced_chain(chain))
        clean_sources = [s for s in (entry.get("new_sources") or []) if s]
        # Invariant 1: no discovery source stamps protocol_id — every write
        # is a nomination and the membership gate is the sole promoter.
        source_tag = clean_sources[0] if clean_sources else ""
        existing = existing_by_key.get(key)
        if existing is None:
            row = Contract(
                address=address,
                chain=chain,
                contract_name=entry.get("contract_name"),
                confidence=entry.get("confidence"),
                discovery_sources=list(clean_sources) or None,
                chains=entry.get("chains"),
                discovery_url=entry.get("discovery_url"),
            )
            session.add(row)
            if protocol_id is not None:
                nominate(session, contract=row, protocol_id=protocol_id, source_tag=source_tag)
            existing_by_key[key] = row
            out.append(row)
            continue

        merged = list(existing.discovery_sources or [])
        for src in clean_sources:
            if src not in merged:
                merged.append(src)
        if merged:
            existing.discovery_sources = merged
        if protocol_id is not None:
            nominate(session, contract=existing, protocol_id=protocol_id, source_tag=source_tag)
        if not existing.contract_name and entry.get("contract_name"):
            existing.contract_name = entry["contract_name"]
        if existing.confidence is None and entry.get("confidence") is not None:
            existing.confidence = entry["confidence"]
        if not existing.chains and entry.get("chains"):
            existing.chains = entry["chains"]
        if not existing.discovery_url and entry.get("discovery_url"):
            existing.discovery_url = entry["discovery_url"]
        out.append(existing)

    return out


def upsert_discovered_contract(
    session: Session,
    *,
    address: str,
    chain: str | None,
    protocol_id: int | None,
    new_sources: list[str],
    contract_name: str | None = None,
    confidence: float | None = None,
    chains: list[str] | None = None,
    discovery_url: str | None = None,
    default_chain: str | None = None,
) -> Contract:
    """Insert or update a discovered contract, unioning ``discovery_sources``.

    Every discovery worker — inventory, DApp crawl, DefiLlama scan,
    upgrade-history backfill — funnels through here so "three sources
    agree" shows up in the data as a three-element array, not as
    whichever writer landed first. The ranking module reads the union
    and applies a corroboration boost.

    When the row exists already:
        - ``discovery_sources`` is unioned (new entries appended, dedup
          preserves order so the first discoverer stays first).
        - the nomination is recorded via the membership gate
          (``nominated_protocol_id``); ``protocol_id`` is never written here
          — promotion is the gate's job (invariant 1).
        - ``contract_name`` / ``confidence`` / ``chains`` /
          ``discovery_url`` are first-writer-wins: later writers only
          fill them if the stored value is missing, so a later
          lower-quality source doesn't stomp a better one.

    *default_chain* is the job's chain (derived from ``Job.chain_id`` via the
    registry); an entry carrying no evidence chain inherits it so no writer
    persists ``chain=NULL`` and mints a duplicate against a sibling writer's
    ``'ethereum'`` stub. Shares the mainnet-coalesced dedup key with
    :func:`bulk_upsert_discovered_contracts`.

    Commit is the caller's responsibility — callers usually batch many
    upserts into one transaction.
    """
    normalized = address.lower()
    chain = canonical_chain(chain) or canonical_chain(default_chain)
    chains = canonical_chain_list(chains)
    # Mainnet-coalesced dedup so a mainnet write finds legacy NULL-chain rows
    # while a non-mainnet write stays isolated. ``first()`` (not
    # ``scalar_one_or_none``) tolerates pre-existing legacy duplicates without
    # raising, mirroring the bulk helper's dict-collapse.
    existing = (
        session.execute(
            select(Contract)
            .where(
                Contract.address == normalized,
                func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(chain),
            )
            .order_by(Contract.id)
            .limit(1)
        )
        .scalars()
        .first()
    )

    clean_sources = [s for s in new_sources if s]
    # See bulk_upsert_discovered_contracts — writes nominate, never stamp.
    source_tag = clean_sources[0] if clean_sources else ""

    if existing is None:
        row = Contract(
            address=normalized,
            chain=chain,
            contract_name=contract_name,
            confidence=confidence,
            discovery_sources=list(clean_sources) or None,
            chains=chains,
            discovery_url=discovery_url,
        )
        session.add(row)
        if protocol_id is not None:
            nominate(session, contract=row, protocol_id=protocol_id, source_tag=source_tag)
        return row

    merged = list(existing.discovery_sources or [])
    for src in clean_sources:
        if src not in merged:
            merged.append(src)
    if merged:
        existing.discovery_sources = merged

    if protocol_id is not None:
        nominate(session, contract=existing, protocol_id=protocol_id, source_tag=source_tag)
    if not existing.contract_name and contract_name:
        existing.contract_name = contract_name
    if existing.confidence is None and confidence is not None:
        existing.confidence = confidence
    if not existing.chains and chains:
        existing.chains = chains
    if not existing.discovery_url and discovery_url:
        existing.discovery_url = discovery_url

    return existing


_PROTOCOL_FK_TABLES = (
    # (table, column) pairs the merge rewrites — an explicit list, not a
    # model-registry walk, and NOT every protocols.id FK in the schema:
    # tables absent here keep whatever their FK's delete action does when the
    # src row is deleted. Includes both CASCADE and SET NULL FKs — the src
    # row is deleted, not nulled, so the destination protocol takes ownership
    # of the enumerated children.
    ("jobs", "protocol_id"),
    ("audit_reports", "protocol_id"),
    ("audit_contract_coverage", "protocol_id"),
    ("contracts", "protocol_id"),
    ("contracts", "nominated_protocol_id"),
    ("contract_membership_witnesses", "protocol_id"),
    ("protocol_deployers", "protocol_id"),
    ("deployer_affinity_challenges", "foreign_protocol_id"),
    ("monitored_contracts", "protocol_id"),
    ("protocol_subscriptions", "protocol_id"),
    ("dapp_interactions", "protocol_id"),
    ("tvl_snapshots", "protocol_id"),
)


def _merge_witness_rows(session: Session, *, src_id: int, dst_id: int) -> int:
    """Rewrite src witness rows to dst. Where both protocols hold the same
    (contract, rule, via_address) key, the destination row survives. A revoked
    dst row is re-armed only by a src observation that POSTDATES the
    revocation — an older observation cannot overturn negative evidence; a
    fresh one re-earns later via ``write_witness``. Returns dropped-src-row
    count."""
    dropped = 0
    src_rows = (
        session.execute(select(ContractMembershipWitness).where(ContractMembershipWitness.protocol_id == src_id))
        .scalars()
        .all()
    )
    for src_row in src_rows:
        via_match = (
            ContractMembershipWitness.via_address.is_(None)
            if src_row.via_address is None
            else ContractMembershipWitness.via_address == src_row.via_address
        )
        dst_row = session.execute(
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.protocol_id == dst_id,
                ContractMembershipWitness.contract_id == src_row.contract_id,
                ContractMembershipWitness.rule == src_row.rule,
                via_match,
            )
        ).scalar_one_or_none()
        if dst_row is None:
            src_row.protocol_id = dst_id
            continue
        if dst_row.revoked_at is not None and src_row.revoked_at is None and src_row.observed_at > dst_row.revoked_at:
            dst_row.revoked_at = None
            dst_row.evidence = src_row.evidence
            dst_row.observed_at = src_row.observed_at
        session.delete(src_row)
        dropped += 1
    return dropped


def _merge_deployer_rows(session: Session, *, src_id: int, dst_id: int) -> tuple[int, list[ProtocolDeployer]]:
    """Rewrite src deployer-registry rows to dst. A same-address row under
    both protocols survives as one row (invariant 7 collision resolved by the
    merge itself: src and dst are the same protocol afterwards) — dst's row is
    kept and revocation resolves conservatively: a revoked side keeps (or
    makes) the survivor revoked, carrying the negative evidence. Returns the
    dropped-src-row count and the surviving revoked rows whose invariant-8
    demotion cascade the caller must run after the FK rewrite."""
    dropped = 0
    cascade: list[ProtocolDeployer] = []
    src_rows = session.execute(select(ProtocolDeployer).where(ProtocolDeployer.protocol_id == src_id)).scalars().all()
    for src_row in src_rows:
        dst_row = session.execute(
            select(ProtocolDeployer).where(
                ProtocolDeployer.protocol_id == dst_id,
                ProtocolDeployer.address == src_row.address,
            )
        ).scalar_one_or_none()
        if dst_row is None:
            src_row.protocol_id = dst_id
            continue
        src_revoked = src_row.revoked_at is not None
        dst_revoked = dst_row.revoked_at is not None
        discarded_evidence = src_row.evidence
        if src_revoked and not dst_revoked:
            # Negative evidence survives the merge: the surviving row adopts
            # src's revocation, and dst's active evidence is the discard.
            discarded_evidence = dst_row.evidence
            dst_row.revoked_at = src_row.revoked_at
            dst_row.revocation_reason = src_row.revocation_reason
            dst_row.evidence = src_row.evidence
            cascade.append(dst_row)
        elif dst_revoked and not src_revoked:
            cascade.append(dst_row)
        logger.info(
            "protocol merge dropped duplicate deployer row",
            extra={
                "address": src_row.address,
                "src_protocol_id": src_id,
                "dst_protocol_id": dst_id,
                "src_revoked_at": src_row.revoked_at.isoformat() if src_row.revoked_at else None,
                "dst_revoked_at": dst_row.revoked_at.isoformat() if dst_row.revoked_at else None,
                "survivor_revocation_reason": dst_row.revocation_reason,
                "discarded_evidence": discarded_evidence,
            },
        )
        session.delete(src_row)
        dropped += 1
    return dropped, cascade


def _merge_protocol_into(session: Session, src: Protocol, dst: Protocol) -> None:
    """Reassign every protocols.id FK from ``src`` to ``dst``, then delete src.

    Used when ``get_or_create_protocol`` discovers that a pre-resolver row
    (NULL canonical_slug) is a duplicate of a freshly-resolved family. A gate
    operation (invariant 1): contract membership, witness rows, and deployer
    rows all move to dst in the same transaction, with the (protocol_id, …)
    unique keys on ``contract_membership_witnesses`` / ``protocol_deployers``
    resolved before the blind FK rewrite. A deployer collision whose survivor
    is revoked runs the invariant-8 demotion cascade after the rewrite.
    ``nominated_protocol_id`` is in ``_PROTOCOL_FK_TABLES`` and is rewritten
    here — never left for the src delete's SET NULL. The remaining enumerated
    tables carry no protocol-keyed uniqueness.
    """
    src_id, dst_id = src.id, dst.id
    if src_id == dst_id:
        return
    moved_members = session.execute(
        select(func.count()).select_from(Contract).where(Contract.protocol_id == src_id)
    ).scalar_one()
    witness_dropped = _merge_witness_rows(session, src_id=src_id, dst_id=dst_id)
    deployer_dropped, cascade_rows = _merge_deployer_rows(session, src_id=src_id, dst_id=dst_id)
    session.flush()
    for table, col in _PROTOCOL_FK_TABLES:
        session.execute(
            text(f"UPDATE {table} SET {col} = :dst WHERE {col} = :src"),
            {"src": src_id, "dst": dst_id},
        )
    # The raw rewrite bypasses the identity map; without this, an in-session
    # Contract still reads its src-era ids (e.g. the member branch in
    # ``nominate``) for the rest of the transaction.
    session.expire_all()
    for deployer_row in cascade_rows:
        # Invariant 8 for the surviving revoked registry row: W4 witnesses
        # resting on it are revoked and members left without an admitting
        # witness are demoted, so reconcile reports zero drift post-merge.
        result = gate_demote_deployer(session, deployer_row=deployer_row, reason="protocol_merge_revoked_deployer")
        logger.info(
            "protocol merge deployer demotion cascade",
            extra={
                "address": deployer_row.address,
                "dst_protocol_id": dst_id,
                "revoked_witness_ids": list(result.revoked_witness_ids),
                "demoted_contract_ids": list(result.demoted_contract_ids),
                "reprobe_contract_ids": list(result.reprobe_contract_ids),
            },
        )
    session.delete(src)
    session.flush()
    if moved_members:
        from services.monitoring.enrollment import mark_enrollment_dirty
        from services.scoring.dirty import SCORE_DIRTY_MEMBERSHIP, mark_protocol_score_dirty

        mark_enrollment_dirty(session, dst_id, MEMBERSHIP_DIRTY_REASON)
        mark_protocol_score_dirty(session, dst_id, SCORE_DIRTY_MEMBERSHIP)
    logger.info(
        "protocol merged (gate operation)",
        extra={
            "src_protocol_id": src_id,
            "dst_protocol_id": dst_id,
            "moved_member_contracts": moved_members,
            "witness_duplicates_dropped": witness_dropped,
            "deployer_duplicates_dropped": deployer_dropped,
        },
    )


def get_or_create_protocol(
    session: Session,
    name: str,
    official_domain: str | None = None,
    canonical_slug: str | None = None,
    aliases: list[str] | None = None,
) -> Protocol:
    """Look up Protocol by canonical slug (preferred) or name, create if missing.

    The slug-keyed branch is the durable fix for duplicate rows: ``"ether fi"``
    and ``"etherfi"`` both resolve to the same DefiLlama family slug, so
    keying on slug collapses them. The name-keyed branch is the fallback
    for protocols without a DefiLlama match (slug is None).

    ``aliases`` is the list of every display-name spelling the resolver
    knows for this family (typically ``resolved["all_names"]``). It is used
    to find pre-resolver duplicate rows whose ``canonical_slug`` is still
    NULL and merge them into the slug-keyed row. Without this, the prod
    incident's two rows (``"ether fi"`` + ``"etherfi"``) would not collapse
    on first post-migration touch — one would adopt the slug and the other
    would orphan.

    Concurrent slug inserts are serialized via ``uq_protocol_canonical_slug``;
    the IntegrityError is caught inside a savepoint and we re-fetch the
    winning row instead of bubbling the failure up to the worker.
    """
    if canonical_slug:
        row = session.execute(select(Protocol).where(Protocol.canonical_slug == canonical_slug)).scalar_one_or_none()
        if row is None:
            # Look at every alias plus the requested name. Match is
            # name + NULL slug — never poach a row that's already owned
            # by a different family.
            candidate_names = [name, *(aliases or [])]
            orphans = list(
                session.execute(
                    select(Protocol).where(
                        Protocol.canonical_slug.is_(None),
                        Protocol.name.in_(candidate_names),
                    )
                ).scalars()
            )
            if orphans:
                # Adopt the first orphan; merge any siblings into it so
                # FK children consolidate onto one row.
                row = orphans[0]
                row.canonical_slug = canonical_slug
                for extra in orphans[1:]:
                    _merge_protocol_into(session, src=extra, dst=row)
            else:
                # Savepoint so a concurrent winner's IntegrityError on
                # uq_protocol_canonical_slug doesn't poison the outer
                # transaction. ``add`` goes inside the savepoint so the
                # session expunges the rejected pending object on rollback —
                # otherwise the next autoflush retries the doomed INSERT.
                try:
                    with session.begin_nested():
                        row = Protocol(name=name, official_domain=official_domain, canonical_slug=canonical_slug)
                        session.add(row)
                        session.flush()
                except IntegrityError:
                    row = session.execute(
                        select(Protocol).where(Protocol.canonical_slug == canonical_slug)
                    ).scalar_one()
                if official_domain and not row.official_domain:
                    row.official_domain = official_domain
                    session.flush()
                return row
        if official_domain and not row.official_domain:
            row.official_domain = official_domain
        session.flush()
        return row

    row = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if row is None:
        row = Protocol(name=name, official_domain=official_domain)
        session.add(row)
        session.flush()
        return row
    if official_domain and not row.official_domain:
        row.official_domain = official_domain
        session.flush()
    return row
