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
    """Bulk :func:`upsert_discovered_contract` with the same first-writer-wins semantics, one ``IN (...)`` lookup
    instead of one SELECT per address.

    Entries have ``address`` plus optional ``chain``, ``new_sources``, ``contract_name``, ``confidence``, ``chains``,
    ``discovery_url``. Entries without a chain inherit *default_chain* (the job's chain) so nobody writes ``chain=NULL``
    and duplicates an ``'ethereum'`` row (NULL ≠ NULL defeats the unique key); ``'unknown'`` is preserved. The caller
    commits.
    """
    if not entries:
        return []

    resolved_default = canonical_chain(default_chain)

    norm_entries: list[tuple[str, str | None, dict[str, Any]]] = []
    for entry in entries:
        address = str(entry["address"]).lower()
        chain = canonical_chain(entry.get("chain")) or resolved_default
        clean_entry = dict(entry)
        clean_entry["chain"] = chain
        clean_entry["chains"] = canonical_chain_list(entry.get("chains"))
        norm_entries.append((address, chain, clean_entry))

    # Query by address set and filter chain in Python (small sets); mainnet-coalesced so legacy NULL-chain rows dedup.
    addresses = list({a for a, _c, _e in norm_entries})
    existing_rows = session.execute(select(Contract).where(Contract.address.in_(addresses))).scalars().all()
    existing_by_key: dict[tuple[str, str], Contract] = {
        (row.address, _mainnet_coalesced_chain(row.chain)): row for row in existing_rows
    }

    out: list[Contract] = []
    for address, chain, entry in norm_entries:
        key = (address, _mainnet_coalesced_chain(chain))
        clean_sources = [s for s in (entry.get("new_sources") or []) if s]
        # Invariant 1: discovery only nominates; the membership gate promotes.
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

    Every discovery worker writes through here so corroboration shows as a multi-element array (ranking boosts it). On
    an existing row: sources are unioned in order; the nomination is recorded via the membership gate (``protocol_id``
    is never written here, invariant 1); ``contract_name``/``confidence``/``chains``/``discovery_url`` are
    first-writer-wins.

    Chainless entries inherit *default_chain*, sharing the mainnet-coalesced key with
    :func:`bulk_upsert_discovered_contracts`. The caller commits.
    """
    normalized = address.lower()
    chain = canonical_chain(chain) or canonical_chain(default_chain)
    chains = canonical_chain_list(chains)
    # ``first()`` tolerates legacy duplicates.
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
    # Nominate, never stamp.
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
    # Explicit list of FKs the merge rewrites (CASCADE and SET NULL alike, since src is deleted); unlisted tables get
    # their FK's delete action.
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
    """Rewrite src witness rows to dst.

    On a shared key dst survives; a revoked dst row is re-armed only by a src observation newer than the revocation.
    Returns dropped src rows.
    """
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
    """Rewrite src deployer rows to dst.

    On a shared address dst's row survives, revoked if either side was. Returns dropped src rows and surviving revoked
    rows, whose invariant-8 demotion the caller runs after the FK rewrite.
    """
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
            # Negative evidence survives; dst's active evidence is discarded.
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

    Used when ``get_or_create_protocol`` finds a pre-resolver duplicate. A gate operation (invariant 1): membership,
    witness and deployer rows move in one transaction, with unique-key collisions resolved before the blind rewrite, and
    revoked deployer survivors demoted after. ``nominated_protocol_id`` is rewritten, not left to SET NULL.
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
    # The raw rewrite bypasses the identity map.
    session.expire_all()
    for deployer_row in cascade_rows:
        # Invariant 8 for the surviving revoked row, so reconcile reports no drift after the merge.
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
    """Look up a Protocol by canonical slug (else name), creating it if missing.

    Keying on the DefiLlama slug collapses spellings ("ether fi"/"etherfi"). ``aliases`` (the resolver's ``all_names``)
    finds pre-resolver rows with NULL slugs and merges them in. Concurrent inserts race on
    ``uq_protocol_canonical_slug``; the IntegrityError is caught in a savepoint and the winner re-fetched.
    """
    if canonical_slug:
        row = session.execute(select(Protocol).where(Protocol.canonical_slug == canonical_slug)).scalar_one_or_none()
        if row is None:
            # Only NULL-slug rows, never another family's.
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
                # Adopt the first orphan and merge the rest into it.
                row = orphans[0]
                row.canonical_slug = canonical_slug
                for extra in orphans[1:]:
                    _merge_protocol_into(session, src=extra, dst=row)
            else:
                # Savepoint so a concurrent winner doesn't poison the outer transaction; ``add`` inside it so rollback
                # expunges the rejected object.
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
