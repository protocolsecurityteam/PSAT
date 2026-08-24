"""Contract and protocol discovery upserts."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import Contract, Protocol
from services.discovery.source_confidence import asserts_ownership
from utils.chains import canonical_chain, canonical_chain_list

from ._chains import _mainnet_coalesced_chain


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
        # Only high-confidence sources may assert protocol ownership.
        # Low-confidence sources (dapp_crawl scraping, upgrade_history
        # traversal of unconfirmed proxies) populate discovery_sources
        # but leave protocol_id NULL until a high-confidence source
        # corroborates. See services/discovery/source_confidence.py.
        owning_protocol_id = protocol_id if asserts_ownership(clean_sources) else None
        existing = existing_by_key.get(key)
        if existing is None:
            row = Contract(
                address=address,
                chain=chain,
                protocol_id=owning_protocol_id,
                contract_name=entry.get("contract_name"),
                confidence=entry.get("confidence"),
                discovery_sources=list(clean_sources) or None,
                chains=entry.get("chains"),
                discovery_url=entry.get("discovery_url"),
            )
            session.add(row)
            existing_by_key[key] = row
            out.append(row)
            continue

        merged = list(existing.discovery_sources or [])
        for src in clean_sources:
            if src not in merged:
                merged.append(src)
        if merged:
            existing.discovery_sources = merged
        if existing.protocol_id is None and owning_protocol_id is not None:
            existing.protocol_id = owning_protocol_id
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
        - ``protocol_id`` is backfilled if null (orphan adoption).
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
    # See bulk_upsert_discovered_contracts — only high-confidence sources
    # may assert protocol ownership.
    owning_protocol_id = protocol_id if asserts_ownership(clean_sources) else None

    if existing is None:
        row = Contract(
            address=normalized,
            chain=chain,
            protocol_id=owning_protocol_id,
            contract_name=contract_name,
            confidence=confidence,
            discovery_sources=list(clean_sources) or None,
            chains=chains,
            discovery_url=discovery_url,
        )
        session.add(row)
        return row

    merged = list(existing.discovery_sources or [])
    for src in clean_sources:
        if src not in merged:
            merged.append(src)
    if merged:
        existing.discovery_sources = merged

    if existing.protocol_id is None and owning_protocol_id is not None:
        existing.protocol_id = owning_protocol_id
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
    # (table, column) for every FK referencing protocols.id. Listed
    # explicitly so the merge step touches every dependent table without
    # depending on a model registry walk. Includes both CASCADE and SET NULL
    # FKs — the orphan row is being deleted, not nulled, so the destination
    # protocol takes ownership of all children.
    ("jobs", "protocol_id"),
    ("audit_reports", "protocol_id"),
    ("audit_contract_coverage", "protocol_id"),
    ("contracts", "protocol_id"),
    ("contracts", "nominated_protocol_id"),
    ("contract_membership_witnesses", "protocol_id"),
    ("protocol_deployers", "protocol_id"),
    ("monitored_contracts", "protocol_id"),
    ("protocol_subscriptions", "protocol_id"),
    ("dapp_interactions", "protocol_id"),
    ("tvl_snapshots", "protocol_id"),
)


def _merge_protocol_into(session: Session, src: Protocol, dst: Protocol) -> None:
    """Reassign every protocols.id FK from ``src`` to ``dst``, then delete src.

    Used when ``get_or_create_protocol`` discovers that a pre-resolver row
    (NULL canonical_slug) is a duplicate of a freshly-resolved family.
    ``contract_membership_witnesses`` and ``protocol_deployers`` DO carry
    (protocol_id, …) uniqueness, so a src+dst pair holding the same key can
    conflict here; the merge becomes a membership-gate operation (spec §5.2)
    in a later change. The remaining tables have no such constraint.
    """
    if src.id == dst.id:
        return
    for table, col in _PROTOCOL_FK_TABLES:
        session.execute(
            text(f"UPDATE {table} SET {col} = :dst WHERE {col} = :src"),
            {"src": src.id, "dst": dst.id},
        )
    session.delete(src)
    session.flush()


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
