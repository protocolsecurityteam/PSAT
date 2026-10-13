"""Admission from internally fetched, replayable publisher declarations."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select

from db.models import Contract, ContractMembershipWitness
from db.queue.discovery import bulk_upsert_discovered_contracts
from services.discovery import membership_gate as gate
from services.discovery.publisher_registry import (
    REGISTRIES,
    SOURCE_TAG,
    WITNESS_RULE,
    parse_lido,
    parse_solidity,
    protocol_key,
    registry_evidence,
    validate_evidence,
    validate_membership_evidence,
)


def register_snapshot(session, protocol, snapshot: dict) -> list[int]:
    return register_snapshots(session, protocol, [snapshot])


def register_snapshots(session, protocol, snapshots: list[dict]) -> list[int]:
    """Reconcile all successfully fetched sources together, preserving independent assertions.

    Requests/research cannot nominate URLs here. Reparse exact content, not supplied address
    rows. Same-chain W1 remains mandatory; rediscovery never revives a revoked assertion.
    A failed source is omitted from this batch, so its dated evidence is retained, not renewed.
    """
    if not snapshots:
        return []
    updates = {}
    entries = []
    for snapshot in snapshots:
        source = next((s for s in REGISTRIES if s.key == snapshot.get("registry")), None)
        if source is None or source.protocol not in {
            protocol_key(protocol.name),
            protocol_key(protocol.canonical_slug),
        }:
            raise ValueError("publisher registry does not identify this protocol")
        if source.key in updates:
            raise ValueError("duplicate source refresh")
        content = snapshot["content"]
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != snapshot.get("sha256"):
            raise ValueError("publisher content digest mismatch")
        parsed = parse_solidity(source, content) if source.repo else parse_lido(source, content)
        declarations = {row["address"]: validate_evidence(registry_evidence(snapshot, row)) for row in parsed}
        if not declarations:
            raise ValueError("publisher registry contains no accepted declarations")
        updates[source.key] = declarations
        entries.extend(
            {
                "address": row["address"],
                "chain": "ethereum",
                "contract_name": row["name"],
                "confidence": 1.0,
                "new_sources": [SOURCE_TAG],
                "discovery_url": snapshot["url"],
            }
            for row in parsed
        )
    bulk_upsert_discovered_contracts(session, protocol_id=protocol.id, default_chain="ethereum", entries=entries)
    fresh_addresses = {entry["address"] for entry in entries}
    standing = {
        w.contract_id: w
        for w in session.execute(
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.protocol_id == protocol.id,
                ContractMembershipWitness.rule == WITNESS_RULE,
            )
        ).scalars()
    }
    rows = list(
        session.execute(
            select(Contract).where(
                (Contract.address.in_(fresh_addresses) | Contract.id.in_(standing)),
                Contract.chain == "ethereum",
            )
        ).scalars()
    )
    seeded, withdrawn = [], []
    for row in rows:
        if row.protocol_id not in (None, protocol.id) or row.nominated_protocol_id != protocol.id:
            continue
        existing = standing.get(row.id)
        if existing is not None and existing.revoked_at is not None:
            continue
        assertions = {item["registry"]: item for item in existing.evidence["assertions"]} if existing else {}
        for key, declarations in updates.items():
            if row.address in declarations:
                assertions[key] = declarations[row.address]
            else:
                assertions.pop(key, None)
        if not assertions:
            if existing is not None:
                reason = "publisher declaration absent from successfully refreshed registries"
                gate.revoke_witness(session, existing, reason=reason)
                gate._demote_if_no_verified_witness(session, contract_id=row.id, protocol_id=protocol.id, reason=reason)
                withdrawn.append(row.address)
            continue
        first = next(iter(assertions.values()))
        evidence = validate_membership_evidence(
            {
                **{key: first[key] for key in ("protocol", "chain_id", "address")},
                "assertions": list(assertions.values()),
            }
        )
        if existing is not None:
            if existing.evidence != evidence:
                existing.evidence = evidence
                existing.observed_at = datetime.now(timezone.utc)
            continue
        witness = gate.write_witness(
            session,
            contract_id=row.id,
            protocol_id=protocol.id,
            rule=WITNESS_RULE,
            evidence=evidence,
            rearm_revoked=False,
        )
        if witness.revoked_at is None:
            seeded.append(row.id)
    if withdrawn:
        gate.evaluate(session, gate.FactsDelta(new_edge_addresses=tuple(sorted(withdrawn))))
    return seeded
