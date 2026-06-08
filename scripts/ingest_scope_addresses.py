"""Ingest contract addresses discovered from audit scope extraction.

Merges JSON output from:
- ``/tmp/agent1_addresses.json`` — etherfi deployment registry (GitHub + docs)
- ``/tmp/agent2_addresses.json`` — addresses extracted from audit PDF text

For each ``(address, chain_id)`` pair:

- If a ``contracts`` row exists:
  - Set ``protocol_id`` to 1 (etherfi) when NULL. Audit coverage's name
    matcher filters by protocol_id — a NULL-protocol row was silently
    invisible.
  - Replace ``contract_name`` when it was NULL or a generic proxy
    placeholder (``UUPSProxy``, ``UpgradeableBeacon``, ``BeaconProxy``),
    since the scope-discovered name is more useful downstream.
- Else insert a new row with ``discovery_source='audit_scope'``.

Idempotent. Pass ``--protocol-id`` to target a different protocol.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select

from db.models import Contract, SessionLocal
from utils.rpc import require_supported_chain_id

_GENERIC_PROXY_NAMES: frozenset[str] = frozenset(
    {"uupsproxy", "upgradeableproxy", "upgradeablebeacon", "beaconproxy", "transparentupgradeableproxy"}
)


def _load(paths: list[Path]) -> list[dict]:
    merged: list[dict] = []
    seen: set[tuple[str, int]] = set()
    errors: list[str] = []
    for p in paths:
        if not p.exists():
            errors.append(f"{p} not found")
            continue
        with p.open() as f:
            entries = json.load(f)
        if not isinstance(entries, list):
            errors.append(f"{p} must contain a JSON list")
            continue
        for e in entries:
            if not isinstance(e, dict):
                errors.append(f"{p} entry must be an object: {e!r}")
                continue
            addr = (e.get("address") or "").lower().strip()
            raw_chain_id = e.get("chain_id")
            try:
                chain_id = require_supported_chain_id(
                    chain_id=raw_chain_id,
                    context=f"audit scope ingest {p} address={addr or '<missing>'}",
                )
            except RuntimeError as exc:
                errors.append(str(exc))
                continue
            name = (e.get("name") or "").strip()
            if not addr or not addr.startswith("0x") or len(addr) != 42:
                errors.append(f"{p} entry has invalid address: {addr!r}")
                continue
            try:
                int(addr[2:], 16)
            except ValueError:
                errors.append(f"{p} entry has non-hex address: {addr!r}")
                continue
            if not name:
                errors.append(f"{p} entry for {addr} chain_id={chain_id} missing name")
                continue
            key = (addr, chain_id)
            if key in seen:
                continue
            seen.add(key)
            merged.append({"address": addr, "chain_id": chain_id, "name": name})
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        raise RuntimeError(f"audit scope ingest failed validation with {len(errors)} error(s)")
    return merged


def ingest(session, entries: list[dict], *, protocol_id: int) -> dict[str, int]:
    inserted = 0
    adopted = 0  # existing row with NULL protocol_id, now set
    renamed = 0  # replaced generic proxy placeholder with real name
    unchanged = 0

    for entry in entries:
        existing = session.execute(
            select(Contract).where(
                Contract.address == entry["address"],
                Contract.chain_id == entry["chain_id"],
            )
        ).scalar_one_or_none()

        if existing is None:
            session.add(
                Contract(
                    address=entry["address"],
                    chain_id=entry["chain_id"],
                    contract_name=entry["name"],
                    protocol_id=protocol_id,
                    discovery_sources=["audit_scope"],
                )
            )
            inserted += 1
            continue

        changed = False
        if existing.protocol_id is None:
            existing.protocol_id = protocol_id
            adopted += 1
            changed = True
        current_name = (existing.contract_name or "").lower()
        if current_name in _GENERIC_PROXY_NAMES or not current_name:
            if existing.contract_name != entry["name"]:
                existing.contract_name = entry["name"]
                renamed += 1
                changed = True
        if not changed:
            unchanged += 1

    session.commit()
    return {
        "inserted": inserted,
        "adopted_null_protocol": adopted,
        "renamed_generic_proxy": renamed,
        "unchanged": unchanged,
        "total_entries": len(entries),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol-id", type=int, default=1, help="Target protocol id (default: 1 = etherfi)")
    parser.add_argument(
        "--input",
        action="append",
        default=None,
        help="JSON file path (repeatable). Defaults to /tmp/agent1_addresses.json + /tmp/agent2_addresses.json",
    )
    args = parser.parse_args()

    paths = (
        [Path(p) for p in args.input]
        if args.input
        else [
            Path("/tmp/agent1_addresses.json"),
            Path("/tmp/agent2_addresses.json"),
        ]
    )
    entries = _load(paths)

    with SessionLocal() as session:
        stats = ingest(session, entries, protocol_id=args.protocol_id)

    for k, v in stats.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
