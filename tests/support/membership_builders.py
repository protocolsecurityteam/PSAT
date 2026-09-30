import uuid

from db.models import Contract, ContractProbeAttempt, Protocol


def _protocol(session) -> Protocol:
    row = Protocol(name=f"proto-{uuid.uuid4().hex[:12]}")
    session.add(row)
    session.flush()
    return row


def _contract(session, address: str, **fields) -> Contract:
    row = Contract(address=address.lower(), chain=fields.pop("chain", "ethereum"), **fields)
    session.add(row)
    session.flush()
    return row


def _probe_read(db_session, subject, value):
    """A bare caller gate is not a W3-D2 derivation; this writes the §3.5 probe read."""
    row = db_session.get(ContractProbeAttempt, (subject.id, 1))
    reads = dict(row.results.get("reads", {})) if row is not None and isinstance(row.results, dict) else {}
    slot = next(
        (
            name
            for name in ("owner", "authority", "admin")
            if name not in reads or reads[name]["value"] == value.lower()
        ),
        "owner",
    )
    reads[slot] = {"value": value.lower()}
    resolved = sorted({read["value"] for read in reads.values()})
    results = {"status": "probed", "code_present": True, "reads": reads, "resolved_addresses": resolved}
    if row is None:
        db_session.add(ContractProbeAttempt(contract_id=subject.id, chain_id=1, block_number=1000, results=results))
    else:
        row.results = results
    db_session.flush()
