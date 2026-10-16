"""Bounded read-only corroboration probes.

One probe is eth_getCode, Etherscan ``getcontractcreation``, owner()/authority(), and the EIP-1967 slots, pinned at one
block. Allowed on any eRPC-routable chain regardless of ``PSAT_SUPPORTED_CHAIN_IDS``. Every outcome is
persisted so parked candidates are explainable. The caller commits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.creation_witnesses import upsert_creation_witness
from db.models import Contract, ContractCreationWitness, ContractProbeAttempt
from services.clients import etherscan
from services.clients.etherscan import CreationRecord, parse_creation_record
from services.clients.rpc import (
    chain_id_for_chain_name,
    erpc_url_for_chain_id,
    eth_call_batch,
    parse_address_result,
    rpc_batch_request,
    rpc_request,
    selector,
)
from utils.chains import chain_by_id, chain_enabled
from utils.evm import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    OWNER_SELECTOR,
)
from utils.logging import record_degraded

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

AUTHORITY_SELECTOR = selector("authority()")

_CREATION_BATCH = 5

# ``chain_id`` for rows whose chain doesn't resolve (e.g. ``unknown``); 0 is no EVM chain, and ``results.status`` keeps
# the raw string.
UNRESOLVABLE_CHAIN_ID = 0

STATUS_PROBED = "probed"
STATUS_NOT_ROUTABLE = "not_routable"
STATUS_RPC_ERROR = "rpc_error"

# The five reads, in persisted order.
_READS = ("owner", "authority", "implementation", "admin", "beacon")

# How long a code-less address's "no creation record" answer is reused. Every probe re-reads ``eth_getCode``, so code
# that appears drops it at once; the window bounds a creation that left no code behind (created and destroyed since).
CREATION_ABSENCE_REVALIDATE_S = 86_400


@dataclass(frozen=True)
class CreationAnswers:
    records: dict[str, CreationRecord]
    # Addresses Etherscan explicitly answered with no creation record (never a failed call).
    no_record: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ProbeResult:
    """One probe's outcome.

    ``None`` means the read determined nothing, never absence; ``attempts`` says which per read.
    """

    contract_id: int
    chain_id: int | None
    routable: bool
    block_number: int | None = None
    code_present: bool | None = None
    creation_tx_hash: str | None = None
    creation_block: int | None = None
    deployer: str | None = None
    # True: allocated at genesis, so ``deployer`` and ``creation_tx_hash`` are absent by fact, not by missing answer.
    created_at_genesis: bool | None = None
    owner: str | None = None
    authority: str | None = None
    implementation: str | None = None
    admin: str | None = None
    beacon: str | None = None
    resolved_addresses: tuple[str, ...] = ()
    attempts: dict[str, Any] | None = None


def _persist_attempt(
    session: Session,
    *,
    contract_id: int,
    chain_id: int | None,
    block_number: int | None,
    results: dict[str, Any],
) -> None:
    """Latest successful probe wins; a failed attempt only adds ``last_error`` and keeps the last good results (their
    ``resolved_addresses`` still feed targeting).
    """
    key_chain = UNRESOLVABLE_CHAIN_ID if chain_id is None else chain_id
    # Concurrent jobs probe the same contract: claim the row atomically, then merge under a row lock.
    inserted = session.execute(
        pg_insert(ContractProbeAttempt)
        .values(contract_id=contract_id, chain_id=key_chain, results=results, block_number=block_number)
        .on_conflict_do_nothing(index_elements=["contract_id", "chain_id"])
        .returning(ContractProbeAttempt.contract_id)
    ).first()
    row = session.execute(
        select(ContractProbeAttempt)
        .where(ContractProbeAttempt.contract_id == contract_id, ContractProbeAttempt.chain_id == key_chain)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if inserted is not None:
        return
    if results.get("status") == STATUS_PROBED:
        row.results = results
        row.block_number = block_number
    else:
        prev = row.results if isinstance(row.results, dict) else {}
        if prev.get("status") == STATUS_PROBED:
            row.results = {**prev, "last_error": results}
        else:
            row.results = results
            row.block_number = block_number
    session.flush()


def fetch_creations(
    session: Session,
    addresses: Sequence[str],
    *,
    chain_id: int,
) -> CreationAnswers:
    """Etherscan ``getcontractcreation`` for *addresses* (5 per call), persisting tx/block/factory/genesis into
    ``contract_creation_witnesses``. An address in neither ``records`` nor ``no_record`` got no answer.
    """
    wanted = sorted({a.lower() for a in addresses})
    out: dict[str, CreationRecord] = {}
    no_record: set[str] = set()
    for start in range(0, len(wanted), _CREATION_BATCH):
        batch = wanted[start : start + _CREATION_BATCH]
        try:
            data = etherscan.get(
                "contract",
                "getcontractcreation",
                chain_id=chain_id,
                empty_result_ok=True,
                contractaddresses=",".join(batch),
            )
        except Exception as exc:
            # Systematic auth/quota failures here silently starve W4 lineage.
            record_degraded(phase="membership_probe_creation_fetch", exc=exc, context={"chain_id": chain_id})
            logger.warning(
                "getcontractcreation failed",
                extra={"batch_size": len(batch), "chain_id": chain_id, "exc_type": type(exc).__name__},
            )
            record_degraded(
                phase="creation_fetch",
                exc=exc,
                context={"batch_size": len(batch), "chain_id": chain_id},
            )
            continue
        result = data.get("result") if isinstance(data, dict) else None
        if result is None and isinstance(data, dict) and str(data.get("status")).strip() == "0":
            no_record.update(batch)
            continue
        if not isinstance(result, list):
            continue
        for item in result:
            record = parse_creation_record(item)
            # A malformed tx is no answer; only genesis licenses a creation without one.
            if record is None or (record.tx_hash is None and not record.genesis):
                continue
            out[record.address] = record
    for addr, record in out.items():
        fields: dict[str, Any] = {
            "creation_tx_hash": record.tx_hash,
            "creation_block": record.block,
            "creation_genesis": record.genesis,
            "no_creation_record_block": None,
        }
        if record.factory is not None:
            fields["creation_factory"] = record.factory
        upsert_creation_witness(session, chain_id=chain_id, address=addr, **fields)
    return CreationAnswers(records=out, no_record=frozenset(no_record))


def _code_verdict(code: Any) -> bool | None:
    """``eth_getCode`` result to a code-present verdict: ``"0x"`` is absence, non-empty even-length hex is presence,
    anything else is no verdict.
    """
    if not isinstance(code, str) or not code.startswith("0x"):
        return None
    body = code[2:].lower()
    if body and (len(body) % 2 or set(body) - set("0123456789abcdef")):
        return None
    return bool(body)


def _record_code_probe(session: Session, *, chain_id: int, address: str, block_number: int, code_absent: bool) -> None:
    fields: dict[str, Any] = {"code_probe_block": block_number, "code_absent_at_probe": code_absent}
    if not code_absent:
        fields["no_creation_record_block"] = None
    upsert_creation_witness(session, chain_id=chain_id, address=address, **fields)


def _creation_absence_stands(session: Session, *, chain_id: int, address: str, block_number: int) -> bool:
    """Whether a kept "no creation record" answer still covers a code-less *address* at *block_number*."""
    witness = session.get(ContractCreationWitness, (chain_id, address))
    if witness is None or witness.no_creation_record_block is None:
        return False
    if witness.creation_tx_hash or witness.creation_genesis:
        return False
    window_blocks = CREATION_ABSENCE_REVALIDATE_S / chain_by_id(chain_id).block_time_s
    return block_number - witness.no_creation_record_block <= window_blocks


def run_probe(session: Session, contract: Contract) -> ProbeResult:
    """Probe *contract* on its own (address, chain) and persist every outcome (code presence to
    ``contract_creation_witnesses``, reads to ``contract_probe_attempts``).
    """
    address = (contract.address or "").lower()
    chain_id = chain_id_for_chain_name(contract.chain)
    rpc_url = erpc_url_for_chain_id(chain_id) if chain_enabled(chain_id) else None
    if not address or rpc_url is None:
        results = {"status": STATUS_NOT_ROUTABLE, "chain": contract.chain}
        _persist_attempt(session, contract_id=contract.id, chain_id=chain_id, block_number=None, results=results)
        return ProbeResult(contract_id=contract.id, chain_id=chain_id, routable=False, attempts=results)
    assert chain_id is not None  # erpc_url_for_chain_id(None) is None

    try:
        raw_block = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
        block_number = int(raw_block, 16)
        code = rpc_request(rpc_url, "eth_getCode", [address, hex(block_number)], chain_id=chain_id)
    except Exception as exc:
        results = {"status": STATUS_RPC_ERROR, "error": str(exc)[:500]}
        _persist_attempt(session, contract_id=contract.id, chain_id=chain_id, block_number=None, results=results)
        return ProbeResult(contract_id=contract.id, chain_id=chain_id, routable=True, attempts=results)

    code_present = _code_verdict(code)
    if code_present is None:
        results = {"status": STATUS_RPC_ERROR, "error": f"malformed eth_getCode result: {str(code)[:100]!r}"}
        _persist_attempt(session, contract_id=contract.id, chain_id=chain_id, block_number=None, results=results)
        return ProbeResult(contract_id=contract.id, chain_id=chain_id, routable=True, attempts=results)
    code_absent = not code_present
    _record_code_probe(session, chain_id=chain_id, address=address, block_number=block_number, code_absent=code_absent)

    creation_tx: str | None = None
    creation_block: int | None = None
    deployer: str | None = None
    genesis: bool | None = None
    try:
        if code_absent and _creation_absence_stands(
            session, chain_id=chain_id, address=address, block_number=block_number
        ):
            creations = CreationAnswers(records={})
        else:
            creations = fetch_creations(session, [address], chain_id=chain_id)
            if code_absent and address in creations.no_record:
                upsert_creation_witness(
                    session, chain_id=chain_id, address=address, no_creation_record_block=block_number
                )
    except Exception as exc:
        record_degraded(phase="membership_probe_creation_fetch", exc=exc, context={"address": address})
        logger.warning(
            "creation fetch failed",
            extra={"address": address, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        record_degraded(
            phase="probe_creation_fetch",
            exc=exc,
            context={"address": address, "chain_id": chain_id},
        )
        creations = CreationAnswers(records={})
    if address in creations.records:
        record = creations.records[address]
        creation_tx, creation_block, deployer, genesis = record.tx_hash, record.block, record.creator, record.genesis
        if deployer and not contract.deployer:
            contract.deployer = deployer

    reads: dict[str, dict[str, Any]] = {}
    values: dict[str, str | None] = dict.fromkeys(_READS)
    if not code_absent:
        block_tag = hex(block_number)
        try:
            call_results = eth_call_batch(
                rpc_url,
                [{"to": address, "data": OWNER_SELECTOR}, {"to": address, "data": AUTHORITY_SELECTOR}],
                block_tag=block_tag,
                chain_id=chain_id,
            )
        except Exception as exc:
            call_results = None
            for read in ("owner", "authority"):
                reads[read] = {"ok": False, "value": None, "error": str(exc)[:200]}
        if call_results is not None:
            for read, result in zip(("owner", "authority"), call_results):
                value = parse_address_result(result.return_data) if result.success else None
                values[read] = value
                reads[read] = {
                    "ok": result.success,
                    "value": value,
                    "error": result.error_message,
                }
        slot_specs = (
            ("implementation", EIP1967_IMPL_SLOT),
            ("admin", EIP1967_ADMIN_SLOT),
            ("beacon", EIP1967_BEACON_SLOT),
        )
        try:
            slot_results = rpc_batch_request(
                rpc_url,
                [("eth_getStorageAt", [address, slot, block_tag]) for _read, slot in slot_specs],
                chain_id=chain_id,
            )
        except Exception as exc:
            for read, _slot in slot_specs:
                reads[read] = {"ok": False, "value": None, "error": str(exc)[:200]}
        else:
            for (read, _slot), raw in zip(slot_specs, slot_results):
                value = parse_address_result(raw)
                values[read] = value
                reads[read] = {"ok": raw is not None, "value": value, "error": None if raw is not None else "no_result"}

    resolved = tuple(sorted({v for v in values.values() if v}))
    results = {
        "status": STATUS_PROBED,
        "code_present": not code_absent,
        "reads": reads,
        "resolved_addresses": list(resolved),
    }
    _persist_attempt(session, contract_id=contract.id, chain_id=chain_id, block_number=block_number, results=results)
    return ProbeResult(
        contract_id=contract.id,
        chain_id=chain_id,
        routable=True,
        block_number=block_number,
        code_present=not code_absent,
        creation_tx_hash=creation_tx,
        creation_block=creation_block,
        deployer=deployer,
        created_at_genesis=genesis,
        owner=values["owner"],
        authority=values["authority"],
        implementation=values["implementation"],
        admin=values["admin"],
        beacon=values["beacon"],
        resolved_addresses=resolved,
        attempts=results,
    )
