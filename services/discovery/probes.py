"""Bounded read-only corroboration probes (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.5).

One probe = eth_getCode + Etherscan ``getcontractcreation`` + owner() /
authority() + the EIP-1967 implementation/admin/beacon slots, all pinned at
one just-read block. Probes may run on ANY eRPC-routable chain regardless of
``PSAT_SUPPORTED_CHAIN_IDS`` (invariant 10). Every outcome — including a read
that resolved nowhere — is persisted so a parked candidate is explainable
(invariant 5). Nothing here commits; the caller does.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from db.models import Contract, ContractCreationWitness, ContractProbeAttempt
from services.clients import etherscan
from services.clients.rpc import (
    chain_id_for_chain_name,
    erpc_url_for_chain_id,
    eth_call_batch,
    parse_address_result,
    rpc_batch_request,
    rpc_request,
    selector,
)
from utils.evm import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    OWNER_SELECTOR,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

AUTHORITY_SELECTOR = selector("authority()")

# Etherscan getcontractcreation accepts at most 5 addresses per call.
_CREATION_BATCH = 5

#: ``contract_probe_attempts.chain_id`` sentinel for a row whose chain name
#: does not resolve to a registry chain id (e.g. the ``unknown`` bucket).
#: 0 is no EVM chain; ``results.status`` carries the raw chain string.
UNRESOLVABLE_CHAIN_ID = 0

STATUS_PROBED = "probed"
STATUS_NOT_ROUTABLE = "not_routable"
STATUS_RPC_ERROR = "rpc_error"

# The five §3.5 resolution reads, in persisted order.
_READS = ("owner", "authority", "implementation", "admin", "beacon")


@dataclass(frozen=True)
class ProbeResult:
    """One probe's outcome. ``None`` on any field means that read did not
    determine a value — never that the value is absent; ``attempts`` records
    which of the two it was, per read."""

    contract_id: int
    chain_id: int | None
    routable: bool
    block_number: int | None = None
    code_present: bool | None = None
    creation_tx_hash: str | None = None
    creation_block: int | None = None
    deployer: str | None = None
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
    key_chain = UNRESOLVABLE_CHAIN_ID if chain_id is None else chain_id
    row = session.get(ContractProbeAttempt, (contract_id, key_chain))
    if row is None:
        row = ContractProbeAttempt(contract_id=contract_id, chain_id=key_chain, results=results)
        session.add(row)
    else:
        row.results = results
    row.block_number = block_number
    session.flush()


def fetch_creations(
    session: Session,
    addresses: Sequence[str],
    *,
    chain_id: int,
) -> dict[str, tuple[str | None, int | None, str | None]]:
    """Etherscan ``getcontractcreation`` for *addresses* (chunked 5/call),
    persisting ``creation_tx_hash``/``creation_block`` into
    ``contract_creation_witnesses``. Returns ``{address: (tx, block, creator)}``
    for the addresses the indexer answered; a missing key means no answer,
    never "no creation"."""
    wanted = sorted({a.lower() for a in addresses})
    out: dict[str, tuple[str | None, int | None, str | None]] = {}
    for start in range(0, len(wanted), _CREATION_BATCH):
        batch = wanted[start : start + _CREATION_BATCH]
        try:
            data = etherscan.get(
                "contract",
                "getcontractcreation",
                chain_id=chain_id,
                contractaddresses=",".join(batch),
            )
        except Exception as exc:
            logger.debug("getcontractcreation failed for %s: %s", batch, exc)
            continue
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list):
            continue
        for item in result:
            if not isinstance(item, dict):
                continue
            addr = item.get("contractAddress")
            tx = item.get("txHash")
            if not isinstance(addr, str) or not isinstance(tx, str):
                continue
            creator = item.get("contractCreator")
            out[addr.lower()] = (
                tx.lower(),
                _coerce_block(item.get("blockNumber")),
                creator.lower() if isinstance(creator, str) else None,
            )
    for addr, (tx, block, _creator) in out.items():
        row = session.get(ContractCreationWitness, (chain_id, addr))
        if row is None:
            row = ContractCreationWitness(chain_id=chain_id, address=addr)
            session.add(row)
        row.creation_tx_hash = tx
        row.creation_block = block
    if out:
        session.flush()
    return out


def _coerce_block(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            return int(raw, 16) if raw.startswith("0x") else int(raw)
        except ValueError:
            return None
    return None


def _record_code_probe(session: Session, *, chain_id: int, address: str, block_number: int, code_absent: bool) -> None:
    row = session.get(ContractCreationWitness, (chain_id, address))
    if row is None:
        row = ContractCreationWitness(chain_id=chain_id, address=address)
        session.add(row)
    row.code_probe_block = block_number
    row.code_absent_at_probe = code_absent
    session.flush()


def run_probe(session: Session, contract: Contract) -> ProbeResult:
    """Probe *contract* on its own (address, chain) and persist every outcome:
    code presence into ``contract_creation_witnesses``, resolution reads into
    ``contract_probe_attempts``."""
    address = (contract.address or "").lower()
    chain_id = chain_id_for_chain_name(contract.chain)
    rpc_url = erpc_url_for_chain_id(chain_id)
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

    code_absent = not isinstance(code, str) or code in ("0x", "0x0", "")
    _record_code_probe(session, chain_id=chain_id, address=address, block_number=block_number, code_absent=code_absent)

    creation_tx: str | None = None
    creation_block: int | None = None
    deployer: str | None = None
    try:
        creations = fetch_creations(session, [address], chain_id=chain_id)
    except Exception as exc:
        logger.debug("creation fetch failed for %s: %s", address, exc)
        creations = {}
    if address in creations:
        creation_tx, creation_block, deployer = creations[address]
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
        owner=values["owner"],
        authority=values["authority"],
        implementation=values["implementation"],
        admin=values["admin"],
        beacon=values["beacon"],
        resolved_addresses=resolved,
        attempts=results,
    )
