"""Resolve and queue split-proxy secondary implementations.

Static analysis (``services/static/contract_analysis_pipeline/secondary_impl.py``) finds the pointer vars a primary
impl's fallback delegatecalls to. This reads them from the proxy's storage, records the addresses on the proxy row, and
queues each as a proxy-child job (``request.proxy_address``) so its authority resolves against the proxy, like the
EIP-1967 impl. Otherwise the admin impl is analysed against its own empty storage and looks ownerless.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from utils.logging import record_degraded

logger = logging.getLogger(__name__)

_ZERO_ADDR = "0x" + "0" * 40


def _address_from_storage_word(word: str | None, offset: int = 0) -> str | None:
    """A 20-byte address from a storage word at ``offset`` bytes from the low end (Solidity packs from the low end).

    Lowercased, or ``None`` for zero or malformed.
    """
    if not isinstance(word, str):
        return None
    raw = word.lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return None
    raw = raw.rjust(64, "0")
    if len(raw) != 64 or offset < 0:
        return None
    end = 64 - 2 * offset
    start = end - 40
    if start < 0:
        return None
    addr = "0x" + raw[start:end]
    if addr == _ZERO_ADDR or len(addr) != 42:
        return None
    return addr


def _has_code(rpc_request: Any, rpc_url: str, addr: str, block: str, *, chain_id: int | None = None) -> bool:
    """Whether ``addr`` has deployed bytecode; makes over-inclusive pointer detection harmless."""
    try:
        code = rpc_request(rpc_url, "eth_getCode", [addr, block], chain_id=chain_id)
    except Exception as exc:
        record_degraded(phase="secondary_impl_get_code", exc=exc, context={"address": addr, "block": block})
        logger.warning("secondary-impl getCode failed (addr=%s): %s", addr, exc)
        return False
    return isinstance(code, str) and len(code.replace("0x", "")) > 0


def resolve_secondary_impl_addresses(
    rpc_url: str,
    proxy_address: str,
    pointers: list[dict[str, Any]],
    *,
    block: str = "latest",
    implementation: str | None = None,
    require_code: bool = True,
    chain_id: int | None = None,
) -> list[str]:
    """Read each pointer slot on the proxy, returning deduped secondary impl addresses (the getter is usually
    non-public). Drops zero, the proxy itself, its EIP-1967 implementation (would double-list functions), and with
    ``require_code`` any codeless address.
    """
    from services.clients.rpc import rpc_request

    if not rpc_url or not proxy_address or not pointers:
        return []
    proxy_lc = proxy_address.lower()
    impl_lc = (implementation or "").lower()
    out: list[str] = []
    seen: set[str] = set()
    for ptr in pointers:
        slot = ptr.get("slot")
        if slot is None:
            continue
        try:
            slot_hex = hex(int(slot))
        except (TypeError, ValueError):
            continue
        try:
            word = rpc_request(rpc_url, "eth_getStorageAt", [proxy_address, slot_hex, block], chain_id=chain_id)
        except Exception as exc:
            record_degraded(
                phase="secondary_impl_slot_read",
                exc=exc,
                context={"proxy_address": proxy_address, "slot": slot_hex},
            )
            logger.warning("secondary-impl slot read failed (proxy=%s slot=%s): %s", proxy_address, slot_hex, exc)
            continue
        addr = _address_from_storage_word(word, int(ptr.get("offset") or 0))
        if not addr or addr in (proxy_lc, impl_lc) or addr in seen:
            continue
        if require_code and not _has_code(rpc_request, rpc_url, addr, block, chain_id=chain_id):
            continue
        seen.add(addr)
        out.append(addr)
    return out


def queue_secondary_impl_jobs(
    session: Any,
    *,
    proxy_contract: Any,
    secondary_addrs: list[str],
    parent_job: Any,
    rpc_url: str,
    proxy_type: str | None,
    root_job_id: str,
    chain: str | None,
    protocol_id: int | None,
    force: bool,
    base_name: str,
) -> list[Any]:
    """Record ``secondary_addrs`` on the proxy row and queue a proxy-child job per new address, deduped by
    ``(address, root_job_id, chain)`` like ``static_worker._resolve_proxy``. Returns the created jobs.
    """
    from sqlalchemy import text as sa_text

    from db.queue import create_job, reconcile_impl_job_for_proxy
    from utils.chains import chain_enabled

    if not secondary_addrs:
        return []
    # Defence in depth (inv. 14): a disabled chain spawns nothing.
    if not chain_enabled(chain):
        logger.info(
            "Skipping secondary-impl spawn: chain not enabled for this deployment",
            extra={"chain": chain, "reason": "chain_not_enabled", "site": "secondary_impl"},
        )
        return []
    proxy_lc = (proxy_contract.address or "").lower()

    # Recorded so the overview absorbs these into the proxy node.
    merged = [a.lower() for a in (proxy_contract.secondary_implementations or [])]
    for addr in secondary_addrs:
        if addr.lower() not in merged:
            merged.append(addr.lower())
    proxy_contract.secondary_implementations = merged
    session.flush()

    created: list[Any] = []
    for addr in secondary_addrs:
        addr_lc = addr.lower()
        if force:
            # Serializes reconcile-then-insert against concurrent workers.
            lock_seed = f"impl-dedupe:{root_job_id}:{chain or '-'}:{addr_lc}"
            lock_key = int(hashlib.sha1(lock_seed.encode()).hexdigest()[:15], 16)
            session.execute(sa_text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})

        decision = reconcile_impl_job_for_proxy(
            session,
            impl_addr=addr_lc,
            proxy_addr=proxy_lc,
            proxy_type=proxy_type,
            chain=chain,
            root_job_id=root_job_id if force else None,
            discovery_relationship="secondary_implementation",
        )
        if decision in ("skip", "backpatched"):
            logger.info("secondary impl %s -> %s (proxy %s)", addr_lc, decision, proxy_lc)
            continue
        child_request: dict[str, Any] = {
            "address": addr_lc,
            "name": f"{base_name}: (secondary_impl)",
            "rpc_url": rpc_url,
            "parent_job_id": str(parent_job.id),
            "root_job_id": root_job_id,
            # Read state from the proxy, like the EIP-1967 impl.
            "proxy_address": proxy_lc,
            "proxy_type": proxy_type,
            "discovery_relationship": "secondary_implementation",
        }
        if chain is not None:
            child_request["chain"] = chain
        if protocol_id:
            child_request["protocol_id"] = protocol_id
        if force:
            child_request["force"] = True
        created.append(create_job(session, child_request))
    return created
