"""Resolve + queue split-proxy *secondary implementations*.

Static analysis (``services/static/contract_analysis_pipeline/secondary_impl.py``)
detects the *pointer* state vars a primary impl's fallback delegatecalls to. This
module reads those pointers against the **proxy's** storage to get the actual
secondary impl addresses, records them on the proxy's ``Contract`` row, and
queues each as a proxy-child analysis job (``request.proxy_address`` = the proxy)
so its authority resolves against the proxy's storage — exactly like the EIP-1967
impl. Without this the admin impl is analysed standalone against its own empty
storage and renders as an ownerless orphan.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

_ZERO_ADDR = "0x" + "0" * 40


def _address_from_storage_word(word: str | None, offset: int = 0) -> str | None:
    """Extract a 20-byte address from a 32-byte storage word.

    ``offset`` is the byte offset from the least-significant byte (Solidity packs
    from the low end), so a packed pointer at ``slot=1 offset=8`` still decodes.
    Returns a lowercased ``0x`` address, or ``None`` for the zero address / a
    malformed word.
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


def resolve_secondary_impl_addresses(
    rpc_url: str,
    proxy_address: str,
    pointers: list[dict[str, Any]],
    *,
    block: str = "latest",
) -> list[str]:
    """Read each pointer's slot against the proxy → deduped secondary impl addrs.

    The pointer's auto-getter is typically non-public (it reverts), so the value
    is read directly from the proxy's storage slot. Zero/self/duplicate values
    are dropped.
    """
    from utils.rpc import rpc_request

    if not rpc_url or not proxy_address or not pointers:
        return []
    proxy_lc = proxy_address.lower()
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
            word = rpc_request(rpc_url, "eth_getStorageAt", [proxy_address, slot_hex, block])
        except Exception as exc:
            logger.warning("secondary-impl slot read failed (proxy=%s slot=%s): %s", proxy_address, slot_hex, exc)
            continue
        addr = _address_from_storage_word(word, int(ptr.get("offset") or 0))
        if addr and addr != proxy_lc and addr not in seen:
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
    """Record ``secondary_addrs`` on the proxy row + queue a proxy-child job per
    new address. Deduped by ``(address, root_job_id, chain)`` like the primary
    impl spawn (``static_worker._resolve_proxy``). Returns the created jobs.
    """
    from sqlalchemy import select
    from sqlalchemy import text as sa_text

    from db.models import Job
    from db.queue import create_job

    if not secondary_addrs:
        return []
    proxy_lc = (proxy_contract.address or "").lower()

    # Record on the proxy row so the company-overview aggregation absorbs these
    # logic contracts into the proxy node (rather than rendering them standalone).
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
            # Advisory xact lock serialises the SELECT-then-INSERT against
            # concurrent static workers in the same cascade.
            lock_seed = f"impl-dedupe:{root_job_id}:{chain or '-'}:{addr_lc}"
            lock_key = int(hashlib.sha1(lock_seed.encode()).hexdigest()[:15], 16)
            session.execute(sa_text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})
            stmt = select(Job).where(
                Job.address == addr_lc,
                Job.request["root_job_id"].as_string() == root_job_id,
            )
            if chain is not None:
                stmt = stmt.where(Job.request["chain"].as_string() == chain)
            existing = session.execute(stmt.limit(1)).scalar_one_or_none()
        else:
            existing = session.execute(select(Job).where(Job.address == addr_lc).limit(1)).scalar_one_or_none()
        if existing is not None:
            logger.info("secondary impl %s already has job %s in this cascade, skipping", addr_lc, existing.id)
            continue
        child_request: dict[str, Any] = {
            "address": addr_lc,
            "name": f"{base_name}: (secondary_impl)",
            "rpc_url": rpc_url,
            "parent_job_id": str(parent_job.id),
            "root_job_id": root_job_id,
            # Read state (incl. authority) from the PROXY, not the secondary's
            # own empty storage — same mechanism the EIP-1967 impl uses.
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
