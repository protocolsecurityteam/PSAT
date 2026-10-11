"""Multi-chain resolution for discovered contracts with ``chains=["unknown"]``.

Probes ``eth_getCode`` via JSON-RPC batches through eRPC (one route per chain), so all chains run in parallel.

1. Probe unknown addresses on the known chains.
2. Probe the remaining supported chains for addresses with no match.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from services.clients.rpc import erpc_url_for_chain_id
from utils.chains import canonical_chain, canonical_chain_list, chain_enabled
from utils.logging import record_degraded

from .inventory_domain import CHAIN_IDS, RateLimiter, _debug_log
from .static_dependencies import has_deployed_code

logger = logging.getLogger(__name__)

_BATCH_RPC_SIZE = 100

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
_RPC_RATE_LIMIT = int(os.getenv("RPC_RATE_LIMIT", "15"))
_FALLBACK_WORKERS = 4


@dataclass
class _ErrorFills:
    """``"0x"`` results written because a read failed, not because there's no code.

    Only a count and the last exception are kept, to avoid pinning tracebacks.
    """

    count: int = 0
    last_exc: BaseException | None = None
    exc_types: set[str] = field(default_factory=set)
    # The fallback fans out across threads; ``count += 1`` needs the lock or it undercounts during outages.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, exc: BaseException | None) -> None:
        with self._lock:
            self.count += 1
            if exc is not None:
                self.last_exc = exc
                self.exc_types.add(type(exc).__name__)


# The in-flight probe's sink, as a ContextVar so read helpers keep their signatures; ``None`` outside a probe.
_probe_error_fills: contextvars.ContextVar[_ErrorFills | None] = contextvars.ContextVar(
    "psat_chain_probe_error_fills", default=None
)


def _record_error_fill(exc: BaseException | None) -> None:
    sink = _probe_error_fills.get()
    if sink is not None:
        sink.record(exc)


def _erpc_url_for_chain(chain_name: str) -> str | None:
    """eRPC route for a chain name, or None when unmapped, not in ``PSAT_SUPPORTED_CHAIN_IDS``, or ``ERPC_BASE_URL``
    is unset (other chains 404).
    """
    chain_id = CHAIN_IDS.get(chain_name)
    if not chain_id or not chain_enabled(chain_id):
        return None
    return erpc_url_for_chain_id(chain_id)


def _individual_get_code(rpc_url: str, addr: str, limiter: RateLimiter, chain_id: int | None) -> tuple[str, str]:
    from .static_dependencies import get_code

    limiter.wait()
    try:
        return addr, get_code(rpc_url, addr, chain_id=chain_id)
    except RuntimeError as exc:
        _record_error_fill(exc)
        return addr, "0x"


def _batch_get_code(rpc_url: str, addresses: list[str], *, chain_id: int | None = None) -> dict[str, str]:
    """Batch ``eth_getCode`` for many addresses, returning ``{address: bytecode_hex}``.

    Sub-batches of ``_BATCH_RPC_SIZE``; falls back to rate-limited individual calls if batching is rejected.
    """
    if not addresses:
        return {}

    from services.clients.rpc import get_code_batch

    results: dict[str, str] = {}
    for i in range(0, len(addresses), _BATCH_RPC_SIZE):
        batch = addresses[i : i + _BATCH_RPC_SIZE]
        try:
            codes = get_code_batch(rpc_url, batch, chain_id=chain_id)
        except RuntimeError:
            codes = {}
        if not codes:
            limiter = RateLimiter(_RPC_RATE_LIMIT)
            with ThreadPoolExecutor(max_workers=_FALLBACK_WORKERS) as executor:
                # Copy context per submission so trace ids survive.
                futures = []
                for addr in batch:
                    ctx = contextvars.copy_context()
                    futures.append(executor.submit(ctx.run, _individual_get_code, rpc_url, addr, limiter, chain_id))
                for future in futures:
                    addr, code = future.result()
                    results[addr] = code
            continue

        for addr in batch:
            if addr.lower() not in codes:
                _record_error_fill(None)
            results[addr] = codes.get(addr.lower(), "0x")

    return results


def _probe_chain_batch(
    addresses: list[str],
    chain_name: str,
    debug: bool = False,
) -> set[str]:
    rpc_url = _erpc_url_for_chain(chain_name)
    if not rpc_url:
        _debug_log(debug, f"  {chain_name}: no eRPC route configured, skipping")
        return set()

    error_fills = _ErrorFills()
    token = _probe_error_fills.set(error_fills)
    try:
        code_map = _batch_get_code(rpc_url, addresses, chain_id=CHAIN_IDS.get(chain_name))
        hits = {addr for addr, code in code_map.items() if has_deployed_code(code)}
    except Exception as exc:
        # An empty result looks like "no code anywhere", so log it. ``probe_chain`` because ``chain`` would collide with
        # a bound context field.
        record_degraded(
            phase="chain_probe",
            exc=exc,
            context={"probe_chain": chain_name, "addresses": len(addresses)},
        )
        logger.warning(
            "Chain probe failed for %s (%d address(es)); chain contributes no membership evidence",
            chain_name,
            len(addresses),
            extra={"probe_chain": chain_name, "exc_type": type(exc).__name__, "addresses": len(addresses)},
        )
        _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
        return set()
    finally:
        _probe_error_fills.reset(token)

    if error_fills.count:
        # ``_batch_get_code`` turns transport errors into ``"0x"``, so this count is the only sign a chain-wide empty
        # result was a failure.
        last_exc = error_fills.last_exc
        if last_exc is not None:
            record_degraded(
                phase="chain_probe",
                exc=last_exc,
                context={"probe_chain": chain_name, "probe_failed": error_fills.count, "addresses": len(addresses)},
            )
        logger.warning(
            "Chain probe could not read %d of %d address(es) on %s; those read as no-code",
            error_fills.count,
            len(addresses),
            chain_name,
            extra={
                "probe_chain": chain_name,
                "probe_failed": error_fills.count,
                "addresses": len(addresses),
                "exc_type": type(last_exc).__name__ if last_exc is not None else None,
                "exc_types": sorted(error_fills.exc_types),
            },
        )

    return hits


def _probe_chains(
    addresses: list[str],
    chains: list[str],
    matched: dict[str, list[str]],
    debug: bool = False,
) -> None:
    with ThreadPoolExecutor(max_workers=min(len(chains), 10)) as executor:
        future_to_chain = {}
        for chain_name in chains:
            ctx = contextvars.copy_context()
            future_to_chain[executor.submit(ctx.run, _probe_chain_batch, addresses, chain_name, debug)] = chain_name
        for future in as_completed(future_to_chain):
            chain_name = future_to_chain[future]
            try:
                hits = future.result()
                for addr in hits:
                    matched[addr].append(chain_name)
                _debug_log(debug, f"  {chain_name}: {len(hits)} hit(s)")
            except Exception as exc:
                record_degraded(
                    phase="chain_probe",
                    exc=exc,
                    context={"probe_chain": chain_name},
                )
                logger.warning(
                    "Chain probe raised for %s; chain contributes no membership evidence",
                    chain_name,
                    extra={"probe_chain": chain_name, "exc_type": type(exc).__name__},
                )
                _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")


def _primary_chain(contract: dict[str, Any]) -> str:
    chains = contract.get("chains", [])
    return (canonical_chain(chains[0]) if chains else None) or "unknown"


def _within_run_evidence_chains(contracts: list[dict[str, Any]]) -> list[str]:
    """Registry chains that evidence-bearing entries in this inventory declare (declared evidence)."""
    chains: list[str] = []
    seen: set[str] = set()
    for c in contracts:
        for ch in canonical_chain_list(c.get("chains", [])) or []:
            if ch not in seen and ch != "unknown" and ch in CHAIN_IDS:
                chains.append(ch)
                seen.add(ch)
    return chains


def resolve_unknown_chains(
    contracts: list[dict[str, Any]],
    declared_chains: list[str] | None = None,
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Resolve ``chains=["unknown"]`` entries by probing ``eth_getCode``; mutates and returns the list.

    ``declared_chains`` enforces declared-chain membership (probing may confirm it, never originate it):

    * ``None`` (standalone callers): the legacy all-chain probe, writing every hit to ``chains``.
    * a list (the pipeline): probe only declared chains (``Protocol.chains``, the requested chain, and within-run
    evidence); hits there go to ``chains``. With no declared evidence, chains stay ``["unknown"]`` and hits are only
    recorded as ``chain_candidates``.
    """
    if not contracts:
        return contracts

    unknowns = [c for c in contracts if _primary_chain(c) == "unknown"]
    if not unknowns:
        _debug_log(debug, "Chain resolution: no unknown-chain contracts to resolve")
        return contracts

    within_run = _within_run_evidence_chains(contracts)

    matched: dict[str, list[str]] = {c["address"]: [] for c in unknowns}
    all_addrs = list(matched.keys())

    if declared_chains is None:
        known_chains = within_run or list(CHAIN_IDS.keys())
        seen = set(known_chains)
        remaining_chains = [ch for ch in CHAIN_IDS if ch not in seen]

        _debug_log(
            debug,
            f"Chain resolution: {len(unknowns)} unknown contract(s), "
            f"probing {len(known_chains)} known chain(s): {known_chains}",
        )

        _probe_chains(all_addrs, known_chains, matched, debug)

        unresolved = [addr for addr, chains in matched.items() if not chains]
        if unresolved and remaining_chains:
            _debug_log(debug, f"Probing {len(remaining_chains)} remaining chain(s) for {len(unresolved)} address(es)")
            _probe_chains(unresolved, remaining_chains, matched, debug)

        resolved_count = 0
        for contract in unknowns:
            chains = matched.get(contract["address"], [])
            if chains:
                contract["chains"] = canonical_chain_list(chains)
                resolved_count += 1
                _debug_log(debug, f"  {contract['address']}: resolved to {chains}")

        _debug_log(debug, f"Chain resolution: resolved {resolved_count}/{len(unknowns)} contract(s)")
        return contracts

    declared_set: list[str] = list(within_run)
    declared_seen: set[str] = set(within_run)
    for ch in canonical_chain_list(declared_chains) or []:
        if ch != "unknown" and ch in CHAIN_IDS and ch not in declared_seen:
            declared_set.append(ch)
            declared_seen.add(ch)

    if declared_set:
        _debug_log(
            debug,
            f"Chain resolution (narrowed): {len(unknowns)} unknown contract(s), "
            f"probing {len(declared_set)} declared chain(s): {declared_set}",
        )
        _probe_chains(all_addrs, declared_set, matched, debug)
        resolved_count = 0
        for contract in unknowns:
            chains = matched.get(contract["address"], [])
            if chains:
                contract["chains"] = canonical_chain_list(chains)
                resolved_count += 1
                _debug_log(debug, f"  {contract['address']}: resolved to {chains}")
        _debug_log(debug, f"Chain resolution (narrowed): resolved {resolved_count}/{len(unknowns)} contract(s)")
        return contracts

    # No declared evidence: presence alone never originates membership.
    _debug_log(
        debug,
        f"Chain resolution (candidates): {len(unknowns)} unknown contract(s) with no declared "
        "evidence; probing every registry chain for candidates only",
    )
    _probe_chains(all_addrs, list(CHAIN_IDS.keys()), matched, debug)
    candidate_count = 0
    for contract in unknowns:
        chains = matched.get(contract["address"], [])
        if chains:
            contract["chain_candidates"] = canonical_chain_list(chains)
            candidate_count += 1
            _debug_log(debug, f"  {contract['address']}: candidate chain(s) {chains} (not written)")
    _debug_log(debug, f"Chain resolution (candidates): recorded {candidate_count}/{len(unknowns)} candidate(s)")
    return contracts


def validate_claimed_chains(
    contracts: list[dict[str, Any]],
    *,
    source_names: tuple[str, ...] = ("exa_deep_research",),
    debug: bool = False,
) -> list[dict[str, Any]]:
    """Verify high-risk AI-claimed chains with ``eth_getCode``; if absent, probe other chains and correct or mark
    unknown.
    """
    targets: list[tuple[dict[str, Any], str, list[str]]] = []
    for contract in contracts:
        sources = set(contract.get("source") or [])
        if sources.isdisjoint(source_names):
            continue
        address = str(contract.get("address") or "").lower()
        chains = canonical_chain_list(contract.get("chains")) or []
        claimed = [chain for chain in chains if chain and chain != "unknown" and chain in CHAIN_IDS]
        if address and claimed:
            targets.append((contract, address, claimed))

    if not targets:
        return contracts

    for contract, address, claimed in targets:
        matched: dict[str, list[str]] = {address: []}
        _probe_chains([address], claimed, matched, debug)
        if matched[address]:
            contract["chains"] = canonical_chain_list(matched[address])
            continue

        remaining = [chain for chain in CHAIN_IDS if chain not in set(claimed)]
        if remaining:
            _probe_chains([address], remaining, matched, debug)
        if matched[address]:
            corrected = canonical_chain_list(matched[address]) or ["unknown"]
            contract["chains"] = corrected
            _debug_log(debug, f"  {address}: corrected claimed chain {claimed} -> {corrected}")
        else:
            contract["chains"] = ["unknown"]
            contract["chain_sanity"] = {
                "status": "unresolved_no_code_on_claimed_or_supported_chains",
                "claimed_chains": claimed,
            }
            _debug_log(debug, f"  {address}: no code on claimed chain(s) {claimed}; marked unknown")

    return contracts
