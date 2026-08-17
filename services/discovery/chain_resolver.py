"""Multi-chain resolution for discovered contracts.

After the inventory pipeline builds contracts, some entries have
``chains=["unknown"]``.  This module probes ``eth_getCode`` via JSON-RPC
batch requests through the eRPC proxy (one per-chain route) to determine
where each contract is actually deployed.

Routes through eRPC (``ERPC_BASE_URL``) like every other read, so all chains
can be probed **in parallel** (~1-2 seconds for hundreds of addresses across
10+ chains) with no direct-provider dependency.

Strategy
--------
1. **Phase 1** -- probe every unknown address on every known chain in
   parallel using JSON-RPC batch requests.
2. **Phase 2** -- for addresses that matched nothing in phase 1, probe
   the remaining supported chains (also in parallel).
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from utils.chains import canonical_chain, canonical_chain_list
from utils.logging import record_degraded
from utils.rpc import erpc_url_for_chain_id, rpc_headers

from .inventory_domain import CHAIN_IDS, RateLimiter, _debug_log
from .static_dependencies import RPC_TIMEOUT_SECONDS, has_deployed_code

logger = logging.getLogger(__name__)

# Max addresses per JSON-RPC batch request.
_BATCH_RPC_SIZE = 100

# Fallback: rate-limited individual calls if batch is rejected.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
_RPC_RATE_LIMIT = int(os.getenv("RPC_RATE_LIMIT", "15"))
_FALLBACK_WORKERS = 4


@dataclass
class _ErrorFills:
    """Error-fills for one chain probe: a ``"0x"`` written because a read failed
    or went unanswered, not because the address has no code there.

    Only a count and the last exception are kept — a live exception per address
    would pin its traceback frames (and the response bodies in them) for the
    whole pass.
    """

    count: int = 0
    last_exc: BaseException | None = None
    exc_types: set[str] = field(default_factory=set)


# Sink for the probe currently in flight. A ContextVar rather than a parameter
# so the read helpers keep their existing signatures (the fallback fan-out
# copies the context, and the object is shared through the copy). ``None``
# outside a probe makes recording a no-op.
_probe_error_fills: contextvars.ContextVar[_ErrorFills | None] = contextvars.ContextVar(
    "psat_chain_probe_error_fills", default=None
)


def _record_error_fill(exc: BaseException | None) -> None:
    sink = _probe_error_fills.get()
    if sink is None:
        return
    sink.count += 1
    if exc is not None:
        sink.last_exc = exc
        sink.exc_types.add(type(exc).__name__)


def _erpc_url_for_chain(chain_name: str) -> str | None:
    """eRPC route for a chain name, or None when the chain isn't mapped or
    ``ERPC_BASE_URL`` is unset."""
    chain_id = CHAIN_IDS.get(chain_name)
    return erpc_url_for_chain_id(chain_id) if chain_id else None


def _individual_get_code(rpc_url: str, addr: str, limiter: RateLimiter) -> tuple[str, str]:
    """Fetch code for a single address with rate limiting -- returns (addr, bytecode_hex)."""
    from .static_dependencies import get_code

    limiter.wait()
    try:
        return addr, get_code(rpc_url, addr)
    except RuntimeError as exc:
        _record_error_fill(exc)
        return addr, "0x"


def _batch_get_code(rpc_url: str, addresses: list[str]) -> dict[str, str]:
    """Batch-fetch eth_getCode for many addresses in a single HTTP request.

    Returns ``{address: bytecode_hex}`` for each address.  Splits into
    sub-batches of ``_BATCH_RPC_SIZE`` to stay within RPC limits.
    Falls back to rate-limited concurrent individual calls if the RPC
    rejects batching.
    """
    if not addresses:
        return {}

    results: dict[str, str] = {}
    for i in range(0, len(addresses), _BATCH_RPC_SIZE):
        batch = addresses[i : i + _BATCH_RPC_SIZE]
        payload = json.dumps(
            [
                {"jsonrpc": "2.0", "id": idx, "method": "eth_getCode", "params": [addr, "latest"]}
                for idx, addr in enumerate(batch)
            ]
        ).encode("utf-8")
        request = urllib.request.Request(
            rpc_url,
            data=payload,
            headers=rpc_headers(
                rpc_url,
                {"Accept": "application/json", "User-Agent": "getContractAddresses/1.0"},
            ),
        )
        try:
            with urllib.request.urlopen(request, timeout=max(RPC_TIMEOUT_SECONDS, 30)) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            body = None

        # A successful batch returns a JSON list.  If we got a dict instead
        # (e.g. RPC error like "too many calls in batch") or an HTTP error,
        # fall back to rate-limited concurrent individual calls.
        if not isinstance(body, list):
            limiter = RateLimiter(_RPC_RATE_LIMIT)
            with ThreadPoolExecutor(max_workers=_FALLBACK_WORKERS) as executor:
                # Per-submission context copy so trace_id/job_id contextvars
                # bound by the calling worker survive into the fallback fan-out.
                futures = []
                for addr in batch:
                    ctx = contextvars.copy_context()
                    futures.append(executor.submit(ctx.run, _individual_get_code, rpc_url, addr, limiter))
                for future in futures:
                    addr, code = future.result()
                    results[addr] = code
            continue

        for item in body:
            idx = item.get("id")
            if idx is not None and 0 <= idx < len(batch):
                # A per-item JSON-RPC error still lands as "0x" below, and the
                # address IS in ``results`` so the fill loop never sees it.
                if item.get("error") is not None or "result" not in item:
                    _record_error_fill(None)
                code = item.get("result") or "0x"
                results[batch[idx]] = code if isinstance(code, str) and code.startswith("0x") else "0x"
        # Fill in any missing addresses (e.g. from errors in individual items).
        # No exception to attach — the RPC answered, just not about this address.
        for addr in batch:
            if addr not in results:
                _record_error_fill(None)
                results[addr] = "0x"

    return results


def _probe_chain_batch(
    addresses: list[str],
    chain_name: str,
    debug: bool = False,
) -> set[str]:
    """Probe all *addresses* on a single chain via the eRPC JSON-RPC batch route."""
    rpc_url = _erpc_url_for_chain(chain_name)
    if not rpc_url:
        _debug_log(debug, f"  {chain_name}: no eRPC route configured, skipping")
        return set()

    error_fills = _ErrorFills()
    token = _probe_error_fills.set(error_fills)
    try:
        code_map = _batch_get_code(rpc_url, addresses)
        hits = {addr for addr, code in code_map.items() if has_deployed_code(code)}
    except Exception as exc:
        # The empty set is indistinguishable from "no address has code here", so
        # the log line is the only place the difference survives: without it a
        # chain-wide probe outage silently shrinks multichain membership.
        record_degraded(
            phase="chain_probe",
            exc=exc,
            context={"chain": chain_name, "addresses": len(addresses)},
        )
        logger.warning(
            "Chain probe failed for %s (%d address(es)); chain contributes no membership evidence",
            chain_name,
            len(addresses),
            extra={"chain": chain_name, "exc_type": type(exc).__name__, "addresses": len(addresses)},
        )
        _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")
        return set()
    finally:
        _probe_error_fills.reset(token)

    if error_fills.count:
        # ``_batch_get_code`` swallows transport errors internally and answers
        # "0x", so a chain-wide outage returns *successfully* with every address
        # reading as no-code. This count is the only signal that the empty
        # membership was a read failure rather than an answer.
        last_exc = error_fills.last_exc
        if last_exc is not None:
            record_degraded(
                phase="chain_probe",
                exc=last_exc,
                context={"chain": chain_name, "probe_failed": error_fills.count, "addresses": len(addresses)},
            )
        logger.warning(
            "Chain probe could not read %d of %d address(es) on %s; those read as no-code",
            error_fills.count,
            len(addresses),
            chain_name,
            extra={
                "chain": chain_name,
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
    """Probe multiple chains in parallel using eRPC batch routes."""
    with ThreadPoolExecutor(max_workers=min(len(chains), 10)) as executor:
        # Per-chain context copy preserves the caller's trace context inside
        # each per-chain batch RPC call.
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
                    context={"chain": chain_name},
                )
                logger.warning(
                    "Chain probe raised for %s; chain contributes no membership evidence",
                    chain_name,
                    extra={"chain": chain_name, "exc_type": type(exc).__name__},
                )
                _debug_log(debug, f"  {chain_name}: probe failed: {exc!r}")


def _primary_chain(contract: dict[str, Any]) -> str:
    """Return the first chain from a contract's chains list, or 'unknown'."""
    chains = contract.get("chains", [])
    return (canonical_chain(chains[0]) if chains else None) or "unknown"


def _within_run_evidence_chains(contracts: list[dict[str, Any]]) -> list[str]:
    """Registry chains any evidence-bearing entry in this inventory declares.

    These are chain-scoped crawler / deployer-expansion results (invariant 3
    evidence): a chain another contract in the same run is already placed on.
    """
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
    """Resolve ``chains=["unknown"]`` entries by probing ``eth_getCode`` across chains.

    Mutates the contract dicts in-place and returns the same list.

    ``declared_chains`` gates the two behaviours (invariant 3 — "probing may
    CONFIRM membership, never ORIGINATE it"):

    * ``None`` (default, standalone callers): the legacy all-chain probe —
      within-run evidence first, then every remaining registry chain — writing
      every hit onto ``chains``. Kept for backward compatibility.
    * a list (the discovery pipeline always passes one, possibly empty): the
      **narrowed** probe. The declared set is the caller's declared chains
      (``Protocol.chains`` + the requested chain) unioned with within-run
      evidence. A hit on a declared chain is corroborated → written to
      ``chains``. When there is no declared evidence at all, no hit can
      originate membership: chains stay ``["unknown"]`` and hits are recorded
      as ``chain_candidates`` — surfaced in the discovery artifact, never
      written to ``chains`` and so never a ``contracts`` row or job.
    """
    if not contracts:
        return contracts

    unknowns = [c for c in contracts if _primary_chain(c) == "unknown"]
    if not unknowns:
        _debug_log(debug, "Chain resolution: no unknown-chain contracts to resolve")
        return contracts

    within_run = _within_run_evidence_chains(contracts)

    # address -> list of chains where it has code
    matched: dict[str, list[str]] = {c["address"]: [] for c in unknowns}
    all_addrs = list(matched.keys())

    if declared_chains is None:
        # Legacy all-chain probe (backward compatibility for standalone callers).
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

    # Narrowed probe (invariant 3). Declared set = caller-declared chains ∪
    # within-run evidence, restricted to the registry.
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

    # No declared evidence: presence alone can never originate membership.
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
    """Verify high-risk AI-supplied chain claims with ``eth_getCode``.

    If a claimed chain has no code, probe the remaining supported chains and
    either correct to the detected chain(s) or mark it unknown.
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
