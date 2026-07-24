"""Per-job batch prefetch for the effects ``cache_lookup`` phase.

The worker's ``_plan`` loop is an N+1: for each of a job's candidates it issues
several single-row DB round-trips (runtime bytecode, the proxy ``Contract`` +
``UpgradeEvent`` existence, and — on the pause path — the function's persisted
pause claim and the contract's principal-by-selector map). On a cold Neon link
those serial round-trips dominated the stage's ``cache_lookup`` wall.

Because the whole candidate set is known before the loop starts, this module
bulk-loads every ``(chain,address)`` / contract-id / function-id keyed row ONCE
into per-session dicts. The individual DB-fetch helpers consult the installed
store first and fall back to their original single-row query when a key was not
prefetched (belt-and-braces: a candidate injected mid-flight, or a caller that
never installed a store, still resolves — byte-identically — the slow way).

The store is keyed on the ``Session`` and cleared when the phase ends, mirroring
``calldata._FACTS_CACHE``. Nothing here changes *what* a verdict is — only how
the rows behind it are fetched (inv.: witness impact zero).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from weakref import WeakKeyDictionary

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    BytecodeCache,
    Contract,
    EffectiveFunction,
    FunctionPrincipal,
    UpgradeEvent,
)


@dataclass
class EffectsPrefetch:
    """Bulk-loaded, per-session row caches for one job's candidate set.

    A key PRESENT in a map is authoritative (it was loaded for exactly the
    candidate set); a key ABSENT means "not prefetched" and the helper falls
    back to its single-row query. So each map distinguishes "loaded, value X"
    from "not loaded" — genuine absences in the DB are stored explicitly (an
    address with no bytecode is simply not a key, and the fallback query then
    returns ``None`` identically)."""

    chain_id: int
    addresses: set[str] = field(default_factory=set)
    bytecode_by_addr: dict[str, str] = field(default_factory=dict)
    contract_by_id: dict[int, Contract] = field(default_factory=dict)
    # contract_ids known (from the same bulk pass) — lets a ``.get`` on the two
    # maps below distinguish "no rows for this contract" from "not prefetched".
    contract_ids: set[int] = field(default_factory=set)
    contract_ids_with_upgrade: set[int] = field(default_factory=set)
    principals_by_selector_by_contract: dict[int, dict[str, str]] = field(default_factory=dict)
    # function_id -> raw ``effective_functions.claims`` value (list / JSON null /
    # None). Stored raw so ``calldata._claim_latch_pairs`` runs its EXACT parse.
    claims_by_function: dict[int, Any] = field(default_factory=dict)
    function_ids: set[int] = field(default_factory=set)


_STORE: "WeakKeyDictionary[Session, EffectsPrefetch]" = WeakKeyDictionary()


def get_prefetch(session: Session) -> EffectsPrefetch | None:
    """The store installed for this session's current effects job, or ``None``."""
    return _STORE.get(session)


def clear_prefetch(session: Session) -> None:
    """Drop the store at the end of the ``cache_lookup`` phase."""
    _STORE.pop(session, None)


def install_prefetch(session: Session, chain_id: int, candidates: list[Any]) -> EffectsPrefetch:
    """Bulk-load every keyed row the ``_plan`` loop will read for ``candidates``.

    One query per table instead of one-per-candidate. The returned store is also
    registered on ``session`` so the deep DB-fetch helpers (which do not receive
    the candidate list) can consult it transparently."""
    addresses = {(c.contract_address or "").lower() for c in candidates if c.contract_address}
    contract_ids = {c.contract_id for c in candidates if isinstance(getattr(c, "contract_id", None), int)}
    function_ids = {c.function_id for c in candidates if isinstance(getattr(c, "function_id", None), int)}

    pf = EffectsPrefetch(chain_id=chain_id, addresses=set(addresses))

    if addresses:
        for addr, code in session.execute(
            select(BytecodeCache.address, BytecodeCache.bytecode).where(
                BytecodeCache.chain_id == chain_id,
                BytecodeCache.address.in_(addresses),
            )
        ).all():
            if isinstance(code, str) and code:
                pf.bytecode_by_addr[addr.lower()] = code

    if contract_ids:
        pf.contract_ids = set(contract_ids)
        for contract in session.execute(select(Contract).where(Contract.id.in_(contract_ids))).scalars().all():
            pf.contract_by_id[contract.id] = contract
        for (cid,) in session.execute(
            select(UpgradeEvent.contract_id).where(UpgradeEvent.contract_id.in_(contract_ids)).distinct()
        ).all():
            pf.contract_ids_with_upgrade.add(cid)
        # Principal-by-selector, one grouped query across every candidate contract.
        # Preserves ``_principals_by_selector``'s first-wins ``setdefault`` by
        # ordering deterministically (function id, then address) so the batched
        # map is stable and matches a per-contract read.
        for cid, selector, address in session.execute(
            select(EffectiveFunction.contract_id, EffectiveFunction.selector, FunctionPrincipal.address)
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(EffectiveFunction.contract_id.in_(contract_ids))
            .order_by(EffectiveFunction.id, FunctionPrincipal.address)
        ).all():
            if isinstance(selector, str) and isinstance(address, str):
                pf.principals_by_selector_by_contract.setdefault(cid, {}).setdefault(selector.lower(), address.lower())

    if function_ids:
        pf.function_ids = set(function_ids)
        for fid, claims in session.execute(
            select(EffectiveFunction.id, EffectiveFunction.claims).where(EffectiveFunction.id.in_(function_ids))
        ).all():
            pf.claims_by_function[fid] = claims

    _STORE[session] = pf
    return pf
