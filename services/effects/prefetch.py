"""Per-job batch prefetch for the effects ``cache_lookup`` phase.

The ``_plan`` loop was N+1 over candidates (bytecode, proxy contract and upgrade rows, pause claims, principals). Since
the candidate set is known upfront, this bulk-loads those rows once per session; helpers check the store first and fall
back to their single-row query. Cleared at phase end, like ``calldata._FACTS_CACHE``. Doesn't change any verdict.
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
    """Bulk-loaded per-session row caches.

    A present key is authoritative; an absent key means "not prefetched" and the helper falls back to its query.
    """

    chain_id: int
    addresses: set[str] = field(default_factory=set)
    bytecode_by_addr: dict[str, str] = field(default_factory=dict)
    contract_by_id: dict[int, Contract] = field(default_factory=dict)
    # Lets lookups distinguish "no rows for this contract" from "not prefetched".
    contract_ids: set[int] = field(default_factory=set)
    contract_ids_with_upgrade: set[int] = field(default_factory=set)
    principals_by_selector_by_contract: dict[int, dict[str, str]] = field(default_factory=dict)
    # Raw ``effective_functions.claims`` so ``calldata._claim_latch_pairs`` runs its exact parse.
    claims_by_function: dict[int, Any] = field(default_factory=dict)
    function_ids: set[int] = field(default_factory=set)


_STORE: "WeakKeyDictionary[Session, EffectsPrefetch]" = WeakKeyDictionary()


def get_prefetch(session: Session) -> EffectsPrefetch | None:
    return _STORE.get(session)


def clear_prefetch(session: Session) -> None:
    _STORE.pop(session, None)


def install_prefetch(session: Session, chain_id: int, candidates: list[Any]) -> EffectsPrefetch:
    """Bulk-load every row the ``_plan`` loop will read for ``candidates``, one query per table, and register the
    store on ``session`` for the deep helpers.
    """
    addresses = {(c.contract_address or "").lower() for c in candidates if c.contract_address}
    contract_ids = {c.contract_id for c in candidates if isinstance(getattr(c, "contract_id", None), int)}
    function_ids = {c.function_id for c in candidates if isinstance(getattr(c, "function_id", None), int)}

    pf = EffectsPrefetch(chain_id=chain_id, addresses=set(addresses))

    # Contracts first: a proxy with function rows is hashed on its implementation's bytecode
    # (``orchestrator._hashable_code_address``), known only from the row. The parity test's query budget catches
    # regressions.
    if contract_ids:
        pf.contract_ids = set(contract_ids)
        for contract in session.execute(select(Contract).where(Contract.id.in_(contract_ids))).scalars().all():
            pf.contract_by_id[contract.id] = contract
            implementation = (contract.implementation or "").strip().lower()
            if contract.is_proxy and implementation.startswith("0x"):
                addresses.add(implementation)
                pf.addresses.add(implementation)

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
        for (cid,) in session.execute(
            select(UpgradeEvent.contract_id).where(UpgradeEvent.contract_id.in_(contract_ids)).distinct()
        ).all():
            pf.contract_ids_with_upgrade.add(cid)
        # Ordered (function id, address) to match ``_principals_by_selector``'s first-wins ``setdefault``.
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
