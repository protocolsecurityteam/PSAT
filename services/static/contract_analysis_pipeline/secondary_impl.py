"""Detect split-proxy *secondary-implementation* pointers.

A "secondary implementation" is a logic contract a proxy reaches **beyond** its
EIP-1967 slot impl: the primary impl's ``fallback``/``receive`` delegatecalls to
an address held in an ordinary state variable (e.g. ether.fi LRTSquared's
``adminImpl``, set via ``setAdminImpl``). PSAT otherwise models only the single
1967 impl, so the secondary is analysed standalone against its own empty storage
and rendered as an ownerless orphan, stranding its (admin) functions.

This module finds the *pointer descriptors* — ``{name, slot, offset}`` — for
each address state var a fallback/receive delegatecalls to. The VALUE (the
secondary impl address) is read from the **proxy's** storage downstream
(``services/discovery/secondary_impl.py``), because the pointer's auto-getter is
typically non-public and reverts. Slot/offset come from Slither's storage
layout, so a packed slot resolves correctly.
"""

from __future__ import annotations

import logging
from typing import Any

from schemas.contract_analysis import SecondaryImplPointer

logger = logging.getLogger(__name__)

_ADDRESS_TYPES = {"address", "address payable"}


def _has_writer(contract: Any, var: Any) -> bool:
    """A non-constructor function writes ``var`` — the ``set*Impl`` half of the
    split-proxy shape. Guards against misfiring on a generic immutable-target
    forwarder."""
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        try:
            if var in fn.all_state_variables_written():
                return True
        except Exception:  # pragma: no cover - slither edge
            continue
    return False


def _fallback_delegatecall_target_vars(contract: Any) -> list[Any]:
    """Address-typed state vars a fallback/receive reads while delegatecalling.

    Conservative: the function must be a fallback/receive, contain a
    delegatecall, read the address var, and the var must have a writer. That is
    exactly the split-proxy dispatch shape; a plain EIP-1967 proxy reads its
    impl from an assembly ``sload`` of a constant slot (no named state var) and
    so yields nothing here.
    """
    out: list[Any] = []
    seen: set[str] = set()
    for fn in getattr(contract, "functions", []) or []:
        if not (getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False)):
            continue
        has_dc = any(
            "delegatecall" in str(ir).lower()
            for node in getattr(fn, "nodes", []) or []
            for ir in getattr(node, "irs", []) or []
        )
        if not has_dc:
            continue
        try:
            reads = fn.all_state_variables_read()
        except Exception:  # pragma: no cover - slither edge
            continue
        for var in reads:
            if str(getattr(var, "type", "")).strip() not in _ADDRESS_TYPES:
                continue
            name = getattr(var, "name", None)
            if not name or name in seen:
                continue
            if not _has_writer(contract, var):
                continue
            seen.add(name)
            out.append(var)
    return out


def detect_secondary_impl_pointers(contract: Any) -> list[SecondaryImplPointer]:
    """Return a pointer descriptor for each secondary-impl pointer.

    Empty for the overwhelming majority of contracts (no fallback delegatecall to
    a named state var). Pointers whose storage slot can't be computed are
    dropped — without a slot the value can't be read from proxy storage.
    """
    pointer_vars = _fallback_delegatecall_target_vars(contract)
    if not pointer_vars:
        return []

    srs = None
    try:
        from slither.tools.read_storage import SlitherReadStorage

        srs = SlitherReadStorage([contract], 20)
    except Exception as exc:  # pragma: no cover - slither tool import/edge
        logger.warning("SlitherReadStorage unavailable; secondary-impl slots unresolved: %s", exc)

    pointers: list[SecondaryImplPointer] = []
    for var in pointer_vars:
        slot: int | None = None
        offset = 0
        if srs is not None:
            try:
                info = srs.get_storage_slot(var, contract)
                raw_slot = getattr(info, "slot", None)
                slot = int(raw_slot) if raw_slot is not None else None
                offset = int(getattr(info, "offset", 0) or 0)
            except Exception as exc:
                logger.warning("secondary-impl slot computation failed for %s: %s", getattr(var, "name", "?"), exc)
        name = getattr(var, "name", None)
        if slot is not None and name:
            pointers.append({"name": str(name), "slot": slot, "offset": offset})
    return pointers
