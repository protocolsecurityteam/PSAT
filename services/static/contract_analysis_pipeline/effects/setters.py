"""Setter scan and storage-pointer aliasing for storage-write attribution."""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from utils.logging import record_degraded

from .selectors import _function_full_name, _node_irs

_UNSCANNED_SAMPLE = 8


# State vars written by any non-constructor function, as Slither attributes writes (memoized per contract).
#
# A setter's existence is dispositive; its absence only proves a var fixed when the scan is complete.
# ``_setter_scan_complete`` checks the blind spots: raw or computed-slot ``sstore`` and any ``delegatecall``. Writes
# through storage-reference callees aren't attributed either; ``_aliased_storage_writes`` resolves those back to their
# origin var, falling back to indeterminate when it can't.
_SETTER_VARS: WeakKeyDictionary[Any, dict[str, list[str]]] = WeakKeyDictionary()
_SETTER_SCAN_COMPLETE: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()
_ALIASED_WRITES: WeakKeyDictionary[Any, tuple[set[str], set[str], bool]] = WeakKeyDictionary()

_STORAGE_ALIAS_DEPTH = 6


def _setter_state_vars(contract: Any) -> dict[str, list[str]]:
    """``{state var: writer signatures}``. The key set classifies; the values name writers.

    ``all_state_variables_written`` is transitive, so each list already contains every external writer and is a floor,
    not a closed set. Aliased-only origins get ``[]``, which is why the projection omits the key there (``[]`` means a
    completed scan found none).
    """
    cached = _SETTER_VARS.get(contract)
    if cached is not None:
        return cached
    setters: dict[str, set[str]] = {}
    # A swallowed failure would read as "no setter", so the shortfall is published as one degraded record per contract.
    unscanned: list[str] = []
    first_failure: Exception | None = None
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        signature = _function_full_name(fn)
        try:
            written = fn.all_state_variables_written()
        except Exception as exc:
            written = []
            unscanned.append(signature)
            first_failure = first_failure or exc
        # Slither's synthetic initializer functions keep contributing membership (else an inline-initialized var with no
        # setter reads as provably fixed) but aren't callable, so they aren't published as writers.
        synthetic = getattr(fn, "is_constructor_variables", False)
        for var in written or []:
            name = getattr(var, "name", None)
            if not name:
                continue
            attributed = setters.setdefault(name, set())
            if not synthetic:
                attributed.add(signature)
    for name in _aliased_storage_writes(contract)[0]:
        setters.setdefault(name, set())
    if first_failure is not None:
        record_degraded(
            phase="static_effects_setter_state_vars",
            exc=first_failure,
            context={
                "contract": getattr(contract, "name", None),
                "functions_unscanned": len(unscanned),
                "functions_unscanned_sample": unscanned[:_UNSCANNED_SAMPLE],
            },
        )
    resolved = {name: sorted(signatures) for name, signatures in setters.items()}
    _SETTER_VARS[contract] = resolved
    return resolved


def _arg_is_param(arg: Any, param: Any) -> bool:
    if arg is param:
        return True
    pname = getattr(param, "name", None)
    return bool(pname) and getattr(arg, "name", None) == pname


def _storage_param_write_status(callee: Any, param: Any, depth: int = 0, seen: set[int] | None = None) -> str:
    """Whether ``callee`` writes through its storage-reference ``param``, directly or by forwarding it: ``writes``,
    ``reads_only`` or ``unresolved`` (no body).
    """
    if callee is None or not getattr(callee, "nodes", None):
        return "unresolved"
    if depth > _STORAGE_ALIAS_DEPTH:
        return "unresolved"
    seen = seen if seen is not None else set()
    if id(callee) in seen:
        # A cycle: can't see the recursive tail, so unresolved, never reads_only.
        return "unresolved"
    seen.add(id(callee))
    pname = getattr(param, "name", None)
    for written in getattr(callee, "variables_written", []) or []:
        if written is param or (pname and getattr(written, "name", None) == pname):
            return "writes"
    status = "reads_only"
    for node in getattr(callee, "nodes", []) or []:
        for ir in _node_irs(node):
            if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                continue
            sub = getattr(ir, "function", None)
            subparams = list(getattr(sub, "parameters", []) or [])
            for sub_param, arg in zip(subparams, getattr(ir, "arguments", []) or []):
                if not getattr(sub_param, "is_storage", False) or not _arg_is_param(arg, param):
                    continue
                result = _storage_param_write_status(sub, sub_param, depth + 1, seen)
                if result == "writes":
                    return "writes"
                if result == "unresolved":
                    status = "unresolved"
    return status


def _resolve_storage_origin(arg: Any, function: Any, seen: set[str] | None = None) -> str | None:
    """The state variable a storage-reference argument aliases (direct, or a local pointer assigned from a var or its
    element), or ``None`` (e.g. from a call return).
    """
    from slither.core.variables.state_variable import StateVariable

    if isinstance(arg, StateVariable):
        return getattr(arg, "name", None)
    aname = getattr(arg, "name", None)
    if not aname:
        return None
    seen = seen if seen is not None else set()
    if aname in seen:
        return None
    seen.add(aname)
    for node in getattr(function, "nodes", []) or []:
        for ir in _node_irs(node):
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None or getattr(lvalue, "name", None) != aname:
                continue
            tn = type(ir).__name__
            if tn == "Assignment":
                return _resolve_storage_origin(getattr(ir, "rvalue", None), function, seen)
            if tn in ("Member", "Index"):
                base = getattr(ir, "variable_left", None)
                if isinstance(base, StateVariable):
                    return getattr(base, "name", None)
                return _resolve_storage_origin(base, function, seen)
            return None  # call-sourced / cast / other — not a single state var
    return None


def _aliased_storage_writes(contract: Any) -> tuple[set[str], set[str], bool]:
    """Resolve storage-pointer aliasing the attributed-write scan misses: ``(resolved_setters, indeterminate_vars,
    contract_unresolvable)``. Resolved origins are real setters; origins aliased into undecidable callees lose
    their no-setter proof; an unresolvable origin makes the whole scan incomplete.
    """
    cached = _ALIASED_WRITES.get(contract)
    if cached is not None:
        return cached
    resolved: set[str] = set()
    indeterminate: set[str] = set()
    contract_unresolvable = False
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        for node in getattr(fn, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                callee = getattr(ir, "function", None)
                params = list(getattr(callee, "parameters", []) or [])
                for param, arg in zip(params, getattr(ir, "arguments", []) or []):
                    if not getattr(param, "is_storage", False):
                        continue
                    status = _storage_param_write_status(callee, param)
                    if status == "reads_only":
                        continue
                    origin = _resolve_storage_origin(arg, fn)
                    if origin is None:
                        contract_unresolvable = True
                    elif status == "writes":
                        resolved.add(origin)
                    else:  # "unresolved" — might write, cannot decide for this origin
                        indeterminate.add(origin)
    result = (resolved, indeterminate, contract_unresolvable)
    _ALIASED_WRITES[contract] = result
    return result


def _setter_scan_complete(contract: Any) -> bool:
    """True iff write attribution is exhaustive, so a missing setter is dispositive.

    False on a residual assembly ``sstore`` (Slither lowers ``x.slot`` writes, so what's left is raw or computed), any
    ``delegatecall``/``callcode``, or an unresolvable storage alias. Scans modifiers too; memoized.
    """
    cached = _SETTER_SCAN_COMPLETE.get(contract)
    if cached is not None:
        return cached
    if _aliased_storage_writes(contract)[2]:
        _SETTER_SCAN_COMPLETE[contract] = False
        return False
    units = list(getattr(contract, "functions", []) or []) + list(getattr(contract, "modifiers", []) or [])
    complete = True
    for unit in units:
        if not complete:
            break
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                tn = type(ir).__name__
                if tn == "LowLevelCall":
                    if getattr(ir, "function_name", None) in ("delegatecall", "callcode"):
                        complete = False
                        break
                elif tn == "SolidityCall":
                    name = getattr(getattr(ir, "function", None), "name", "") or ""
                    if name.startswith(("sstore(", "delegatecall(", "callcode(")):
                        complete = False
                        break
            if not complete:
                break
    _SETTER_SCAN_COMPLETE[contract] = complete
    return complete
