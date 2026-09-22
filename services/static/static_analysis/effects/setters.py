"""Setter scan and storage-pointer aliasing for storage-write attribution."""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from utils.logging import record_degraded

from .selectors import _function_full_name, _node_irs

# How many unscanned function signatures a degraded record names individually;
# the count is always exact.
_UNSCANNED_SAMPLE = 8


# Contract-level setter set: state vars written by any non-constructor function
# body, as Slither attributes writes. A setter's *existence* is a dispositive
# fact. Its *absence* is only a sound proof that a non-immutable var cannot be
# redirected post-deploy when the scan is DISPOSITIVELY COMPLETE — i.e. Slither
# attributed every write in the contract's code. Two blind spots break that
# precondition and are checked by ``_setter_scan_complete``: a raw/computed-slot
# ``sstore`` (Slither attributes ``x.slot`` writes to ``x`` but not
# ``sstore(0, …)`` / keccak-slot writes), and any ``delegatecall`` (foreign code
# can write any slot as this contract). When the scan is incomplete, "no setter"
# degrades to ``indeterminate`` — never a proven-negative "fixed destination".
# A third blind spot — storage-pointer aliasing — is resolved separately by
# ``_aliased_storage_writes``: a state var written only through a callee taking a
# ``storage`` reference (``using X for`` / library / internal storage-lib idiom)
# is not attributed by ``all_state_variables_written`` either. We follow the
# aliasing to attribute the write back to its origin var (a real setter), and
# only fall back to indeterminate for the aliases we genuinely cannot resolve.
# Memoized per contract for the build pass.
_SETTER_VARS: WeakKeyDictionary[Any, dict[str, list[str]]] = WeakKeyDictionary()
_SETTER_SCAN_COMPLETE: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()
_ALIASED_WRITES: WeakKeyDictionary[Any, tuple[set[str], set[str], bool]] = WeakKeyDictionary()

# Recursion depth for following a storage reference through forwarding callees.
_STORAGE_ALIAS_DEPTH = 6


def _setter_state_vars(contract: Any) -> dict[str, list[str]]:
    """``{state var name: the signatures that write it}`` for this contract.

    The KEY SET is what classifies (``_state_var_target_kind`` asks only
    membership), and it is built exactly as before — every non-constructor
    function's attributed writes, plus the storage-pointer-aliased origins. The
    values are the writer identities that were already in hand at the loop and
    were previously discarded.

    ``all_state_variables_written`` is transitive, so an internal helper's write
    also lands on every function that reaches it: the value list therefore
    already CONTAINS every externally callable writer, and is a floor on who
    can redirect the variable, never a closed set. An aliased-only origin gets
    an EMPTY list — the write is real but this pass attributed no signature to
    it — which is why the projection omits the key rather than publishing
    ``[]`` there (``[]`` is reserved for a completed scan that found none)."""
    cached = _SETTER_VARS.get(contract)
    if cached is not None:
        return cached
    setters: dict[str, set[str]] = {}
    # A swallowed write-set failure empties this function's contribution to the
    # KEY SET, which downstream reads as "no setter" — a proven claim built on a
    # failed scan. This module is deliberately logger-free (pure analysis), so
    # the shortfall is published as a degraded record on the owning job instead;
    # collected across the loop so one bad contract is one record, not one per
    # function.
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
        # Slither synthesises ``slitherConstructorVariables`` /
        # ``slitherConstructorConstantVariables`` to hold declaration-site
        # initialisers. They MUST keep contributing membership — dropping them
        # would turn a var with an inline initialiser and no setter into a
        # proven "fixed destination" it was never proven to be — but they are
        # not callable, so publishing one as a writer whose principal can
        # redirect the destination names a function nobody can invoke.
        synthetic = getattr(fn, "is_constructor_variables", False)
        for var in written or []:
            name = getattr(var, "name", None)
            if not name:
                continue
            attributed = setters.setdefault(name, set())
            if not synthetic:
                attributed.add(signature)
    # Storage-pointer-aliased writes Slither did not attribute, resolved back to
    # their origin state var — these are real, redirecting setters.
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
    """Whether ``callee`` writes through its storage-reference parameter
    ``param`` — directly (``param.field = …`` / ``param[…] = …``, which puts
    ``param`` in the callee's ``variables_written``) or transitively (forwarding
    ``param`` into another storage-writing callee). Returns ``writes`` /
    ``reads_only`` / ``unresolved`` (callee body absent — cannot decide)."""
    if callee is None or not getattr(callee, "nodes", None):
        return "unresolved"
    if depth > _STORAGE_ALIAS_DEPTH:
        return "unresolved"
    seen = seen if seen is not None else set()
    if id(callee) in seen:
        # A recursion cycle: we cannot see whether the write happens down the
        # recursive tail. Fail toward unresolved (-> indeterminate), never
        # reads_only — that would let a genuinely-redirected var read as a
        # proven-fixed "no setter".
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
    """The origin state-variable NAME a storage-reference argument aliases, or
    ``None`` when it cannot be tied to a single declared state var. Handles a
    direct state var and a local storage pointer assigned from a state var or a
    member/index of one (``Box storage b = box;`` / ``= boxes[k];``). A pointer
    sourced from a call return is unresolvable — ``None``."""
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
    """Resolve storage-pointer aliasing the attributed-write scan misses.

    Returns ``(resolved_setters, indeterminate_vars, contract_unresolvable)``:
    * ``resolved_setters`` — origin state vars written through a storage-ref
      alias that resolved to a definite variable: real setters (-> storage_setter).
    * ``indeterminate_vars`` — origin vars aliased into a callee whose
      write-through status couldn't be decided; their no-setter proof is unsound
      so they degrade to indeterminate (not storage_no_setter).
    * ``contract_unresolvable`` — a write-through alias whose origin var itself
      couldn't be resolved (unknown which var was redirected): no no-setter proof
      in the contract is sound, so the whole scan is incomplete.
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
    """True iff Slither's write attribution is exhaustive for this contract, so
    the *absence* of a setter is dispositive. False when a value could be
    written through a channel the attributed-write scan cannot see:

    * an unattributed assembly ``sstore`` — Slither lowers ``sstore(x.slot, …)``
      to an attributed write of ``x`` (no ``sstore`` IR survives), so a residual
      ``SolidityCall sstore(...)`` IR is exactly the raw-numeric / computed-slot
      write it could not attribute;
    * a ``delegatecall`` / ``callcode`` — foreign code executes in this
      contract's storage context and may write any slot;
    * a storage-pointer alias written through a callee whose ORIGIN state var
      could not be resolved (``_aliased_storage_writes`` third element) — some
      unknown var was redirected.

    Modifiers are scanned too (assembly can live in a guard body). Memoized."""
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
