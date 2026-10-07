"""ProvenanceEngine: worklist forward dataflow over Slither IR, mapping each SSA value to the set of ``Source``
records it came from.

Lattice values are ``frozenset[Source]`` (empty is unreached; ``{Source(kind="top")}`` is saturated by cycles, depth
caps or unknown opcodes). Phis union; the worklist runs to a fixed point. Classification comes from IR shape and operand
types, never helper names.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, get_args

from eth_utils.crypto import keccak

from .predicate_types import OperandSource
from .slither_compat import (
    SLITHER_AVAILABLE,
    Assignment,
    Binary,
    Constant,
    HighLevelCall,
    Index,
    InternalCall,
    Length,
    LibraryCall,
    LocalVariable,
    LowLevelCall,
    Member,
    NewArray,
    NewContract,
    NewElementaryType,
    OperationWithLValue,
    Phi,
    ReferenceVariable,
    Return,
    Send,
    SolidityCall,
    SolidityVariable,
    StateVariable,
    TemporaryVariable,
    Transfer,
    TypeConversion,
    Unary,
    Unpack,
    Variable,
)

# Derived from the published Literal so the two can't drift.
SOURCE_KINDS: tuple[OperandSource, ...] = get_args(OperandSource)


@dataclass(frozen=True)
class Source:
    """One origin record for an SSA value; frozen so sets of them hash for cycle detection and fixed-point checks."""

    kind: OperandSource
    parameter_index: int | None = None
    parameter_name: str | None = None
    state_variable_name: str | None = None
    callee: str | None = None
    # Hash of constituent source sets, keeping nested call shape without recursion.
    callee_args_digest: str | None = None
    callee_signature: str | None = None
    callee_selector: str | None = None
    constant_value: str | None = None
    value_type: str | None = None
    computed_kind: str | None = None
    block_context_kind: str | None = None
    member_path: tuple[str, ...] = ()
    # The constant slot a getter-less internal address accessor ``sload``s (Governable ``_pendingGovernor``), so
    # resolution can ``eth_getStorageAt`` it.
    storage_slot: str | None = None
    # Origins that reached a ``computed``, ``view_call`` or ``external_call`` value through its arguments, which the
    # hash or call digest otherwise makes opaque (so a hash-commitment guard loses its parameter, and a role read loses
    # that it consumed the caller). ``None`` is not determined; ``frozenset()`` means only constants; non-empty lists
    # the origins. Members have ``derived_from=None`` (``arg_origins`` splices them flat), so one level deep.
    derived_from: frozenset["Source"] | None = None

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise ValueError(f"unknown source kind {self.kind!r}")
        # ``is_top`` is an O(1) membership test that requires every top Source to equal ``_TOP_SOURCE``, so no metadata
        # on top.
        if self.kind == "top" and (
            self.parameter_index is not None
            or self.parameter_name is not None
            or self.state_variable_name is not None
            or self.callee is not None
            or self.callee_args_digest is not None
            or self.callee_signature is not None
            or self.callee_selector is not None
            or self.constant_value is not None
            or self.value_type is not None
            or self.computed_kind is not None
            or self.block_context_kind is not None
            or self.member_path
            or self.storage_slot is not None
            or self.derived_from is not None
        ):
            raise ValueError("Source(kind='top') must be the bare sentinel — no metadata fields")


SourceSet = frozenset[Source]
EMPTY: SourceSet = frozenset()
_TOP_SOURCE = Source(kind="top")
TOP: SourceSet = frozenset({_TOP_SOURCE})


def _solidity_type_name(value: Any) -> str | None:
    type_obj = getattr(value, "type", None)
    if type_obj is None:
        return None
    type_name = getattr(type_obj, "name", None) or str(type_obj)
    return type_name or None


def is_top(s: SourceSet) -> bool:
    # Valid because of the ``__post_init__`` invariant above.
    return _TOP_SOURCE in s


def union(a: SourceSet, b: SourceSet) -> SourceSet:
    """Lattice join; TOP absorbs."""
    if is_top(a) or is_top(b):
        return TOP
    return a | b


def arg_origins(args_union: SourceSet) -> frozenset[Source]:
    """The flat ``derived_from`` of an argument source set: a computed argument contributes itself (stripped) and its
    own origins, so ``keccak256(abi.encode(receiver))`` still names ``receiver``. Constants are dropped, so empty
    means only constants. Members' ``derived_from=None`` marks them stripped, not undetermined.
    """
    origins: set[Source] = set()
    for source in args_union:
        if source.kind == "constant":
            continue
        if source.derived_from is not None:
            origins.update(source.derived_from)
        origins.add(replace(source, derived_from=None))
    return frozenset(origins)


def _constant_storage_slot_for_accessor(callee: Any) -> str | None:
    """The 32-byte slot a getter-less internal address accessor reads via a single constant ``sload``
    (``Governable._pendingGovernor()``), or ``None``. Limited to address returns and one constant slot so a
    bytes32 flag can't be misread as a principal.
    """
    if callee is None:
        return None
    try:
        from services.static.contract_analysis_pipeline.secondary_impl import (
            _SLOT_CONST_TYPES,
            _any_transitive_ir,
            _const_slot_value,
            _ir_is_sload,
        )
    except Exception:  # pragma: no cover - import edge
        return None
    return_type = getattr(callee, "return_type", None)
    if not (return_type and len(return_type) == 1 and str(return_type[0]) in ("address", "address payable")):
        return None
    if not _any_transitive_ir(callee, _ir_is_sload):
        return None
    try:
        read = list(callee.all_state_variables_read())
    except Exception:  # pragma: no cover - slither edge
        return None
    consts = [v for v in read if getattr(v, "is_constant", False) and str(getattr(v, "type", "")) in _SLOT_CONST_TYPES]
    if len(consts) != 1:
        return None
    val = _const_slot_value(consts[0])
    if val is None or val < 0:
        return None
    return "0x" + format(val, "064x")


# ``PSAT_PROVENANCE_INTERNAL_CALL_DEPTH`` and ``PSAT_PROVENANCE_WORKLIST_CAP`` override the defaults.
def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


DEFAULT_INTERNAL_CALL_DEPTH = _env_int("PSAT_PROVENANCE_INTERNAL_CALL_DEPTH", 4)
DEFAULT_WORKLIST_ITER_CAP = _env_int("PSAT_PROVENANCE_WORKLIST_CAP", 200)
# A value rewritten more often than this is churning, not converging.
DEFAULT_WIDEN_AFTER = _env_int("PSAT_PROVENANCE_WIDEN_AFTER", 8)


def widen(s: SourceSet) -> SourceSet:
    """Widening: drop ``callee_args_digest`` from members (and their ``derived_from``).

    The digest hashes the set itself, so self-referential assignments (``inv = f(inv)`` in OZ ``Math.mulDiv``) mint new
    variants forever; every other field is finite per function. The digest is never published and ``derived_from``
    origins survive, so nothing observable is lost.
    """
    if is_top(s):
        return s
    out = []
    changed = False
    for src in s:
        derived = src.derived_from
        if derived:
            stripped = frozenset(
                replace(o, callee_args_digest=None) if o.callee_args_digest is not None else o for o in derived
            )
            if stripped != derived:
                derived = stripped
        if src.callee_args_digest is not None or derived is not src.derived_from:
            src = replace(src, callee_args_digest=None, derived_from=derived)
            changed = True
        out.append(src)
    return frozenset(out) if changed else s


@dataclass
class ProvenanceMap:
    """Per-SSA-value provenance for one function, keyed by Slither variable name."""

    sources: dict[str, SourceSet]
    # Per-run rewrite counts for the widening trigger.
    update_counts: dict[str, int] = field(default_factory=dict)

    def get(self, var_name: str) -> SourceSet:
        return self.sources.get(var_name, EMPTY)

    def set(self, var_name: str, value: SourceSet) -> bool:
        """Set ``name``; True if it changed.

        After ``DEFAULT_WIDEN_AFTER`` rewrites the store becomes ``widen(prev | value)``: monotone (several writers
        otherwise oscillate) and finite. Converging values never widen.
        """
        prev = self.sources.get(var_name, EMPTY)
        if prev == value:
            return False
        count = self.update_counts.get(var_name, 0)
        if count >= DEFAULT_WIDEN_AFTER:
            value = widen(union(prev, value))
            if prev == value:
                return False
        self.update_counts[var_name] = count + 1
        self.sources[var_name] = value
        return True


class ProvenanceEngine:
    """Forward dataflow over a function's SSA IR: ``ProvenanceEngine(function).run()``, then
    ``engine.provenance.get(name)``.
    """

    def __init__(
        self,
        function: Any,  # slither.core.declarations.Function
        *,
        internal_call_depth: int = DEFAULT_INTERNAL_CALL_DEPTH,
        worklist_cap: int = DEFAULT_WORKLIST_ITER_CAP,
        parameter_bindings: dict[str, SourceSet] | None = None,
    ) -> None:
        if not SLITHER_AVAILABLE:
            raise RuntimeError("ProvenanceEngine requires slither to be importable")
        self.function = function
        self.internal_call_depth = internal_call_depth
        self.worklist_cap = worklist_cap
        self.provenance = ProvenanceMap(sources={})
        # Parameter-binding frames for internal callees and modifiers; top is active.
        self._binding_frames: list[dict[str, SourceSet]] = []
        if parameter_bindings:
            self._binding_frames.append(dict(parameter_bindings))
        self._call_stack: list[str] = []
        # ``(callee, bindings) -> return_sources``, so the worklist's repeated visits run each sub-engine once. Not
        # passed to sub-engines: their call stack differs.
        self._sub_engine_memo: dict[tuple[str, frozenset], frozenset] = {}
        # Solidity variables, constants and state variables classify purely from the object, so cache by id for this
        # engine's lifetime. Locals, temporaries and references change as dataflow converges and aren't cached.
        self._leaf_value_source_cache: dict[int, SourceSet] = {}
        # Iterations of the last run, for convergence checks.
        self.iterations_run: int = 0

    def run(self) -> ProvenanceMap:
        """Seed parameters and msg values, then iterate to a fixed point or the cap."""
        self._seed_parameters()
        nodes = list(self._iter_nodes())
        iterations = 0
        changed = True
        while changed and iterations < self.worklist_cap:
            changed = False
            for node in nodes:
                if self._step_node(node):
                    changed = True
            iterations += 1
        # Widening keeps this well under the cap; the cap backstops growth widening doesn't cover.
        self.iterations_run = iterations
        if iterations >= self.worklist_cap:
            # Unknown values stay empty; consumers read absent as unknown.
            pass
        return self.provenance

    def _seed_parameters(self) -> None:
        """Seed each formal (and each modifier's formals) as a ``parameter`` source."""
        bindings = self._active_bindings()
        for idx, param in enumerate(self.function.parameters):
            name = self._var_name(param)
            if not name:
                continue
            if bindings is not None and name in bindings:
                self.provenance.set(name, bindings[name])
                continue
            self.provenance.set(
                name,
                frozenset(
                    {
                        Source(
                            kind="parameter",
                            parameter_index=idx,
                            parameter_name=getattr(param, "name", None),
                        )
                    }
                ),
            )
        # Modifier formals are seeded with their modifier-scope index; call-site binding substitution is separate.
        for modifier in getattr(self.function, "modifiers", []) or []:
            for idx, param in enumerate(getattr(modifier, "parameters", []) or []):
                name = self._var_name(param)
                if not name or name in self.provenance.sources:
                    continue
                self.provenance.set(
                    name,
                    frozenset(
                        {
                            Source(
                                kind="parameter",
                                parameter_index=idx,
                                parameter_name=getattr(param, "name", None),
                            )
                        }
                    ),
                )

    def _active_bindings(self) -> dict[str, SourceSet] | None:
        return self._binding_frames[-1] if self._binding_frames else None

    def _iter_nodes(self) -> Iterable[Any]:
        # Function body only. Slither shares a modifier's SSA across callers, so its entry Phi unions every call site's
        # arguments; when a modifier parameter shares a name with the function's (``onlyRole(bytes32 role)``), that
        # pollutes the function's provenance and defeats the sub-engine memo (CumulativeMerkleDrop went from 0.02 s to
        # 18 s). Gates inside modifiers are still found by RevertDetector and built with fresh engines per link.
        yield from self.function.nodes

    def _step_node(self, node: Any) -> bool:
        """Apply transfer functions to a node's IRs; True if anything changed."""
        any_changed = False
        for ir in node.irs_ssa:
            if self._step_ir(ir):
                any_changed = True
        return any_changed

    def _step_ir(self, ir: Any) -> bool:
        # Imports are lazy so this module loads without solc.
        if isinstance(ir, Assignment):
            return self._handle_assignment(ir)
        if isinstance(ir, TypeConversion):
            return self._handle_type_conversion(ir)
        if isinstance(ir, Phi):
            return self._handle_phi(ir)
        if isinstance(ir, Binary):
            return self._handle_binary(ir)
        if isinstance(ir, Unary):
            return self._handle_unary(ir)
        if isinstance(ir, Index):
            return self._handle_index(ir)
        if isinstance(ir, Length):
            return self._handle_length(ir)
        if isinstance(ir, Member):
            return self._handle_member(ir)
        if isinstance(ir, SolidityCall):
            return self._handle_solidity_call(ir)
        if isinstance(ir, LowLevelCall):
            return self._handle_low_level_call(ir)
        if isinstance(ir, HighLevelCall):
            return self._handle_external_call(ir)
        if isinstance(ir, (InternalCall, LibraryCall)):
            return self._handle_internal_call(ir)
        if isinstance(ir, Unpack):
            return self._handle_unpack(ir)
        if isinstance(ir, (NewContract, NewArray, NewElementaryType)):
            return self._handle_new(ir)
        if isinstance(ir, (Send, Transfer)):
            return self._handle_send_transfer(ir)
        if isinstance(ir, Return):
            # Callee return propagation is handled in _handle_internal_call.
            return False
        # Unknown opcode: top, so consumers see it as opaque.
        if isinstance(ir, OperationWithLValue):
            lv = ir.lvalue
            if lv is not None:
                return self.provenance.set(self._var_name(lv), TOP)
        return False

    def _handle_assignment(self, ir: Any) -> bool:
        rvalue_sources = self._sources_for_value(ir.rvalue)
        return self.provenance.set(self._var_name(ir.lvalue), rvalue_sources)

    def _handle_type_conversion(self, ir: Any) -> bool:
        # Casts preserve origin.
        rvalue = getattr(ir, "variable", None) or getattr(ir, "rvalue", None)
        if rvalue is None:
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        sources = self._sources_for_value(rvalue)
        return self.provenance.set(self._var_name(ir.lvalue), sources)

    def _handle_phi(self, ir: Any) -> bool:
        # Phis union their inputs and the lvalue's existing set (so bound parameters survive). A parameter's ENTRYPOINT
        # Phi is excluded: Slither makes its inputs every internal call site's arguments, which imported other frames
        # (``onlyA(msg.sender)`` made ``account`` caller-tainted inside ``onlyA``'s own frame). Seeding already wrote
        # this frame's truth.
        if self._is_entry_parameter_phi(ir):
            return False
        result: SourceSet = self.provenance.get(self._var_name(ir.lvalue))
        for incoming in ir.rvalues:
            result = union(result, self._sources_for_value(incoming))
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _is_entry_parameter_phi(self, ir: Any) -> bool:
        """True for the entry Phi of one of this function's formals, whose inputs live in other frames.

        State-variable entry Phis classify frame-independently and are handled normally.
        """
        node = getattr(ir, "node", None)
        node_type = getattr(getattr(node, "type", None), "name", "")
        if node_type != "ENTRYPOINT":
            return False
        name = self._var_name(getattr(ir, "lvalue", None))
        if not name:
            return False
        base = _strip_ssa_suffix(name)
        return any(self._var_name(param) in (name, base) for param in getattr(self.function, "parameters", ()) or ())

    def _handle_binary(self, ir: Any) -> bool:
        operand_sources = union(
            self._sources_for_value(ir.variable_left),
            self._sources_for_value(ir.variable_right),
        )
        if is_top(operand_sources):
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        # One ``computed`` source with a digest of the operand union: flat, but keeps taint shape.
        result = (
            frozenset(
                {
                    Source(
                        kind="computed",
                        computed_kind=str(getattr(ir, "type", "binary")),
                        callee_args_digest=_digest(operand_sources),
                    )
                }
            )
            | operand_sources
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_unary(self, ir: Any) -> bool:
        operand_sources = self._sources_for_value(ir.rvalue)
        if is_top(operand_sources):
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        result = (
            frozenset(
                {
                    Source(
                        kind="computed",
                        computed_kind=str(getattr(ir, "type", "unary")),
                        callee_args_digest=_digest(operand_sources),
                        # Keep the negated value's origins readable so ``!hasRole(msg.sender, ...)`` still shows the
                        # caller.
                        derived_from=arg_origins(operand_sources),
                    )
                }
            )
            | operand_sources
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_index(self, ir: Any) -> bool:
        """``map[k]``: union of base and key sources plus a ``computed`` tag carrying the key origin."""
        base = getattr(ir, "variable_left", None)
        key = getattr(ir, "variable_right", None)
        base_sources = self._sources_for_value(base) if base is not None else EMPTY
        key_sources = self._sources_for_value(key) if key is not None else EMPTY
        result = union(base_sources, key_sources)
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_length(self, ir: Any) -> bool:
        """``.length`` inherits the array's provenance (tagged ``length``), so loop bounds over ``params.length``
        converge instead of saturating.
        """
        base = getattr(ir, "value", None)
        sources = self._sources_for_value(base) if base is not None else EMPTY
        if is_top(sources) or sources == EMPTY:
            return self.provenance.set(self._var_name(ir.lvalue), sources or TOP)
        wrapper = frozenset(
            {
                Source(
                    kind="computed",
                    computed_kind="length",
                    callee_args_digest=_digest(sources),
                )
            }
        )
        return self.provenance.set(self._var_name(ir.lvalue), union(sources, wrapper))

    def _handle_member(self, ir: Any) -> bool:
        """``s.field``: base sources plus a ``computed`` tag ``member.<field>`` the builder reads for field paths."""
        base = getattr(ir, "variable_left", None)
        field = getattr(ir, "variable_right", None)
        base_sources = self._sources_for_value(base) if base is not None else EMPTY
        # The field name is a Constant; repr for odd shapes.
        field_name: str | None = None
        if field is not None:
            field_name = getattr(field, "value", None) or getattr(field, "name", None) or str(field)
        from slither.core.declarations import Enum as EnumDeclaration

        if isinstance(base, EnumDeclaration) and field_name in base.values:
            return self.provenance.set(
                self._var_name(ir.lvalue),
                frozenset(
                    {Source(kind="constant", constant_value=str(base.values.index(field_name)), value_type="uint256")}
                ),
            )
        if not field_name or is_top(base_sources):
            return self.provenance.set(self._var_name(ir.lvalue), base_sources)
        projected_sources = frozenset(
            replace(source, member_path=source.member_path + (field_name,))
            for source in base_sources
            if source.kind == "state_variable"
        )
        wrapper = frozenset(
            {
                Source(
                    kind="computed",
                    computed_kind=f"member.{field_name}",
                    callee_args_digest=_digest(base_sources),
                )
            }
        )
        return self.provenance.set(self._var_name(ir.lvalue), union(union(base_sources, projected_sources), wrapper))

    def _handle_solidity_call(self, ir: Any) -> bool:
        """``ecrecover`` gets ``signature_recovery``; hashes and other builtins are ``computed``."""
        callee_name = getattr(ir.function, "name", "") if hasattr(ir, "function") else ""
        if callee_name == "ecrecover()" or callee_name.startswith("ecrecover"):
            args_union = self._union_of_args(ir.arguments)
            result = frozenset(
                {
                    Source(
                        kind="signature_recovery",
                        callee="ecrecover",
                        callee_args_digest=_digest(args_union),
                    )
                }
            )
            return self.provenance.set(self._var_name(ir.lvalue), result)
        # Carry argument origins on ``derived_from`` so a hash-commitment gate (``history[nonce] !=
        # keccak256(abi.encode(receiver, ...))``) stays bound to what it constrains.
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        if is_top(args_union):
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        result = frozenset(
            {
                Source(
                    kind="computed",
                    computed_kind=callee_name or "solidity_call",
                    callee_args_digest=_digest(args_union),
                    derived_from=arg_origins(args_union),
                )
            }
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_external_call(self, ir: Any) -> bool:
        """A high-level call; records the callee name for routing."""
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        # The fallback ``function_name`` is a Constant when unresolved.
        raw_callee_name = getattr(getattr(ir, "function", None), "name", None) or getattr(ir, "function_name", None)
        callee_name = str(raw_callee_name) if raw_callee_name is not None else None
        callee_signature = _callee_signature(ir)
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        result = frozenset(
            {
                Source(
                    kind="external_call",
                    callee=callee_name,
                    callee_args_digest=_digest(args_union),
                    callee_signature=callee_signature,
                    callee_selector=_dispatch_selector(getattr(ir, "function", None), callee_signature),
                    # The only readable record that, e.g., ``msg.sender`` was consumed.
                    derived_from=arg_origins(args_union),
                )
            }
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_low_level_call(self, ir: Any) -> bool:
        """``addr.call``/``staticcall``/``delegatecall``: tag the call kind and carry the destination and argument
        provenance into the result tuple, so later checks see where the target came from. Unpacked values inherit
        it.
        """
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        # ``function_name`` is a Constant; a raw Constant once crashed the predicate-tree write.
        kind = str(getattr(ir, "function_name", None) or "low_level_call")
        dest_sources = self._sources_for_value(getattr(ir, "destination", None))
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        # delegatecall is tagged external_call but keeps destination provenance.
        result = frozenset(
            {
                Source(
                    kind="external_call",
                    callee=kind,  # "call" / "staticcall" / "delegatecall"
                    callee_args_digest=_digest(union(dest_sources, args_union)),
                )
            }
        )
        result = union(result, dest_sources)
        result = union(result, args_union)
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_unpack(self, ir: Any) -> bool:
        """Each unpacked component inherits the whole tuple's provenance (Slither doesn't track per position)."""
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        # ``ir.tuple``, or ``ir.rvalue`` on older Slither.
        tup = getattr(ir, "tuple", None) or getattr(ir, "rvalue", None)
        if tup is None:
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        sources = self._sources_for_value(tup)
        return self.provenance.set(self._var_name(ir.lvalue), sources)

    def _handle_internal_call(self, ir: Any) -> bool:
        """Recurse into the callee with bound parameters (up to ``internal_call_depth``) and return the union of its
        return values' provenance.
        """
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        callee = getattr(ir, "function", None)
        callee_name = getattr(callee, "full_name", None) or getattr(callee, "name", None)
        accessor_slot = _constant_storage_slot_for_accessor(callee)
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        # Cycle/depth guard. ``derived_from`` keeps argument provenance readable next to the digest.
        call_tag = Source(
            kind="view_call",
            callee=callee_name,
            callee_signature=callee_name,
            callee_selector=_dispatch_selector(callee, callee_name),
            callee_args_digest=_digest(args_union),
            storage_slot=accessor_slot,
            derived_from=arg_origins(args_union),
        )
        if callee is None or len(self._call_stack) >= self.internal_call_depth or callee_name in self._call_stack:
            return self.provenance.set(self._var_name(ir.lvalue), frozenset({call_tag}))
        bindings: dict[str, SourceSet] = {}
        for param, arg in zip(callee.parameters, getattr(ir, "arguments", ())):
            name = self._var_name(param)
            if name:
                bindings[name] = self._sources_for_value(arg)
        memo_key = (callee_name or "?", frozenset(bindings.items()))
        cached = self._sub_engine_memo.get(memo_key)
        if cached is not None:
            return self.provenance.set(self._var_name(ir.lvalue), cached)
        sub = ProvenanceEngine(
            callee,
            internal_call_depth=self.internal_call_depth - 1,
            worklist_cap=self.worklist_cap,
            parameter_bindings=bindings,
        )
        sub._call_stack = self._call_stack + [callee_name or "?"]
        sub.run()
        return_sources = self._collect_return_sources(callee, sub.provenance)
        if not return_sources:
            return_sources = frozenset({call_tag})
        else:
            return_sources = union(return_sources, frozenset({call_tag}))
        self._sub_engine_memo[memo_key] = return_sources
        return self.provenance.set(self._var_name(ir.lvalue), return_sources)

    def _handle_new(self, ir: Any) -> bool:
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        result = frozenset(
            {
                Source(
                    kind="computed",
                    computed_kind="new",
                    callee_args_digest=_digest(args_union),
                )
            }
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_send_transfer(self, ir: Any) -> bool:
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        return self.provenance.set(
            self._var_name(ir.lvalue), frozenset({Source(kind="computed", computed_kind="send_transfer")})
        )

    def _sources_for_value(self, value: Any) -> SourceSet:
        if value is None:
            return EMPTY
        cached = self._leaf_value_source_cache.get(id(value))
        if cached is not None:
            return cached
        if isinstance(value, SolidityVariable):
            result = self._classify_solidity_variable(value)
            self._leaf_value_source_cache[id(value)] = result
            return result
        if isinstance(value, Constant):
            result: SourceSet = frozenset(
                {
                    Source(
                        kind="constant",
                        constant_value=str(value.value),
                        value_type=_solidity_type_name(value),
                    )
                }
            )
            self._leaf_value_source_cache[id(value)] = result
            return result
        if isinstance(value, StateVariable):
            result = frozenset(
                {
                    Source(
                        kind="state_variable",
                        state_variable_name=value.name,
                    )
                }
            )
            self._leaf_value_source_cache[id(value)] = result
            return result
        # References take whatever provenance is computed for them; SSA names fall back to the base name (seeded by
        # bindings).
        if isinstance(value, (LocalVariable, TemporaryVariable, ReferenceVariable)):
            name = self._var_name(value)
            if name:
                sources = self.provenance.get(name)
                if not sources:
                    base = _strip_ssa_suffix(name)
                    if base != name:
                        sources = self.provenance.get(base)
                return sources
            return EMPTY
        if isinstance(value, Variable):
            name = self._var_name(value)
            if not name:
                return EMPTY
            sources = self.provenance.get(name)
            if not sources:
                base = _strip_ssa_suffix(name)
                if base != name:
                    sources = self.provenance.get(base)
            return sources
        return EMPTY

    def _classify_solidity_variable(self, var: Any) -> SourceSet:
        """``msg.sender``, ``tx.origin``, ``block.*`` by name: these are language keywords, not user identifiers."""
        name = getattr(var, "name", "")
        if name == "msg.sender":
            return frozenset({Source(kind="msg_sender")})
        if name == "tx.origin":
            return frozenset({Source(kind="tx_origin")})
        if name == "this":
            # ``require(msg.sender == address(this))`` self-call gates.
            return frozenset({Source(kind="self_address")})
        if name in (
            "block.timestamp",
            "block.number",
            "block.chainid",
            "block.coinbase",
            "block.difficulty",
            "block.gaslimit",
            "now",
            "block.basefee",
            "block.prevrandao",
        ):
            return frozenset(
                {
                    Source(
                        kind="block_context",
                        block_context_kind=name.split(".", 1)[-1] if "." in name else name,
                    )
                }
            )
        if name in ("msg.value", "msg.data", "msg.sig", "msg.gas"):
            return frozenset({Source(kind="computed", computed_kind=name)})
        return TOP  # unknown Solidity keyword — be safe

    def _union_of_args(self, args: Iterable[Any]) -> SourceSet:
        out: SourceSet = EMPTY
        for arg in args:
            out = union(out, self._sources_for_value(arg))
        return out

    def _collect_return_sources(self, callee: Any, prov: ProvenanceMap) -> SourceSet:
        """Union of the provenance of every returned value, including Solidity variables returned directly."""
        # Read from the sub-engine's map.
        original = self.provenance
        self.provenance = prov
        try:
            out: SourceSet = EMPTY
            for node in callee.nodes:
                for ir in getattr(node, "irs_ssa", ()):
                    if isinstance(ir, Return):
                        for v in getattr(ir, "values", ()):
                            out = union(out, self._sources_for_value(v))
            return out
        finally:
            self.provenance = original

    @staticmethod
    def _var_name(var: Any) -> str:
        return getattr(var, "name", None) or ""


def _strip_ssa_suffix(name: str) -> str:
    """Strip the SSA suffix (``account_1`` -> ``account``) so seeded base names are found."""
    if not name:
        return name
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


def _callee_signature(ir: Any) -> str | None:
    fn = getattr(ir, "function", None)
    for attr in ("full_name", "signature_str"):
        value = getattr(fn, attr, None)
        if isinstance(value, str) and "(" in value and value.endswith(")"):
            return value.rsplit(".", 1)[-1]
    value = getattr(ir, "function_name", None)
    if isinstance(value, str) and "(" in value and value.endswith(")"):
        return value.rsplit(".", 1)[-1]
    return None


def _dispatch_selector(callee: Any, declared_signature: str | None) -> str | None:
    # ``callee_signature`` keeps Slither's spelling; the selector is the one the call dispatches.
    from .predicate_artifacts import dispatch_selector

    return dispatch_selector(callee, declared_signature)


def _canonical_source_key(source: "Source") -> str:
    """Deterministic content key over every field of a Source, including the digest and ``derived_from`` (one level)."""
    return "\x1f".join(
        str(part)
        for part in (
            source.kind,
            source.parameter_index,
            source.parameter_name,
            source.state_variable_name,
            source.callee,
            source.callee_args_digest,
            source.callee_signature,
            source.callee_selector,
            source.constant_value,
            source.value_type,
            source.computed_kind,
            source.block_context_kind,
            "/".join(source.member_path or ()),
            source.storage_slot,
            "None"
            if source.derived_from is None
            else "|".join(f"{_source_token(origin):016x}" for origin in sorted_tokens(source.derived_from)),
        )
    )


def sorted_tokens(members: "frozenset[Source]") -> "list[Source]":
    """Members ordered by content token, independent of set iteration order."""
    return sorted(members, key=_source_token)


def _source_token(source: "Source") -> int:
    """Content-stable 64-bit token for a Source, cached on the instance.

    A structural cache deep-compared dataclasses on every lookup (134M ``__eq__`` calls on one unit).
    """
    token = source.__dict__.get("_content_token")
    if token is None:
        token = int.from_bytes(keccak(text=_canonical_source_key(source))[:8], "big")
        # Bypasses the frozen guard; not a field, so repr/eq/hash ignore it.
        object.__setattr__(source, "_content_token", token)
    return token


def _digest(s: SourceSet) -> str:
    """Order-independent, process-stable digest of a SourceSet (XOR of member tokens).

    The previous ``hash()`` depended on PYTHONHASHSEED and flipped which tied operand got published between runs.
    O(members); a frozenset has no duplicates to cancel.
    """
    acc = 0
    for member in s:
        acc ^= _source_token(member)
    return f"{acc & 0xFFFFFFFF:08x}"
