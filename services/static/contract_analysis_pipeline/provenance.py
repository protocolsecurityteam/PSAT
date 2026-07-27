"""ProvenanceEngine — worklist-based forward dataflow over Slither IR.

Tracks the source(s) of every SSA value reachable in a function context.
Output: a ``ProvenanceMap`` from SSA value → set of ``Source`` records.
The predicate builder consumes this to populate ``Operand`` records on
each leaf.

Design (per /tmp/psat-plans/generic-predicate-pipeline-v4.md):

* Lattice element per value = a ``frozenset[Source]``. Bottom is the
  empty set (unreached); top is ``{Source(kind="top")}`` (saturated by
  cycle / depth cap / unknown opcode).
* Worklist iterates IR opcodes in CFG order, applying transfer
  functions until fixed point. Phi nodes union incoming sources.
* Cycle handling: same SSA value re-encountered while we have an
  in-flight tag for it yields ``top``. Loop-carried Phi joins
  converge or saturate.

This module is intentionally name-free — no helper-name seed lists like
the deleted ``MsgSenderTaint``. Every classification comes from IR
shape and operand type.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Any, Iterable

from eth_utils.crypto import keccak

# Slither IR types — imported lazily where they aren't part of the
# module's public surface so this file remains importable in test
# environments without solc.

try:
    from slither.core.declarations import SolidityVariable  # type: ignore[import]
    from slither.core.variables import Variable  # type: ignore[import]
    from slither.core.variables.local_variable import LocalVariable  # type: ignore[import]
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]
    from slither.slithir.operations import (  # type: ignore[import]
        Assignment,
        Binary,
        HighLevelCall,
        Index,
        InternalCall,
        Length,
        LibraryCall,
        LowLevelCall,
        Member,
        NewArray,
        NewContract,
        NewElementaryType,
        OperationWithLValue,
        Phi,
        Return,
        Send,
        SolidityCall,
        Transfer,
        TypeConversion,
        Unary,
        Unpack,
    )
    from slither.slithir.variables import Constant, ReferenceVariable, TemporaryVariable  # type: ignore[import]

    SLITHER_AVAILABLE = True
except Exception:  # pragma: no cover — only when slither unavailable
    SLITHER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Source record — one origin tag for an SSA value.
# ---------------------------------------------------------------------------


SOURCE_KINDS = (
    "msg_sender",
    "tx_origin",
    "parameter",
    "state_variable",
    "constant",
    "view_call",
    "external_call",
    "computed",
    "block_context",
    "signature_recovery",
    "self_address",
    "top",
)


@dataclass(frozen=True)
class Source:
    """One origin record for an SSA value.

    Equality is structural (frozen dataclass). Provenance sets are
    ``frozenset[Source]`` so they hash cleanly for cycle detection and
    fixed-point comparison.
    """

    kind: str  # one of SOURCE_KINDS
    parameter_index: int | None = None
    parameter_name: str | None = None
    state_variable_name: str | None = None
    callee: str | None = None
    # Hash of constituent source frozensets — used to keep view_call /
    # external_call recursive shape without making Source recursive.
    callee_args_digest: str | None = None
    callee_signature: str | None = None
    callee_selector: str | None = None
    constant_value: str | None = None
    value_type: str | None = None
    computed_kind: str | None = None
    block_context_kind: str | None = None
    member_path: tuple[str, ...] = ()
    # Keccak/constant slot a getter-less internal *address* accessor reads via
    # inline ``sload(<constant>)`` (Governable ``_pendingGovernor`` →
    # keccak256("LRTSquare.pending.governor")). Carried so resolution can read
    # the live value via ``eth_getStorageAt``; ``None`` for everything else.
    storage_slot: str | None = None
    # Which origins reached a ``computed`` value through its *arguments*. A
    # ``keccak256``/``abi.encode`` collapses its inputs into one opaque value;
    # without this the parameter a hash-commitment guard commits is gone by the
    # time a leaf is built. Three states, and consumers must tell them apart:
    #   ``None``        — not determined; nothing populated it for this Source
    #   ``frozenset()`` — determined: only constants reached the computation
    #   non-empty       — determined: exactly these origins reached it
    # Members are themselves ``Source`` records with ``derived_from=None``, which
    # bounds the nesting at one level: ``arg_origins`` splices an argument's own
    # (already flattened) origins in rather than nesting them, so the projection
    # is transitively complete without making the dataclass recursive.
    derived_from: frozenset["Source"] | None = None

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise ValueError(f"unknown source kind {self.kind!r}")
        # The "top" lattice element is a bare sentinel — no metadata
        # fields. ``is_top`` does an O(1) ``_TOP_SOURCE in set`` check,
        # which only works if every kind="top" instance hashes/equals
        # ``_TOP_SOURCE``. Enforce that here so a future caller can't
        # silently break the optimization by tagging a "top with
        # metadata".
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
    # O(1) frozenset hash lookup. Equivalence with the prior
    # ``any(src.kind == "top" for src in s)`` is held by the
    # ``__post_init__`` invariant above: every kind="top" Source
    # equals (and hashes as) ``_TOP_SOURCE``.
    return _TOP_SOURCE in s


def union(a: SourceSet, b: SourceSet) -> SourceSet:
    """Lattice join: union of source sets, with TOP absorbing."""
    if is_top(a) or is_top(b):
        return TOP
    return a | b


def arg_origins(args_union: SourceSet) -> frozenset[Source]:
    """The ``Source.derived_from`` projection of an argument source set.

    Flat by construction: an argument that is itself a ``computed`` value with
    its own ``derived_from`` contributes both itself (stripped, so the
    derivation shape survives) and its already-flattened origins, so
    ``keccak256(abi.encode(receiver))`` still names ``receiver``. Constants are
    dropped — they carry no origin — which is what makes the empty set mean
    "determined: only constants reached this".

    Every member is stored with ``derived_from=None``. That is a *stripped*
    marker, not a claim of "not determined" about the member: the member's own
    origins have already been spliced into this same set.
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
    """The keccak/constant slot a getter-less internal *address* accessor reads
    via inline ``sload(<constant>)`` — e.g. ``Governable._pendingGovernor()``
    reading ``keccak256("LRTSquare.pending.governor")``. Returns the 0x-padded
    32-byte slot so resolution can ``eth_getStorageAt`` it (the accessor has no
    public getter to call); ``None`` for anything that isn't an unambiguous
    single-constant-slot *address* reader. Reuses the split-proxy sload-constant
    detection — the only existing place this pattern is mined — and is tightened
    to address returns + exactly one constant slot so a non-address ``sload``
    (e.g. a bytes32 flag) can't be misread as a 20-byte principal."""
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


# ---------------------------------------------------------------------------
# Per-function provenance map + engine.
# ---------------------------------------------------------------------------


# Configuration knobs (tunable at call site / via env).
# PSAT_PROVENANCE_INTERNAL_CALL_DEPTH overrides the default recursion
# depth for InternalCall/LibraryCall — useful for stress-testing on
# complex inheritance chains, or for cutting off depth on benchmarks.
# PSAT_PROVENANCE_WORKLIST_CAP overrides the worklist iteration cap.
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


@dataclass
class ProvenanceMap:
    """Per-SSA-value provenance for one function context.

    Keyed by Slither variable name (string) since SSA values from
    Slither expose a stable ``name`` attribute. Phi nodes share the
    base name with versioning Slither already handles.
    """

    sources: dict[str, SourceSet]

    def get(self, var_name: str) -> SourceSet:
        return self.sources.get(var_name, EMPTY)

    def set(self, var_name: str, value: SourceSet) -> bool:
        """Returns True if this set changed the value (used by worklist
        to detect convergence)."""
        prev = self.sources.get(var_name, EMPTY)
        if prev == value:
            return False
        self.sources[var_name] = value
        return True


class ProvenanceEngine:
    """Forward dataflow over a function's SSA IR.

    Lifecycle:
        engine = ProvenanceEngine(function)
        engine.run()                  # populates internal map to fixed point
        sources = engine.provenance.get("some_ssa_var")
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
        # Stack of ParameterBindingEnv frames pushed when recursing into
        # internal callees / modifiers. Top of stack is the active env.
        self._binding_frames: list[dict[str, SourceSet]] = []
        if parameter_bindings:
            self._binding_frames.append(dict(parameter_bindings))
        # Track in-flight callees to break cycles.
        self._call_stack: list[str] = []
        # Per-engine memo: (callee_full_name, frozenset(bindings.items()))
        # → return_sources. The worklist iterates to fixed point so a
        # callee may be re-visited many times within ONE run() — caching
        # keeps each unique (callee, bindings) sub-engine run to a single
        # invocation rather than O(worklist_iterations) re-walks.
        # Sub-engines created by _handle_internal_call inherit a fresh
        # cache; the memo is intentionally not propagated downward
        # because the call_stack at the deeper level differs and would
        # invalidate the keys.
        self._sub_engine_memo: dict[tuple[str, frozenset], frozenset] = {}
        # Per-engine cache for leaf-value source classification —
        # SolidityVariable / Constant / StateVariable are PURE functions
        # of the value object, not of engine state. The worklist iterates
        # to fixed point so the same operand is re-resolved many times
        # within ONE run() — caching by id collapses each unique value
        # to a single classification call. Bounded lifetime (= engine
        # instance), so no cross-Slither-instance id-reuse risk.
        # Variable subtypes (Local/Temporary/Reference/Variable) are NOT
        # cached because their provenance changes as dataflow converges.
        self._leaf_value_source_cache: dict[int, SourceSet] = {}

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------

    def run(self) -> ProvenanceMap:
        """Seed parameter and msg-related variables, then iterate the
        worklist until fixed point or cap hit."""
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
        if iterations >= self.worklist_cap:
            # Saturate any value we still don't know about by leaving
            # it empty; consumers treat absent ⇒ unknown. The cap is
            # high enough that real contracts converge well before.
            pass
        return self.provenance

    # ------------------------------------------------------------------
    # Seeding
    # ------------------------------------------------------------------

    def _seed_parameters(self) -> None:
        """Bind each formal parameter to a `parameter` source. Also
        seeds modifier-scope parameters so the engine can resolve
        operands inside modifier bodies."""
        bindings = self._active_bindings()
        for idx, param in enumerate(self.function.parameters):
            name = self._var_name(param)
            if not name:
                continue
            if bindings is not None and name in bindings:
                # Substituted from caller — use caller's provenance.
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
        # Modifier parameters: each modifier's formal parameters get
        # seeded as local `parameter` sources. ParameterBindingEnv (a
        # later sub-task) will substitute these with the invocation
        # arguments at the call site so the leaf reports the
        # function-level parameter index correctly. For now, the
        # modifier-scope parameter index is what's recorded — fine
        # for operand classification but not for argument binding to
        # the calling function.
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

    # ------------------------------------------------------------------
    # IR walk
    # ------------------------------------------------------------------

    def _iter_nodes(self) -> Iterable[Any]:
        # Function body only — modifier nodes are deliberately excluded.
        #
        # Slither shares the modifier's SSA-IR across every caller, so the
        # entry Phi for a modifier parameter unions ALL call-site
        # arguments (one per function that uses the modifier). When the
        # modifier parameter shares a name with the function's parameter
        # (e.g. ``modifier onlyRole(bytes32 role)`` and
        # ``function revokeRole(bytes32 role, address account)``), that
        # Phi pollutes the function's ``role`` provenance with every
        # other caller's argument — state vars, TMPs of unrelated helpers,
        # etc. The pollution grows the binding sets unboundedly, so the
        # per-IR ``_sub_engine_memo`` keyed on ``(callee, bindings)``
        # never hits across worklist iterations and the engine respawns
        # the same sub-engines until the 200-iter cap. On CumulativeMerkleDrop
        # this turned a 0.02 s build into an 18 s one (revokeRole).
        #
        # Cross-fn gates that live inside the modifier (the canonical case:
        # ``onlyRole`` -> ``_checkRole`` -> ``if (!hasRole(...)) revert``)
        # are still discovered by RevertDetector's recursive scan, and the
        # predicate builder walks them through ``_build_chain_bindings``
        # which spawns a fresh ProvenanceEngine for each link with the
        # call-site bindings — that path is unaffected.
        yield from self.function.nodes

    def _step_node(self, node: Any) -> bool:
        """Apply transfer functions to all IRs in this CFG node.
        Returns True if any provenance value changed."""
        any_changed = False
        for ir in node.irs_ssa:
            if self._step_ir(ir):
                any_changed = True
        return any_changed

    def _step_ir(self, ir: Any) -> bool:
        # Dispatch on Slither IR class. We import lazily so this file
        # is importable without solc available in test envs.
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
            # Returns don't bind a new lvalue here — caller handles
            # callee-return propagation via _handle_internal_call.
            return False
        # Unknown opcode: assign top to its lvalue (if any) so the
        # consumer surfaces it as opaque rather than guessing.
        if isinstance(ir, OperationWithLValue):
            lv = ir.lvalue
            if lv is not None:
                return self.provenance.set(self._var_name(lv), TOP)
        return False

    # ------------------------------------------------------------------
    # Transfer functions
    # ------------------------------------------------------------------

    def _handle_assignment(self, ir: Any) -> bool:
        rvalue_sources = self._sources_for_value(ir.rvalue)
        return self.provenance.set(self._var_name(ir.lvalue), rvalue_sources)

    def _handle_type_conversion(self, ir: Any) -> bool:
        # Type cast preserves origin — `address(payable(x))` keeps x's source.
        rvalue = getattr(ir, "variable", None) or getattr(ir, "rvalue", None)
        if rvalue is None:
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        sources = self._sources_for_value(rvalue)
        return self.provenance.set(self._var_name(ir.lvalue), sources)

    def _handle_phi(self, ir: Any) -> bool:
        # Phi joins all incoming SSA versions with set union. Also
        # unions with the lvalue's existing source set so caller-
        # bound parameters seeded before the IR walk aren't
        # clobbered. Slither's parameter-Phi at function entry
        # represents the caller's binding via incoming SSA values
        # the engine can't resolve in the callee's scope; the
        # binding lives in the seeded source set.
        result: SourceSet = self.provenance.get(self._var_name(ir.lvalue))
        for incoming in ir.rvalues:
            result = union(result, self._sources_for_value(incoming))
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_binary(self, ir: Any) -> bool:
        # The result of a binary op is ``computed`` with the union of
        # its operand sources tagged for downstream consumers.
        operand_sources = union(
            self._sources_for_value(ir.variable_left),
            self._sources_for_value(ir.variable_right),
        )
        if is_top(operand_sources):
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        # Wrap in a single ``computed`` source with a digest of the
        # operand union — keeps the provenance flat but preserves
        # taint-shape for downstream analysis.
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
                    )
                }
            )
            | operand_sources
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_index(self, ir: Any) -> bool:
        """``map[k]`` — the lvalue is a ReferenceVariable whose access
        path includes the base mapping plus the key. Provenance is the
        union of base + key sources, plus a ``computed`` tag carrying
        the key origin so downstream consumers can route on it."""
        base = getattr(ir, "variable_left", None)
        key = getattr(ir, "variable_right", None)
        base_sources = self._sources_for_value(base) if base is not None else EMPTY
        key_sources = self._sources_for_value(key) if key is not None else EMPTY
        result = union(base_sources, key_sources)
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_length(self, ir: Any) -> bool:
        """``arr.length`` / ``str.length`` — propagates the array's
        provenance to the length value, tagged with
        ``computed_kind="length"``. Loop bounds reading
        ``params.length`` thus inherit the parameter taint of the
        array, which lets the worklist converge on loop-carried
        values without saturating to TOP.
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
        """``s.field`` — propagate base sources AND tag the result with
        a ``computed`` source whose ``computed_kind`` is
        ``member.<field_name>``. Predicate builder reads computed_kind
        to surface the field path; e.g. for
        ``records[key].adminRole`` the leaf will see both the base
        provenance (state_variable _roles + parameter role) and the
        field tag (``member.adminRole``).
        """
        base = getattr(ir, "variable_left", None)
        field = getattr(ir, "variable_right", None)
        base_sources = self._sources_for_value(base) if base is not None else EMPTY
        # Slither's Member.variable_right is a Constant whose value is
        # the field name string. Fall back to repr for unusual shapes.
        field_name: str | None = None
        if field is not None:
            field_name = getattr(field, "value", None) or getattr(field, "name", None) or str(field)
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
        """``ecrecover``, ``keccak256``, ``addmod``, etc. ecrecover
        gets a dedicated ``signature_recovery`` source tag. Hash
        functions get ``computed``."""
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
        # Other Solidity built-ins: hash family → computed. The arguments'
        # origins ride along on ``derived_from`` — a hash-commitment gate
        # (``publicDepositHistory[nonce] != keccak256(abi.encode(receiver, …))``)
        # otherwise reaches the leaf builder with every parameter it commits
        # already collapsed into an opaque digest, so the leaf can be *captured*
        # without ever being *bound* to what it constrains.
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
        """High-level call to a known interface — ``other.method(args)``.
        Records the callee name (function symbol) so the predicate
        builder can route on it."""
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        callee_name = getattr(getattr(ir, "function", None), "name", None) or getattr(ir, "function_name", None)
        callee_signature = _callee_signature(ir)
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        result = frozenset(
            {
                Source(
                    kind="external_call",
                    callee=callee_name,
                    callee_args_digest=_digest(args_union),
                    callee_signature=callee_signature,
                    callee_selector=_selector_for_signature(callee_signature),
                )
            }
        )
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_low_level_call(self, ir: Any) -> bool:
        """``addr.call(data)`` / ``staticcall`` / ``delegatecall``.

        LowLevelCall has no resolved function symbol (the target is an
        arbitrary address). What matters for downstream analysis:
          - the call kind (call/staticcall/delegatecall) — delegatecall
            in particular executes target code in our context, so we
            preserve the kind in ``computed_kind``;
          - the destination's provenance (where the target address
            came from) — propagated into the result so a later check
            on the call result can see if the target was caller-
            controlled / state-loaded / parameter-loaded.

        Result is a tuple (bool, bytes) which Slither models as a
        TupleVariable lvalue; subsequent ``Unpack`` IRs split it into
        the individual return values. Each unpacked value inherits the
        tuple's provenance.
        """
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        kind = getattr(ir, "function_name", None) or "low_level_call"
        dest_sources = self._sources_for_value(getattr(ir, "destination", None))
        args_union = self._union_of_args(getattr(ir, "arguments", ()))
        # delegatecall is special — we tag it as external_call (it's still
        # external from a control-flow perspective; the predicate builder
        # treats delegatecall result the same as call result), but the
        # destination provenance travels through so a downstream check
        # can flag delegatecall-to-untrusted-target if needed.
        result = frozenset(
            {
                Source(
                    kind="external_call",
                    callee=kind,  # "call" / "staticcall" / "delegatecall"
                    callee_args_digest=_digest(union(dest_sources, args_union)),
                )
            }
        )
        # Also propagate destination + args sources so unpacked tuple
        # inherits caller/state/parameter taint.
        result = union(result, dest_sources)
        result = union(result, args_union)
        return self.provenance.set(self._var_name(ir.lvalue), result)

    def _handle_unpack(self, ir: Any) -> bool:
        """``Unpack`` splits a tuple lvalue into its components. Each
        component inherits the tuple's full provenance — Slither doesn't
        track per-tuple-position taint, so we conservatively forward
        the whole set."""
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        # The tuple operand is exposed as `ir.tuple` on Slither; fall
        # back to ``ir.rvalue`` for older versions.
        tup = getattr(ir, "tuple", None) or getattr(ir, "rvalue", None)
        if tup is None:
            return self.provenance.set(self._var_name(ir.lvalue), TOP)
        sources = self._sources_for_value(tup)
        return self.provenance.set(self._var_name(ir.lvalue), sources)

    def _handle_internal_call(self, ir: Any) -> bool:
        """Recurse into the callee's body, with parameter bindings
        substituted, up to ``internal_call_depth``. Returns the
        callee's union of return-value provenance."""
        if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
            return False
        callee = getattr(ir, "function", None)
        callee_name = getattr(callee, "full_name", None) or getattr(callee, "name", None)
        # Slot a getter-less address accessor sload()s, so resolution can read
        # the live value even though the accessor has no public getter.
        accessor_slot = _constant_storage_slot_for_accessor(callee)
        # Cycle / depth guard.
        call_tag = Source(
            kind="view_call",
            callee=callee_name,
            callee_signature=callee_name,
            callee_selector=_selector_for_signature(callee_name),
            callee_args_digest=_digest(self._union_of_args(getattr(ir, "arguments", ()))),
            storage_slot=accessor_slot,
        )
        if callee is None or len(self._call_stack) >= self.internal_call_depth or callee_name in self._call_stack:
            args_union = self._union_of_args(getattr(ir, "arguments", ()))
            tag = frozenset(
                {
                    Source(
                        kind="view_call",
                        callee=callee_name,
                        callee_args_digest=_digest(args_union),
                        callee_signature=callee_name,
                        callee_selector=_selector_for_signature(callee_name),
                        storage_slot=accessor_slot,
                    )
                }
            )
            return self.provenance.set(self._var_name(ir.lvalue), tag)
        # Recurse into callee's IR with bindings.
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
        # Callee return provenance: union of all returned values' sources.
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

    # ------------------------------------------------------------------
    # Source resolution for an arbitrary IR operand
    # ------------------------------------------------------------------

    def _sources_for_value(self, value: Any) -> SourceSet:
        if value is None:
            return EMPTY
        # Per-engine leaf cache: bounded lifetime, no cross-instance
        # id-reuse risk. Lookup by id is O(1) and short-circuits the
        # isinstance chain below for the dominant repeated cases.
        cached = self._leaf_value_source_cache.get(id(value))
        if cached is not None:
            return cached
        # SolidityVariable: msg.sender / tx.origin / block.* / now etc.
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
        # ReferenceVariable (e.g., result of Index/Member) — propagate
        # whatever provenance has been computed for the reference.
        # Slither's SSA suffixes parameter names with ``_N``; if the
        # SSA name has no entry but the base name does (seeded via
        # parameter_bindings), fall back to the base.
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
        # Bare Variable fallback.
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
        """msg.sender → msg_sender; tx.origin → tx_origin; block.* →
        block_context; rest → top.

        Detection is by ``var.name``. This is NOT user-identifier name
        matching (that's the bad pattern we deleted) — these are
        Solidity language keywords with a fixed enum on Slither's side.
        """
        name = getattr(var, "name", "")
        if name == "msg.sender":
            return frozenset({Source(kind="msg_sender")})
        if name == "tx.origin":
            return frozenset({Source(kind="tx_origin")})
        if name == "this":
            # Self-address — the contract's own address, structurally
            # an authority operand for self-call gates like
            # ``require(msg.sender == address(this))``.
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
        """Union the provenance of every value the callee returns.

        Uses ``_sources_for_value`` so SolidityVariable returns
        (``return msg.sender``) classify even when there's no
        intermediate assignment writing them into ``prov``."""
        # Snapshot self.provenance so _sources_for_value reads from
        # the sub-engine's run instead of the caller's state.
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _strip_ssa_suffix(name: str) -> str:
    """Slither's SSA gives ``account_1`` for the first version of
    the parameter ``account``. When parameter_bindings seeds
    ``account``, downstream IR walks reference ``account_1`` — so
    if the SSA-named lookup misses, fall back to the base name."""
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


def _selector_for_signature(signature: str | None) -> str | None:
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _digest(s: SourceSet) -> str:
    """Stable digest of a SourceSet for nesting via ``callee_args_digest``.

    Source is frozen so ``hash(s)`` is stable; we hex it for the JSON
    serializer's benefit (artifacts are JSON, ints aren't).
    """
    return f"{abs(hash(s)) & 0xFFFFFFFF:08x}"
