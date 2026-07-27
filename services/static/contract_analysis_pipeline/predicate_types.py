"""Typed shapes for the predicate-based access analysis output.

These are the semantic schema types — the static stage emits a
``PredicateTree`` per guarded function describing the structural gates
that admit it, and the resolver evaluates that tree. No
shape-name labels in the routing path; shape labels are diagnostic
only.

The plan is /tmp/psat-plans/generic-predicate-pipeline-v{4,5,6,7}.md.

These types live in their own module so the runtime predicate builder,
the schema, and the resolver can import them without circular deps.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

# ---------------------------------------------------------------------------
# Operand — where a value in a predicate originates.
# ---------------------------------------------------------------------------


OperandSource = Literal[
    "msg_sender",
    "tx_origin",
    "parameter",
    "state_variable",
    "constant",
    "view_call",  # internal call returning a value
    "external_call",  # high-level call to another contract
    "computed",  # arithmetic / hash / abi.encode result
    "block_context",  # block.timestamp / number / chainid / coinbase
    "signature_recovery",  # ecrecover / EIP-1271 isValidSignature output
    "top",  # provenance saturated (cycles, depth cap)
]


class Operand(TypedDict):
    source: OperandSource
    parameter_index: NotRequired[int | None]
    parameter_name: NotRequired[str | None]
    state_variable_name: NotRequired[str | None]
    member_path: NotRequired[list[str]]
    callee: NotRequired[str | None]
    callee_signature: NotRequired[str | None]
    callee_selector: NotRequired[str | None]
    callee_args: NotRequired[list["Operand"]]
    # Keccak/constant storage slot a getter-less internal address accessor reads
    # via inline ``sload(<constant>)`` (e.g. Governable ``_pendingGovernor``).
    # Lets resolution read the live value through ``eth_getStorageAt`` when no
    # public getter exists. Absent for every other operand.
    storage_slot: NotRequired[str | None]
    # Set when ``msg.sender == <mapping>[<param>]`` gates a function on a mapping
    # value keyed by a function parameter (L1BaseSyncPool ``receivers[originEid]``,
    # claim #3 group C). ``mapping_name`` is the storage mapping; ``mapping_writer_specs``
    # are the value-enumeration WriterEventSpecs the contract-wide mapping-event pass
    # attaches. Resolution enumerates the mapping's VALUE set (the authorized callers)
    # from those setter events rather than reading a getter. Absent for every other operand.
    mapping_name: NotRequired[str | None]
    mapping_writer_specs: NotRequired[list[dict[str, Any]] | None]
    constant_value: NotRequired[str | None]
    value_type: NotRequired[str | None]
    computed_kind: NotRequired[str | None]
    block_context_kind: NotRequired[str | None]
    # Which origins reached this value through the arguments of the computation
    # that produced it — the parameters a ``keccak256``/``abi.encode`` commitment
    # binds, which the digest would otherwise have collapsed. Present on every
    # ``source == "computed"`` operand and on no other, so absence means the
    # question does not apply. Three states on a computed operand, and a consumer
    # must distinguish all three:
    #   key absent   — not a computed operand
    #   ``None``     — computed, argument provenance NOT DETERMINED (nothing
    #                  populated it; today that is every computed operand except
    #                  the ones a Solidity built-in call produced)
    #   ``[]``       — computed, determined: only constants reached it
    #   non-empty    — computed, determined: exactly these origins reached it
    # ``op.get("derived_from") or []`` therefore reads not-determined as
    # proven-none and is wrong; test for ``None`` explicitly.
    derived_from: NotRequired[list["Operand"] | None]


# ---------------------------------------------------------------------------
# SetDescriptor — instructions for a membership predicate.
# ---------------------------------------------------------------------------


SetKind = Literal[
    "mapping_membership",
    "array_contains",
    "external_set",
    "bitwise_role_flag",  # only inside unsupported leaves
    "diamond_facet_acl",  # only inside unsupported leaves
]


class AuthorityContract(TypedDict):
    address_source: Operand
    abi_hint: NotRequired[str | None]


RoleDomainSource = Literal[
    "compile_time_constants",
    "role_granted_history",
    "abi_declared",
    "manual_pinned",
]


class RoleDomain(TypedDict):
    parameter_index: int
    auto_seed_default_admin: bool
    sources: list[RoleDomainSource]
    recursive_role_admin_expansion: bool


class SelectorContext(TypedDict):
    selectors: list[str]


class EventHint(TypedDict):
    event_address: str
    topic0: str
    topics_to_keys: dict[int, int]
    data_to_keys: dict[int, int]
    direction: Literal["add", "remove", "set"]
    key_value_taint: NotRequired[str | None]
    event_signature: NotRequired[str | None]
    event_name: NotRequired[str | None]
    mapping_name: NotRequired[str | None]
    key_position: NotRequired[int | None]
    indexed_positions: NotRequired[list[int]]
    value_position: NotRequired[int | None]
    writer_function: NotRequired[str | None]


class ValuePredicate(TypedDict):
    """Filter on the *value* a mapping read returns.

    The static layer used to collapse ``map[k] == const`` into
    ``truthy_value`` only, dropping both the operator and the RHS
    structure. ``ValuePredicate`` preserves the polarity-folded form so
    downstream backends (HyperSync direct replay, durable indexer,
    trace replay) can filter latest-value state by the predicate the
    contract actually checks.

    Always describes the **allowed** value(s) — i.e. an
    ``if (m[k] != 10) revert`` source ends up as
    ``op="eq", rhs_values=["10"]``.
    """

    op: Literal["eq", "ne", "lt", "lte", "gt", "gte", "in", "any_nonzero"]
    rhs_values: list[str]
    value_type: str  # solidity type, e.g. "uint256", "address", "bytes32"
    mask: NotRequired[str | None]  # optional bit-mask for flag patterns


class SetDescriptor(TypedDict):
    kind: SetKind
    storage_var: NotRequired[str | None]
    storage_slot: NotRequired[str | None]
    key_sources: list[Operand]
    truthy_value: NotRequired[str | None]
    # First-class form of the same constraint ``truthy_value`` partially
    # captured. Adapters that understand value predicates (D.2-D.5)
    # filter members by ``op``+``rhs_values`` against latest mapping
    # values; older adapters that only read ``truthy_value`` keep
    # working unchanged.
    value_predicate: NotRequired[ValuePredicate | None]
    enumeration_hint: NotRequired[list[EventHint]]
    authority_contract: NotRequired[AuthorityContract | None]
    role_domain: NotRequired[RoleDomain | None]
    selector_context: NotRequired[SelectorContext | None]
    callee_function: NotRequired[str | None]
    callee_signature: NotRequired[str | None]
    callee_selector: NotRequired[str | None]


# ---------------------------------------------------------------------------
# LeafPredicate + PredicateTree.
# ---------------------------------------------------------------------------


LeafKind = Literal[
    "membership",
    "equality",
    "comparison",
    "external_bool",
    "signature_auth",
    "unsupported",
]

LeafOperator = Literal[
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "truthy",
    "falsy",
]

AuthorityRole = Literal[
    "caller_authority",
    "delegated_authority",
    "time",
    "reentrancy",
    "pause",
    "business",
    "one_shot",
]


Confidence = Literal["high", "medium", "low"]


class LeafPredicate(TypedDict):
    kind: LeafKind
    operator: LeafOperator
    authority_role: AuthorityRole
    confidence: NotRequired[Confidence]
    operands: list[Operand]
    set_descriptor: NotRequired[SetDescriptor | None]
    unsupported_reason: NotRequired[str | None]
    references_msg_sender: bool
    parameter_indices: list[int]
    expression: str
    basis: list[str]
    # external_bool / bool-result provenance (the caller-taint default's
    # structural discriminators — absent on trees built before they were
    # stamped, and consumers must tolerate that):
    # declared callee mutability: "view" / "pure" / "nonview" (effectful
    # external, incl. wrapper libraries whose body reaches an external
    # call) / "nonview_library" (effectful library touching only the
    # contract's own storage).
    callee_state_mutability: NotRequired[str | None]
    # The RevertGate kind that produced this leaf ("require",
    # "external_call_revert", "try_catch_revert", …): a result-checked
    # require gates on the returned bool; a void statement call gates on
    # the callee's entire revert surface.
    gate_kind: NotRequired[str | None]
    # Canonical ABI signature of the callee (arg TYPES, used e.g. for the
    # bytes32[] merkle-witness discriminator — never the callee name).
    callee_signature: NotRequired[str | None]
    # Where the one-shot latch this leaf reads lives on-chain, so resolution
    # can read its live value (consumed vs live) against the deployment
    # address. Stamped by ``one_shot.apply_one_shot_pass`` on the version-var
    # leaf of an initializer-family gate; absent everywhere else. Keys:
    # ``kind`` ("storage"|"getter"), ``slot``/``byte_offset``/``size_bytes``/
    # ``value_type``/``variable`` for storage reads, ``selector`` for getter
    # reads, ``expected_version`` (reinitializer target), ``standard``.
    one_shot_latch: NotRequired[dict[str, Any] | None]
    # True when the leaf matched the name-free structural latch detector but
    # NOT a recognized initializer standard. A candidate never changes the
    # badge statically — only a confirmed on-chain latch read does.
    one_shot_candidate: NotRequired[bool]


PredicateOp = Literal["AND", "OR", "LEAF"]


class PredicateTree(TypedDict, total=False):
    op: PredicateOp
    children: list["PredicateTree"]
    leaf: LeafPredicate | None


# ---------------------------------------------------------------------------
# Helpers for constructing canonical predicate values.
# ---------------------------------------------------------------------------


def make_leaf_node(leaf: LeafPredicate) -> PredicateTree:
    tree: PredicateTree = {"op": "LEAF", "leaf": leaf}
    return tree


def make_and_node(children: list[PredicateTree]) -> PredicateTree:
    if len(children) == 1:
        return children[0]
    tree: PredicateTree = {"op": "AND", "children": children}
    return tree


def make_or_node(children: list[PredicateTree]) -> PredicateTree:
    if len(children) == 1:
        return children[0]
    tree: PredicateTree = {"op": "OR", "children": children}
    return tree


def operand(source: OperandSource, /, **kwargs: Any) -> Operand:
    """Construct an Operand with sensible defaults. Kwargs are merged
    into the typed dict; unknown keys raise (TypedDict total=False
    accepts NotRequired keys, but typos slip through — keep keys
    matching the type)."""
    payload: Operand = {"source": source}  # type: ignore[typeddict-item]
    payload.update(kwargs)  # type: ignore[typeddict-item]
    return payload
