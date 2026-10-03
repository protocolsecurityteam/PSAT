"""Typed shapes for predicate-based access analysis: a ``PredicateTree`` per guarded function, evaluated by the
resolver. Shape labels are diagnostic only. Separate module to avoid import cycles.
"""

from __future__ import annotations

from typing import Any, Final, Literal, TypedDict, get_args

from typing_extensions import NotRequired

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
    "self_address",  # address(this) — published; resolution adapters match on it
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
    # The constant slot a getter-less address accessor ``sload``s (Governable ``_pendingGovernor``), for
    # ``eth_getStorageAt``.
    storage_slot: NotRequired[str | None]
    # For ``msg.sender == mapping[param]`` (L1BaseSyncPool ``receivers[originEid]``): the mapping and the setter-event
    # specs resolution replays to enumerate its value set.
    mapping_name: NotRequired[str | None]
    mapping_writer_specs: NotRequired[list[dict[str, Any]] | None]
    constant_value: NotRequired[str | None]
    value_type: NotRequired[str | None]
    computed_kind: NotRequired[str | None]
    block_context_kind: NotRequired[str | None]
    # Origins that reached a computed value through its arguments (the parameters a ``keccak256``/``abi.encode``
    # commitment binds). Only on ``computed`` operands. ``None`` is not determined, ``[]`` means only constants,
    # non-empty lists the origins. ``op.get("derived_from") or []`` conflates not-determined with none: test for
    # ``None``.
    derived_from: NotRequired[list["Operand"] | None]
    # The one storage element this operand read (``<state var>[key](.member)*``): the canonical base, member path and
    # the key's entry-parameter slot. The builder publishes one source, so ``bids[_bidId].bidderAddress`` keeps only the
    # parameter or the collection; these record the half it dropped, adding to ``source`` rather than changing it.
    #
    # All three or none (a base without its key isn't a cell); absence means no element read was resolved.
    # ``element_key_param_index``: absent (none resolved), ``None`` (key proven to be ``msg.sender``), or the slot int.
    # Keys that can't be pinned publish no element fields.
    element_base_variable: NotRequired[str]
    element_member_path: NotRequired[list[str]]
    element_key_param_index: NotRequired[int | None]


SetKind = Literal[
    "signature_threshold",
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
    """Filter on the value a mapping read returns, polarity-folded so it states the allowed values (``if (m[k] != 10)
    revert`` gives ``op="eq", rhs_values=["10"]``), so backends can filter latest values by what the contract
    checks.
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
    # Full form of ``truthy_value``; older adapters keep reading ``truthy_value``.
    value_predicate: NotRequired[ValuePredicate | None]
    enumeration_hint: NotRequired[list[EventHint]]
    authority_contract: NotRequired[AuthorityContract | None]
    role_domain: NotRequired[RoleDomain | None]
    selector_context: NotRequired[SelectorContext | None]
    callee_function: NotRequired[str | None]
    callee_signature: NotRequired[str | None]
    callee_selector: NotRequired[str | None]
    membership_inventory: NotRequired[dict[str, Any]]


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

# The ordering operators swaps and threshold predicates allow.
ComparisonOperator = Literal["lt", "lte", "gt", "gte"]

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
    source_function: NotRequired[str]
    source_node_id: NotRequired[int]
    # Caller-taint discriminators, absent on older trees. Callee mutability: ``view``/``pure``, ``nonview`` (effectful
    # external, including wrapper libraries that make external calls), or ``nonview_library`` (effectful, own storage
    # only).
    callee_state_mutability: NotRequired[str | None]
    # The producing RevertGate kind: a result-checked require gates on the bool; a void statement call on its whole
    # revert surface.
    gate_kind: NotRequired[str | None]
    # Canonical callee signature (argument types, e.g. the ``bytes32[]`` merkle-witness discriminator), never the name.
    callee_signature: NotRequired[str | None]
    # Where the one-shot latch lives, so resolution can read consumed vs live (``one_shot.apply_one_shot_pass``, version
    # leaves only). Keys: ``kind`` (storage|getter), ``slot``/``byte_offset``/``size_bytes``/``value_type``/``variable``
    # or ``selector``, ``expected_version``, ``standard``.
    one_shot_latch: NotRequired[dict[str, Any] | None]
    # Matched the name-free latch detector but no initializer standard; only an on-chain read can make it a badge.
    one_shot_candidate: NotRequired[bool]
    # Operands an additive sub-expression fed this comparison that the two-slot ``operands`` couldn't hold
    # (``_stamp_absorbed_operands``). A sibling list; consumers needing the whole expression take the union. An opaque
    # ``computed`` member is not determined.
    absorbed_operands: NotRequired[list[Operand]]


PredicateOp = Literal["AND", "OR", "LEAF"]


class PredicateTree(TypedDict, total=False):
    op: PredicateOp
    children: list["PredicateTree"]
    leaf: LeafPredicate | None
    # Root-only: this tree's builder ran the absorbed-operand recorder, so a missing ``absorbed_operands`` means none.
    # Older trees silently dropped one side of comparisons, so conclusions from absence (``effects.calldata``'s
    # ``no_time_reference``) must require this marker.
    operand_absorption: NotRequired[str]
    # Root-only: a latch candidate found on a require-bearing modifier whose guard saturated, so it can't ride a leaf.
    # Read by the one-shot probe.
    one_shot_candidate_latch: NotRequired[dict[str, Any]]


# The only question is whether the recorder ran; absence is the other answer.
OperandAbsorption = Literal["recorded"]
OPERAND_ABSORPTION_RECORDED: Final[OperandAbsorption] = "recorded"

# Minted by the effects pass, matched by scoring and the calldata prober.
StateVarTargetKind = Literal["constant", "immutable", "storage_setter", "storage_no_setter"]
TARGET_KIND_STORAGE_SETTER: Final[StateVarTargetKind] = "storage_setter"
TARGET_KIND_STORAGE_NO_SETTER: Final[StateVarTargetKind] = "storage_no_setter"
STATE_VAR_TARGET_KINDS: frozenset[str] = frozenset(get_args(StateVarTargetKind))


def mark_operand_absorption_recorded(tree: PredicateTree | None) -> None:
    """Stamp the absorption marker on a tree root (idempotent; it describes the builder, so once per tree)."""
    if isinstance(tree, dict):
        tree["operand_absorption"] = OPERAND_ABSORPTION_RECORDED


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
