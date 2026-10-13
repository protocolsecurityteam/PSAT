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
    "authorization_threshold",
    "state_authority",
    "authorization_unresolved",
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
    writer_scope_ids: NotRequired[list[str]]


LeafKind = Literal[
    "membership",
    "equality",
    "comparison",
    "external_bool",
    "signature_auth",
    "authorization",
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
    structural_predicate: NotRequired[dict[str, Any]]
    authority_proof: NotRequired[dict[str, Any]]
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
    reach_read: NotRequired[dict[str, Any]]


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

# Basis on leaves stating where a gate is reached: alternatives to a gate, never gates themselves. A reach condition
# opens a path only once read true at a block (``REACH_READ``); read false it opens nothing, and unread it is not
# determined.
REACH_CONDITION_BASIS: Final = "revert_path_condition"

# Leaf key: ``{"expression": <reach_read recipe>, "holds": bool}``, the outcome this leaf's alternative states. Every
# leaf of one outcome carries the whole outcome. Absent when the condition can't be stated as exact reads.
REACH_READ: Final = "reach_read"

# The basis tag resolution publishes for a reach condition it couldn't read: a path that may be open.
REACH_NOT_DETERMINED: Final = "reach_condition_not_determined"


def is_reach_condition(leaf: Any) -> bool:
    return isinstance(leaf, dict) and REACH_CONDITION_BASIS in (leaf.get("basis") or [])


# ``root_caller`` is the root ``msg.sender`` rewritten into an inlined callee's frame.
_CALLER_SOURCES: Final = frozenset({"msg_sender", "tx_origin", "signature_recovery", "root_caller"})


def _leaf_operands(leaf: dict[str, Any]) -> list[Any]:
    descriptor = leaf.get("set_descriptor") or {}
    return [
        *(leaf.get("operands") or []),
        *(leaf.get("absorbed_operands") or []),
        *(descriptor.get("key_sources") or []),
    ]


def _derives_from_caller(operand: Any, depth: int = 0) -> bool:
    if not isinstance(operand, dict) or depth > 8:
        return False
    if operand.get("source") in _CALLER_SOURCES:
        return True
    inner = [*(operand.get("derived_from") or []), *(operand.get("callee_args") or [])]
    return any(_derives_from_caller(op, depth + 1) for op in inner)


def is_read_reach_condition(leaf: Any) -> bool:
    """A reach condition resolution reads at a block rather than resolving to callers: one with no caller operand. A
    caller operand says who passes, so that leaf resolves to callers like any gate leaf.
    """
    if not is_reach_condition(leaf) or leaf.get("references_msg_sender"):
        return False
    return not any(isinstance(op, dict) and op.get("source") in _CALLER_SOURCES for op in _leaf_operands(leaf))


def names_controllers(leaf: Any) -> bool:
    """Whether a leaf's state says who passes: any leaf but a reach condition that involves the caller nowhere, not
    even through what a call or computation it reads was given.
    """
    if not isinstance(leaf, dict) or not is_reach_condition(leaf) or leaf.get("references_msg_sender"):
        return True
    return any(_derives_from_caller(op) for op in _leaf_operands(leaf))


def is_read_reach_tree(tree: Any) -> bool:
    """Whether every leaf of ``tree`` is a reach condition read at a block."""
    if not isinstance(tree, dict):
        return False
    if tree.get("op") == "LEAF":
        return is_read_reach_condition(tree.get("leaf"))
    children = tree.get("children") or []
    return bool(children) and all(is_read_reach_tree(child) for child in children)


def mark_reach_condition(leaf: Any) -> None:
    if isinstance(leaf, dict) and not is_reach_condition(leaf):
        leaf["basis"] = [*(leaf.get("basis") or []), REACH_CONDITION_BASIS]


# An inline-assembly revert's gate is recorded as ``allowed_when_true`` whichever way it reverts.
INLINE_ASM_REVERT_BASIS: Final = "inline assembly conditional revert"

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
