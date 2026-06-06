"""Schemas owned by the static contract-analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias, TypedDict

from typing_extensions import NotRequired

OperandSource = Literal[
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
    "top",
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
    constant_value: NotRequired[str | None]
    value_type: NotRequired[str | None]
    computed_kind: NotRequired[str | None]
    block_context_kind: NotRequired[str | None]


SetKind = Literal[
    "mapping_membership",
    "array_contains",
    "external_set",
    "bitwise_role_flag",
    "diamond_facet_acl",
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


WriterEventDirection = Literal["add", "remove", "set"]


class EventHint(TypedDict):
    event_address: str
    topic0: str
    topics_to_keys: dict[int, int]
    data_to_keys: dict[int, int]
    direction: WriterEventDirection
    key_value_taint: NotRequired[str | None]
    event_signature: NotRequired[str | None]
    event_name: NotRequired[str | None]
    mapping_name: NotRequired[str | None]
    key_position: NotRequired[int | None]
    indexed_positions: NotRequired[list[int]]
    value_position: NotRequired[int | None]
    writer_function: NotRequired[str | None]


class ValuePredicate(TypedDict):
    op: Literal["eq", "ne", "lt", "lte", "gt", "gte", "in", "any_nonzero"]
    rhs_values: list[str]
    value_type: str
    mask: NotRequired[str | None]


class PredicateSetDescriptor(TypedDict):
    kind: SetKind
    storage_var: NotRequired[str | None]
    storage_slot: NotRequired[str | None]
    key_sources: list[Operand]
    truthy_value: NotRequired[str | None]
    value_predicate: NotRequired[ValuePredicate | None]
    enumeration_hint: NotRequired[list[EventHint]]
    authority_contract: NotRequired[AuthorityContract | None]
    role_domain: NotRequired[RoleDomain | None]
    selector_context: NotRequired[SelectorContext | None]
    callee_function: NotRequired[str | None]
    callee_signature: NotRequired[str | None]
    callee_selector: NotRequired[str | None]


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
]

PredicateConfidence = Literal["high", "medium", "low"]
PredicateOp = Literal["AND", "OR", "LEAF"]


class LeafPredicate(TypedDict):
    kind: LeafKind
    operator: LeafOperator
    authority_role: AuthorityRole
    confidence: NotRequired[PredicateConfidence]
    operands: list[Operand]
    set_descriptor: NotRequired[PredicateSetDescriptor | None]
    unsupported_reason: NotRequired[str | None]
    references_msg_sender: bool
    parameter_indices: list[int]
    expression: str
    basis: list[str]


class PredicateTree(TypedDict, total=False):
    op: PredicateOp
    children: list["PredicateTree"]
    leaf: LeafPredicate | None


def make_leaf_node(leaf: LeafPredicate) -> PredicateTree:
    return {"op": "LEAF", "leaf": leaf}


def make_and_node(children: list[PredicateTree]) -> PredicateTree:
    if len(children) == 1:
        return children[0]
    return {"op": "AND", "children": children}


def make_or_node(children: list[PredicateTree]) -> PredicateTree:
    if len(children) == 1:
        return children[0]
    return {"op": "OR", "children": children}


def operand(source: OperandSource, /, **kwargs: Any) -> Operand:
    payload: Operand = {"source": source}  # type: ignore[typeddict-item]
    payload.update(kwargs)  # type: ignore[typeddict-item]
    return payload


class SinkRecord(TypedDict):
    id: str
    function: str
    kind: str
    target: str
    selector: str | None


class EffectInfo(TypedDict):
    function: str
    selector: str
    abi_signature: str
    sinks: list[SinkRecord]
    effects: list[str]
    effect_labels: list[str]
    effect_targets: list[str]
    action_summary: str
    writer_selectors: list[str]


class EffectsArtifact(TypedDict):
    schema_version: str
    contract_name: str | None
    functions: dict[str, EffectInfo]


class WriterEventSpec(TypedDict):
    mapping_name: str
    event_signature: str
    event_name: str
    key_position: int
    key_positions_by_index: dict[int, int]
    indexed_positions: list[int]
    direction: WriterEventDirection
    writer_function: str
    value_position: int | None


class EventMetadata(TypedDict):
    signature: str
    arg_types: list[str]
    indexed_positions: list[int]


ReentrancyPauseGuardKind = Literal["reentrancy", "pause"]


class PauseInfo(TypedDict):
    pause_state_vars: list[str]
    pause_toggle_functions: list[str]
    reentrancy_state_vars: list[str]
    reentrancy_guarded_functions: list[str]


RevertKind = Literal[
    "require",
    "assert",
    "custom_revert",
    "if_revert",
    "inline_asm",
    "try_catch_revert",
    "external_call_revert",
    "opaque",
]

Polarity = Literal["allowed_when_true", "allowed_when_false"]


@dataclass
class RevertGate:
    kind: RevertKind
    condition_value: Any = None
    polarity: Polarity = "allowed_when_true"
    node: Any = None
    containing_function: Any = None
    call_chain: list[Any] = field(default_factory=list)
    expression_text: str = ""
    basis: list[str] = field(default_factory=list)
    unsupported_reason: str | None = None


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
    kind: str
    parameter_index: int | None = None
    parameter_name: str | None = None
    state_variable_name: str | None = None
    callee: str | None = None
    callee_args_digest: str | None = None
    callee_signature: str | None = None
    callee_selector: str | None = None
    constant_value: str | None = None
    value_type: str | None = None
    computed_kind: str | None = None
    block_context_kind: str | None = None
    member_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise ValueError(f"unknown source kind {self.kind!r}")
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
        ):
            raise ValueError("Source(kind='top') must be the bare sentinel — no metadata fields")


SourceSet: TypeAlias = frozenset[Source]
EMPTY: SourceSet = frozenset()
_TOP_SOURCE = Source(kind="top")
TOP: SourceSet = frozenset({_TOP_SOURCE})


def is_top(sources: SourceSet) -> bool:
    return _TOP_SOURCE in sources


def source_union(a: SourceSet, b: SourceSet) -> SourceSet:
    if is_top(a) or is_top(b):
        return TOP
    return a | b


@dataclass
class ProvenanceMap:
    sources: dict[str, SourceSet]

    def get(self, var_name: str) -> SourceSet:
        return self.sources.get(var_name, EMPTY)

    def set(self, var_name: str, value: SourceSet) -> bool:
        prev = self.sources.get(var_name, EMPTY)
        if prev == value:
            return False
        self.sources[var_name] = value
        return True


__all__ = [
    "AuthorityContract",
    "AuthorityRole",
    "EMPTY",
    "EffectInfo",
    "EffectsArtifact",
    "EventHint",
    "EventMetadata",
    "LeafKind",
    "LeafOperator",
    "LeafPredicate",
    "Operand",
    "OperandSource",
    "PauseInfo",
    "Polarity",
    "PredicateConfidence",
    "PredicateOp",
    "PredicateSetDescriptor",
    "PredicateTree",
    "ProvenanceMap",
    "ReentrancyPauseGuardKind",
    "RevertGate",
    "RevertKind",
    "RoleDomain",
    "RoleDomainSource",
    "SOURCE_KINDS",
    "SelectorContext",
    "SetKind",
    "SinkRecord",
    "Source",
    "SourceSet",
    "TOP",
    "ValuePredicate",
    "WriterEventDirection",
    "WriterEventSpec",
    "is_top",
    "make_and_node",
    "make_leaf_node",
    "make_or_node",
    "operand",
    "source_union",
]
