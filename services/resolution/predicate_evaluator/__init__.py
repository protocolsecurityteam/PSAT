"""Predicate-tree evaluator — the bridge from static stage to resolver.

Takes a ``PredicateTree`` (from ``services.static.static_analysis.
predicates.build_predicate_tree``) and produces a ``CapabilityExpr``
describing the principal set / capability shape that gates the
function. Recursive: AND/OR nodes compose via the closed combinators
in ``capabilities.py``.

Per v6 round-5 #3 fix, dispatch order is:
  1. kind == "unsupported"           → CapabilityExpr.unsupported(reason)
  2. authority_role ∈ {reentrancy, pause, business, time} →
     conditional_universal (anyone, with the side condition)
  3. caller_authority / delegated_authority — dispatch on leaf kind:
     - membership   → adapter.enumerate(set_descriptor) → finite_set
     - equality     → resolve operand → finite_set([address])
     - external_bool→ external_check_only
     - signature_auth → signature_witness
     - comparison   → conditional_universal (caller-priority comparisons
                       are exotic; mostly time-gates, already handled)

Adapters are pluggable: the caller passes an ``AdapterRegistry`` (week 5
deliverable). Without adapters, membership leaves return finite_set with
quality=lower_bound and empty members — the structural skeleton is
correct, just unfilled.
"""

from __future__ import annotations

from .adapters import (
    SetAdapter,
    _NullAdapter,
)
from .authority import (
    _AUTHORITY_GETTER_BASENAMES,
    _AUTHORITY_SELECTOR,
    _BURN_ADDRESS,
    _GOVERNOR_SELECTOR,
    _OWNER_SELECTOR,
    _PENDING_AUTHORITY_BASENAMES,
    _SLOT_KEYWORD_TO_GETTER,
    _canonical_authority_selector_for_slot,
    _enumerate_param_keyed_mapping_values,
    _is_pending_authority_accessor_operand,
    _leaf_is_keyed_set_membership,
    _live_authority_result,
    _live_resolve_authority,
    _live_resolve_authority_slot,
    _nullary_getter_selector,
    _oz_v5_namespaced_authority_selector,
    _pending_authority_base,
    _pending_ceiling_capability,
    _public_getter_selector_for_internal_accessor,
    _resolve_authority_via_getters,
    _resolve_param_keyed_authority_mapping,
    _view_call_caller_selects_key,
)
from .binding import (
    _bind_callee_parameters,
    _bind_value,
    _bound_parameter_operand,
    _callee_argument_operands,
    _is_caller_source,
    _is_target_call_operand,
    _normalize_operand_for_call_arg,
    _normalize_tree_for_frame,
    _normalize_value_for_frame,
    _promote_bound_caller_leaf,
    _resolve_static_external_call_operand,
    _selector_for_signature,
    _tree_for_signature_or_selector,
)
from .core import (
    EvaluationContext,
    _condition_group_description,
    _evaluate_leaf,
    _has_caller_keyed_value_predicate,
    _is_opaque_bool_return_predicate,
    _maybe_inline_cross_contract_call,
    _side_condition_capability,
    _side_conditions_from_tree,
    evaluate_tree,
    evaluate_tree_with_registry,
)
from .descriptors import (
    _condition_from_leaf,
    _external_check_from_descriptor,
    _first_hint_value,
    _normalize_membership_decline_for_negation,
    _resolve_external_bool,
    _resolve_signer_from_leaf,
    _stamp_caller_gate_check,
    _target_address_from_descriptor,
)
from .equality import (
    _leaf_has_caller_operand,
    _resolve_contextual_equality,
    _resolve_equality_principal,
    _resolve_operand_static_value,
)
from .materialization import (
    _conditional_result_needs_materialization,
    _inline_result_needs_materialization,
    _materialize_external_check_from_candidates,
    _or_result_needs_materialization,
    _public_without_root_cofinites,
)
from .membership import (
    _call_unary_bytes32_view,
    _observed_event_key_words,
    _observed_event_key_words_from_hypersync,
    _resolve_view_key_membership,
)
from .permit import (
    _PERMIT_FAMILY_SIGNATURES,
    _SIGNATURE_VERIFIER_CALLEES,
    _is_permit_family_signature,
    _leaf_is_permit_shape,
)
from .telemetry import (
    _DELEGATED_GATE_UNRESOLVED_COUNTS,
    _GUARD_FIRE_COUNTS,
    _adapter_declined_external_set,
    _adapter_deferred_pending_index,
    _bump_resolve_counter,
    _frame_is_inlined,
    _is_zero_address,
    _pass_live_read_memo,
    _record_delegated_gate_unresolved,
    _record_guard_fire,
    _state_var_lookup_key,
    _tag_caller_subject,
)

__all__ = [
    "EvaluationContext",
    "SetAdapter",
    "_AUTHORITY_GETTER_BASENAMES",
    "_AUTHORITY_SELECTOR",
    "_BURN_ADDRESS",
    "_DELEGATED_GATE_UNRESOLVED_COUNTS",
    "_GOVERNOR_SELECTOR",
    "_GUARD_FIRE_COUNTS",
    "_NullAdapter",
    "_OWNER_SELECTOR",
    "_PENDING_AUTHORITY_BASENAMES",
    "_PERMIT_FAMILY_SIGNATURES",
    "_SIGNATURE_VERIFIER_CALLEES",
    "_SLOT_KEYWORD_TO_GETTER",
    "_adapter_declined_external_set",
    "_adapter_deferred_pending_index",
    "_bind_callee_parameters",
    "_bind_value",
    "_bound_parameter_operand",
    "_bump_resolve_counter",
    "_call_unary_bytes32_view",
    "_callee_argument_operands",
    "_canonical_authority_selector_for_slot",
    "_condition_from_leaf",
    "_condition_group_description",
    "_conditional_result_needs_materialization",
    "_enumerate_param_keyed_mapping_values",
    "_evaluate_leaf",
    "_external_check_from_descriptor",
    "_first_hint_value",
    "_frame_is_inlined",
    "_has_caller_keyed_value_predicate",
    "_inline_result_needs_materialization",
    "_is_caller_source",
    "_is_opaque_bool_return_predicate",
    "_is_pending_authority_accessor_operand",
    "_is_permit_family_signature",
    "_is_target_call_operand",
    "_is_zero_address",
    "_leaf_has_caller_operand",
    "_leaf_is_keyed_set_membership",
    "_leaf_is_permit_shape",
    "_live_authority_result",
    "_live_resolve_authority",
    "_live_resolve_authority_slot",
    "_materialize_external_check_from_candidates",
    "_maybe_inline_cross_contract_call",
    "_normalize_membership_decline_for_negation",
    "_normalize_operand_for_call_arg",
    "_normalize_tree_for_frame",
    "_normalize_value_for_frame",
    "_nullary_getter_selector",
    "_observed_event_key_words",
    "_observed_event_key_words_from_hypersync",
    "_or_result_needs_materialization",
    "_oz_v5_namespaced_authority_selector",
    "_pass_live_read_memo",
    "_pending_authority_base",
    "_pending_ceiling_capability",
    "_promote_bound_caller_leaf",
    "_public_getter_selector_for_internal_accessor",
    "_public_without_root_cofinites",
    "_record_delegated_gate_unresolved",
    "_record_guard_fire",
    "_resolve_authority_via_getters",
    "_resolve_contextual_equality",
    "_resolve_equality_principal",
    "_resolve_external_bool",
    "_resolve_operand_static_value",
    "_resolve_param_keyed_authority_mapping",
    "_resolve_signer_from_leaf",
    "_resolve_static_external_call_operand",
    "_resolve_view_key_membership",
    "_selector_for_signature",
    "_side_condition_capability",
    "_side_conditions_from_tree",
    "_stamp_caller_gate_check",
    "_state_var_lookup_key",
    "_tag_caller_subject",
    "_target_address_from_descriptor",
    "_tree_for_signature_or_selector",
    "_view_call_caller_selects_key",
    "evaluate_tree",
    "evaluate_tree_with_registry",
]
