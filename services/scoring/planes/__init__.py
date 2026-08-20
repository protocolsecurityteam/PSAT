"""The resolution planes the Layer-2 fold reads to resolve a signal's references.

Signals carry references — ``function_principals`` ids and ``<chain>::<address>``
entity keys — so the fold is the first place that can turn them into units,
dollars and breadth. Every read here is ordered, read-only, and publishes its
own three-state: an unreadable or absent witness lands on ``not_determined`` and
is counted in the provenance block rather than defaulted to a number.
"""

from __future__ import annotations

from services.scoring.planes._shared import (
    CONTROL_RELATIONS as CONTROL_RELATIONS,
)
from services.scoring.planes._shared import (
    EDGE_WITNESS_ADMIN_COLUMN as EDGE_WITNESS_ADMIN_COLUMN,
)
from services.scoring.planes._shared import (
    EDGE_WITNESS_BEACON_COLUMN as EDGE_WITNESS_BEACON_COLUMN,
)
from services.scoring.planes._shared import (
    EDGE_WITNESS_CONTROL_GRAPH as EDGE_WITNESS_CONTROL_GRAPH,
)
from services.scoring.planes._shared import (
    NATIVE_ASSET as NATIVE_ASSET,
)
from services.scoring.planes._shared import (
    ROLE_SCOPED_RELATIONS as ROLE_SCOPED_RELATIONS,
)
from services.scoring.planes._shared import (
    SCOPE_NOT_DETERMINED as SCOPE_NOT_DETERMINED,
)
from services.scoring.planes._shared import (
    SCOPE_ROLES as SCOPE_ROLES,
)
from services.scoring.planes._shared import (
    SCOPE_STATE_VAR as SCOPE_STATE_VAR,
)
from services.scoring.planes._shared import (
    ZERO_ADDRESS as ZERO_ADDRESS,
)
from services.scoring.planes._shared import (
    EdgeScope as EdgeScope,
)
from services.scoring.planes._shared import (
    _float as _float,
)
from services.scoring.planes._shared import (
    _lower as _lower,
)
from services.scoring.planes._shared import (
    _round_presented as _round_presented,
)
from services.scoring.planes._shared import (
    is_zero_key as is_zero_key,
)
from services.scoring.planes._shared import (
    parse_edge_scope as parse_edge_scope,
)
from services.scoring.planes._shared import (
    typed_receipt_is_resolved as typed_receipt_is_resolved,
)
from services.scoring.planes.act_as import (
    _ACT_AS_RANK as _ACT_AS_RANK,
)
from services.scoring.planes.act_as import (
    ACT_AS_CALL_SITE_GATE_NOT_DELEGATED as ACT_AS_CALL_SITE_GATE_NOT_DELEGATED,
)
from services.scoring.planes.act_as import (
    ACT_AS_CALL_SITE_IS_PUBLIC as ACT_AS_CALL_SITE_IS_PUBLIC,
)
from services.scoring.planes.act_as import (
    ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED as ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED,
)
from services.scoring.planes.act_as import (
    ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE as ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE,
)
from services.scoring.planes.act_as import (
    ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE as ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE,
)
from services.scoring.planes.act_as import (
    ACT_AS_NO_CALL_SITE as ACT_AS_NO_CALL_SITE,
)
from services.scoring.planes.act_as import (
    ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION as ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION,
)
from services.scoring.planes.act_as import (
    ACT_AS_NO_DESTINATION_ACL as ACT_AS_NO_DESTINATION_ACL,
)
from services.scoring.planes.act_as import (
    ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT as ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT,
)
from services.scoring.planes.act_as import (
    ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS as ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS,
)
from services.scoring.planes.act_as import (
    ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS as ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS,
)
from services.scoring.planes.act_as import (
    ACT_AS_RECEIVER_NOT_READ as ACT_AS_RECEIVER_NOT_READ,
)
from services.scoring.planes.act_as import (
    ACT_AS_RECEIVER_READ_FAILED as ACT_AS_RECEIVER_READ_FAILED,
)
from services.scoring.planes.act_as import (
    ACT_AS_WITNESS_CALLER_STATE_VARIABLE as ACT_AS_WITNESS_CALLER_STATE_VARIABLE,
)
from services.scoring.planes.act_as import (
    ACT_AS_WITNESS_DESTINATION_ACL as ACT_AS_WITNESS_DESTINATION_ACL,
)
from services.scoring.planes.act_as import (
    ACT_AS_WITNESSED as ACT_AS_WITNESSED,
)
from services.scoring.planes.act_as import (
    ActAsPlane as ActAsPlane,
)
from services.scoring.planes.act_as import (
    ActAsStep as ActAsStep,
)
from services.scoring.planes.act_as import (
    ActAsVerdict as ActAsVerdict,
)
from services.scoring.planes.act_as import (
    DestinationAcceptance as DestinationAcceptance,
)
from services.scoring.planes.act_as import (
    load_act_as_plane as load_act_as_plane,
)
from services.scoring.planes.conditions import (
    HOP_NOT_DETERMINED as HOP_NOT_DETERMINED,
)
from services.scoring.planes.conditions import (
    HOP_WALKED as HOP_WALKED,
)
from services.scoring.planes.conditions import (
    PREDICATES_COLUMN_HOLDS_NO_ARRAY as PREDICATES_COLUMN_HOLDS_NO_ARRAY,
)
from services.scoring.planes.conditions import (
    PREDICATES_EXTRACTED as PREDICATES_EXTRACTED,
)
from services.scoring.planes.conditions import (
    PREDICATES_FUNCTION_NOT_LOCATED as PREDICATES_FUNCTION_NOT_LOCATED,
)
from services.scoring.planes.conditions import (
    SURFACE_DESTINATION_FUNCTIONS as SURFACE_DESTINATION_FUNCTIONS,
)
from services.scoring.planes.conditions import (
    SURFACE_FUNCTION_PRINCIPAL as SURFACE_FUNCTION_PRINCIPAL,
)
from services.scoring.planes.conditions import (
    SURFACE_NONE as SURFACE_NONE,
)
from services.scoring.planes.conditions import (
    WALKED_COVERAGE as WALKED_COVERAGE,
)
from services.scoring.planes.conditions import (
    WALKED_NO_FUNCTION as WALKED_NO_FUNCTION,
)
from services.scoring.planes.conditions import (
    WALKED_ON_ANALYSED_FULLY as WALKED_ON_ANALYSED_FULLY,
)
from services.scoring.planes.conditions import (
    WALKED_ON_ANALYSED_PARTLY as WALKED_ON_ANALYSED_PARTLY,
)
from services.scoring.planes.conditions import (
    WALKED_ON_UNANALYSED as WALKED_ON_UNANALYSED,
)
from services.scoring.planes.conditions import (
    ConditionPlane as ConditionPlane,
)
from services.scoring.planes.conditions import (
    DestinationFunction as DestinationFunction,
)
from services.scoring.planes.conditions import (
    DestinationPredicates as DestinationPredicates,
)
from services.scoring.planes.conditions import (
    HopConditions as HopConditions,
)
from services.scoring.planes.conditions import (
    _caller_self_pins as _caller_self_pins,
)
from services.scoring.planes.conditions import (
    _stored_predicates as _stored_predicates,
)
from services.scoring.planes.conditions import (
    load_condition_plane as load_condition_plane,
)
from services.scoring.planes.conferral import (
    CONFERRAL_CONFERRED as CONFERRAL_CONFERRED,
)
from services.scoring.planes.conferral import (
    CONFERRAL_OUTCOMES as CONFERRAL_OUTCOMES,
)
from services.scoring.planes.conferral import (
    CONFERRAL_ROLE_NOT_LICENSED as CONFERRAL_ROLE_NOT_LICENSED,
)
from services.scoring.planes.conferral import (
    CONFERRAL_SCOPE_NOT_DETERMINED as CONFERRAL_SCOPE_NOT_DETERMINED,
)
from services.scoring.planes.conferral import (
    CONFERRAL_VARIABLE_NOT_REWRITTEN as CONFERRAL_VARIABLE_NOT_REWRITTEN,
)
from services.scoring.planes.conferral import (
    CONFERRAL_WRITES_NOT_EXTRACTED as CONFERRAL_WRITES_NOT_EXTRACTED,
)
from services.scoring.planes.conferral import (
    ConferralPlane as ConferralPlane,
)
from services.scoring.planes.conferral import (
    ConferralVerdict as ConferralVerdict,
)
from services.scoring.planes.conferral import (
    GateGrant as GateGrant,
)
from services.scoring.planes.conferral import (
    LicensedFunction as LicensedFunction,
)
from services.scoring.planes.conferral import (
    load_conferral_plane as load_conferral_plane,
)
from services.scoring.planes.control import (
    REFUSAL_MALFORMED_NODE_ID as REFUSAL_MALFORMED_NODE_ID,
)
from services.scoring.planes.control import (
    REFUSAL_SELF_EDGE as REFUSAL_SELF_EDGE,
)
from services.scoring.planes.control import (
    REFUSAL_ZERO_ANCHOR as REFUSAL_ZERO_ANCHOR,
)
from services.scoring.planes.control import (
    REFUSAL_ZERO_PRINCIPAL as REFUSAL_ZERO_PRINCIPAL,
)
from services.scoring.planes.control import (
    ControlClosure as ControlClosure,
)
from services.scoring.planes.control import (
    ControlEdge as ControlEdge,
)
from services.scoring.planes.control import (
    RefusedEdge as RefusedEdge,
)
from services.scoring.planes.control import (
    RenouncedAuthority as RenouncedAuthority,
)
from services.scoring.planes.control import (
    load_control_closure as load_control_closure,
)
from services.scoring.planes.deletability import (
    AUTHORITY_CONTROLLER_ID as AUTHORITY_CONTROLLER_ID,
)
from services.scoring.planes.deletability import (
    CALLER_TAINTED_AUTHORITY_UNRESOLVED as CALLER_TAINTED_AUTHORITY_UNRESOLVED,
)
from services.scoring.planes.deletability import (
    CROSSCHECK_AGREES as CROSSCHECK_AGREES,
)
from services.scoring.planes.deletability import (
    CROSSCHECK_DISAGREES as CROSSCHECK_DISAGREES,
)
from services.scoring.planes.deletability import (
    CROSSCHECK_NOT_COMPARED as CROSSCHECK_NOT_COMPARED,
)
from services.scoring.planes.deletability import (
    CROSSCHECK_NOT_CORROBORATED as CROSSCHECK_NOT_CORROBORATED,
)
from services.scoring.planes.deletability import (
    DELETABILITY_ARM_GATING_AUTHORITY as DELETABILITY_ARM_GATING_AUTHORITY,
)
from services.scoring.planes.deletability import (
    DELETABILITY_ARM_HOST as DELETABILITY_ARM_HOST,
)
from services.scoring.planes.deletability import (
    DELETABILITY_ARMS as DELETABILITY_ARMS,
)
from services.scoring.planes.deletability import (
    DELETABILITY_AUTHORITY_NOT_UNIQUE as DELETABILITY_AUTHORITY_NOT_UNIQUE,
)
from services.scoring.planes.deletability import (
    DELETABILITY_AUTHORITY_SETTERS as DELETABILITY_AUTHORITY_SETTERS,
)
from services.scoring.planes.deletability import (
    DELETABILITY_AUTHORITY_SOURCES_DISAGREE as DELETABILITY_AUTHORITY_SOURCES_DISAGREE,
)
from services.scoring.planes.deletability import (
    DELETABILITY_AUTHORITY_TAINTED as DELETABILITY_AUTHORITY_TAINTED,
)
from services.scoring.planes.deletability import (
    DELETABILITY_AUTHORITY_UNRESOLVED as DELETABILITY_AUTHORITY_UNRESOLVED,
)
from services.scoring.planes.deletability import (
    DELETABILITY_DELETABLE as DELETABILITY_DELETABLE,
)
from services.scoring.planes.deletability import (
    DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED as DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED,
)
from services.scoring.planes.deletability import (
    DELETABILITY_HOST_SETTERS as DELETABILITY_HOST_SETTERS,
)
from services.scoring.planes.deletability import (
    DELETABILITY_MEMBERSHIP_NOT_EXACT as DELETABILITY_MEMBERSHIP_NOT_EXACT,
)
from services.scoring.planes.deletability import (
    DELETABILITY_NO_PRINCIPAL_ADDRESS as DELETABILITY_NO_PRINCIPAL_ADDRESS,
)
from services.scoring.planes.deletability import (
    DELETABILITY_NO_SETTER_ROW as DELETABILITY_NO_SETTER_ROW,
)
from services.scoring.planes.deletability import (
    DELETABILITY_NOT_DETERMINED as DELETABILITY_NOT_DETERMINED,
)
from services.scoring.planes.deletability import (
    DELETABILITY_PROVEN_NOT_DELETABLE as DELETABILITY_PROVEN_NOT_DELETABLE,
)
from services.scoring.planes.deletability import (
    DELETABILITY_REASONS as DELETABILITY_REASONS,
)
from services.scoring.planes.deletability import (
    DELETABILITY_SETTERS as DELETABILITY_SETTERS,
)
from services.scoring.planes.deletability import (
    DELETABILITY_STATES as DELETABILITY_STATES,
)
from services.scoring.planes.deletability import (
    MEMBERSHIP_QUALITY_EXACT as MEMBERSHIP_QUALITY_EXACT,
)
from services.scoring.planes.deletability import (
    SOLMATE_ROLES_AUTHORITY_STEP as SOLMATE_ROLES_AUTHORITY_STEP,
)
from services.scoring.planes.deletability import (
    DeletabilityPlane as DeletabilityPlane,
)
from services.scoring.planes.deletability import (
    DeletabilityVerdict as DeletabilityVerdict,
)
from services.scoring.planes.deletability import (
    SetterPrincipal as SetterPrincipal,
)
from services.scoring.planes.deletability import (
    authority_deletability as authority_deletability,
)
from services.scoring.planes.deletability import (
    load_deletability_plane as load_deletability_plane,
)
from services.scoring.planes.principals import (
    PrincipalFacts as PrincipalFacts,
)
from services.scoring.planes.principals import (
    _safe_protection_verdict as _safe_protection_verdict,
)
from services.scoring.planes.principals import (
    load_principal_plane as load_principal_plane,
)
from services.scoring.planes.principals import (
    load_role_holder_floors as load_role_holder_floors,
)
from services.scoring.planes.provenance import (
    UNCONSUMED_REACH_REASONS as UNCONSUMED_REACH_REASONS,
)
from services.scoring.planes.provenance import (
    UNCONSUMED_REASON_UNCLASSIFIED as UNCONSUMED_REASON_UNCLASSIFIED,
)
from services.scoring.planes.provenance import (
    discovery_relation_entities as discovery_relation_entities,
)
from services.scoring.planes.provenance import (
    load_audit_posture as load_audit_posture,
)
from services.scoring.planes.provenance import (
    load_ledgers as load_ledgers,
)
from services.scoring.planes.provenance import (
    load_upgrade_provenance as load_upgrade_provenance,
)
from services.scoring.planes.provenance import (
    native_value_state as native_value_state,
)
from services.scoring.planes.provenance import (
    perimeter_state as perimeter_state,
)
from services.scoring.planes.provenance import (
    plane_row_counts as plane_row_counts,
)
from services.scoring.planes.provenance import (
    unconsumed_reach_relations as unconsumed_reach_relations,
)
from services.scoring.planes.router_flow import (
    ROUTE_AMOUNT_AUTHORED as ROUTE_AMOUNT_AUTHORED,
)
from services.scoring.planes.router_flow import (
    ROUTE_CLASSIFICATIONS as ROUTE_CLASSIFICATIONS,
)
from services.scoring.planes.router_flow import (
    ROUTE_NEITHER_CONJUNCT as ROUTE_NEITHER_CONJUNCT,
)
from services.scoring.planes.router_flow import (
    ROUTE_NO_FLOW_WITNESS as ROUTE_NO_FLOW_WITNESS,
)
from services.scoring.planes.router_flow import (
    ROUTE_NOT_DETERMINED as ROUTE_NOT_DETERMINED,
)
from services.scoring.planes.router_flow import (
    ROUTE_TARGET_CONSTRAINED as ROUTE_TARGET_CONSTRAINED,
)
from services.scoring.planes.router_flow import (
    RouteClassification as RouteClassification,
)
from services.scoring.planes.router_flow import (
    RouterFlow as RouterFlow,
)
from services.scoring.planes.router_flow import (
    RouterFlowPlane as RouterFlowPlane,
)
from services.scoring.planes.router_flow import (
    load_router_flow_plane as load_router_flow_plane,
)
from services.scoring.planes.value import (
    _REDUCTION_COUNTERS as _REDUCTION_COUNTERS,
)
from services.scoring.planes.value import (
    ASSET_AIRDROP_DELIVERED as ASSET_AIRDROP_DELIVERED,
)
from services.scoring.planes.value import (
    ASSET_BELOW_RESOLUTION as ASSET_BELOW_RESOLUTION,
)
from services.scoring.planes.value import (
    ASSET_PRICED as ASSET_PRICED,
)
from services.scoring.planes.value import (
    ASSET_PROVEN_ZERO as ASSET_PROVEN_ZERO,
)
from services.scoring.planes.value import (
    ASSET_UNPRICED as ASSET_UNPRICED,
)
from services.scoring.planes.value import (
    CEILING_ADMITTED as CEILING_ADMITTED,
)
from services.scoring.planes.value import (
    CEILING_ADMITTING_REASONS as CEILING_ADMITTING_REASONS,
)
from services.scoring.planes.value import (
    CEILING_AIRDROP_DETERMINED as CEILING_AIRDROP_DETERMINED,
)
from services.scoring.planes.value import (
    CEILING_ALIAS_AMBIGUOUS as CEILING_ALIAS_AMBIGUOUS,
)
from services.scoring.planes.value import (
    CEILING_ASSET_LIST_TRUNCATED as CEILING_ASSET_LIST_TRUNCATED,
)
from services.scoring.planes.value import (
    CEILING_BELOW_RESOLUTION as CEILING_BELOW_RESOLUTION,
)
from services.scoring.planes.value import (
    CEILING_NO_ROWS as CEILING_NO_ROWS,
)
from services.scoring.planes.value import (
    CEILING_PROVEN_EMPTY as CEILING_PROVEN_EMPTY,
)
from services.scoring.planes.value import (
    CEILING_REASONS as CEILING_REASONS,
)
from services.scoring.planes.value import (
    CEILING_UNPRICED as CEILING_UNPRICED,
)
from services.scoring.planes.value import (
    DISPOSITION_REFUSALS as DISPOSITION_REFUSALS,
)
from services.scoring.planes.value import (
    DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED as DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED,
)
from services.scoring.planes.value import (
    DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED as DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED,
)
from services.scoring.planes.value import (
    DISPOSITION_REFUSED_UNPRICED_POSITIONS as DISPOSITION_REFUSED_UNPRICED_POSITIONS,
)
from services.scoring.planes.value import (
    DISPOSITION_REFUSED_UNSCANNED_ACCOUNT as DISPOSITION_REFUSED_UNSCANNED_ACCOUNT,
)
from services.scoring.planes.value import (
    EMPTY_REFUSALS as EMPTY_REFUSALS,
)
from services.scoring.planes.value import (
    EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE as EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE,
)
from services.scoring.planes.value import (
    EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED as EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED,
)
from services.scoring.planes.value import (
    EMPTY_REFUSED_UNPRICED_POSITIONS as EMPTY_REFUSED_UNPRICED_POSITIONS,
)
from services.scoring.planes.value import (
    EMPTY_REFUSED_UNSCANNED_ACCOUNT as EMPTY_REFUSED_UNSCANNED_ACCOUNT,
)
from services.scoring.planes.value import (
    SHEET_AIRDROP_DETERMINED as SHEET_AIRDROP_DETERMINED,
)
from services.scoring.planes.value import (
    SHEET_BELOW_RESOLUTION as SHEET_BELOW_RESOLUTION,
)
from services.scoring.planes.value import (
    SHEET_NO_ROWS as SHEET_NO_ROWS,
)
from services.scoring.planes.value import (
    SHEET_NOT_DETERMINED as SHEET_NOT_DETERMINED,
)
from services.scoring.planes.value import (
    SHEET_PRICED as SHEET_PRICED,
)
from services.scoring.planes.value import (
    SHEET_PROVEN_EMPTY as SHEET_PROVEN_EMPTY,
)
from services.scoring.planes.value import (
    SHEET_UNPRICED as SHEET_UNPRICED,
)
from services.scoring.planes.value import (
    AliasCycleError as AliasCycleError,
)
from services.scoring.planes.value import (
    ValuePlane as ValuePlane,
)
from services.scoring.planes.value import (
    _alias_fixed_point as _alias_fixed_point,
)
from services.scoring.planes.value import (
    _reduce_observations as _reduce_observations,
)
from services.scoring.planes.value import (
    _resolve_asset_disposition as _resolve_asset_disposition,
)
from services.scoring.planes.value import (
    ceiling_for as ceiling_for,
)
from services.scoring.planes.value import (
    load_entity_alias as load_entity_alias,
)
from services.scoring.planes.value import (
    load_proven_eoa_entities as load_proven_eoa_entities,
)
from services.scoring.planes.value import (
    load_value_plane as load_value_plane,
)

__all__ = [
    "ACT_AS_CALL_SITE_GATE_NOT_DELEGATED",
    "ACT_AS_CALL_SITE_IS_PUBLIC",
    "ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED",
    "ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE",
    "ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE",
    "ACT_AS_NO_CALL_SITE",
    "ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION",
    "ACT_AS_NO_DESTINATION_ACL",
    "ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT",
    "ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS",
    "ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS",
    "ACT_AS_RECEIVER_NOT_READ",
    "ACT_AS_RECEIVER_READ_FAILED",
    "ACT_AS_WITNESSED",
    "ACT_AS_WITNESS_CALLER_STATE_VARIABLE",
    "ACT_AS_WITNESS_DESTINATION_ACL",
    "ASSET_AIRDROP_DELIVERED",
    "ASSET_BELOW_RESOLUTION",
    "ASSET_PRICED",
    "ASSET_PROVEN_ZERO",
    "ASSET_UNPRICED",
    "CEILING_ADMITTED",
    "CEILING_ADMITTING_REASONS",
    "CEILING_AIRDROP_DETERMINED",
    "CEILING_ALIAS_AMBIGUOUS",
    "CEILING_ASSET_LIST_TRUNCATED",
    "CEILING_BELOW_RESOLUTION",
    "CEILING_NO_ROWS",
    "CEILING_PROVEN_EMPTY",
    "CEILING_REASONS",
    "CEILING_UNPRICED",
    "DISPOSITION_REFUSALS",
    "DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED",
    "DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED",
    "DISPOSITION_REFUSED_UNPRICED_POSITIONS",
    "DISPOSITION_REFUSED_UNSCANNED_ACCOUNT",
    "EMPTY_REFUSALS",
    "EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE",
    "EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED",
    "EMPTY_REFUSED_UNSCANNED_ACCOUNT",
    "EMPTY_REFUSED_UNPRICED_POSITIONS",
    "CONFERRAL_CONFERRED",
    "CONFERRAL_OUTCOMES",
    "CONFERRAL_ROLE_NOT_LICENSED",
    "CONFERRAL_SCOPE_NOT_DETERMINED",
    "CONFERRAL_VARIABLE_NOT_REWRITTEN",
    "CONFERRAL_WRITES_NOT_EXTRACTED",
    "CONTROL_RELATIONS",
    "AUTHORITY_CONTROLLER_ID",
    "CALLER_TAINTED_AUTHORITY_UNRESOLVED",
    "CROSSCHECK_AGREES",
    "CROSSCHECK_DISAGREES",
    "CROSSCHECK_NOT_COMPARED",
    "CROSSCHECK_NOT_CORROBORATED",
    "DELETABILITY_ARMS",
    "DELETABILITY_ARM_GATING_AUTHORITY",
    "DELETABILITY_ARM_HOST",
    "DELETABILITY_AUTHORITY_NOT_UNIQUE",
    "DELETABILITY_AUTHORITY_SETTERS",
    "DELETABILITY_AUTHORITY_SOURCES_DISAGREE",
    "DELETABILITY_AUTHORITY_TAINTED",
    "DELETABILITY_AUTHORITY_UNRESOLVED",
    "DELETABILITY_DELETABLE",
    "DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED",
    "DELETABILITY_HOST_SETTERS",
    "DELETABILITY_MEMBERSHIP_NOT_EXACT",
    "DELETABILITY_NOT_DETERMINED",
    "DELETABILITY_NO_PRINCIPAL_ADDRESS",
    "DELETABILITY_NO_SETTER_ROW",
    "DELETABILITY_PROVEN_NOT_DELETABLE",
    "DELETABILITY_REASONS",
    "DELETABILITY_SETTERS",
    "DELETABILITY_STATES",
    "MEMBERSHIP_QUALITY_EXACT",
    "SOLMATE_ROLES_AUTHORITY_STEP",
    "EDGE_WITNESS_ADMIN_COLUMN",
    "EDGE_WITNESS_CONTROL_GRAPH",
    "PREDICATES_COLUMN_HOLDS_NO_ARRAY",
    "PREDICATES_EXTRACTED",
    "PREDICATES_FUNCTION_NOT_LOCATED",
    "REFUSAL_MALFORMED_NODE_ID",
    "REFUSAL_ZERO_ANCHOR",
    "REFUSAL_ZERO_PRINCIPAL",
    "SCOPE_NOT_DETERMINED",
    "SCOPE_ROLES",
    "SCOPE_STATE_VAR",
    "SHEET_AIRDROP_DETERMINED",
    "SHEET_BELOW_RESOLUTION",
    "SHEET_NOT_DETERMINED",
    "SHEET_NO_ROWS",
    "SHEET_PRICED",
    "SHEET_PROVEN_EMPTY",
    "SHEET_UNPRICED",
    "UNCONSUMED_REACH_REASONS",
    "ZERO_ADDRESS",
    "is_zero_key",
    "ActAsPlane",
    "ActAsStep",
    "ActAsVerdict",
    "ConferralPlane",
    "ConferralVerdict",
    "ControlClosure",
    "ControlEdge",
    "DeletabilityPlane",
    "ROUTE_AMOUNT_AUTHORED",
    "ROUTE_CLASSIFICATIONS",
    "ROUTE_NEITHER_CONJUNCT",
    "ROUTE_NOT_DETERMINED",
    "ROUTE_NO_FLOW_WITNESS",
    "ROUTE_TARGET_CONSTRAINED",
    "RouteClassification",
    "RouterFlow",
    "RouterFlowPlane",
    "DeletabilityVerdict",
    "DestinationAcceptance",
    "DestinationPredicates",
    "EdgeScope",
    "GateGrant",
    "LicensedFunction",
    "PrincipalFacts",
    "RefusedEdge",
    "RenouncedAuthority",
    "SetterPrincipal",
    "ValuePlane",
    "authority_deletability",
    "ceiling_for",
    "load_act_as_plane",
    "load_audit_posture",
    "discovery_relation_entities",
    "load_conferral_plane",
    "load_control_closure",
    "load_deletability_plane",
    "load_router_flow_plane",
    "load_ledgers",
    "load_principal_plane",
    "load_proven_eoa_entities",
    "load_role_holder_floors",
    "load_upgrade_provenance",
    "load_value_plane",
    "native_value_state",
    "parse_edge_scope",
    "perimeter_state",
    "plane_row_counts",
    "typed_receipt_is_resolved",
]
