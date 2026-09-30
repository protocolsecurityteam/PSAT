"""Company-level governance overview, staged so each step is testable:

1. ``resolve_company_jobs`` — the protocol's completed member jobs.
2. ``prefetch_contracts`` — Contract rows by job, address+chain fallback for ``copy_static_cache`` reassignment.
3. ``resolve_implementation_contracts`` — impl rows for proxies.
4. ``build_governance_view`` — contract entries, hierarchy, principals, fund flows.
5. ``assemble_company_payload`` — protocol-wide views and final dict.

This ``__init__`` re-exports the pre-split surface, including private names tests import.
"""

from .entity_keys import _coalesce_chain, _entity_addr, _entity_chain, _entity_key
from .functions_view import build_functions_for_protocol
from .governance_view import build_governance_view
from .jobs import (
    CompanyNotFound,
    GovernanceView,
    _job_chain_name,
    _job_matches_contract_chain,
    _job_recency,
    _secondary_impl_contracts,
    _time_phase,
    prefetch_contracts,
    resolve_company_jobs,
    resolve_implementation_contracts,
)
from .payload import (
    all_addresses_for_protocol,
    assemble_company_payload,
    build_company_overview,
    controllers_for_protocol,
)
from .prefetch import _prefetch_child_tables
from .principals import (
    _ACTIVE_OWNER_CONTROLLER_IDS,
    _MONITORED_TYPE_FOR_CONTROLLER,
    _MONITORED_TYPE_LOOKUP,
    _PASSTHROUGH_CONTROLLER_TYPES,
    _PRINCIPAL_TYPES,
    _SETTLED_CONTROLLER_TYPES,
    _build_principal_lookup,
    _claim_ids_list,
    _is_active_owner_controller,
    _principal_lookup_meta,
    _principal_lookup_type,
    _trim_control_graph,
)

__all__ = [
    "CompanyNotFound",
    "GovernanceView",
    "_ACTIVE_OWNER_CONTROLLER_IDS",
    "_MONITORED_TYPE_FOR_CONTROLLER",
    "_MONITORED_TYPE_LOOKUP",
    "_PASSTHROUGH_CONTROLLER_TYPES",
    "_PRINCIPAL_TYPES",
    "_SETTLED_CONTROLLER_TYPES",
    "_build_principal_lookup",
    "_claim_ids_list",
    "_coalesce_chain",
    "_entity_addr",
    "_entity_chain",
    "_entity_key",
    "_is_active_owner_controller",
    "_job_chain_name",
    "_job_matches_contract_chain",
    "_job_recency",
    "_prefetch_child_tables",
    "_principal_lookup_meta",
    "_principal_lookup_type",
    "_secondary_impl_contracts",
    "_time_phase",
    "_trim_control_graph",
    "all_addresses_for_protocol",
    "assemble_company_payload",
    "build_company_overview",
    "build_functions_for_protocol",
    "build_governance_view",
    "controllers_for_protocol",
    "prefetch_contracts",
    "resolve_company_jobs",
    "resolve_implementation_contracts",
]
