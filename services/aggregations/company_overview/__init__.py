"""Company-level governance overview.

Decomposed from a single ~700-line endpoint into stages so each step is
testable on its own. ``build_company_overview`` is the orchestrator
called by the router.

Stages (each returns plain Python data, not ORM rows that pin a session):

1. ``resolve_company_jobs`` — protocol lookup with legacy-company fallback
   that walks ``parent_job_id`` chains for older jobs that don't carry a
   protocol_id.
2. ``prefetch_contracts`` — batch fetch ``Contract`` rows by ``job_id``,
   with an address+chain fallback for jobs whose Contract row was
   reassigned by ``copy_static_cache`` to a newer job.
3. ``resolve_implementation_contracts`` — for proxy contracts in the
   inventory, locate the impl Contract row keyed by impl address.
4. ``build_governance_view`` — merges the above with prefetched child
   tables to produce the contract entries, ownership hierarchy,
   non-contract principals, and inter-contract fund-flow edges.
5. ``assemble_company_payload`` — adds the protocol-wide views
   (all_addresses, latest TVL) and shapes the final dict.

Package layout: ``entity_keys`` (composite chain::address tokens),
``jobs`` (stages 1–3), ``prefetch`` (child-table fan-out), ``principals``
(controller vocabulary + principal lookup), ``governance_view`` (stage 4),
``functions_view`` (the /functions payload), ``payload`` (stage 5 + the
orchestrators). This ``__init__`` re-exports the full pre-split module
surface — including the private names tests and sibling services import —
so ``services.aggregations.company_overview.X`` keeps resolving unchanged.
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
