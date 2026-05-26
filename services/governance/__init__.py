"""Governance-view helpers shared by aggregation services.

Two slices live here:

- ``principals`` — turn ``EffectiveFunction`` / ``FunctionPrincipal`` rows
  into the dict shape the company-overview / analysis-detail aggregators
  serialize. Includes the role-promotion logic that filters out the
  generic ``authority_kind`` controller when a more specific principal
  (Safe, EOA, ...) covers the same authority slot.

- ``proxies`` — display-name resolution and proxy/impl entry merging for
  the analyses listing.
"""

from .primary_controller import PRINCIPAL_PRIORITY, assign_primary_controllers
from .principals import (
    _build_company_function_entry,
    _function_principal_payload,
    _is_generic_authority_contract_principal,
    _role_value_from_origin,
)
from .proxies import GENERIC_PROXY_NAMES, _display_name, _merge_proxy_impl_entries

__all__ = [
    "GENERIC_PROXY_NAMES",
    "PRINCIPAL_PRIORITY",
    "_build_company_function_entry",
    "_display_name",
    "_function_principal_payload",
    "_is_generic_authority_contract_principal",
    "_merge_proxy_impl_entries",
    "_role_value_from_origin",
    "assign_primary_controllers",
]
