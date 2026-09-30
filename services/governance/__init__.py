"""Governance-view helpers shared by aggregation services."""

from .primary_controller import PRINCIPAL_PRIORITY, assign_primary_controllers
from .principals import (
    TERMINAL_PRINCIPAL_TYPES,
    _build_company_function_entry,
    _function_principal_payload,
    _is_generic_authority_contract_principal,
    _role_value_from_origin,
    is_terminal_principal_type,
    resolve_terminal_principal,
)
from .proxies import GENERIC_PROXY_NAMES, _display_name, _merge_proxy_impl_entries

__all__ = [
    "GENERIC_PROXY_NAMES",
    "PRINCIPAL_PRIORITY",
    "TERMINAL_PRINCIPAL_TYPES",
    "_build_company_function_entry",
    "_display_name",
    "_function_principal_payload",
    "_is_generic_authority_contract_principal",
    "_merge_proxy_impl_entries",
    "_role_value_from_origin",
    "assign_primary_controllers",
    "is_terminal_principal_type",
    "resolve_terminal_principal",
]
