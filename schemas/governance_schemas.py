"""Public schemas for governance-facing response shapes."""

from __future__ import annotations

from typing_extensions import NotRequired, TypedDict

from schemas.common import Address, ChainId, Contract, JsonObject

FunctionPrincipalPayload = JsonObject
GovernanceFunctionController = JsonObject
GovernanceAuthorityRole = JsonObject
GovernanceFunctionEntry = JsonObject
GovernanceControlDetail = JsonObject
GovernancePrincipal = JsonObject


class AnalysisListEntry(TypedDict):
    run_name: str
    job_id: str
    address: Address | None
    contract: NotRequired[Contract]
    chain_id: ChainId | None
    company: str | None
    parent_job_id: str | None
    rank_score: float | None
    is_proxy: bool
    proxy_type: str | None
    implementation_address: Address | None
    proxy_address: Address | None
    available_artifacts: NotRequired[list[str]]
    contract_name: NotRequired[str]
    display_name: NotRequired[str]
    proxy_address_display: NotRequired[Address | None]
    proxy_type_display: NotRequired[str | None]


__all__ = [
    "AnalysisListEntry",
    "FunctionPrincipalPayload",
    "GovernanceAuthorityRole",
    "GovernanceControlDetail",
    "GovernanceFunctionController",
    "GovernanceFunctionEntry",
    "GovernancePrincipal",
]
