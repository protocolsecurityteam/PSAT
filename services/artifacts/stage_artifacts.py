"""Canonical stage artifact helpers.

The storage layer remains a generic ``job_id + artifact_name -> JSON`` store.
This module defines the pipeline convention: one canonical ``StageArtifact``
per pipeline stage.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract as ContractRow
from db.models import Job
from db.queue import get_artifact
from schemas.common import (
    ArtifactReference,
    Contract,
    JsonObject,
    StageArtifact,
    StageContext,
    make_contract,
    make_stage_context,
)
from utils.rpc import require_supported_chain_id

StagePayloadT = TypeVar("StagePayloadT")

DISCOVERY_ARTIFACT = "discovery_artifact"
SELECTION_ARTIFACT = "selection_artifact"
STATIC_ANALYSIS_ARTIFACT = "static_analysis_artifact"
RESOLUTION_ARTIFACT = "resolution_artifact"
POLICY_ARTIFACT = "policy_artifact"
MONITORING_ARTIFACT = "monitoring_artifact"
AGGREGATION_ARTIFACT = "aggregation_artifact"
CRAWLER_ARTIFACT = "crawler_artifact"
AUDIT_ARTIFACT = "audit_artifact"

CANONICAL_ARTIFACT_NAMES = frozenset(
    {
        DISCOVERY_ARTIFACT,
        SELECTION_ARTIFACT,
        STATIC_ANALYSIS_ARTIFACT,
        RESOLUTION_ARTIFACT,
        POLICY_ARTIFACT,
        MONITORING_ARTIFACT,
        AGGREGATION_ARTIFACT,
        CRAWLER_ARTIFACT,
        AUDIT_ARTIFACT,
    }
)

_STAGE_FIELD_LOOKUP: dict[str, tuple[tuple[str, str], ...]] = {
    "discovery_contracts": ((DISCOVERY_ARTIFACT, "contracts"),),
    "discovery_inventory": ((DISCOVERY_ARTIFACT, "inventory"),),
    "discovery_metadata": ((DISCOVERY_ARTIFACT, "metadata"),),
    "discovery_audit_reports": ((DISCOVERY_ARTIFACT, "audit_reports"),),
    "discovery_summary": ((DISCOVERY_ARTIFACT, "summary"),),
    "crawler_discovered_contracts": ((CRAWLER_ARTIFACT, "discovered_contracts"),),
    "crawler_address_details": ((CRAWLER_ARTIFACT, "address_details"),),
    "crawler_interactions": ((CRAWLER_ARTIFACT, "interactions"),),
    "crawler_summary": ((CRAWLER_ARTIFACT, "summary"),),
    "selection_ranked_contracts": ((SELECTION_ARTIFACT, "ranked_contracts"),),
    "selection_selected_contracts": ((SELECTION_ARTIFACT, "selected_contracts"),),
    "selection_child_jobs": ((SELECTION_ARTIFACT, "child_jobs"),),
    "selection_result": ((SELECTION_ARTIFACT, "summary"),),
    "contract_analysis": ((STATIC_ANALYSIS_ARTIFACT, "contract_analysis"),),
    "control_tracking_plan": ((STATIC_ANALYSIS_ARTIFACT, "control_tracking_plan"),),
    "predicate_trees": ((STATIC_ANALYSIS_ARTIFACT, "predicate_trees"),),
    "effects": ((STATIC_ANALYSIS_ARTIFACT, "effects"),),
    "control_snapshot": ((RESOLUTION_ARTIFACT, "control_snapshot"),),
    "classified_addresses": ((RESOLUTION_ARTIFACT, "classified_addresses"),),
    "nested_artifacts": ((RESOLUTION_ARTIFACT, "nested_artifacts"),),
    # After policy graph refresh, the policy artifact is the latest graph.
    "resolved_control_graph": (
        (POLICY_ARTIFACT, "resolved_control_graph"),
        (RESOLUTION_ARTIFACT, "resolved_control_graph"),
    ),
    "effective_permissions": ((POLICY_ARTIFACT, "effective_permissions"),),
    "principal_labels": ((POLICY_ARTIFACT, "principal_labels"),),
    "principal_history": ((POLICY_ARTIFACT, "principal_history"),),
    "coverage_matches": ((AUDIT_ARTIFACT, "coverage_matches"),),
}

_RETIRED_RAW_STAGE_ARTIFACT_NAMES = frozenset(
    {
        "contract_inventory",
        "discovery_meta",
        "audit_reports",
        "dapp_crawl_results",
        "defillama_scan_results",
        "defillama_full_scan",
        "selection_summary",
    }
)


def canonical_artifact_names() -> set[str]:
    return set(CANONICAL_ARTIFACT_NAMES)


def expand_available_artifact_names(names: Iterable[str]) -> set[str]:
    out = set(names)
    if DISCOVERY_ARTIFACT in out:
        out.update(
            {
                "discovery_contracts",
                "discovery_inventory",
                "discovery_metadata",
                "discovery_audit_reports",
                "discovery_summary",
            }
        )
    if CRAWLER_ARTIFACT in out:
        out.update(
            {
                "crawler_discovered_contracts",
                "crawler_address_details",
                "crawler_interactions",
                "crawler_summary",
            }
        )
    if SELECTION_ARTIFACT in out:
        out.update(
            {
                "selection_ranked_contracts",
                "selection_selected_contracts",
                "selection_child_jobs",
                "selection_result",
            }
        )
    if STATIC_ANALYSIS_ARTIFACT in out:
        out.update({"contract_analysis", "control_tracking_plan", "predicate_trees", "effects"})
    if RESOLUTION_ARTIFACT in out:
        out.update({"control_snapshot", "resolved_control_graph", "classified_addresses", "nested_artifacts"})
    if POLICY_ARTIFACT in out:
        out.update({"effective_permissions", "principal_labels", "principal_history", "resolved_control_graph"})
    if AUDIT_ARTIFACT in out:
        out.update({"coverage_matches"})
    return out


def is_stage_artifact(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("context"), dict)
        and isinstance(value.get("data"), dict)
        and isinstance(value.get("stage"), str)
        and isinstance(value.get("kind"), str)
    )


def stage_payload(value: Any) -> dict[str, Any] | None:
    if not is_stage_artifact(value):
        return None
    data = value.get("data")
    return data if isinstance(data, dict) else None


def make_job_contract(session: Session, job: Job, contract_row: ContractRow | None = None) -> Contract:
    row = contract_row
    if row is None:
        row = session.execute(select(ContractRow).where(ContractRow.job_id == job.id).limit(1)).scalar_one_or_none()
    if row is None and job.address:
        chain_id = require_supported_chain_id(
            chain_id=job.chain_id,
            context=f"contract artifact lookup for job {job.id}",
        )
        stmt = select(ContractRow).where(
            ContractRow.address == job.address.lower(),
            ContractRow.chain_id == chain_id,
        )
        row = session.execute(stmt.limit(1)).scalar_one_or_none()

    if row is None:
        chain_id = job.chain_id
        if chain_id is None:
            raise RuntimeError(f"contract artifact for job {job.id} requires chain_id")
        if not job.address:
            raise RuntimeError(f"contract artifact for job {job.id} requires address")
        return make_contract(
            address=job.address,
            chain_id=chain_id,
            name=job.name,
            label=job.name,
        )

    chain_id = row.chain_id
    if chain_id is None:
        raise RuntimeError(f"contract artifact for job {job.id} requires chain_id")
    request = job.request if isinstance(job.request, dict) else {}
    request_proxy_address = request.get("proxy_address") if isinstance(request.get("proxy_address"), str) else None
    implementation_addresses = [
        item for item in [row.implementation, *(row.secondary_implementations or [])] if isinstance(item, str) and item
    ]
    if request_proxy_address and row.address:
        implementation_addresses.insert(0, row.address)
    contract_address = row.address or job.address
    if not contract_address:
        raise RuntimeError(f"contract artifact for job {job.id} requires address")
    return make_contract(
        address=contract_address,
        chain_id=chain_id,
        name=row.contract_name,
        label=job.name,
        is_proxy=bool(row.is_proxy or request_proxy_address),
        proxy_address=request_proxy_address or (row.address if row.is_proxy else None),
        implementation_addresses=implementation_addresses,
        admin_addresses=[row.admin] if row.admin else [],
        beacon_addresses=[row.beacon] if row.beacon else [],
        deployer_address=row.deployer,
        proxy_type=request.get("proxy_type") if isinstance(request.get("proxy_type"), str) else row.proxy_type,
    )


def make_job_stage_context(
    job: Job,
    *,
    stage: str,
    schema_version: str,
    chain_id: int | None = None,
    block_number: int | None = None,
) -> StageContext:
    request = job.request if isinstance(job.request, dict) else {}
    resolved_chain_id = chain_id if chain_id is not None else job.chain_id
    if resolved_chain_id is None and job.address:
        raise ValueError(f"stage context for job {job.id} requires explicit chain_id")
    return make_stage_context(
        schema_version=schema_version,
        stage=stage,
        chain_id=resolved_chain_id,
        run_id=str(request.get("root_job_id")) if request.get("root_job_id") else None,
        job_id=str(job.id),
        company=job.company,
        protocol_id=job.protocol_id,
        block_number=block_number,
    )


def make_stage_artifact(
    *,
    kind: str,
    stage: str,
    schema_version: str,
    context: Mapping[str, Any],
    data: StagePayloadT,
    artifacts: Mapping[str, ArtifactReference] | None = None,
    contract: Contract | None = None,
    errors: Sequence[JsonObject] | None = None,
    sources: Sequence[ArtifactReference] | None = None,
) -> StageArtifact[StagePayloadT]:
    payload: StageArtifact[StagePayloadT] = {
        "kind": kind,
        "stage": stage,
        "schema_version": schema_version,
        "context": dict(context),  # type: ignore[typeddict-item]
        "data": data,
        "artifacts": dict(artifacts or {}),
    }
    if contract is not None:
        payload["contract"] = contract
    if errors is not None:
        payload["errors"] = list(errors)
    if sources is not None:
        payload["sources"] = list(sources)
    return payload


def get_stage_payload(session: Session, job_id: Any, artifact_name: str) -> dict[str, Any] | None:
    raw = get_artifact(session, job_id, artifact_name)
    payload = stage_payload(raw)
    return payload


def is_stage_field_name(name: str) -> bool:
    return name in _STAGE_FIELD_LOOKUP or name in _RETIRED_RAW_STAGE_ARTIFACT_NAMES


def get_artifact_field(session: Session, job_id: Any, field_name: str) -> Any:
    """Read a modeled payload field from its canonical stage artifact."""
    if field_name in _RETIRED_RAW_STAGE_ARTIFACT_NAMES:
        return None
    for artifact_name, payload_key in _STAGE_FIELD_LOOKUP.get(field_name, ()):
        payload = get_stage_payload(session, job_id, artifact_name)
        if payload is not None and payload_key in payload:
            return payload[payload_key]
    return None


def get_artifact_or_stage_field(session: Session, job_id: Any, name: str) -> Any:
    """Read canonical stage fields or ordinary non-stage artifacts.

    Modeled stage field names such as ``contract_analysis`` are never read from
    raw rows here; they must come from their canonical stage artifact.
    """
    if is_stage_field_name(name):
        return get_artifact_field(session, job_id, name)
    return get_artifact(session, job_id, name)
