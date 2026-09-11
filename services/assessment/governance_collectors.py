"""Pinned-block collectors for common Governor, Timelock, and Safe families."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from eth_abi.abi import decode, encode
from eth_utils.crypto import keccak
from sqlalchemy.orm import Session

from schemas.temporal_assessment import (
    AnalysisProducer,
    ClaimKind,
    ClockKind,
    ConfigurationParameter,
    DerivationRule,
    DiagnosticCode,
    EvidenceKind,
    OperationState,
    ProposalState,
    ScopeKind,
    SubjectKind,
    SubjectRole,
)
from services.assessment.governance import ChainPoint, record_configuration, record_proposal_state
from services.assessment.repository import publish_diagnostic, publish_scoped_claim
from services.clients.rpc import EthCallResult, eth_call_batch, rpc_request


@dataclass(frozen=True)
class Getter:
    signature: str
    output: str
    parameter: ConfigurationParameter | None = None
    clock: ClockKind | None = None


@dataclass
class GovernanceCollection:
    point: ChainPoint
    families: list[str]
    values: dict[str, Any]
    proposals: dict[str, dict[str, Any]]
    operations: dict[str, dict[str, Any]]
    diagnostics: list[dict[str, str]]


_CONFIG_GETTERS = (
    Getter("votingDelay()", "uint256", ConfigurationParameter.voting_delay, ClockKind.block_number),
    Getter("votingPeriod()", "uint256", ConfigurationParameter.voting_period, ClockKind.block_number),
    Getter("proposalThreshold()", "uint256", ConfigurationParameter.proposal_threshold),
    Getter("getMinDelay()", "uint256", ConfigurationParameter.minimum_delay, ClockKind.timestamp),
    Getter("getThreshold()", "uint256", ConfigurationParameter.safe_threshold),
    Getter("getOwners()", "address[]", ConfigurationParameter.safe_signers),
)

_PROPOSAL_STATES = {
    0: ProposalState.pending,
    1: ProposalState.active,
    2: ProposalState.cancelled,
    3: ProposalState.defeated,
    4: ProposalState.succeeded,
    5: ProposalState.queued,
    6: ProposalState.expired,
    7: ProposalState.executed,
}


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def _calldata(signature: str, types: Sequence[str] = (), values: Sequence[Any] = ()) -> str:
    return _selector(signature) + encode(list(types), list(values)).hex()


def _decode(result: EthCallResult, output: str) -> Any | None:
    if not result.success or not result.return_data.startswith("0x"):
        return None
    raw = bytes.fromhex(result.return_data[2:])
    if not raw:
        return None
    try:
        value = decode([output], raw)[0]
    except Exception:
        return None
    if output == "address[]":
        return [str(item).lower() for item in value]
    return int(value) if output.startswith("uint") else value


def _chain_point(rpc_url: str, chain_id: int) -> ChainPoint:
    head = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
    if not isinstance(head, str):
        raise RuntimeError("eth_blockNumber did not return a hex quantity")
    number = int(head, 16)
    block = rpc_request(rpc_url, "eth_getBlockByNumber", [hex(number), False], chain_id=chain_id)
    block_hash = block.get("hash") if isinstance(block, Mapping) else None
    if not isinstance(block_hash, str) or len(block_hash) != 66:
        raise RuntimeError("latest block has no canonical hash")
    return {"chain_id": chain_id, "block_number": number, "block_hash": block_hash.lower()}


def probe_governance(
    *,
    rpc_url: str,
    chain_id: int,
    address: str,
    proposal_ids: Sequence[int] = (),
    operation_ids: Sequence[str] = (),
) -> GovernanceCollection:
    """Observe supported getters together at one canonical block."""
    point = _chain_point(rpc_url, chain_id)
    target = address.lower()
    block_tag = hex(point["block_number"])
    config_results = eth_call_batch(
        rpc_url,
        [{"to": target, "data": _calldata(getter.signature)} for getter in _CONFIG_GETTERS],
        block_tag,
        chain_id=chain_id,
    )
    values = {
        getter.signature: value
        for getter, result in zip(_CONFIG_GETTERS, config_results)
        if (value := _decode(result, getter.output)) is not None
    }
    families: list[str] = []
    if {"votingDelay()", "votingPeriod()"} <= values.keys():
        families.append("openzeppelin_governor")
    if "getMinDelay()" in values:
        families.append("openzeppelin_timelock")
    if {"getThreshold()", "getOwners()"} <= values.keys():
        families.append("safe")

    proposals: dict[str, dict[str, Any]] = {}
    proposal_calls: list[dict[str, str]] = []
    for proposal_id in proposal_ids:
        proposal_calls.extend(
            {"to": target, "data": _calldata(signature, ("uint256",), (proposal_id,))}
            for signature in (
                "state(uint256)",
                "proposalSnapshot(uint256)",
                "proposalDeadline(uint256)",
                "proposalEta(uint256)",
            )
        )
    proposal_results = eth_call_batch(rpc_url, proposal_calls, block_tag, chain_id=chain_id)
    for offset, proposal_id in enumerate(proposal_ids):
        group = proposal_results[offset * 4 : offset * 4 + 4]
        decoded = [_decode(result, "uint256") for result in group]
        state = _PROPOSAL_STATES.get(decoded[0]) if decoded and decoded[0] is not None else None
        proposals[str(proposal_id)] = {
            "state": state,
            "snapshot": decoded[1] if len(decoded) > 1 else None,
            "deadline": decoded[2] if len(decoded) > 2 else None,
            "eta": decoded[3] if len(decoded) > 3 else None,
        }

    operations: dict[str, dict[str, Any]] = {}
    operation_calls: list[dict[str, str]] = []
    valid_operations: list[str] = []
    for operation_id in operation_ids:
        if not isinstance(operation_id, str) or not operation_id.startswith("0x") or len(operation_id) != 66:
            continue
        valid_operations.append(operation_id.lower())
        operation_calls.extend(
            {"to": target, "data": _calldata(signature, ("bytes32",), (bytes.fromhex(operation_id[2:]),))}
            for signature in (
                "getTimestamp(bytes32)",
                "isOperationPending(bytes32)",
                "isOperationReady(bytes32)",
                "isOperationDone(bytes32)",
            )
        )
    operation_results = eth_call_batch(rpc_url, operation_calls, block_tag, chain_id=chain_id)
    for offset, operation_id in enumerate(valid_operations):
        group = operation_results[offset * 4 : offset * 4 + 4]
        timestamp = _decode(group[0], "uint256") if group else None
        flags = [_decode(result, "bool") for result in group[1:]]
        state = (
            OperationState.executed
            if len(flags) > 2 and flags[2] is True
            else OperationState.ready
            if len(flags) > 1 and flags[1] is True
            else OperationState.scheduled
            if flags and flags[0] is True
            else None
        )
        operations[operation_id] = {"timestamp": timestamp, "state": state}

    diagnostics: list[dict[str, str]] = []
    if not families:
        diagnostics.append({"code": "unsupported_code", "message": "No supported governance family matched"})
    return GovernanceCollection(point, families, values, proposals, operations, diagnostics)


def collect_governance(
    session: Session,
    job_id: Any,
    *,
    rpc_url: str,
    chain_id: int,
    address: str,
    proposal_ids: Sequence[int] = (),
    operation_ids: Sequence[str] = (),
) -> GovernanceCollection:
    """Probe and append supported observations to temporal Assessment."""
    collection = probe_governance(
        rpc_url=rpc_url,
        chain_id=chain_id,
        address=address,
        proposal_ids=proposal_ids,
        operation_ids=operation_ids,
    )
    manifest = {"collector": "governance_getters", "families": collection.families}
    for diagnostic in collection.diagnostics:
        publish_diagnostic(
            session,
            job_id,
            producer=AnalysisProducer.governance,
            code=DiagnosticCode(diagnostic["code"]),
            message=diagnostic["message"],
            implementation=manifest,
        )
    by_signature = {getter.signature: getter for getter in _CONFIG_GETTERS}
    for signature, value in collection.values.items():
        getter = by_signature[signature]
        if getter.parameter is None:
            continue
        unit = (
            "seconds"
            if getter.parameter == ConfigurationParameter.minimum_delay
            else "addresses"
            if getter.parameter == ConfigurationParameter.safe_signers
            else "count"
        )
        record_configuration(
            session,
            job_id,
            contract_address=address,
            point=collection.point,
            parameter=getter.parameter,
            value=value,
            unit=unit,
            clock=getter.clock,
            source={"method": "eth_call", "signature": signature},
            implementation=manifest,
        )
    for proposal_id, observation in collection.proposals.items():
        state = observation.get("state")
        if isinstance(state, ProposalState):
            record_proposal_state(
                session,
                job_id,
                governor_address=address,
                proposal_id=proposal_id,
                point=collection.point,
                state=state,
                source={"method": "eth_call", "signature": "state(uint256)"},
                implementation=manifest,
            )
        for field, clock in (
            ("snapshot", ClockKind.block_number),
            ("deadline", ClockKind.block_number),
            ("eta", ClockKind.timestamp),
        ):
            value = observation.get(field)
            if value is None:
                continue
            publish_scoped_claim(
                session,
                job_id,
                producer=AnalysisProducer.governance,
                subject_kind=SubjectKind.proposal,
                subject_identity={"chain_id": chain_id, "governor": address.lower(), "proposal_id": proposal_id},
                subject_role=SubjectRole.proposal,
                natural_key=f"proposal:{address.lower()}:{proposal_id}:timing:{field}",
                evidence_kind=EvidenceKind.chain_read,
                evidence_payload={"field": field, "value": str(value), "clock": clock.value},
                evidence_source={
                    "kind": "chain_read",
                    "method": "eth_call",
                    "signature": f"proposal{field.title()}(uint256)",
                },
                claim_kind=ClaimKind.proposal_timing,
                proposition={"kind": "proposal_timing", "field": field, "value": str(value), "clock": clock.value},
                scope_kind=ScopeKind.point,
                scope={"kind": "point", "at": collection.point},
                rule=DerivationRule.proposal_timing,
                implementation=manifest,
            )
    for operation_id, observation in collection.operations.items():
        state = observation.get("state")
        if not isinstance(state, OperationState):
            continue
        publish_scoped_claim(
            session,
            job_id,
            producer=AnalysisProducer.governance,
            subject_kind=SubjectKind.operation,
            subject_identity={"chain_id": chain_id, "timelock": address.lower(), "operation_id": operation_id},
            subject_role=SubjectRole.operation,
            natural_key=f"operation:{address.lower()}:{operation_id}",
            evidence_kind=EvidenceKind.chain_read,
            evidence_payload={"state": state.value, "timestamp": observation.get("timestamp")},
            evidence_source={"kind": "chain_read", "method": "eth_call", "signature": "getTimestamp(bytes32)"},
            claim_kind=ClaimKind.operation_state,
            proposition={"kind": "operation_state", "state": state.value},
            scope_kind=ScopeKind.point,
            scope={"kind": "point", "at": collection.point},
            rule=DerivationRule.operation_state,
            implementation=manifest,
        )
    session.commit()
    return collection


__all__ = ["GovernanceCollection", "collect_governance", "probe_governance"]
