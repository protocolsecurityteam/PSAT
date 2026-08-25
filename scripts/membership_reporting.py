"""Shared verdict/report helpers for the membership operator CLIs
(DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.3.3, §5.4).

Everything here re-uses the gate's own verification internals — the verdict a
CLI reports is the verdict ``membership_gate`` would reach, never a fork of it
(invariant 13).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from db.models import (
    ADMITTING_WITNESS_RULES,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
)
from services.clients.rpc import chain_id_for_chain_name
from services.discovery import membership_gate as gate
from services.discovery.membership_gate import _probe_controller_values, _witness_fact_holds

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def would_promote(session: Session, contract: Contract, protocol_id: int) -> bool:
    """The gate's own promotion verdict for (contract, protocol) from stored
    witnesses, computed without persisting anything: ``promote`` runs inside a
    savepoint that is always rolled back. A member row is tested with its
    stamp cleared so the verdict is earned, not assumed."""
    savepoint = session.begin_nested()
    try:
        if contract.protocol_id is not None:
            contract.protocol_id = None
            session.flush()
        return gate.promote(session, contract=contract, protocol_id=protocol_id)
    finally:
        savepoint.rollback()


def active_witness_rules(session: Session, *, contract_id: int, protocol_id: int) -> list[str]:
    return sorted(
        {row.rule for row in gate.active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id)}
    )


def closest_miss(session: Session, contract: Contract, protocol_id: int) -> dict[str, Any]:
    """Which witness rule came nearest and what named piece of evidence is
    missing (invariant 5's skip+log posture). Token fields only, never
    composed prose."""
    address = (contract.address or "").lower()
    chain_id = chain_id_for_chain_name(contract.chain)
    if chain_id is None:
        return {"nearest_rule": "w1_code", "missing": "chain_not_resolvable", "chain": contract.chain}
    code_row = session.get(ContractCreationWitness, (chain_id, address)) if address else None
    code_probed = code_row is not None and code_row.code_probe_block is not None

    witness_rows = sorted(
        session.execute(
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.contract_id == contract.id,
                ContractMembershipWitness.protocol_id == protocol_id,
            )
        ).scalars(),
        key=lambda r: r.id,
    )
    active_admitting = [r for r in witness_rows if r.revoked_at is None and r.rule in ADMITTING_WITNESS_RULES]

    verified = [
        row
        for row in active_admitting
        if _witness_fact_holds(
            session,
            contract=contract,
            protocol_id=protocol_id,
            rule=row.rule,
            evidence=row.evidence,
            via_address=row.via_address,
        )
    ]
    if verified:
        # An admitting witness verifies, so the only thing withholding
        # membership is the W1 code precondition (invariant 3).
        if not code_probed:
            missing = "w1_code_probe"
        elif code_row is not None and code_row.code_absent_at_probe:
            missing = "code_present_at_latest_probe"
        else:
            missing = "w1_code_witness_for_contract_chain"
        return {"nearest_rule": verified[0].rule, "missing": missing, "chain_id": chain_id}
    for row in active_admitting:
        return {
            "nearest_rule": row.rule,
            "missing": "via_fact_not_held",
            "via": row.via_address,
        }
    for row in witness_rows:
        if row.revoked_at is not None and row.rule in ADMITTING_WITNESS_RULES:
            return {
                "nearest_rule": row.rule,
                "missing": "witness_revoked",
                "via": row.via_address,
                "revoked_at": row.revoked_at.isoformat(),
            }

    deployer = (contract.deployer or "").lower()
    if deployer and ADDRESS_RE.match(deployer):
        verdict = gate.classify_deployer(session, protocol_id=protocol_id, address=deployer)
        if verdict.trust_class is not None:
            return {"nearest_rule": "w4_deployer", "missing": "creation_witness", "deployer": deployer}
        return {
            "nearest_rule": "w4_deployer",
            "missing": str(verdict.evidence.get("reason")),
            "deployer": deployer,
        }

    attempt = session.get(ContractProbeAttempt, (contract.id, chain_id))
    if attempt is not None and isinstance(attempt.results, dict):
        status = attempt.results.get("status")
        if status == "probed":
            resolved = sorted(_probe_controller_values(session, contract))
            if resolved:
                return {
                    "nearest_rule": "w3_control",
                    "missing": "resolved_controller_not_in_perimeter",
                    "resolved": resolved,
                    "probed_block": attempt.block_number,
                }
            return {
                "nearest_rule": "w3_control",
                "missing": "no_controller_resolved_by_probe",
                "probed_block": attempt.block_number,
            }
        return {"nearest_rule": None, "missing": f"probe_{status}"}
    if not deployer:
        return {"nearest_rule": "w4_deployer", "missing": "deployer_not_determined"}
    return {"nearest_rule": None, "missing": "no_probe_attempt"}


def format_detail(detail: dict[str, Any]) -> str:
    return " ".join(f"{key}={detail[key]}" for key in sorted(detail))


def format_row_line(
    kind: str, *, contract_id: int, address: str, chain: str | None, protocol_id: int, detail: dict[str, Any]
) -> str:
    return (
        f"{kind.upper():<8} contract={contract_id} address={address} chain={chain or 'ethereum'} "
        f"protocol={protocol_id} {format_detail(detail)}"
    )
