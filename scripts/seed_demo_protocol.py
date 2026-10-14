"""Seed a small fake protocol into the local database, for clicking through the company page and its exports.

Not real data and never for production: every row is invented. Re-running replaces the demo; ``--remove`` deletes it::

    uv run python -m scripts.seed_demo_protocol
    uv run python -m scripts.seed_demo_protocol --name my-demo
    uv run python -m scripts.seed_demo_protocol --remove

Then open http://127.0.0.1:5173/company/demo-protocol.

What it covers, so each export section has something to show:

* a proxy (``Vault``) with its implementation, owned by a 2-of-3 Safe, pausable;
* a ``Treasury`` governed by an outside timelock with a two-day delay;
* a ``FeeController`` driven by a plain EOA;
* a ``Token`` whose summary was never written, so its yes/no fields stay "Not determined";
* a computed score with two deductions.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import (
    Contract,
    ContractSummary,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    Protocol,
    ProtocolScore,
    SessionLocal,
)
from utils import claim_ids

DEFAULT_NAME = "demo-protocol"
CHAIN = "ethereum"
MODEL_VERSION = "1.4.1-provisional"


def _addr(n: int) -> str:
    # Fixed, recognisable addresses, so a re-run replaces rather than duplicates (``uq_contract_address_chain``).
    return f"0xde30{n:036x}"


VAULT_PROXY = _addr(1)
VAULT_IMPL = _addr(2)
FEE_CONTROLLER = _addr(3)
TREASURY = _addr(4)
TOKEN = _addr(5)
SAFE = _addr(0x5AFE)
SAFE_OWNERS = [_addr(0xA1), _addr(0xA2), _addr(0xA3)]
# Outside the protocol's own contracts, so they surface as privileged principals rather than as members.
TIMELOCK = _addr(0x71C)
ADMIN_EOA = _addr(0xE0A)
DEMO_ADDRESSES = [VAULT_PROXY, VAULT_IMPL, FEE_CONTROLLER, TREASURY, TOKEN]


def _job(session: Session, protocol: Protocol, address: str, name: str, *, is_proxy: bool = False) -> Job:
    now = datetime.now(timezone.utc)
    job = Job(
        id=uuid.uuid4(),
        address=address,
        company=protocol.name,
        protocol_id=protocol.id,
        name=name,
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"address": address, "chain": CHAIN, "seed": "demo"},
        is_proxy=is_proxy,
        analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        created_at=now,
        updated_at=now,
    )
    session.add(job)
    session.flush()
    return job


def _contract(
    session: Session,
    protocol: Protocol,
    address: str,
    name: str,
    *,
    is_proxy: bool = False,
    implementation: str | None = None,
    summary: dict | None = None,
) -> Contract:
    job = _job(session, protocol, address, name, is_proxy=is_proxy)
    contract = Contract(
        address=address,
        job_id=job.id,
        protocol_id=protocol.id,
        chain=CHAIN,
        contract_name=name,
        is_proxy=is_proxy,
        proxy_type="eip1967" if is_proxy else None,
        implementation=implementation,
    )
    session.add(contract)
    session.flush()
    if summary is not None:
        session.add(ContractSummary(contract_id=contract.id, **summary))
    return contract


def _guarded(
    session: Session,
    contract: Contract,
    principal: str,
    principal_type: str,
    functions: list[tuple[str, str, str]],
    details: dict | None = None,
) -> None:
    """Functions on *contract* that only *principal* may call, plus the graph node that makes it a principal."""
    for name, signature, claim in functions:
        ef = EffectiveFunction(
            contract_id=contract.id,
            function_name=name,
            selector="0x" + uuid.uuid5(uuid.NAMESPACE_OID, f"{contract.address}:{signature}").hex[:8],
            abi_signature=signature,
            effect_labels=[],
            claims=[{"claim_id": claim, "tier": "standard_exact"}],
            effect_targets=[],
            action_summary=name,
            authority_public=False,
            authority_roles=[],
        )
        session.add(ef)
        session.flush()
        session.add(
            FunctionPrincipal(
                function_id=ef.id,
                address=principal,
                resolved_type=principal_type,
                origin="semantic_capability:finite_set",
                principal_type="controller",
                details=details,
            )
        )
    session.add(
        ControlGraphNode(
            contract_id=contract.id, address=principal, resolved_type=principal_type, details=details or {}
        )
    )


def _score_document(protocol: Protocol) -> dict:
    """Shaped like ``ScoreDocument.document()``; the figures are invented."""
    findings = [
        {
            "capability": claim_ids.UPGRADE_IMPLEMENTATION,
            "chain": CHAIN,
            "principal_unit": f"{CHAIN}::{SAFE}",
            "access_path": "direct",
            "raw_points": 18.0,
            "net_points_lambda": 18.0,
            "value_at_stake_usd": 2_500_000.0,
            "n_functions": 1,
            "n_entities": 1,
            "example_functions": ["upgradeToAndCall"],
            "host_entities": [f"{CHAIN}::{VAULT_PROXY}"],
            "reach_entities": [f"{CHAIN}::{VAULT_PROXY}"],
            "citations": [],
            "citations_total": 0,
            "witness_tiers": ["standard_exact"],
            "counterfactual": "add a timelock in front of the Safe, or raise its threshold",
        },
        {
            "capability": claim_ids.FLOW_OUT,
            "chain": CHAIN,
            "principal_unit": f"{CHAIN}::{TIMELOCK}",
            "access_path": "direct",
            "raw_points": 9.0,
            "net_points_lambda": 7.2,
            "value_at_stake_usd": 400_000.0,
            "n_functions": 1,
            "n_entities": 1,
            "example_functions": ["withdraw"],
            "host_entities": [f"{CHAIN}::{TREASURY}"],
            "reach_entities": [f"{CHAIN}::{TREASURY}"],
            "citations": [],
            "citations_total": 0,
            "witness_tiers": ["standard_exact"],
            "counterfactual": "lengthen the timelock delay",
        },
    ]
    return {
        "model_version": MODEL_VERSION,
        "grade_state": "computed",
        "grade_lambda": 74.8,
        "grade_exposure": 2_900_000.0,
        "confidence_pct": 82.5,
        "perimeter_state": "settled",
        "findings": findings,
        "earned_negatives": [],
        "warnings": [],
        "model_parameters": {"demo": True},
        "uncalibrated_arms": [],
    }


def remove(session: Session, name: str) -> bool:
    protocol = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    # Contracts and jobs outlive their protocol (ON DELETE SET NULL), so they go first; contract children cascade.
    contract_ids = select(Contract.id).where(Contract.address.in_(DEMO_ADDRESSES), Contract.chain == CHAIN)
    job_ids = list(session.execute(select(Contract.job_id).where(Contract.id.in_(contract_ids))).scalars())
    if protocol is not None:
        job_ids += list(session.execute(select(Job.id).where(Job.protocol_id == protocol.id)).scalars())
    session.execute(delete(Contract).where(Contract.id.in_(contract_ids)))
    if job_ids:
        session.execute(delete(Job).where(Job.id.in_([j for j in job_ids if j is not None])))
    if protocol is not None:
        session.delete(protocol)
    session.commit()
    return protocol is not None


def seed(session: Session, name: str) -> None:
    remove(session, name)
    protocol = Protocol(name=name)
    session.add(protocol)
    session.flush()

    known = {"source_verified": True, "is_factory": False, "standards": []}
    vault_flags = {**known, "control_model": "ownable", "is_pausable": True, "has_timelock": False}
    vault = _contract(
        session,
        protocol,
        VAULT_PROXY,
        "VaultProxy",
        is_proxy=True,
        implementation=VAULT_IMPL,
        summary={**vault_flags, "is_upgradeable": True},
    )
    impl = _contract(
        session,
        protocol,
        VAULT_IMPL,
        "Vault",
        summary={**vault_flags, "is_upgradeable": False},
    )
    fee_controller = _contract(
        session,
        protocol,
        FEE_CONTROLLER,
        "FeeController",
        summary={**known, "control_model": "ownable", "is_pausable": False, "has_timelock": False},
    )
    treasury = _contract(
        session,
        protocol,
        TREASURY,
        "Treasury",
        summary={**known, "control_model": "governance", "is_pausable": False, "has_timelock": True},
    )
    # No summary row: every yes/no field on this contract is unread, not "no".
    _contract(session, protocol, TOKEN, "DemoToken")

    safe_details = {"owners": SAFE_OWNERS, "threshold": 2}
    for contract in (vault, impl):
        session.add(
            ControllerValue(
                contract_id=contract.id,
                controller_id="owner",
                value=SAFE,
                resolved_type="safe",
                source="Ops Safe",
                details=safe_details,
            )
        )
        _guarded(
            session,
            contract,
            SAFE,
            "safe",
            [
                ("upgradeToAndCall", "upgradeToAndCall(address,bytes)", claim_ids.UPGRADE_IMPLEMENTATION),
                ("pause", "pause()", claim_ids.PAUSE_SET),
            ],
            details=safe_details,
        )
    session.add(
        ControllerValue(
            contract_id=treasury.id,
            controller_id="owner",
            value=TIMELOCK,
            resolved_type="timelock",
            source="Treasury Timelock",
            details={"delay": 172_800},
        )
    )
    _guarded(
        session,
        treasury,
        TIMELOCK,
        "timelock",
        [("withdraw", "withdraw(address,uint256)", claim_ids.FLOW_OUT)],
        details={"delay": 172_800},
    )
    session.add(
        ControllerValue(
            contract_id=fee_controller.id,
            controller_id="owner",
            value=ADMIN_EOA,
            resolved_type="eoa",
            source="Fee admin",
        )
    )
    handover = ("transferOwnership", "transferOwnership(address)", claim_ids.OWNERSHIP_TRANSFER)
    _guarded(session, fee_controller, ADMIN_EOA, "eoa", [handover])

    document = _score_document(protocol)
    session.add(
        ProtocolScore(
            protocol_id=protocol.id,
            model_version=MODEL_VERSION,
            trigger="manual",
            grade_state=document["grade_state"],
            grade_lambda=document["grade_lambda"],
            grade_exposure=document["grade_exposure"],
            confidence_pct=document["confidence_pct"],
            perimeter_state=document["perimeter_state"],
            findings=document,
            provenance={"demo": "seeded by scripts/seed_demo_protocol.py"},
            model_parameters=document["model_parameters"],
        )
    )
    session.commit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default=DEFAULT_NAME, help=f"protocol name (default: {DEFAULT_NAME})")
    parser.add_argument("--remove", action="store_true", help="delete the demo protocol and its rows, then exit")
    args = parser.parse_args(argv)

    with SessionLocal() as session:
        if args.remove:
            found = remove(session, args.name)
            print(f"Removed {args.name}." if found else f"No protocol named {args.name}; cleared leftover demo rows.")
            return 0
        seed(session, args.name)
    print(f"Seeded {args.name}: open http://127.0.0.1:5173/company/{args.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
