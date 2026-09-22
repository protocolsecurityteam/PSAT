"""Verified Governor proposal scenarios on a pinned, local Anvil fork."""

from __future__ import annotations

import socket
from collections.abc import Mapping
from typing import Any

from eth_abi.abi import decode, encode
from eth_utils.crypto import keccak
from sqlalchemy.orm import Session

from schemas.temporal_assessment import (
    AnalysisProducer,
    BindingPhase,
    ClaimKind,
    ClockKind,
    ConfigurationParameter,
    DerivationRule,
    DiagnosticCode,
    EvidenceKind,
    ScopeKind,
    SubjectKind,
    SubjectRole,
)
from services.assessment.governance import (
    ChainPoint,
    record_applied_configuration,
    record_configuration,
    record_scenario_configuration,
)
from services.assessment.governance_collectors import _CONFIG_GETTERS, _decode, _selector
from services.assessment.repository import publish_diagnostic, publish_scoped_claim
from services.clients.rpc import rpc_headers, rpc_request
from services.effects.anvil import SubprocessAnvil, assert_post_cancun

_PROPOSAL_EVENT = "ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)"
_PROPOSAL_TOPIC = "0x" + keccak(text=_PROPOSAL_EVENT).hex()
_PROPOSAL_TYPES = [
    "uint256",
    "address",
    "address[]",
    "uint256[]",
    "string[]",
    "bytes[]",
    "uint256",
    "uint256",
    "string",
]


def proposal_from_receipt(
    *,
    rpc_url: str,
    chain_id: int,
    governor: str,
    proposal_id: int,
    transaction_hash: str,
    baseline: ChainPoint,
) -> dict[str, Any]:
    """Verify the full OZ event payload against a canonical proposal receipt."""
    receipt = rpc_request(rpc_url, "eth_getTransactionReceipt", [transaction_hash], chain_id=chain_id)
    if not isinstance(receipt, Mapping) or receipt.get("status") != "0x1":
        raise ValueError("proposal transaction has no successful receipt")
    number = int(str(receipt["blockNumber"]), 16)
    if number > baseline["block_number"]:
        raise ValueError("proposal was created after the scenario baseline")
    block = rpc_request(rpc_url, "eth_getBlockByNumber", [hex(number), False], chain_id=chain_id)
    if (
        not isinstance(block, Mapping)
        or str(block.get("hash", "")).lower() != str(receipt.get("blockHash", "")).lower()
    ):
        raise ValueError("proposal receipt is not in the canonical chain")
    matches = []
    for log in receipt.get("logs", []):
        if not isinstance(log, Mapping) or str(log.get("address", "")).lower() != governor.lower():
            continue
        topics = log.get("topics")
        if topics != [_PROPOSAL_TOPIC]:
            continue
        try:
            values = decode(_PROPOSAL_TYPES, bytes.fromhex(str(log["data"])[2:]))
        except (ValueError, KeyError) as exc:
            raise ValueError("malformed ProposalCreated event") from exc
        if int(values[0]) == proposal_id:
            matches.append((log, values))
    if len(matches) != 1:
        raise ValueError("proposal receipt lacks one matching ProposalCreated event")
    log, values = matches[0]
    targets, amounts, signatures, calldatas = values[2], values[3], values[4], values[5]
    if not targets or len(targets) > 32 or not (len(targets) == len(amounts) == len(signatures) == len(calldatas)):
        raise ValueError("proposal action bundle is empty, oversized, or malformed")
    # OpenZeppelin Governor stores the complete calldata in the event. The
    # signatures array is a compatibility field and must be blank for this ABI.
    if any(signatures):
        raise ValueError("legacy signature-based actions are unsupported")
    actions = [
        {
            "kind": "call",
            "chain_id": chain_id,
            "sender": governor.lower(),
            "target": str(target).lower(),
            "calldata": "0x" + bytes(data).hex(),
            "value": str(amount),
        }
        for target, amount, data in zip(targets, amounts, calldatas)
    ]
    description_hash = keccak(text=str(values[8]))
    computed_id = int.from_bytes(
        keccak(
            encode(
                ["address[]", "uint256[]", "bytes[]", "bytes32"],
                [
                    [action["target"] for action in actions],
                    [int(action["value"]) for action in actions],
                    [bytes.fromhex(action["calldata"][2:]) for action in actions],
                    description_hash,
                ],
            )
        ),
        "big",
    )
    if computed_id != proposal_id:
        raise ValueError("ProposalCreated action bundle does not hash to proposal id")
    return {
        "actions": actions,
        "description_hash": description_hash,
        "vote_start": int(values[6]),
        "vote_end": int(values[7]),
        "source": {
            "transaction_hash": transaction_hash.lower(),
            "block_number": number,
            "block_hash": str(receipt["blockHash"]).lower(),
            "log_index": int(str(log["logIndex"]), 16),
        },
    }


def _bind_creation_period(
    session: Session,
    job_id: Any,
    *,
    rpc_url: str,
    chain_id: int,
    governor: str,
    proposal_id: int,
    proposal: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> str:
    """Bind a creation-period getter corroborated by OZ proposal timing."""
    event = proposal["source"]
    block_tag = {"blockHash": event["block_hash"], "requireCanonical": True}
    raw = rpc_request(
        rpc_url,
        "eth_call",
        [
            {"to": governor, "data": _selector("CLOCK_MODE()")},
            block_tag,
        ],
        chain_id=chain_id,
    )
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ValueError("Governor CLOCK_MODE is unavailable")
    try:
        mode = decode(["string"], bytes.fromhex(raw[2:]))[0]
    except (ValueError, IndexError) as exc:
        raise ValueError("Governor CLOCK_MODE has unsupported output") from exc
    if not str(mode).startswith("mode=blocknumber"):
        raise ValueError(f"Governor clock mode is unsupported: {mode}")
    period = proposal["vote_end"] - proposal["vote_start"]
    if period <= 0:
        raise ValueError("ProposalCreated has no positive voting period")

    def uint_at_creation(signature: str, with_id: bool = False) -> int:
        data = _selector(signature)
        if with_id:
            data += encode(["uint256"], [proposal_id]).hex()
        answer = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": governor, "data": data}, block_tag],
            chain_id=chain_id,
        )
        if not isinstance(answer, str) or not answer.startswith("0x"):
            raise ValueError(f"{signature} was unreadable at proposal creation")
        try:
            return int(decode(["uint256"], bytes.fromhex(answer[2:]))[0])
        except (ValueError, IndexError) as exc:
            raise ValueError(f"{signature} had unsupported output") from exc

    if (
        uint_at_creation("votingPeriod()") != period
        or uint_at_creation("proposalSnapshot(uint256)", True) != proposal["vote_start"]
        or uint_at_creation("proposalDeadline(uint256)", True) != proposal["vote_end"]
    ):
        raise ValueError("creation getter and ProposalCreated timing disagree")
    point: ChainPoint = {"chain_id": chain_id, "block_number": event["block_number"], "block_hash": event["block_hash"]}
    binding_event = {key: value for key, value in event.items() if key != "log_index"}
    source = {
        "kind": EvidenceKind.chain_event.value,
        "event": "ProposalCreated",
        "corroborating_getters": ["votingPeriod()", "proposalSnapshot(uint256)", "proposalDeadline(uint256)"],
        "event_log_index": event["log_index"],
        **binding_event,
    }
    configuration_claim = record_configuration(
        session,
        job_id,
        contract_address=governor,
        point=point,
        parameter=ConfigurationParameter.voting_period,
        value=period,
        unit="blocks",
        clock=ClockKind.block_number,
        source=source,
        implementation=manifest,
        evidence_kind=EvidenceKind.chain_event,
        preserve_publication_point=True,
    )
    session.flush()
    return record_applied_configuration(
        session,
        job_id,
        governor_address=governor,
        proposal_id=str(proposal_id),
        point=point,
        phase=BindingPhase.creation,
        configuration_claim=configuration_claim,
        source=source,
        implementation=manifest,
        evidence_kind=EvidenceKind.chain_event,
        preserve_publication_point=True,
    )


def _available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def execute_proposal_scenario(
    session: Session,
    job_id: Any,
    *,
    rpc_url: str,
    chain_id: int,
    governor: str,
    proposal_id: int,
    proposal_transaction_hash: str,
    sender: str,
    baseline: ChainPoint,
    transport: Any | None = None,
) -> list[str]:
    """Execute one verified proposal and publish only changed getter readbacks.

    The sender is caller intent, but the Governor's access checks run on fork.
    A rejected execution yields a diagnostic and never a scenario claim.
    """
    manifest = {"collector": "governor_proposal_fork", "event": _PROPOSAL_EVENT}
    if baseline["chain_id"] != chain_id:
        raise ValueError("scenario chain differs from baseline")

    def diagnostic(code: DiagnosticCode, message: str) -> list[str]:
        publish_diagnostic(
            session, job_id, producer=AnalysisProducer.scenario, code=code, message=message, implementation=manifest
        )
        session.commit()
        return []

    try:
        proposal = proposal_from_receipt(
            rpc_url=rpc_url,
            chain_id=chain_id,
            governor=governor,
            proposal_id=proposal_id,
            transaction_hash=proposal_transaction_hash,
            baseline=baseline,
        )
    except (RuntimeError, ValueError, KeyError, TypeError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        return diagnostic(DiagnosticCode.missing_evidence, f"Proposal action verification failed: {message}")

    try:
        _bind_creation_period(
            session,
            job_id,
            rpc_url=rpc_url,
            chain_id=chain_id,
            governor=governor,
            proposal_id=proposal_id,
            proposal=proposal,
            manifest=manifest,
        )
        session.commit()
    except (RuntimeError, ValueError, TypeError) as exc:
        session.rollback()
        diagnostic(DiagnosticCode.unsupported_clock, f"Creation-phase voting period binding unavailable: {exc}")

    _, _, proposal_claim, _ = publish_scoped_claim(
        session,
        job_id,
        producer=AnalysisProducer.governance,
        subject_kind=SubjectKind.proposal,
        subject_identity={"chain_id": chain_id, "governor": governor.lower(), "proposal_id": str(proposal_id)},
        subject_role=SubjectRole.proposal,
        natural_key=f"proposal:{governor.lower()}:{proposal_id}:contents",
        evidence_kind=EvidenceKind.chain_event,
        evidence_payload={
            "actions": proposal["actions"],
            "description_hash": "0x" + proposal["description_hash"].hex(),
        },
        evidence_source={"kind": EvidenceKind.chain_event.value, **proposal["source"]},
        claim_kind=ClaimKind.proposal_contents,
        proposition={"kind": ClaimKind.proposal_contents.value, "actions": proposal["actions"]},
        scope_kind=ScopeKind.point,
        scope={
            "kind": ScopeKind.point.value,
            "at": {
                "chain_id": chain_id,
                "block_number": proposal["source"]["block_number"],
                "block_hash": proposal["source"]["block_hash"],
            },
        },
        rule=DerivationRule.proposal_contents,
        implementation=manifest,
        preserve_publication_point=True,
    )
    session.commit()
    # The event and creation binding are historical point facts. Restore the
    # canonical current point with a fresh receipt verification at the pinned
    # baseline before a fork failure can leave the latest publication historical.
    publish_scoped_claim(
        session,
        job_id,
        producer=AnalysisProducer.governance,
        subject_kind=SubjectKind.proposal,
        subject_identity={"chain_id": chain_id, "governor": governor.lower(), "proposal_id": str(proposal_id)},
        subject_role=SubjectRole.proposal,
        natural_key=f"proposal:{governor.lower()}:{proposal_id}:contents:baseline_verification",
        evidence_kind=EvidenceKind.chain_read,
        evidence_payload={"proposal_event": proposal["source"], "actions": proposal["actions"]},
        evidence_source={
            "kind": EvidenceKind.chain_read.value,
            "method": "eth_getTransactionReceipt",
            "transaction_hash": proposal["source"]["transaction_hash"],
            "verified_at": baseline,
        },
        claim_kind=ClaimKind.proposal_contents,
        proposition={"kind": ClaimKind.proposal_contents.value, "actions": proposal["actions"]},
        scope_kind=ScopeKind.point,
        scope={"kind": ScopeKind.point.value, "at": baseline},
        rule=DerivationRule.proposal_contents,
        implementation=manifest,
        prerequisite_claims=[proposal_claim],
    )
    session.commit()

    owned = transport is None
    port = _available_port() if owned else None
    try:
        if owned:
            assert port is not None
            transport = SubprocessAnvil(
                port=port,
                hardfork_name="prague",
                fork_url=rpc_url,
                fork_headers=rpc_headers(rpc_url),
                fork_block_number=baseline["block_number"],
            )
        if transport.fork_block_number() != baseline["block_number"]:
            return diagnostic(DiagnosticCode.stale_baseline, "Fork height differs from pinned baseline")
        assert_post_cancun(transport)
        if owned:
            fork_block = rpc_request(
                f"http://127.0.0.1:{port}", "eth_getBlockByNumber", [hex(baseline["block_number"]), False]
            )
            if str(fork_block.get("hash", "")).lower() != baseline["block_hash"].lower():
                return diagnostic(DiagnosticCode.stale_baseline, "Fork block hash differs from pinned baseline")
        elif str(transport.block_hash(baseline["block_number"])).lower() != baseline["block_hash"].lower():
            return diagnostic(DiagnosticCode.stale_baseline, "Injected fork hash differs from pinned baseline")

        getter_specs = [getter for getter in _CONFIG_GETTERS if getter.parameter is not None]
        targets = list(dict.fromkeys([governor.lower(), *(action["target"] for action in proposal["actions"])]))

        def read_values() -> dict[str, dict[str, Any]]:
            found = {}
            for target in targets:
                values = {}
                for getter in getter_specs:
                    result = transport.call({"to": target, "data": _selector(getter.signature)})
                    value = _decode(result, getter.output)
                    if value is not None:
                        values[getter.signature] = value
                found[target] = values
            return found

        before = read_values()
        if not any(before.values()):
            return diagnostic(DiagnosticCode.unsupported_code, "No supported configuration getter was readable on fork")
        baseline_claims: dict[tuple[str, str], str] = {}
        for target, values in before.items():
            for getter in getter_specs:
                if getter.signature not in values:
                    continue
                assert getter.parameter is not None
                unit = (
                    "seconds"
                    if getter.parameter == ConfigurationParameter.minimum_delay
                    else ("addresses" if getter.parameter == ConfigurationParameter.safe_signers else "count")
                )
                baseline_claims[(target, getter.signature)] = record_configuration(
                    session,
                    job_id,
                    contract_address=target,
                    point=baseline,
                    parameter=getter.parameter,
                    value=values[getter.signature],
                    unit=unit,
                    clock=getter.clock,
                    source={"method": "eth_call", "signature": getter.signature, "environment": "fork_baseline"},
                    implementation=manifest,
                )
        session.commit()
        actions = proposal["actions"]
        calldata = (
            "0x"
            + (
                keccak(text="execute(address[],uint256[],bytes[],bytes32)")[:4]
                + encode(
                    ["address[]", "uint256[]", "bytes[]", "bytes32"],
                    [
                        [a["target"] for a in actions],
                        [int(a["value"]) for a in actions],
                        [bytes.fromhex(a["calldata"][2:]) for a in actions],
                        proposal["description_hash"],
                    ],
                )
            ).hex()
        )
        total_value = sum(int(action["value"]) for action in actions)
        if total_value > 10**19:
            return diagnostic(
                DiagnosticCode.unsupported_parameter, "Proposal requires more ETH than fork sender fixture"
            )
        tx = {"from": sender.lower(), "to": governor.lower(), "data": calldata, "value": hex(total_value)}
        snapshot = transport.snapshot()
        try:
            transport.impersonate(sender.lower())
            try:
                probe = transport.call(tx)
                if not probe.success:
                    return diagnostic(
                        DiagnosticCode.execution_failure,
                        f"Governor execution reverted: {probe.error_message or probe.revert_data}",
                    )
                tx_hash = transport.send(tx)
                transport.mine()
            finally:
                transport.stop_impersonate(sender.lower())
            receipt = (
                rpc_request(f"http://127.0.0.1:{port}", "eth_getTransactionReceipt", [tx_hash])
                if owned
                else transport.receipt(tx_hash)
            )
            if not isinstance(receipt, Mapping) or receipt.get("status") != "0x1":
                return diagnostic(DiagnosticCode.execution_failure, "Fork transaction had no successful receipt")
            after = read_values()
            lost = [
                f"{target}:{signature}"
                for target in targets
                for signature in before[target]
                if signature not in after[target]
            ]
            if lost:
                diagnostic(
                    DiagnosticCode.incomplete_coverage, f"Post-execution getter readback unavailable: {', '.join(lost)}"
                )
            changed = [
                (target, getter, after[target][getter.signature])
                for target in targets
                for getter in getter_specs
                if getter.signature in before[target]
                and getter.signature in after[target]
                and before[target][getter.signature] != after[target][getter.signature]
            ]
            if not changed:
                return diagnostic(
                    DiagnosticCode.incomplete_coverage, "Proposal executed but no supported configuration changed"
                )
            execution = {
                "success": True,
                "fork_block_number": baseline["block_number"],
                "transaction_hash": tx_hash,
                "proposal_event": proposal["source"],
                "getter_before": before,
                "getter_after": after,
                "hardfork": transport.hardfork(),
                "versions": transport.versions(),
            }
            claims = []
            for target, getter, value in changed:
                assert getter.parameter is not None
                unit = (
                    "seconds"
                    if getter.parameter == ConfigurationParameter.minimum_delay
                    else ("addresses" if getter.parameter == ConfigurationParameter.safe_signers else "count")
                )
                claim, _ = record_scenario_configuration(
                    session,
                    job_id,
                    contract_address=target,
                    baseline=baseline,
                    step=len(actions),
                    parameter=getter.parameter,
                    value=value,
                    unit=unit,
                    actions=actions,
                    assumptions=[
                        {
                            "kind": "impersonated_sender",
                            "address": sender.lower(),
                            "funded_balance_wei": str(10**19) if owned else "transport_defined",
                        }
                    ],
                    prerequisite_claims=[proposal_claim, baseline_claims[(target, getter.signature)]],
                    implementation=manifest,
                    execution=execution,
                )
                claims.append(claim)
            session.commit()
            return claims
        finally:
            if not transport.revert(snapshot):
                raise RuntimeError("failed to restore scenario fork snapshot")
    except Exception as exc:
        session.rollback()
        return diagnostic(DiagnosticCode.execution_failure, f"Fork scenario failed: {type(exc).__name__}")
    finally:
        if owned and transport is not None:
            transport.close()


__all__ = ["execute_proposal_scenario", "proposal_from_receipt"]
