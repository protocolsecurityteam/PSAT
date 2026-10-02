"""Every test pins a way an unread witness could become a published number: a ``not_determined`` input must produce
no finding and no escalation. The prototype's -30λ delegatecall row said only "I could not resolve the operand".
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

import pytest

from db.models import Contract, EffectiveFunction, EffectVerdict, FunctionPrincipal, Job, Protocol, RoleHolderPlane
from services.scoring.cli import distill_protocol_in_memory
from services.scoring.constants import (
    DEST_SEVERITY_CONSTRAINED_OTHER,
    DEST_SEVERITY_DELEGATECALL_SELF,
    DEST_SEVERITY_EXEC_SELF,
    DEST_SEVERITY_UNCONSTRAINED,
    FLOW_SEVERITY_CALLER_ARBITRARY,
    FLOW_SEVERITY_MSG_VALUE_PASSTHROUGH,
    FLOW_SEVERITY_MSG_VALUE_SELF_RETURN,
    ROLE_BREADTH_MULTI_HOLDER_WEAKNESS,
    UNCHARGED_PRODUCT_BASES,
    WEAKNESS_SAFE_SUPERMAJORITY,
    WEAKNESS_SAFE_UNCREDITED,
)
from services.scoring.distill import (
    MSG_VALUE_ARM_PASSTHROUGH,
    MSG_VALUE_ARM_SELF_RETURN,
    MSG_VALUE_REPETITION_RESIDUAL,
    SELF_SERVICE_BASIS,
    SELF_SERVICE_DISCLOSE_SIBLING,
    SELF_SERVICE_DISCLOSE_UPGRADE,
    SELF_SERVICE_UNCHARGED_NOTE,
    distill_contract_signals,
    distill_job_signals,
)
from services.scoring.fold import _NOTE_WARNINGS, compute_protocol_score
from services.scoring.planes import (
    CONTROL_RELATIONS,
    REFUSAL_MALFORMED_NODE_ID,
    REFUSAL_SELF_EDGE,
    REFUSAL_ZERO_ANCHOR,
    REFUSAL_ZERO_PRINCIPAL,
    SHEET_BELOW_RESOLUTION,
    SHEET_NO_ROWS,
    SHEET_PROVEN_EMPTY,
    UNCONSUMED_REASON_UNCLASSIFIED,
    load_audit_posture,
    load_control_closure,
    load_value_plane,
    unconsumed_reach_relations,
)
from services.scoring.population import current_signals_for_protocol
from services.scoring.schema import entity_key
from utils.scoring_status import (
    DESTINATION_STATE_CONSTRAINED_PROVEN,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_DETERMINED,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    GRADE_STATE_NOT_DETERMINED,
    PRINCIPAL_STATE_ENUMERATED,
    REACH_GATE_LICENSED,
    REACH_GATE_NOT_DETERMINED,
    SEVERITY_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_REACH,
)


def _identity(signal) -> tuple:
    return (signal.chain, signal.deployment_address, signal.contract_id, signal.selector, signal.claim_id)


VAULT = "0x1111111111111111111111111111111111111111"
SAFE = "0x2222222222222222222222222222222222222222"
OWNERS = [f"0x{str(index) * 40}" for index in range(1, 7)]
OTHER_OWNERS = [f"0x{letter * 40}" for letter in "abcdef"]


class _Corpus:
    def __init__(self, session, protocol, job):
        self.session = session
        self.protocol = protocol
        self.job = job
        self.contracts: list[Contract] = []

    def contract(self, address: str, *, chain: str | None = "ethereum", implementation: str | None = None) -> Contract:
        row = Contract(
            address=address,
            chain=chain,
            protocol_id=self.protocol.id,
            job_id=self.job.id,
            implementation=implementation,
        )
        self.session.add(row)
        self.session.commit()
        self.contracts.append(row)
        return row

    def function(
        self,
        contract: Contract,
        *,
        name: str,
        claims: list[dict[str, Any]],
        openness: str | None = "restricted",
        selector: str | None = None,
        deployment_address: str | None = None,
        capability_expr: Any = None,
        conditions: Any = None,
    ) -> EffectiveFunction:
        row = EffectiveFunction(
            contract_id=contract.id,
            deployment_address=deployment_address or contract.address,
            function_name=name,
            selector=selector or ("0x" + uuid.uuid4().hex[:8]),
            abi_signature=f"{name}()",
            authority_public=openness == "open",
            authority_openness=openness,
            claims=claims,
            capability_expr=capability_expr,
            conditions=conditions,
        )
        self.session.add(row)
        self.session.commit()
        return row

    def principal(
        self,
        function: EffectiveFunction,
        *,
        address: str,
        resolved_type: str,
        details: dict[str, Any] | None = None,
    ) -> FunctionPrincipal:
        row = FunctionPrincipal(
            function_id=function.id,
            address=address,
            resolved_type=resolved_type,
            details=details if details is not None else {},
        )
        self.session.add(row)
        self.session.commit()
        return row

    def signals(self, contract: Contract):
        return distill_contract_signals(self.session, contract, job_id=self.job.id)

    def only(self, contract: Contract, claim_id: str):
        matches = [s for s in self.signals(contract) if s.claim_id == claim_id]
        assert len(matches) == 1, f"expected one {claim_id} signal, got {len(matches)}"
        return matches[0]

    def score(self):
        signals = distill_protocol_in_memory(self.session, self.protocol.id)
        return compute_protocol_score(self.session, self.protocol.id, signals=signals)


@pytest.fixture()
def corpus(db_session):
    protocol = Protocol(name=f"scorer-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    job = Job(id=uuid.uuid4(), protocol_id=protocol.id)
    db_session.add(job)
    db_session.commit()
    fixture = _Corpus(db_session, protocol, job)
    try:
        yield fixture
    finally:
        db_session.rollback()
        for contract in fixture.contracts:
            db_session.query(Contract).filter_by(id=contract.id).delete()
        db_session.query(Job).filter_by(id=job.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


def _delegatecall(destination: dict[str, Any], constraint: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": "delegatecall.execute",
        "tier": "idiom_structural",
        "witness": {"kind": "delegatecall_sink", "destination": destination, "destination_constraint": constraint},
    }


def _flow_out(observed: dict[str, Any] | None, flows: list[dict[str, Any]] | None, tier: str) -> dict[str, Any]:
    witness: dict[str, Any] = {"kind": "value_flow", "direction": "out"}
    if flows is not None:
        witness["flows"] = flows
    if observed is not None:
        witness["observed"] = observed
    return {"claim_id": "flow.out", "tier": tier, "witness": witness}


def _safe_details(owners: list[str], threshold: int, protection: dict[str, Any] | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {"owners": owners, "threshold": threshold, "trace": []}
    if protection is not None:
        details["safe_protection"] = protection
    return details


_PROVEN_EMPTY_MODULES = {
    "guard": "proven_zero",
    "module_set": [],
    "module_set_basis": "storage_linked_list_terminated",
    "modules_head": "0x" + "0" * 63 + "1",
    "probe_block": 100,
    "protection_is_upper_bound": "not_determined",
}


def test_unread_delegatecall_destination_scores_nothing(corpus):
    """Grading ``unresolved_operand`` as ``unconstrained`` took an unmodified OZ ``multicall`` to an F."""
    contract = corpus.contract("0x" + "a" * 40)
    function = corpus.function(
        contract,
        name="multicall",
        claims=[
            _delegatecall(
                {"target_kind": "indeterminate", "reason": "unresolved_operand"},
                {"state": "not_determined"},
            )
        ],
        openness="open",
    )
    assert function.id
    signal = corpus.only(contract, "delegatecall.execute")

    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert not signal.enters_grade
    assert "destination_not_determined_row_withheld" in signal.witness_notes

    document = corpus.score()
    assert document.findings == []
    assert document.grade_state == GRADE_STATE_NOT_DETERMINED
    assert "population_scored_to_nothing" in document.provenance["population"]["disposition"]


def test_unread_exec_destination_scores_nothing(corpus):
    contract = corpus.contract("0x" + "b" * 40)
    corpus.function(
        contract,
        name="manage",
        claims=[
            {
                "claim_id": "exec.arbitrary",
                "tier": "idiom_structural",
                "witness": {"kind": "param_taint", "destination_kind": "param", "destination_constraint": {}},
            }
        ],
        openness="open",
    )
    signal = corpus.only(contract, "exec.arbitrary")
    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert not signal.enters_grade


def _exec_param_claim(param: str) -> dict[str, Any]:
    return {
        "claim_id": "exec.arbitrary",
        "tier": "idiom_structural",
        "witness": {
            "kind": "param_taint",
            "destination_kind": "param",
            "destination_param": param,
            "destination_constraint": {"state": "not_determined"},
        },
    }


def _caller_arbitrary_verdict(function: EffectiveFunction, *, sentinel_param: str | None) -> EffectVerdict:
    witness: dict[str, Any] = {
        "value_moved": True,
        "observation": "executed",
        "destination_shape": "caller_arbitrary",
        "shape_proved_by": "simulation",
    }
    if sentinel_param is not None:
        witness["sentinel_param"] = sentinel_param
    return EffectVerdict(
        function_id=function.id,
        chain_id=1,
        contract_address=function.deployment_address,
        selector=function.selector,
        effect_class="value_out",
        behavior_hash="bh",
        verdict="proven",
        tier="tier1",
        witness=witness,
    )


def test_fork_caller_arbitrary_is_consumed_on_the_destination_parameter(corpus):
    """The 15 proven verdicts the exec arm never read."""
    contract = corpus.contract("0x" + "1a" * 20)
    function = corpus.function(contract, name="manage", claims=[_exec_param_claim("target")], openness="restricted")
    corpus.session.add(_caller_arbitrary_verdict(function, sentinel_param="target"))
    corpus.session.commit()

    signal = corpus.only(contract, "exec.arbitrary")
    assert signal.destination.state == DESTINATION_STATE_UNCONSTRAINED_PROVEN
    assert signal.severity.state == SEVERITY_STATE_PROVEN
    assert signal.severity.value == DEST_SEVERITY_UNCONSTRAINED
    assert "fork:simulation+destination_param" in signal.severity_basis


def test_fork_caller_arbitrary_about_another_parameter_licenses_nothing(corpus):
    """The common shape: the sentinel lands in the payload slot, proving nothing about the destination parameter."""
    contract = corpus.contract("0x" + "1b" * 20)
    function = corpus.function(contract, name="manage", claims=[_exec_param_claim("target")], openness="restricted")
    corpus.session.add(_caller_arbitrary_verdict(function, sentinel_param="data"))
    corpus.session.commit()

    signal = corpus.only(contract, "exec.arbitrary")
    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert not signal.enters_grade
    assert "fork_caller_arbitrary_witness_is_about_another_parameter" in signal.witness_notes


def _caller_relative_flow(kind: str) -> dict[str, Any]:
    return _flow_out(
        None,
        [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": kind}}],
        "idiom_structural",
    )


def test_an_open_gate_licenses_no_escalation_where_the_caller_cannot_name_the_payee(corpus):
    """The token's history picks the payee, so an open gate is the safe "anyone may settle" shape.

    Whether the open-caller ruling reaches this kind is the owner's call.
    """
    contract = corpus.contract("0x" + "2b" * 20)
    corpus.function(contract, name="claimWithdraw", claims=[_caller_relative_flow("token_owner")], openness="open")

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert not signal.enters_grade
    assert "destination_token_owner_open_gate_licenses_no_escalation" in signal.witness_notes


@pytest.mark.parametrize(
    ("kind", "note"),
    [
        ("msg_sender", "constraint_only_as_strong_as_the_caller_gate"),
        ("token_owner", "destination_is_the_current_owner_of_a_caller_chosen_token_id"),
    ],
    ids=["msg_sender", "token_owner"],
)
def test_caller_relative_destination_behind_a_gate_is_the_constrained_convention(corpus, kind, note):
    contract = corpus.contract("0x" + ("2c" if kind == "msg_sender" else "2d") * 20)
    corpus.function(contract, name="rescueTokens", claims=[_caller_relative_flow(kind)], openness="restricted")

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_CONSTRAINED_PROVEN
    assert signal.destination.value == f"constrained:{kind}"
    assert signal.severity.value == DEST_SEVERITY_CONSTRAINED_OTHER
    assert note in signal.witness_notes
    if kind == "token_owner":
        assert "constraint_only_as_strong_as_the_caller_gate" not in signal.witness_notes


def test_caller_relative_destination_with_an_unread_gate_stays_undetermined(corpus):
    contract = corpus.contract("0x" + "2e" * 20)
    corpus.function(
        contract, name="unwrapForEEthAndBurn", claims=[_caller_relative_flow("msg_sender")], openness="not_determined"
    )

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert not signal.enters_grade
    assert "destination_msg_sender_caller_gate_unread" in signal.witness_notes


def test_an_indeterminate_member_still_blocks_a_caller_relative_conjunction(corpus):
    contract = corpus.contract("0x" + "3a" * 20)
    corpus.function(
        contract,
        name="withdraw",
        claims=[
            _flow_out(
                None,
                [
                    {"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "msg_sender"}},
                    {"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "indeterminate"}},
                ],
                "idiom_structural",
            )
        ],
        openness="open",
    )

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert not signal.enters_grade


def _msg_value_flow(target: str, **over: Any) -> dict[str, Any]:
    flow: dict[str, Any] = {
        "kind": "low_level_value_call",
        "from_is_self": True,
        "amount_kind": {"kind": "msg_value", "tier": "dispositive_ast"},
        "target_kind": {"kind": target, "tier": "dispositive_ast"},
    }
    flow.update(over)
    return flow


def _msg_value_claims(*flows: dict[str, Any]) -> list[dict[str, Any]]:
    return [_flow_out(None, list(flows), "idiom_structural")]


def test_msg_value_returned_to_the_caller_carries_no_severity_of_its_own(corpus):
    """W3a: the payout moves no position the caller didn't just fund, so it's priced at a named zero."""
    contract = corpus.contract("0x" + "4a" * 20)
    corpus.function(
        contract, name="unwrapL2Eth", claims=_msg_value_claims(_msg_value_flow("msg_sender")), openness="restricted"
    )

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_CONSTRAINED_PROVEN
    assert signal.destination.value == "constrained:msg_sender"
    assert signal.severity.state == SEVERITY_STATE_PROVEN
    assert signal.severity.value == FLOW_SEVERITY_MSG_VALUE_SELF_RETURN
    assert signal.severity_basis == (MSG_VALUE_ARM_SELF_RETURN,)
    assert MSG_VALUE_ARM_SELF_RETURN in signal.witness_notes
    assert MSG_VALUE_ARM_PASSTHROUGH not in signal.witness_notes
    assert MSG_VALUE_REPETITION_RESIDUAL in signal.witness_notes
    assert MSG_VALUE_REPETITION_RESIDUAL in _NOTE_WARNINGS


def test_msg_value_self_return_answers_the_withhold_it_is_pending_on(corpus):
    """This is the amount witness the withhold is pending on, so it's read first."""
    contract = corpus.contract("0x" + "4d" * 20)
    corpus.function(contract, name="refund", claims=_msg_value_claims(_msg_value_flow("msg_sender")), openness="open")

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_UNCONSTRAINED_PROVEN
    assert signal.destination.value == "caller_arbitrary"
    assert signal.severity.state == SEVERITY_STATE_PROVEN
    assert signal.severity.value == FLOW_SEVERITY_MSG_VALUE_SELF_RETURN
    assert signal.severity_basis == (MSG_VALUE_ARM_SELF_RETURN,)
    assert "destination_msg_sender_with_open_caller_gate" in signal.witness_notes
    assert "flow_severity_withheld_pending_amount_witness" not in signal.witness_notes


def test_msg_value_passed_through_to_a_fixed_payee_is_uncharged_product(corpus):
    """W3b, owner-ruled: the caller's own ETH to an unnameable payee is uncharged product surface at a named zero."""
    contract = corpus.contract("0x" + "4b" * 20)
    corpus.function(contract, name="receive", claims=_msg_value_claims(_msg_value_flow("immutable")), openness="open")

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_CONSTRAINED_PROVEN
    assert signal.destination.value == "immutable_fixed"
    assert signal.severity.state == SEVERITY_STATE_PROVEN
    assert signal.severity.value == FLOW_SEVERITY_MSG_VALUE_PASSTHROUGH
    assert signal.severity.value == 0.0
    assert signal.severity_basis == (MSG_VALUE_ARM_PASSTHROUGH,)
    assert MSG_VALUE_ARM_PASSTHROUGH in signal.severity_basis
    assert MSG_VALUE_ARM_PASSTHROUGH in UNCHARGED_PRODUCT_BASES
    assert MSG_VALUE_ARM_PASSTHROUGH in signal.witness_notes
    assert MSG_VALUE_ARM_SELF_RETURN not in signal.witness_notes
    # Preserved for the earned negative the fold leaves behind.
    assert "fixed_destination_conditional_on_upgrade_authority" in signal.witness_notes


_MSG_VALUE_REFUSALS = [
    # ``amount_kinds`` is emitted exactly where sites disagreed.
    (
        "several_fold",
        "5a",
        _msg_value_claims(
            _msg_value_flow(
                "msg_sender",
                amount_kind={"kind": "several", "tier": "dispositive_ast"},
                amount_kinds=[
                    {"kind": "msg_value", "tier": "dispositive_ast"},
                    {"kind": "capped_by_balance", "tier": "dispositive_ast"},
                ],
            )
        ),
        "amount_fold_disagreed",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    # The breakdown is the producer saying the scalar isn't proven.
    (
        "breakdown_beside_a_msg_value_scalar",
        "5b",
        _msg_value_claims(
            _msg_value_flow(
                "msg_sender",
                amount_kinds=[
                    {"kind": "msg_value", "tier": "dispositive_ast"},
                    {"kind": "param", "tier": "dispositive_ast"},
                ],
            )
        ),
        "amount_fold_disagreed",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    # A traced msg.value means the tracer reached the opcode, not that the amount is this call's value.
    (
        "traced_amount",
        "5c",
        _msg_value_claims(_msg_value_flow("msg_sender", amount_kind={"kind": "msg_value", "tier": "static_trace"})),
        "amount_not_dispositive_ast",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    (
        "sibling_flow_is_not_msg_value",
        "5d",
        _msg_value_claims(
            _msg_value_flow("msg_sender"),
            _msg_value_flow("msg_sender", amount_kind={"kind": "param", "tier": "dispositive_ast"}),
        ),
        "amount_not_msg_value",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    (
        "source_not_self",
        "5e",
        _msg_value_claims(
            {
                "kind": "low_level_value_call",
                "amount_kind": {"kind": "msg_value", "tier": "dispositive_ast"},
                "target_kind": {"kind": "msg_sender", "tier": "dispositive_ast"},
            }
        ),
        "flow_source_not_self",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    (
        "target_breakdown",
        "5f",
        _msg_value_claims(
            _msg_value_flow(
                "several",
                target_kinds=[
                    {"kind": "msg_sender", "tier": "dispositive_ast"},
                    {"kind": "immutable", "tier": "dispositive_ast"},
                ],
            )
        ),
        "target_fold_disagreed",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    (
        "third_payee_kind",
        "6a",
        _msg_value_claims(_msg_value_flow("storage_setter")),
        "target_not_a_witnessed_arm",
        None,
    ),
    # The bound is per entry: two entries paying the caller move twice what was attached.
    (
        "multiple_paying_entries",
        "6b",
        _msg_value_claims(_msg_value_flow("msg_sender"), _msg_value_flow("msg_sender")),
        "multiple_out_flow_entries",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    (
        "one_entry_per_arm",
        "6d",
        _msg_value_claims(_msg_value_flow("msg_sender"), _msg_value_flow("immutable")),
        "multiple_out_flow_entries",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
    (
        "unreadable_kind",
        "6c",
        _msg_value_claims(
            _msg_value_flow("msg_sender"),
            {"kind": "low_level_value_call", "from_is_self": True, "target_kind": {"kind": "msg_sender"}},
        ),
        "flow_kind_unreadable",
        DEST_SEVERITY_CONSTRAINED_OTHER,
    ),
]


@pytest.mark.parametrize(
    ("slug", "claims", "reason", "severity"),
    [case[1:] for case in _MSG_VALUE_REFUSALS],
    ids=[case[0] for case in _MSG_VALUE_REFUSALS],
)
def test_msg_value_return_refuses(corpus, slug, claims, reason, severity):
    from services.scoring import distill as D

    assert D._msg_value_return(claims) == D._MsgValueReturn(arm=None, refusal=reason)

    contract = corpus.contract("0x" + slug * 20)
    corpus.function(contract, name="withdraw", claims=claims, openness="restricted")

    signal = corpus.only(contract, "flow.out")
    assert f"msg_value_return_refused:{reason}" in signal.witness_notes
    assert MSG_VALUE_ARM_SELF_RETURN not in signal.witness_notes
    assert MSG_VALUE_ARM_PASSTHROUGH not in signal.witness_notes
    assert MSG_VALUE_ARM_SELF_RETURN not in signal.severity_basis
    assert MSG_VALUE_REPETITION_RESIDUAL not in signal.witness_notes
    if severity is None:
        assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
        assert not signal.enters_grade
    else:
        assert signal.severity.state == SEVERITY_STATE_PROVEN
        assert signal.severity.value == severity


def test_a_payout_that_never_mentions_msg_value_is_asked_nothing(corpus):
    """Where the amount is a parameter the question doesn't arise; a reason there would spread over every flow."""
    contract = corpus.contract("0x" + "4c" * 20)
    corpus.function(
        contract,
        name="rescueTokens",
        claims=_msg_value_claims(
            _msg_value_flow("msg_sender", amount_kind={"kind": "param", "tier": "dispositive_ast"})
        ),
        openness="restricted",
    )

    signal = corpus.only(contract, "flow.out")
    assert not [note for note in signal.witness_notes if note.startswith("msg_value_return_refused")]
    assert MSG_VALUE_ARM_SELF_RETURN not in signal.witness_notes
    assert MSG_VALUE_ARM_PASSTHROUGH not in signal.witness_notes
    assert signal.severity.value == DEST_SEVERITY_CONSTRAINED_OTHER
    assert signal.severity_basis == ("constrained:msg_sender+restricted_caller",)


def _proven_ssp(**over: Any) -> dict[str, Any]:
    fact = {
        "state": "proven_self_service",
        "w1_basis": "keyed_by_caller",
        "w2_basis": "clear_dominates_calls",
        "record": "bids",
        "disclosures": [SELF_SERVICE_DISCLOSE_UPGRADE, SELF_SERVICE_DISCLOSE_SIBLING],
    }
    fact.update(over)
    return fact


def _ss_flow(target: str = "msg_sender", ssp: dict[str, Any] | str | None = "proven", **over: Any) -> dict[str, Any]:
    flow: dict[str, Any] = {
        "kind": "callee_erc20_selector",
        "from_is_self": True,
        "amount_kind": {"kind": "bounded_by_storage", "tier": "dispositive_ast"},
        "target_kind": {"kind": target, "tier": "dispositive_ast"},
    }
    if ssp == "proven":
        flow["self_service_payout"] = _proven_ssp()
    elif ssp is not None:
        flow["self_service_payout"] = ssp
    flow.update(over)
    return flow


def _ss_claims(*flows: dict[str, Any]) -> list[dict[str, Any]]:
    return [_flow_out(None, list(flows), "idiom_structural")]


def test_self_service_bound_conjuncts():
    """G2: drop any of W1, W2, caller-relative payee or readable sibling flow and a named refusal replaces the proof."""
    from services.scoring import distill as D

    proven = D._self_service_bound(_ss_claims(_ss_flow()))
    assert proven.proven is True
    assert proven.refusal is None
    assert SELF_SERVICE_DISCLOSE_UPGRADE in proven.disclosures
    assert SELF_SERVICE_DISCLOSE_SIBLING in proven.disclosures

    c1 = D._self_service_bound(_ss_claims(_ss_flow(ssp={"state": "not_determined", "reason": "guard_not_mandatory"})))
    assert c1 == D._SelfServiceBound(proven=False, refusal="guard_not_mandatory")
    c2 = D._self_service_bound(_ss_claims(_ss_flow(ssp={"state": "not_determined", "reason": "no_clearing_write"})))
    assert c2 == D._SelfServiceBound(proven=False, refusal="no_clearing_write")
    c3 = D._self_service_bound(_ss_claims(_ss_flow(target="immutable")))
    assert c3 == D._SelfServiceBound(proven=False, refusal="payee_not_caller_relative")
    c3b = D._self_service_bound(_ss_claims(_ss_flow(from_is_self=False)))
    assert c3b == D._SelfServiceBound(proven=False, refusal="flow_source_not_self")
    c4 = D._self_service_bound(_ss_claims(_ss_flow(), _ss_flow(ssp=None)))
    assert c4 == D._SelfServiceBound(proven=False, refusal="unread_out_flow")

    not_asked = D._self_service_bound(_ss_claims(_msg_value_flow("msg_sender")))
    assert not_asked == D._SELF_SERVICE_NOT_ASKED
    blocked = [{"claim_id": "flow.out", "tier": "policy_derived", "witness": {"kind": "value_flow", "flows": []}}]
    assert D._self_service_bound(blocked) == D._SELF_SERVICE_NOT_ASKED


def test_self_service_refused_open_payout_stays_at_the_interim_withhold(corpus):
    """Back to the U-IW withhold, never a cheaper number."""
    contract = corpus.contract("0x" + "52" * 20)
    corpus.function(
        contract,
        name="cancelBid",
        claims=_ss_claims(_ss_flow(ssp={"state": "not_determined", "reason": "guard_not_mandatory"})),
        openness="open",
    )

    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_UNCONSTRAINED_PROVEN
    assert signal.severity.state == SEVERITY_STATE_NOT_DETERMINED
    assert signal.severity_basis == ()
    assert not signal.enters_grade
    assert "flow_severity_withheld_pending_amount_witness" in signal.witness_notes
    assert "self_service_bound_refused:guard_not_mandatory" in signal.witness_notes
    assert SELF_SERVICE_BASIS not in signal.severity_basis


def test_self_service_uncharged_row_is_excluded_and_leaves_an_earned_negative(corpus):
    """G1 + G7: no finding, but the disclosures ride an earned negative."""
    contract = corpus.contract("0x" + "53" * 20)
    corpus.function(contract, name="cancelBid", claims=_ss_claims(_ss_flow()), openness="open")

    document = corpus.score()
    assert [f for f in document.findings if f["capability"] == "flow.out"] == []
    assert document.provenance["population"]["rows_uncharged_product"] == 1
    assert document.provenance["population"]["signals_entering_grade"] == 1

    payload = document.document()
    negatives = [e for e in payload["earned_negatives"] if e["state"] == "uncharged_product_surface"]
    assert len(negatives) == 1
    (neg,) = negatives
    assert neg["function"] == "cancelBid"
    assert neg["basis"] == [SELF_SERVICE_BASIS]
    assert neg["conditional_on"] == SELF_SERVICE_DISCLOSE_UPGRADE
    assert neg["residual"] == SELF_SERVICE_DISCLOSE_SIBLING
    # ... and surface as warnings too (the warning channel).
    kinds = {w["kind"] for w in payload["warnings"]}
    assert SELF_SERVICE_DISCLOSE_UPGRADE in kinds
    assert SELF_SERVICE_DISCLOSE_SIBLING in kinds
    assert SELF_SERVICE_UNCHARGED_NOTE in kinds


def test_uncharged_product_basis_value_disagreement_warns_and_does_not_exclude():
    """G8: the disagreement never buys a silent exclusion.

    Its corpus count is 0 (checked by the differential harness).
    """
    import types
    from typing import cast

    from services.scoring.fold import _is_uncharged_product, _uncharged_product
    from services.scoring.schema import SEVERITY_STATE_PROVEN as PROVEN
    from services.scoring.schema import Tri

    def sig(value: float) -> Any:
        return cast(
            Any,
            types.SimpleNamespace(
                severity_basis=(SELF_SERVICE_BASIS,),
                severity=Tri.proven(PROVEN, value),
                chain="ethereum",
                deployment_address="0x" + "aa" * 20,
                function_name="cancelBid",
                claim_id="flow.out",
            ),
        )

    warnings: list[dict[str, Any]] = []
    assert _uncharged_product(sig(0.0), warnings) is True
    assert warnings == []
    assert _uncharged_product(sig(0.35), warnings) is False
    assert [w["kind"] for w in warnings] == ["uncharged_product_basis_value_disagreement"]

    # pause.set builds up from zero; that's a real charge.
    plain_zero = cast(
        Any, types.SimpleNamespace(severity_basis=("capability_class_base",), severity=Tri.proven(PROVEN, 0.0))
    )
    assert _is_uncharged_product(plain_zero) is False


def test_not_applicable_is_a_different_fact_from_not_determined(corpus):
    contract = corpus.contract("0x" + "d" * 40)
    corpus.function(
        contract,
        name="pause",
        claims=[{"claim_id": "pause.set", "tier": "idiom_structural", "witness": {}}],
        selector="0x8456cb59",
    )
    corpus.function(
        contract,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
        selector="0x3659cfe6",
    )
    corpus.function(
        contract,
        name="multicall",
        claims=[_delegatecall({"target_kind": "indeterminate"}, {"state": "not_determined"})],
        selector="0xac9650d8",
    )
    pause = corpus.only(contract, "pause.set")
    upgrade = corpus.only(contract, "upgrade.implementation")
    delegatecall = corpus.only(contract, "delegatecall.execute")

    # An upgrade names a new implementation and this scorer has no destination model for it.
    assert pause.destination.state == DESTINATION_STATE_NOT_APPLICABLE
    assert upgrade.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert delegatecall.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert upgrade.enters_grade and not delegatecall.enters_grade


def test_self_delegatecall_is_proven_fixed_and_benign(corpus):
    contract = corpus.contract("0x" + "e" * 40)
    corpus.function(
        contract,
        name="multicall",
        claims=[_delegatecall({"target_kind": "self"}, {"state": "constrained", "binding": "literal_self"})],
        openness="open",
    )
    signal = corpus.only(contract, "delegatecall.execute")
    assert signal.destination.state == DESTINATION_STATE_CONSTRAINED_PROVEN
    assert signal.destination.value == "self"
    assert signal.severity.state == SEVERITY_STATE_PROVEN
    assert signal.severity.value == DEST_SEVERITY_DELEGATECALL_SELF


def test_self_exec_is_fixed_but_not_benign(corpus):
    contract = corpus.contract("0x" + "f" * 40)
    corpus.function(
        contract,
        name="forward",
        claims=[
            {
                "claim_id": "exec.arbitrary",
                "tier": "idiom_structural",
                "witness": {"destination": {"target_kind": "self"}, "destination_constraint": {}},
            }
        ],
    )
    signal = corpus.only(contract, "exec.arbitrary")
    assert signal.destination.state == DESTINATION_STATE_CONSTRAINED_PROVEN
    assert signal.severity.value == DEST_SEVERITY_EXEC_SELF
    assert DEST_SEVERITY_EXEC_SELF > DEST_SEVERITY_DELEGATECALL_SELF


def test_constrained_destination_severity_comes_from_the_guard(corpus):
    contract = corpus.contract("0x" + "1a" * 20)
    corpus.function(
        contract,
        name="exec",
        claims=[
            {
                "claim_id": "exec.arbitrary",
                "tier": "standard_exact",
                "witness": {"destination_constraint": {"state": "constrained", "guard": "some_guard"}},
            }
        ],
    )
    signal = corpus.only(contract, "exec.arbitrary")
    assert signal.severity.value == DEST_SEVERITY_CONSTRAINED_OTHER


def test_caller_arbitrary_needs_a_behavioural_existence_proof(corpus):
    contract = corpus.contract("0x" + "2a" * 20)
    corpus.function(
        contract,
        name="staticOnly",
        claims=[
            _flow_out(
                {"destination_shape": "caller_arbitrary", "shape_proved_by": "static", "reach_determined": False},
                [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "param"}}],
                "standard_exact",
            )
        ],
        selector="0x11111111",
    )
    corpus.function(
        contract,
        name="forked",
        claims=[
            _flow_out(
                {
                    "destination_shape": "caller_arbitrary",
                    "shape_proved_by": "simulation",
                    "reach_determined": True,
                    "observed_reach_value_usd": 1000.0,
                    "observed_reach_holders": [VAULT],
                },
                [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "param"}}],
                "behavioral_observed",
            )
        ],
        selector="0x22222222",
    )
    signals = {s.function_name: s for s in corpus.signals(contract)}
    assert signals["staticOnly"].destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert not signals["staticOnly"].enters_grade
    assert signals["forked"].destination.state == DESTINATION_STATE_UNCONSTRAINED_PROVEN
    assert signals["forked"].severity.value == FLOW_SEVERITY_CALLER_ARBITRARY


def test_zero_reach_floor_is_not_a_proven_bound(corpus):
    contract = corpus.contract("0x" + "4a" * 20)
    corpus.function(
        contract,
        name="zeroFloor",
        claims=[
            _flow_out(
                {"reach_indeterminate": True, "observed_reach_floor_usd": 0.0},
                [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "immutable"}}],
                "standard_exact",
            )
        ],
        selector="0x33333333",
    )
    corpus.function(
        contract,
        name="absentFloor",
        claims=[
            _flow_out(
                {"reach_indeterminate": True},
                [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "immutable"}}],
                "standard_exact",
            )
        ],
        selector="0x44444444",
    )
    signals = {s.function_name: s for s in corpus.signals(contract)}
    assert signals["zeroFloor"].value_state == VALUE_STATE_NOT_DETERMINED
    assert "reach_floor_not_a_bound" in signals["zeroFloor"].witness_notes
    assert signals["absentFloor"].value_state == VALUE_STATE_NOT_DETERMINED
    assert "reach_floor_absent" in signals["absentFloor"].witness_notes


def test_freeze_value_membership_is_gated_on_the_latch_proof(corpus):
    contract = corpus.contract("0x" + "5a" * 20)
    corpus.function(
        contract,
        name="pauseUnproven",
        claims=[{"claim_id": "pause.set", "tier": "idiom_structural", "witness": {}}],
        selector="0x55555555",
    )
    corpus.function(
        contract,
        name="pauseProven",
        claims=[
            {
                "claim_id": "pause.set",
                "tier": "behavioral_observed",
                "witness": {"observed": {"pause_effective": True, "observed_blast_radius": ["a()"]}},
            }
        ],
        selector="0x66666666",
    )
    signals = {s.function_name: s for s in corpus.signals(contract)}
    assert signals["pauseUnproven"].value_state == VALUE_STATE_NOT_DETERMINED
    assert signals["pauseProven"].value_state == VALUE_STATE_PROVEN_REACH
    assert signals["pauseUnproven"].severity.state == SEVERITY_STATE_PROVEN


def test_null_openness_is_never_read_as_restricted(corpus):
    contract = corpus.contract("0x" + "7a" * 20)
    corpus.function(
        contract,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
        openness=None,
    )
    signal = corpus.only(contract, "upgrade.implementation")
    assert signal.authority_openness == "not_determined"
    document = corpus.score()
    assert document.findings == []
    assert "unresolved_reachability" in {w["kind"] for w in document.warnings}


def test_two_functions_reaching_one_vault_charge_it_once(corpus):
    contract = corpus.contract("0x" + "8a" * 20)
    for index, selector in enumerate(("0x77777777", "0x88888888")):
        function = corpus.function(
            contract,
            name=f"exit{index}",
            claims=[
                _flow_out(
                    {
                        "destination_shape": "caller_arbitrary",
                        "shape_proved_by": "simulation",
                        "reach_determined": True,
                        "observed_reach_value_usd": 1000.0,
                        "observed_reach_holders": [VAULT],
                    },
                    [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "param"}}],
                    "behavioral_observed",
                )
            ],
            selector=selector,
        )
        corpus.principal(function, address=SAFE, resolved_type="safe", details=_safe_details(OWNERS, 4))

    document = corpus.score()
    flow = [f for f in document.findings if f["capability"] == "flow.out"]
    assert len(flow) == 1
    assert flow[0]["n_functions"] == 2
    assert flow[0]["value_at_stake_usd"] == 1000.0


def test_same_safe_on_two_chains_stays_two_units(corpus):
    mainnet = corpus.contract("0x" + "ab" * 20, chain="ethereum")
    optimism = corpus.contract("0x" + "ac" * 20, chain="optimism")
    for contract in (mainnet, optimism):
        function = corpus.function(
            contract,
            name="upgradeTo",
            claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
        )
        corpus.principal(function, address=SAFE, resolved_type="safe", details=_safe_details(OWNERS, 4))

    document = corpus.score()
    units = {f["principal_unit"] for f in document.findings}
    assert units == {f"ethereum::{SAFE}", f"optimism::{SAFE}"}


def test_unpriced_value_is_a_confidence_hit_not_a_zero(corpus):
    contract = corpus.contract("0x" + "ad" * 20)
    function = corpus.function(
        contract,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    corpus.principal(function, address=SAFE, resolved_type="safe", details=_safe_details(OWNERS, 4))

    document = corpus.score()
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["value_band"] == "not_determined"
    assert finding["raw_points"] > 0
    assert "value_at_stake_at_band_floor" in {w["kind"] for w in document.warnings}


def test_safe_protection_withholds_the_kn_credit(corpus):
    protected = corpus.contract("0x" + "ae" * 20)
    exposed = corpus.contract("0x" + "af" * 20)
    # Identical owners would make them one power and hide the point.
    for contract, owners, protection in (
        (protected, OWNERS, _PROVEN_EMPTY_MODULES),
        (exposed, OTHER_OWNERS, {**_PROVEN_EMPTY_MODULES, "protection_is_upper_bound": True}),
    ):
        function = corpus.function(
            contract,
            name="upgradeTo",
            claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
        )
        corpus.principal(
            function,
            address=contract.address,
            resolved_type="safe",
            details=_safe_details(owners, 5, protection),
        )

    document = corpus.score()
    weakness = {f["principal_unit"]: f["weakness"] for f in document.findings}
    assert weakness[f"ethereum::{protected.address}"] == WEAKNESS_SAFE_SUPERMAJORITY
    assert weakness[f"ethereum::{exposed.address}"] == WEAKNESS_SAFE_UNCREDITED


def test_role_holder_floor_raises_breadth_and_never_lowers_it(corpus, db_session):
    contract = corpus.contract("0x" + "ba" * 20)
    registry = "0x" + "bb" * 20
    role_hash = "0x" + "cc" * 32
    db_session.add(
        RoleHolderPlane(
            chain_id=1,
            registry_address=registry,
            role_hash=role_hash,
            holders=[OWNERS[0], OWNERS[1]],
            holders_basis="pinned_has_role_confirmed",
            as_of_block=100,
            coverage="lower_bound",
            holder_set_exhaustive="not_determined",
            role_name_basis="not_determined",
            cursor_page_completeness="not_determined",
            cursor_first_indexed_block_basis="not_determined",
            cursor_enrollment_bases={},
            candidate_count=2,
            unconfirmed_candidate_count=0,
            fold_chain_disagreements=[],
        )
    )
    db_session.commit()
    function = corpus.function(
        contract,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    details = _safe_details(OWNERS, 5)
    details["trace"] = [{"step": "enumerable_role_store", "authority": registry, "role_labels": {role_hash: "ROLE"}}]
    corpus.principal(function, address=SAFE, resolved_type="safe", details=details)

    try:
        document = corpus.score()
        finding = document.findings[0]
        assert WEAKNESS_SAFE_SUPERMAJORITY < ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
        assert finding["weakness"] == ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
    finally:
        db_session.query(RoleHolderPlane).filter_by(registry_address=registry).delete()
        db_session.commit()


def test_no_population_and_scored_to_nothing_are_different(corpus):
    empty = corpus.score()
    assert empty.grade_state == GRADE_STATE_NOT_DETERMINED
    assert "no_population" in empty.provenance["population"]["disposition"]

    contract = corpus.contract("0x" + "bc" * 20)
    corpus.function(
        contract,
        name="multicall",
        claims=[_delegatecall({"target_kind": "indeterminate"}, {"state": "not_determined"})],
        openness="open",
    )
    scored_to_nothing = corpus.score()
    assert scored_to_nothing.grade_state == GRADE_STATE_NOT_DETERMINED
    assert "population_scored_to_nothing" in scored_to_nothing.provenance["population"]["disposition"]


def test_contract_typed_principal_scores_nothing(corpus):
    contract = corpus.contract("0x" + "cb" * 20)
    function = corpus.function(
        contract,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    corpus.principal(function, address="0x" + "cd" * 20, resolved_type="contract", details={})

    signal = corpus.only(contract, "upgrade.implementation")
    assert signal.principal_state == PRINCIPAL_STATE_ENUMERATED

    document = corpus.score()
    assert document.findings == []
    assert "contract_gated_unknown_path" in {w["kind"] for w in document.warnings}


def test_token_identity_forbids_pricing_and_does_not_zero_the_row(corpus):
    contract = corpus.contract("0x" + "ce" * 20)
    function = corpus.function(
        contract,
        name="exitNft",
        claims=[
            _flow_out(
                {
                    "destination_shape": "caller_arbitrary",
                    "shape_proved_by": "simulation",
                    "reach_determined": True,
                    "observed_reach_value_usd": 5000.0,
                    "observed_reach_holders": [VAULT],
                },
                [
                    {
                        "kind": "callee_erc20_selector",
                        "from_is_self": True,
                        "target_kind": {"kind": "param"},
                        "amount_kind": {"kind": "token_identity"},
                    }
                ],
                "behavioral_observed",
            )
        ],
    )
    corpus.principal(function, address=SAFE, resolved_type="safe", details=_safe_details(OWNERS, 4))

    signal = corpus.only(contract, "flow.out")
    assert signal.gate_input("token_identity").is_determined

    document = corpus.score()
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["raw_points"] > 0
    assert finding["undetermined_instances"][0]["why"].startswith("token_identity")


def test_both_feeding_modes_produce_the_same_document(corpus, db_session):
    """Distil-in-memory and distil-then-persist are one implementation.

    Two contracts whose ids and addresses sort in OPPOSITE orders, so a fold that
    inherited in-memory iteration order rather than the pinned population order
    would produce a different document rather than the same one by luck.
    """
    from services.scoring.population import replace_contract_signals

    first = corpus.contract("0x" + "fa" * 20)
    second = corpus.contract("0x" + "0a" * 20)
    for index, contract in enumerate((first, second)):
        function = corpus.function(
            contract,
            name=f"upgradeTo{index}",
            claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
            selector=f"0x1111111{index}",
        )
        corpus.principal(function, address=SAFE, resolved_type="safe", details=_safe_details(OWNERS, 4))
        corpus.function(
            contract,
            name=f"pause{index}",
            claims=[{"claim_id": "pause.set", "tier": "idiom_structural", "witness": {}}],
            selector=f"0x2222222{index}",
        )

    in_memory_signals = distill_protocol_in_memory(db_session, corpus.protocol.id)
    in_memory = compute_protocol_score(db_session, corpus.protocol.id, signals=in_memory_signals)

    for contract in (first, second):
        signals = distill_contract_signals(db_session, contract, job_id=corpus.job.id)
        replace_contract_signals(db_session, contract_id=contract.id, signals=signals, job_id=corpus.job.id)
    db_session.commit()
    persisted_signals = current_signals_for_protocol(db_session, corpus.protocol.id)
    persisted = compute_protocol_score(db_session, corpus.protocol.id)

    # A commutative fold could hide an ordering bug.
    assert [_identity(s) for s in in_memory_signals] == [_identity(s) for s in persisted_signals]
    assert in_memory_signals == persisted_signals
    assert persisted.document() == in_memory.document()
    assert persisted.provenance["subsumed_rows"] == in_memory.provenance["subsumed_rows"]
    assert persisted.provenance["principal_units"] == in_memory.provenance["principal_units"]
    assert persisted.provenance["exposure_gaps"] == in_memory.provenance["exposure_gaps"]


def test_r2_a_foreign_protocols_backlink_licenses_no_reach(corpus, db_session):
    """Payloads use the producer's real shape; an earlier fixture wrote ``gated_contract_address = manager.address``,
    so the join was inert on every real row.
    """
    from db.models import ControlGraphNode, Protocol

    other = Protocol(name=f"other-{uuid.uuid4().hex[:8]}")
    db_session.add(other)
    db_session.flush()
    foreign = Contract(address="0x" + "e1" * 20, chain="ethereum", protocol_id=other.id)
    db_session.add(foreign)
    db_session.commit()

    manager = corpus.contract("0x" + "e2" * 20)
    db_session.add(
        ControlGraphNode(
            contract_id=foreign.id,
            node_type="contract",
            address=manager.address,
            details={
                "gated_contract_backlink": {
                    "gated_contract_address": foreign.address,
                    "declared_vault_matches_gated_contract": True,
                    "probe_block": 100,
                }
            },
        )
    )
    db_session.commit()
    try:
        corpus.function(
            manager,
            name="manage",
            claims=[{"claim_id": "roles.grant", "tier": "standard_exact", "witness": {}}],
        )
        signal = corpus.only(manager, "roles.grant")
        assert signal.reach_gate_state == REACH_GATE_NOT_DETERMINED
        assert all(entity_key("ethereum", foreign.address) != key for key in signal.value_entity_keys)

        # So the negative above is a scope decision, not a recogniser that never fires.
        vault = corpus.contract("0x" + "e3" * 20)
        db_session.add(
            ControlGraphNode(
                contract_id=vault.id,
                node_type="contract",
                address=manager.address,
                details={
                    "gated_contract_backlink": {
                        "gated_contract_address": vault.address,
                        "declared_vault_matches_gated_contract": True,
                        "probe_block": 100,
                    }
                },
            )
        )
        db_session.commit()
        licensed = corpus.only(manager, "roles.grant")
        assert licensed.reach_gate_state == REACH_GATE_LICENSED
        assert entity_key("ethereum", vault.address) in licensed.value_entity_keys
    finally:
        db_session.query(ControlGraphNode).filter_by(contract_id=foreign.id).delete()
        db_session.query(Contract).filter_by(id=foreign.id).delete()
        db_session.query(Protocol).filter_by(id=other.id).delete()
        db_session.commit()


def _balance(session, contract: Contract, *, usd: str, token: str) -> None:
    from db.models import ContractBalance

    session.add(
        ContractBalance(
            contract_id=contract.id,
            token_address=token,
            decimals=18,
            raw_balance="1",
            usd_value=Decimal(usd),
        )
    )
    session.commit()


def _audit(session, protocol_id: int, auditor: str):
    from db.models import AuditReport

    report = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.invalid/{auditor}",
        auditor=auditor,
        title=f"{auditor} review",
    )
    session.add(report)
    session.commit()
    return report


def _coverage(session, protocol_id: int, contract: Contract, report, *, status: str, commit: str | None = None) -> None:
    from db.models import AuditContractCoverage

    session.add(
        AuditContractCoverage(
            contract_id=contract.id,
            audit_report_id=report.id,
            protocol_id=protocol_id,
            matched_name="Vault",
            match_type="direct",
            match_confidence="high",
            equivalence_status=status,
            matched_commit_sha=commit,
        )
    )
    session.commit()


def test_audit_posture_weighs_contracts_and_value_not_coverage_rows(corpus, db_session):
    token = "0x" + "d2" * 20
    proxy = corpus.contract("0x" + "c4" * 20, implementation="0x" + "c5" * 20)
    impl = corpus.contract("0x" + "c5" * 20)
    unaudited = corpus.contract("0x" + "c6" * 20)
    _balance(db_session, proxy, usd="1000.00", token=token)
    _balance(db_session, unaudited, usd="25.00", token=token)
    _coverage(
        db_session,
        corpus.protocol.id,
        impl,
        _audit(db_session, corpus.protocol.id, "alpha"),
        status="proven",
        commit="0" * 40,
    )
    _coverage(
        db_session, corpus.protocol.id, impl, _audit(db_session, corpus.protocol.id, "beta"), status="hash_mismatch"
    )

    plane = load_value_plane(db_session, corpus.protocol.id)
    posture = load_audit_posture(db_session, corpus.protocol.id, plane)
    assert posture["reports_on_file"] == 2
    assert posture["rows"] == 2
    assert posture["contracts_total"] == 3
    assert posture["contracts_covered"] == 1
    assert posture["contracts_proven"] == 1
    # The audit reviewed the implementation but the proxy holds the balance.
    assert posture["value_covered_usd"] == 1000.0
    assert posture["value_proven_usd"] == 1000.0
    assert posture["non_coverage_classified"] == {"deployed_source_provably_differs": 1}


def test_a_proven_equivalence_without_its_commit_is_not_a_proof(corpus, db_session):
    token = "0x" + "d4" * 20
    anchored = corpus.contract("0x" + "d5" * 20)
    unanchored = corpus.contract("0x" + "d6" * 20)
    _balance(db_session, anchored, usd="500.00", token=token)
    _balance(db_session, unanchored, usd="700.00", token=token)
    _coverage(
        db_session,
        corpus.protocol.id,
        anchored,
        _audit(db_session, corpus.protocol.id, "delta"),
        status="proven",
        commit="0" * 40,
    )
    _coverage(
        db_session,
        corpus.protocol.id,
        unanchored,
        _audit(db_session, corpus.protocol.id, "epsilon"),
        status="proven",
        commit=None,
    )

    posture = load_audit_posture(db_session, corpus.protocol.id, load_value_plane(db_session, corpus.protocol.id))
    assert posture["contracts_covered"] == 2
    assert posture["value_covered_usd"] == 1200.0
    assert posture["proven_equivalence"] == 1
    assert posture["contracts_proven"] == 1
    assert posture["value_proven_usd"] == 500.0


def test_audit_discovery_that_ran_and_found_nothing_publishes_zero(corpus, db_session):
    from db.models import Artifact

    corpus.contract("0x" + "d7" * 20)
    db_session.add(Artifact(job_id=corpus.job.id, name="audit_reports", data={"reports": []}))
    db_session.commit()

    posture = load_audit_posture(db_session, corpus.protocol.id, load_value_plane(db_session, corpus.protocol.id))
    assert posture["reports_on_file"] == 0
    assert posture["contracts_covered"] == 0
    assert posture["contracts_proven"] == 0


def _balance_row(
    session,
    contract: Contract,
    *,
    usd: str | None,
    token: str | None,
    observed: str | None = None,
    block: int | None = None,
    raw: str = "1",
) -> None:
    """``ck_contract_balances_token_block_null`` keeps ERC-20 rows unpinned, so most are ordered by write order."""
    from db.models import ContractBalance

    session.add(
        ContractBalance(
            contract_id=contract.id,
            token_address=token,
            decimals=18,
            raw_balance=raw,
            usd_value=None if usd is None else Decimal(usd),
            observed_address=observed,
            block_number=block,
        )
    )
    session.commit()


def test_a_sheet_of_rounding_dust_publishes_no_total_and_names_why(corpus, db_session):
    token = "0x" + "d7" * 20
    other = "0x" + "d8" * 20
    contract = corpus.contract("0x" + "f5" * 20)
    _balance_row(db_session, contract, usd="0.00", token=token, observed=contract.address, raw="3500000")
    _balance_row(db_session, contract, usd=None, token=other, observed=contract.address, raw="900")

    plane = load_value_plane(db_session, corpus.protocol.id)
    key = entity_key("ethereum", contract.address)
    assert plane.sheet_state(key) == SHEET_BELOW_RESOLUTION
    assert plane.total(key) is None
    # Never a zero denominator standing in for "holds nothing".
    assert plane.provenance["tracked_total_usd"] is None
    assert plane.provenance["sheet_states"][SHEET_BELOW_RESOLUTION] == 1
    assert sum(plane.provenance["sheet_states"].values()) == 1
    assert plane.provenance["sheet_states"][SHEET_PROVEN_EMPTY] == 0


def test_the_sheet_state_census_counts_the_entities_nobody_has_read(corpus, db_session):
    """V2: the census walked observation maps, so ``no_rows`` could never increment."""
    read = corpus.contract("0x" + "e1" * 20)
    corpus.contract("0x" + "e2" * 20)
    corpus.contract("0x" + "e3" * 20)
    _balance_row(db_session, read, usd="1500.00", token="0x" + "e9" * 20, observed=read.address)

    states = load_value_plane(db_session, corpus.protocol.id).provenance["sheet_states"]
    assert states[SHEET_NO_ROWS] == 2
    assert states["priced"] == 1
    assert sum(states.values()) == 3


def test_the_zero_address_is_refused_at_both_ends_and_the_refusal_is_counted(corpus, db_session):
    """R10: admitting it makes every renounced authority one principal's closure."""
    from db.models import ControlGraphEdge

    zero = "0x" + "0" * 40
    anchor = corpus.contract("0x" + "f6" * 20)
    real = "0x" + "ab" * 20
    for from_node, to_node, label in (
        (anchor.address, zero, "owner"),
        (zero, real, "authority"),
        (anchor.address, real, "roleRegistry"),
    ):
        db_session.add(
            ControlGraphEdge(
                contract_id=anchor.id,
                from_node_id=f"address:{from_node}",
                to_node_id=f"address:{to_node}",
                relation="controller_value",
                label=label,
            )
        )
    db_session.commit()

    closure = load_control_closure(db_session, corpus.protocol.id)
    assert closure.refusal_counts() == {
        REFUSAL_MALFORMED_NODE_ID: 0,
        REFUSAL_SELF_EDGE: 0,
        REFUSAL_ZERO_ANCHOR: 1,
        REFUSAL_ZERO_PRINCIPAL: 1,
    }
    assert entity_key("ethereum", zero) not in closure.principals()
    assert closure.controlled_by(entity_key("ethereum", zero)) == ()
    assert closure.controlled_by(entity_key("ethereum", real)) == (entity_key("ethereum", anchor.address),)


def test_an_edge_with_an_unkeyable_endpoint_is_refused_by_name_not_dropped(corpus, db_session):
    from db.models import ControlGraphEdge

    anchor = corpus.contract("0x" + "f7" * 20)
    real = "0x" + "ac" * 20
    for from_node, to_node in ((anchor.address, ""), ("", real)):
        db_session.add(
            ControlGraphEdge(
                contract_id=anchor.id,
                from_node_id=f"address:{from_node}",
                to_node_id=f"address:{to_node}",
                relation="controller_value",
                label="owner",
            )
        )
    db_session.commit()

    closure = load_control_closure(db_session, corpus.protocol.id)
    assert closure.refusal_counts()[REFUSAL_MALFORMED_NODE_ID] == 2
    assert closure.controlled_by(entity_key("ethereum", real)) == ()


def test_a_controller_value_pointing_at_the_zero_address_is_an_earned_negative(corpus, db_session):
    """R18: counted apart from the refusal it coincides with."""
    from db.models import ControlGraphEdge

    zero = "0x" + "0" * 40
    anchor = corpus.contract("0x" + "f7" * 20)
    db_session.add(
        ControlGraphEdge(
            contract_id=anchor.id,
            from_node_id=f"address:{anchor.address}",
            to_node_id=f"address:{zero}",
            relation="controller_value",
            label="owner",
        )
    )
    db_session.commit()

    closure = load_control_closure(db_session, corpus.protocol.id)
    assert closure.renounced_counts() == {
        "edges": 1,
        "authority_slots": 1,
        "anchors": 1,
        # Which slot distinguishes a renunciation from a pointer nobody wired.
        "authority_slots_by_label": {"owner": 1},
    }
    renounced = closure.renounced[0]
    assert renounced.anchor == entity_key("ethereum", anchor.address)
    assert renounced.scope.state_var == "owner"
    assert closure.refusal_counts()[REFUSAL_ZERO_PRINCIPAL] == 1


def test_every_excluded_relation_is_enumerated_with_its_count_and_reason(corpus, db_session):
    """R13: the bound is discovery-fixed, so unmentioned or currently empty relations are still published with
    counts.
    """
    from db.models import CONTROL_EDGE_RELATIONS, ControlGraphEdge

    anchor = corpus.contract("0x" + "f8" * 20)
    for relation, label in (
        ("safe_owner", "safe owner"),
        ("external_call_target", "liquidityPool"),
        ("controller_value_unattributed", "accountantState.payoutAddress"),
        ("capability_principal", None),
        ("controller_value", "owner"),
        ("some_relation_nobody_classified", "x"),
    ):
        db_session.add(
            ControlGraphEdge(
                contract_id=anchor.id,
                from_node_id=f"address:{anchor.address}",
                to_node_id="address:0x" + "ac" * 20,
                relation=relation,
                label=label,
            )
        )
    db_session.commit()

    published = unconsumed_reach_relations(db_session, corpus.protocol.id)
    relations = published["relations"]
    assert "controller_value" not in relations
    for relation in ("safe_owner", "external_call_target", "controller_value_unattributed", "capability_principal"):
        assert relations[relation]["edges"] == 1
        assert relations[relation]["classified"] is True
    for relation in set(CONTROL_EDGE_RELATIONS) - set(CONTROL_RELATIONS):
        assert relation in relations
    assert relations["timelock_owner"]["edges"] == 0
    assert relations["some_relation_nobody_classified"] == {
        "edges": 1,
        "reason": UNCONSUMED_REASON_UNCLASSIFIED,
        "classified": False,
    }
    assert published["edges_excluded_total"] == 5


def test_targeted_recovery_keeps_original_asset_facts_and_sibling_signals(corpus):
    from dataclasses import replace

    from db.queue import store_artifact

    contract = corpus.contract("0x" + "ad" * 20)
    claim = _flow_out(None, None, "idiom_structural")
    claim["witness"]["sink_receivers"] = {
        "transfer": {"receiver_provenance": "contract_state_unresolved", "auto_getter_selector": "0x38d52e0f"}
    }
    flow = corpus.function(
        contract,
        name="withdraw",
        selector="0x12345678",
        claims=[claim],
    )
    corpus.function(
        contract,
        name="upgradeTo",
        selector="0x87654321",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    store_artifact(
        corpus.session,
        corpus.job.id,
        "flow_asset_addresses",
        data={
            "receivers": [
                {
                    "asset_getter_selector": "0x38d52e0f",
                    "asset_address": VAULT,
                    "asset_address_status": "resolved",
                    "asset_identity_invariant": "immutable",
                }
            ]
        },
    )
    expected = distill_job_signals(corpus.session, corpus.job)[contract.id]
    retry = Job(
        id=uuid.uuid4(),
        protocol_id=corpus.protocol.id,
        request={"effects_resume_work_id": 1, "effects_function_ids": [flow.id]},
    )
    corpus.session.add(retry)
    corpus.session.flush()
    resumed = distill_job_signals(corpus.session, retry, contract_ids=[contract.id])
    assert set(resumed) == {contract.id}
    assert {s.claim_id for s in resumed[contract.id]} == {"flow.out", "upgrade.implementation"}
    assert [replace(s, job_id=corpus.job.id) for s in resumed[contract.id]] == expected
    assert next(s for s in resumed[contract.id] if s.claim_id == "flow.out").gate_input("asset_identity").is_determined
