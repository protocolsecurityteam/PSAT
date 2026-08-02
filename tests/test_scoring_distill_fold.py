"""Distillation and the protocol fold, against a fixture corpus.

Every test here pins a way an unread witness could become a published number.
The adversarial half is the point: a ``not_determined`` destination, constraint,
value, weakness or principal state must produce NO finding and NO escalation,
because the defect this scorer exists to avoid is a third state read as a
positive fact — the prototype's −30λ delegatecall row, whose database row said
only "I could not resolve the operand".
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

import pytest

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Job, Protocol, RoleHolderPlane
from services.scoring.cli import distill_protocol_in_memory
from services.scoring.constants import (
    DEST_SEVERITY_CONSTRAINED_OTHER,
    DEST_SEVERITY_DELEGATECALL_SELF,
    DEST_SEVERITY_EXEC_SELF,
    FLOW_SEVERITY_CALLER_ARBITRARY,
    ROLE_BREADTH_MULTI_HOLDER_WEAKNESS,
    WEAKNESS_SAFE_SUPERMAJORITY,
    WEAKNESS_SAFE_UNCREDITED,
)
from services.scoring.distill import distill_contract_signals, distill_job_signals
from services.scoring.fold import compute_protocol_score
from services.scoring.planes import load_audit_posture, load_value_plane
from services.scoring.population import current_signals_for_protocol
from services.scoring.schema import entity_key
from utils.scoring_status import (
    DESTINATION_STATE_CONSTRAINED_PROVEN,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_DETERMINED,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    GRADE_STATE_NOT_DETERMINED,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    REACH_GATE_LICENSED,
    REACH_GATE_NOT_DETERMINED,
    SEVERITY_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_REACH,
)


def _identity(signal) -> tuple:
    """The population's total-order key, which both feeding modes must agree on."""
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


# --------------------------------------------------------------------------
# Adversarial: an unread witness must never become a graded fact
# --------------------------------------------------------------------------


def test_unread_delegatecall_destination_scores_nothing(corpus):
    """The banned defect class, as a permanent regression test.

    The row publishes the honest third state — ``indeterminate`` /
    ``unresolved_operand`` — and a scorer that graded it ``unconstrained`` took
    an unmodified OpenZeppelin ``multicall`` to an F.
    """
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
    """The same collapse is reachable on ``exec.arbitrary`` and is closed there too."""
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


def test_destination_fold_is_a_meet_not_last_wins(corpus):
    """One unread site makes the function's destination unread as a whole."""
    contract = corpus.contract("0x" + "c" * 40)
    corpus.function(
        contract,
        name="twoSites",
        claims=[
            _delegatecall({"target_kind": "self"}, {"state": "constrained", "guard": "literal_self"}),
            _delegatecall({"target_kind": "indeterminate"}, {"state": "not_determined"}),
        ],
    )
    signal = corpus.only(contract, "delegatecall.execute")
    assert signal.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert not signal.enters_grade


def test_not_applicable_is_a_different_fact_from_not_determined(corpus):
    """``not_applicable`` comes from an allow-list, never from "not in the bearing tuple"."""
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

    # A latch is genuinely destination-free; an upgrade names a new
    # implementation and this scorer has no destination model for it.
    assert pause.destination.state == DESTINATION_STATE_NOT_APPLICABLE
    assert upgrade.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert delegatecall.destination.state == DESTINATION_STATE_NOT_DETERMINED
    assert upgrade.enters_grade and not delegatecall.enters_grade


def test_self_delegatecall_is_proven_fixed_and_benign(corpus):
    """``address(this)`` preserves ``msg.sender``, so every sub-call re-runs its own gate."""
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
    """A plain call to self makes ``msg.sender`` the contract, which a gate may trust."""
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


def test_unwitnessed_reach_is_not_the_entity_balance_sheet(corpus):
    """A proven destination does not license reading the balance sheet as a reach."""
    contract = corpus.contract("0x" + "3a" * 20)
    corpus.function(
        contract,
        name="sweep",
        claims=[
            _flow_out(
                None,
                [{"kind": "callee_erc20_selector", "from_is_self": True, "target_kind": {"kind": "immutable"}}],
                "standard_exact",
            )
        ],
    )
    signal = corpus.only(contract, "flow.out")
    assert signal.destination.state == DESTINATION_STATE_CONSTRAINED_PROVEN
    assert signal.value_state == VALUE_STATE_NOT_DETERMINED
    assert signal.value_entity_keys == ()


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
    # Severity is proven on both: the capability's existence is the component.
    assert signals["pauseUnproven"].severity.state == SEVERITY_STATE_PROVEN


def test_restricted_function_without_principals_stays_undetermined(corpus):
    contract = corpus.contract("0x" + "6a" * 20)
    corpus.function(
        contract,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    signal = corpus.only(contract, "upgrade.implementation")
    assert signal.principal_state == PRINCIPAL_STATE_NOT_DETERMINED
    assert signal.principal_refs == ()

    document = corpus.score()
    assert document.findings == []
    kinds = {w["kind"] for w in document.warnings}
    assert "restricted_privileged_no_principal" in kinds


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


# --------------------------------------------------------------------------
# The fold: units, value and determinism
# --------------------------------------------------------------------------


def test_two_functions_reaching_one_vault_charge_it_once(corpus):
    """MAX per (entity, asset), never SUM."""
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


def test_chain_aliases_collapse_to_one_entity(corpus):
    """``mainnet``/NULL and ``ethereum`` are one chain, so one entity key."""
    legacy = corpus.contract("0x" + "9a" * 20, chain="mainnet")
    corpus.function(
        legacy,
        name="upgradeTo",
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    signals = corpus.signals(legacy)
    assert signals[0].chain == "ethereum"
    assert signals[0].value_entity_keys[0].startswith("ethereum::")


def test_same_safe_on_two_chains_stays_two_units(corpus):
    """Same address is not proof of same owner set (#158 / strategy §7.4)."""
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
    """A proven module means k/n is an upper bound, so the demotion is denied."""
    protected = corpus.contract("0x" + "ae" * 20)
    exposed = corpus.contract("0x" + "af" * 20)
    # Disjoint owner sets, so the two Safes stay two units: identical owners
    # would make them one power and the max-weakness fold would hide the point.
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
        # 5/6 alone earns the supermajority weakness; two proven holders raise it.
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


def test_two_folds_of_one_state_are_identical(corpus):
    contract = corpus.contract("0x" + "bd" * 20)
    for index, selector in enumerate(("0x99999999", "0xaaaaaaaa")):
        function = corpus.function(
            contract,
            name=f"fn{index}",
            claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
            selector=selector,
        )
        corpus.principal(function, address=SAFE, resolved_type="safe", details=_safe_details(OWNERS, 4))
        corpus.principal(function, address=OWNERS[0], resolved_type="eoa", details={})

    first = corpus.score()
    second = corpus.score()
    assert first.document() == second.document()
    assert first.provenance == second.provenance


def test_job_signals_group_by_contract_not_deployment_address(corpus):
    """Split-proxy siblings share one deployment address and must not collide."""
    proxy = "0x" + "be" * 20
    first = corpus.contract("0x" + "bf" * 20)
    second = corpus.contract("0x" + "ca" * 20)
    for contract in (first, second):
        corpus.function(
            contract,
            name="upgradeTo",
            claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
            deployment_address=proxy,
            selector="0x3659cfe6",
        )
    grouped = distill_job_signals(corpus.session, corpus.job)
    assert set(grouped) >= {first.id, second.id}
    assert len(grouped[first.id]) == 1
    assert len(grouped[second.id]) == 1
    assert grouped[first.id][0].deployment_address == proxy
    assert grouped[second.id][0].deployment_address == proxy
    assert grouped[first.id][0].contract_id != grouped[second.id][0].contract_id


def test_contract_typed_principal_scores_nothing(corpus):
    """ "An EOA controls the gating CONTRACT" is not "an EOA can call this"."""
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
    """§7.5: distil-in-memory and distil-then-persist are one implementation.

    Two contracts whose ids and addresses sort in OPPOSITE orders, so a fold that
    inherited the in-memory iteration order instead of the pinned population
    order would produce a different document rather than the same one by luck.
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

    # The SEQUENCES, not just the documents: comparing only the folded output
    # lets an ordering bug hide behind a fold that happens to be commutative on
    # this fixture.
    assert [_identity(s) for s in in_memory_signals] == [_identity(s) for s in persisted_signals]
    assert in_memory_signals == persisted_signals
    assert persisted.document() == in_memory.document()
    assert persisted.provenance["subsumed_rows"] == in_memory.provenance["subsumed_rows"]
    assert persisted.provenance["principal_units"] == in_memory.provenance["principal_units"]
    assert persisted.provenance["exposure_gaps"] == in_memory.provenance["exposure_gaps"]


def test_r2_a_foreign_protocols_backlink_licenses_no_reach(corpus, db_session):
    """A reach licence from another protocol's graph is not this protocol's fact."""
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
                    "gated_contract_address": manager.address,
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

        # Positive control: the same backlink inside THIS protocol does license
        # the pairing, so the negative above is a scope decision and not a
        # recogniser that never fires.
        vault = corpus.contract("0x" + "e3" * 20)
        db_session.add(
            ControlGraphNode(
                contract_id=vault.id,
                node_type="contract",
                address=manager.address,
                details={
                    "gated_contract_backlink": {
                        "gated_contract_address": manager.address,
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


# --------------------------------------------------------------------------
# The value plane and the audit posture, as the document publishes them
# --------------------------------------------------------------------------


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


def test_the_tracked_total_is_published_and_folds_the_impl_onto_its_proxy(corpus, db_session):
    """The exposure denominator is emitted, not left to be back-solved."""
    token = "0x" + "d1" * 20
    proxy = corpus.contract("0x" + "c1" * 20, implementation="0x" + "c2" * 20)
    impl = corpus.contract("0x" + "c2" * 20)
    _balance(db_session, proxy, usd="1000.00", token=token)
    _balance(db_session, impl, usd="400.00", token=token)

    plane = load_value_plane(db_session, corpus.protocol.id)
    # One entity, one asset: MAX, never the 1400.00 the two rows would sum to.
    assert plane.provenance["tracked_total_usd"] == 1000.0
    assert plane.total(entity_key("ethereum", impl.address)) == 1000.0


def test_an_unpriced_perimeter_publishes_no_tracked_total(corpus, db_session):
    """Nothing priced is not_determined, never a proven zero."""
    corpus.contract("0x" + "c3" * 20)

    plane = load_value_plane(db_session, corpus.protocol.id)
    assert plane.provenance["tracked_total_usd"] is None


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
    # Two audits of one contract are two rows and ONE covered contract.
    assert posture["contracts_covered"] == 1
    assert posture["contracts_proven"] == 1
    # The proxy holds the balance and the audit reviewed the implementation, so
    # the money behind that audit is the proxy's — counted once, and the
    # unaudited contract's $25 is not in it.
    assert posture["value_covered_usd"] == 1000.0
    assert posture["value_proven_usd"] == 1000.0
    assert posture["non_coverage_classified"] == {"deployed_source_provably_differs": 1}


def test_audit_posture_value_is_null_when_no_covered_entity_is_priced(corpus, db_session):
    audited = corpus.contract("0x" + "c7" * 20)
    priced = corpus.contract("0x" + "c8" * 20)
    _balance(db_session, priced, usd="500.00", token="0x" + "d3" * 20)
    _coverage(
        db_session,
        corpus.protocol.id,
        audited,
        _audit(db_session, corpus.protocol.id, "gamma"),
        status="proven",
        commit="0" * 40,
    )

    posture = load_audit_posture(db_session, corpus.protocol.id, load_value_plane(db_session, corpus.protocol.id))
    assert posture["contracts_covered"] == 1
    assert posture["contracts_proven"] == 1
    # An unpriced audited contract contributes nothing and is never read as $0.
    assert posture["value_covered_usd"] is None
    assert posture["value_proven_usd"] is None
