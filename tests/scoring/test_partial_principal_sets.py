"""A role set that isn't proven whole answers nothing: a ``lower_bound`` finite set leaves its signal
``not_determined``, and an anchor whose member replay never completed is an unread controller set in the score and on
Surface, not a contract nobody controls. An ``exact`` set beside them keeps everything it had.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from db.models import (
    Contract,
    ControlGraphNode,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    Protocol,
)
from services.aggregations.company_overview import build_company_overview
from services.resolution.mapping_enumerator import MAPPING_ENUMERATION_STATUS as RESOLVER_STATUS_KEY
from services.scoring.cli import distill_protocol_in_memory
from services.scoring.distill import distill_contract_signals
from services.scoring.fold import compute_protocol_score
from services.scoring.planes import MAPPING_ENUMERATION_STATUS, controllers_not_determined, load_control_closure
from services.scoring.schema import entity_key
from tests.conftest import requires_postgres
from utils.scoring_status import PRINCIPAL_STATE_ENUMERATED, PRINCIPAL_STATE_NOT_DETERMINED

pytestmark = requires_postgres

FINITE_SET = "semantic_capability:finite_set"
UPGRADE = [{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}]


def _address(tag: str) -> str:
    return "0x" + (uuid.uuid4().hex + tag.encode().hex())[:40]


class _World:
    def __init__(self, session) -> None:
        self.session = session
        self.protocol = Protocol(name=f"partial-{uuid.uuid4().hex[:8]}")
        session.add(self.protocol)
        session.flush()
        self.contracts: list[Contract] = []
        self.jobs: list[Job] = []

    def contract(self, address: str, *, chain: str = "ethereum") -> Contract:
        job = Job(
            id=uuid.uuid4(),
            address=address,
            protocol_id=self.protocol.id,
            status=JobStatus.completed,
            stage=JobStage.done,
            request={"address": address, "chain": chain},
            chain_id=1 if chain == "ethereum" else 8453,
        )
        self.session.add(job)
        self.session.flush()
        row = Contract(address=address, chain=chain, protocol_id=self.protocol.id, job_id=job.id, contract_name=address)
        self.session.add(row)
        self.session.commit()
        self.jobs.append(job)
        self.contracts.append(row)
        return row

    def gated(self, contract: Contract, name: str, member: str, quality: str | None) -> EffectiveFunction:
        function = EffectiveFunction(
            contract_id=contract.id,
            deployment_address=contract.address,
            function_name=name,
            selector="0x" + uuid.uuid4().hex[:8],
            abi_signature=f"{name}()",
            authority_public=False,
            authority_openness="restricted",
            claims=UPGRADE,
        )
        self.session.add(function)
        self.session.flush()
        details: dict[str, Any] = {"trace": []}
        if quality is not None:
            details["membership_quality"] = quality
        self.session.add(
            FunctionPrincipal(
                function_id=function.id, address=member, resolved_type="eoa", origin=FINITE_SET, details=details
            )
        )
        self.session.commit()
        return function

    def replay(self, graph_of: Contract, node_address: str, status: str) -> None:
        self.session.add(
            ControlGraphNode(
                contract_id=graph_of.id,
                address=node_address,
                node_type="contract",
                resolved_type="timelock",
                analyzed=True,
                details={"address": node_address, MAPPING_ENUMERATION_STATUS: status},
            )
        )
        self.session.commit()

    def score(self):
        return compute_protocol_score(
            self.session, self.protocol.id, signals=distill_protocol_in_memory(self.session, self.protocol.id)
        )

    def cleanup(self) -> None:
        self.session.rollback()
        for contract in self.contracts:
            self.session.query(Contract).filter_by(id=contract.id).delete()
        for job in self.jobs:
            self.session.query(Job).filter_by(id=job.id).delete()
        self.session.query(Protocol).filter_by(id=self.protocol.id).delete()
        self.session.commit()


@pytest.fixture
def world(db_session):
    built = _World(db_session)
    yield built
    built.cleanup()


def _signal(world: _World, contract: Contract, name: str):
    (signal,) = [s for s in distill_contract_signals(world.session, contract, job_id=None) if s.function_name == name]
    return signal


def test_the_scoring_status_key_is_the_one_the_resolver_writes():
    assert MAPPING_ENUMERATION_STATUS == RESOLVER_STATUS_KEY


@pytest.mark.parametrize(
    ("quality", "note"),
    [
        pytest.param("lower_bound", "principal_set_not_exact:lower_bound", id="lower-bound"),
        pytest.param(None, "principal_set_not_exact:not_determined", id="quality-absent"),
    ],
)
def test_a_finite_set_short_of_exact_leaves_its_signal_not_determined(world, quality, note):
    vault = world.contract(_address("vault"))
    world.gated(vault, "upgradeTo", _address("eoa"), quality)

    signal = _signal(world, vault, "upgradeTo")
    assert signal.principal_state == PRINCIPAL_STATE_NOT_DETERMINED
    assert signal.principal_refs == ()
    assert note in signal.witness_notes


def test_an_exact_finite_set_is_still_enumerated(world):
    vault = world.contract(_address("vault"))
    member = _address("eoa")
    world.gated(vault, "upgradeTo", member, "exact")

    signal = _signal(world, vault, "upgradeTo")
    assert signal.principal_state == PRINCIPAL_STATE_ENUMERATED
    assert [ref.address for ref in signal.principal_refs] == [member.lower()]
    assert not any(n.startswith("principal_set_not_exact") for n in signal.witness_notes)


def test_replay_status_is_not_determined_only_where_no_graph_completed_it():
    statuses = {
        "ethereum::0xa": {"error"},
        "ethereum::0xb": {"error", "complete"},
        "base::0xa": {"complete"},
        "ethereum::0xc": {"incomplete_timeout", "skipped"},
    }
    assert controllers_not_determined(statuses) == {
        "ethereum::0xa": "error",
        "ethereum::0xc": "incomplete_timeout,skipped",
    }


def test_errored_timelock_lower_bound_set_and_exact_set_together(world, db_session):
    vault = world.contract(_address("vault"))
    timelock = world.contract(_address("timelock"))
    exact_member, partial_member = _address("exact"), _address("partial")
    world.gated(vault, "upgradeTo", exact_member, "exact")
    world.gated(vault, "upgradeToAndCall", partial_member, "lower_bound")
    world.replay(timelock, timelock.address, "error")
    world.replay(vault, vault.address, "complete")

    closure = load_control_closure(db_session, world.protocol.id)
    timelock_key = entity_key("ethereum", timelock.address)
    assert closure.controllers_not_determined == {timelock_key: "error"}

    document = world.score()
    (finding,) = document.findings
    assert finding["principal_unit"] == entity_key("ethereum", exact_member)
    assert finding["weakness"] == 0.9
    assert "restricted_privileged_no_principal" in {w["kind"] for w in document.warnings}
    assert document.provenance["closure_admission"]["controller_enumeration_not_determined"] == {timelock_key: "error"}
    confidence = document.model_parameters["confidence_detail"]
    assert confidence["controller_enumeration_not_determined"] == 1

    payload = build_company_overview(db_session, world.protocol.name)
    by_address = {entry["address"]: entry for entry in payload["contracts"]}
    assert by_address[timelock.address.lower()]["controller_enumeration"] == {
        "state": "not_determined",
        "status": "error",
    }
    assert by_address[vault.address.lower()]["controller_enumeration"] == {"state": "complete"}


def test_the_same_world_proven_whole_keeps_its_findings_and_charges_nothing(world, db_session):
    vault = world.contract(_address("vault"))
    timelock = world.contract(_address("timelock"))
    exact_member, other_member = _address("exact"), _address("other")
    world.gated(vault, "upgradeTo", exact_member, "exact")
    world.gated(vault, "upgradeToAndCall", other_member, "exact")
    world.replay(timelock, timelock.address, "complete")

    assert load_control_closure(db_session, world.protocol.id).controllers_not_determined == {}
    document = world.score()
    assert {f["principal_unit"] for f in document.findings} == {
        entity_key("ethereum", exact_member),
        entity_key("ethereum", other_member),
    }
    assert all(f["weakness"] == 0.9 for f in document.findings)
    assert "restricted_privileged_no_principal" not in {w["kind"] for w in document.warnings}
    assert document.provenance["closure_admission"]["controller_enumeration_not_determined"] == {}
    assert document.model_parameters["confidence_detail"]["controller_enumeration_not_determined"] == 0


def test_an_unread_controller_set_is_charged_against_its_entity_and_keyed_by_chain(world, db_session):
    timelock_address = _address("timelock")
    mainnet = world.contract(timelock_address)
    base = world.contract(timelock_address, chain="base")
    world.gated(mainnet, "upgradeTo", _address("eoa"), "exact")
    world.replay(mainnet, timelock_address, "error")
    world.replay(base, timelock_address, "complete")

    closure = load_control_closure(db_session, world.protocol.id)
    assert closure.controllers_not_determined == {entity_key("ethereum", timelock_address): "error"}

    charged = world.score().model_parameters["confidence_detail"]
    db_session.query(ControlGraphNode).filter(ControlGraphNode.contract_id == mainnet.id).delete()
    db_session.commit()
    uncharged = world.score().model_parameters["confidence_detail"]
    assert charged["reachability_answered_pct"] < uncharged["reachability_answered_pct"]
    assert charged["capability_scored_pct"] < uncharged["capability_scored_pct"]
