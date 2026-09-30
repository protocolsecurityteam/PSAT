"""W5: the insert half of the FP->CGN fold.

An address named only in ``function_principals`` had no control-graph node, so every node-driven spawn path was
blind to it (73 addresses on PR-161). A ``timelock`` mints ``node_type='contract'`` and the existing perimeter
gates give it a job; ``safe`` / ``eoa`` mint ``principal`` and get none, asserted against a counted
``create_job``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from db.models import (
    EDGE_RELATION_CAPABILITY_PRINCIPAL,
    Contract,
    ControlGraphEdge,
    ControlGraphNode,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    Protocol,
)
from services.discovery.perimeter import (
    ZERO_ADDRESS,
    queue_discovered_contracts,
)
from services.governance.control_graph_types import materialize_fp_principal_nodes
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

# One constant on every FP row, so the idempotence key must never touch it.
FINITE_SET = "semantic_capability:finite_set"


def _addr() -> str:
    return ("0x" + uuid.uuid4().hex + "0" * 8).lower()


@pytest.fixture()
def anchor(db_session):
    """The root node gives a minted node its depth; its absence is pinned separately."""
    protocol = Protocol(name=f"w5-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()

    gated_address = _addr()
    contract = Contract(protocol_id=protocol.id, address=gated_address, chain="ethereum")
    db_session.add(contract)
    db_session.commit()

    db_session.add(
        ControlGraphNode(
            contract_id=contract.id,
            deployment_address=None,
            address=gated_address,
            node_type="contract",
            resolved_type="contract",
            label="root",
            depth=0,
            analyzed=True,
            graph_max_depth=6,
        )
    )
    db_session.commit()

    try:
        yield protocol, contract
    finally:
        db_session.rollback()
        db_session.query(Job).filter_by(protocol_id=protocol.id).delete()
        db_session.query(Contract).filter_by(protocol_id=protocol.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


def _fp(db_session, contract, address, *, resolved_type, count=1, name="gated", origin=FINITE_SET):
    for i in range(count):
        fn = EffectiveFunction(
            contract_id=contract.id,
            deployment_address=None,
            function_name=f"{name}{i}",
            selector=f"0x{i:08x}",
        )
        db_session.add(fn)
        db_session.flush()
        db_session.add(
            FunctionPrincipal(
                function_id=fn.id,
                address=address,
                resolved_type=resolved_type,
                origin=origin,
                principal_type="controller",
            )
        )
    db_session.commit()


def _mint(db_session, contract, **kwargs) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ledger, payloads = materialize_fp_principal_nodes(
        db_session, contract_id=contract.id, deployment_address=None, **kwargs
    )
    db_session.commit()
    return dict(ledger), payloads


def _nodes(db_session, contract, address=None):
    q = db_session.query(ControlGraphNode).filter_by(contract_id=contract.id)
    if address is not None:
        q = q.filter(ControlGraphNode.address == address)
    return q.all()


def _rewrite_the_scope(db_session, contract):
    """The resolution and policy stages rewrite this scope wholesale before the mint."""
    from services.resolution.graph_tables import replace_control_graph_rows

    replace_control_graph_rows(
        db_session,
        contract_id=contract.id,
        deployment_address=None,
        resolved_graph={
            "max_depth": 6,
            "nodes": [
                {
                    "id": f"address:{contract.address}",
                    "address": contract.address,
                    "node_type": "contract",
                    "resolved_type": "contract",
                    "label": "root",
                    "depth": 0,
                    "analyzed": True,
                    "details": {},
                }
            ],
            "edges": [],
        },
    )
    db_session.commit()


def _edges(db_session, contract, relation=None):
    q = db_session.query(ControlGraphEdge).filter_by(contract_id=contract.id)
    if relation is not None:
        q = q.filter(ControlGraphEdge.relation == relation)
    return q.all()


def test_timelock_fp_row_mints_the_exact_witnessed_node(db_session, anchor, monkeypatch):
    """``analyzed`` False and ``analysis_state`` NULL keep the perimeter from spawning on a node no walk produced; no
    walk horizon covered it, so ``graph_max_depth`` is NULL.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock", count=3)

    ledger, payloads = _mint(db_session, contract)

    minted = _nodes(db_session, contract, timelock)
    assert len(minted) == 1
    node = minted[0]
    assert node.node_type == "contract"
    assert node.resolved_type == "timelock"
    # Display sites fall back to ``label``, so any constant would become the principal's identity.
    assert node.label is None
    assert node.contract_name is None
    assert node.analyzed is False
    assert node.analysis_state is None
    assert node.graph_max_depth is None
    assert node.depth == 1  # root node depth 0 + 1
    assert node.deployment_address is None
    assert node.details == {
        "control_graph_basis": "fp_materialization",
        "fp_function_count": 3,
        "fp_origins": [FINITE_SET],
        "fp_principal_types": ["controller"],
    }

    edges = _edges(db_session, contract, EDGE_RELATION_CAPABILITY_PRINCIPAL)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.from_node_id == f"address:{contract.address}"
    assert edge.to_node_id == f"address:{timelock}"
    assert edge.label is None
    assert edge.source_controller_id is None
    assert edge.notes == ["functions=3"]

    assert ledger["site"] == "fp_materialization"
    assert ledger["walked"] is True
    assert ledger["budget_used"] == 1
    assert ledger["queued"] == [{"address": timelock, "resolved_type": "timelock"}]
    assert ledger["omitted"] == []
    assert ledger["out_of_population"] == []
    assert ledger["minted"] == [
        {
            "address": timelock,
            "node_type": "contract",
            "resolved_type": "timelock",
            "contract_id": contract.id,
            "deployment_address": None,
            "fp_function_count": 3,
        }
    ]
    assert [p["id"] for p in payloads] == [f"address:{timelock}"]
    assert payloads[0]["analyzed"] is False
    assert payloads[0]["analysis_state"] is None


def test_the_edge_relation_is_not_role_principal(db_session, anchor, monkeypatch):
    """``role_principal`` asserts a witnessed role, which upstream declined to assert for exactly this population."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    _fp(db_session, contract, _addr(), resolved_type="timelock")

    _mint(db_session, contract)

    assert {e.relation for e in _edges(db_session, contract)} == {EDGE_RELATION_CAPABILITY_PRINCIPAL}
    assert _edges(db_session, contract, "role_principal") == []


@pytest.mark.parametrize("resolved_type", ["safe", "eoa"])
def test_non_analyzable_principal_mints_a_node_and_provably_no_job(db_session, anchor, monkeypatch, resolved_type):
    """A silent skip is the defect, so the refusal is asserted three ways."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type=resolved_type, count=2)

    ledger, payloads = _mint(db_session, contract)

    node = _nodes(db_session, contract, principal)[0]
    assert node.node_type == "principal"
    assert node.resolved_type == resolved_type
    assert node.analyzed is False

    assert ledger["minted"] == [
        {
            "address": principal,
            "node_type": "principal",
            "resolved_type": resolved_type,
            "contract_id": contract.id,
            "deployment_address": None,
            "fp_function_count": 2,
        }
    ]
    assert ledger["queued"] == []
    assert ledger["omitted"] == []
    assert ledger["out_of_population"] == [{"address": principal, "reason": "not_analyzable_type"}]

    calls: list[Any] = []
    real_create_job = __import__("db.queue", fromlist=["create_job"]).create_job

    def counting_create_job(*args, **kwargs):
        calls.append(args)
        return real_create_job(*args, **kwargs)

    monkeypatch.setattr("services.discovery.perimeter.create_job", counting_create_job)

    job = Job(
        stage=JobStage.policy,
        status=JobStatus.processing,
        address=contract.address,
        chain_id=1,
        request={"address": contract.address, "chain": "ethereum"},
    )
    db_session.add(job)
    db_session.commit()

    spawn = queue_discovered_contracts(
        db_session,
        job,
        {"root_contract_address": contract.address, "max_depth": 6, "nodes": payloads, "edges": []},
        "https://rpc.example",
        site="policy_refresh",
        chain_name="ethereum",
        budget=8,
        fp_materialized_addresses=[p["address"] for p in payloads],
    )

    assert calls == []
    assert spawn["queued"] == []
    assert spawn["omitted"] == []
    assert spawn["out_of_population"] == [{"address": principal, "reason": "not_contract_node"}]
    assert db_session.query(Job).filter(Job.address == principal).all() == []


def test_end_to_end_the_timelock_gets_one_job_and_the_safe_gets_none(db_session, anchor, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock, safe = sorted([_addr(), _addr()])
    _fp(db_session, contract, timelock, resolved_type="timelock", name="tl")
    _fp(db_session, contract, safe, resolved_type="safe", name="sf")

    _ledger, payloads = _mint(db_session, contract)
    assert len(payloads) == 2

    job = Job(
        stage=JobStage.policy,
        status=JobStatus.processing,
        address=contract.address,
        chain_id=1,
        request={"address": contract.address, "chain": "ethereum"},
    )
    db_session.add(job)
    db_session.commit()

    spawn = queue_discovered_contracts(
        db_session,
        job,
        {"root_contract_address": contract.address, "max_depth": 6, "nodes": payloads, "edges": []},
        "https://rpc.example",
        site="policy_refresh",
        chain_name="ethereum",
        budget=8,
        depth_cap=2,
        fp_materialized_addresses=[p["address"] for p in payloads],
    )

    assert [q["address"] for q in spawn["queued"]] == [timelock]
    assert spawn["out_of_population"] == [{"address": safe, "reason": "not_contract_node"}]
    assert spawn["omitted"] == []
    assert len(db_session.query(Job).filter(Job.address == timelock).all()) == 1
    assert db_session.query(Job).filter(Job.address == safe).all() == []


def test_a_walk_node_that_is_unanalyzed_is_still_refused(db_session, anchor, monkeypatch):
    """The walk reached it and did not analyse it; only a node the walk never offered is admitted."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    other = _addr()
    job = Job(
        stage=JobStage.policy,
        status=JobStatus.processing,
        address=contract.address,
        chain_id=1,
        request={"address": contract.address, "chain": "ethereum"},
    )
    db_session.add(job)
    db_session.commit()

    walk_node = {
        "id": f"address:{other}",
        "address": other,
        "node_type": "contract",
        "resolved_type": "contract",
        "label": "role principal",
        "contract_name": None,
        "depth": 1,
        "analyzed": False,
        "details": {"source": "semantic_capability:role_grant"},
    }
    spawn = queue_discovered_contracts(
        db_session,
        job,
        {"root_contract_address": contract.address, "max_depth": 6, "nodes": [walk_node], "edges": []},
        "https://rpc.example",
        site="policy_refresh",
        chain_name="ethereum",
        budget=8,
    )

    assert spawn["queued"] == []
    assert spawn["out_of_population"] == [{"address": other, "reason": "not_analyzed"}]


def test_a_forged_basis_marker_does_not_buy_admission(db_session, anchor, monkeypatch):
    """Admission is membership of the caller's minted set, never a node field: ``details`` is copied verbatim from
    upstream and forgeable.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    from services.discovery.perimeter import CONTROL_GRAPH_BASIS_KEY, FP_MATERIALIZATION_BASIS

    _protocol, contract = anchor
    forged = _addr()
    job = Job(
        stage=JobStage.policy,
        status=JobStatus.processing,
        address=contract.address,
        chain_id=1,
        request={"address": contract.address, "chain": "ethereum"},
    )
    db_session.add(job)
    db_session.commit()

    forged_node = {
        "id": f"address:{forged}",
        "address": forged,
        "node_type": "contract",
        "resolved_type": "timelock",
        "label": None,
        "contract_name": None,
        "depth": 1,
        "analyzed": False,
        "details": {CONTROL_GRAPH_BASIS_KEY: FP_MATERIALIZATION_BASIS},
    }
    graph = {"root_contract_address": contract.address, "max_depth": 6, "nodes": [forged_node], "edges": []}

    spawn = queue_discovered_contracts(
        db_session,
        job,
        graph,
        "https://rpc.example",
        site="policy_refresh",
        chain_name="ethereum",
        budget=8,
        fp_materialized_addresses=[],
    )

    assert spawn["queued"] == []
    assert spawn["out_of_population"] == [{"address": forged, "reason": "not_analyzed"}]
    assert db_session.query(Job).filter(Job.address == forged).all() == []

    admitted = queue_discovered_contracts(
        db_session,
        job,
        graph,
        "https://rpc.example",
        site="policy_refresh",
        chain_name="ethereum",
        budget=8,
        fp_materialized_addresses=[forged],
    )
    assert [q["address"] for q in admitted["queued"]] == [forged]


def test_mint_is_idempotent(db_session, anchor, monkeypatch):
    """``existing_node`` is out-of-population and consumes no budget."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock")

    _mint(db_session, contract)
    second, payloads = _mint(db_session, contract)

    assert len(_nodes(db_session, contract, timelock)) == 1
    assert len(_edges(db_session, contract, EDGE_RELATION_CAPABILITY_PRINCIPAL)) == 1
    assert second["minted"] == []
    assert second["queued"] == []
    assert second["omitted"] == []
    assert second["out_of_population"] == [{"address": timelock, "reason": "existing_node"}]
    assert second["budget_used"] == 0
    assert payloads == []


def test_the_ledger_never_names_an_uncommitted_row(db_session, anchor, monkeypatch):
    """The ledger may be persisted on a fresh session, so the mint commits before recording or a rollback would
    publish rows that don't exist.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session as SASession

    from tests.conftest import DATABASE_URL

    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock")

    ledger, _payloads = materialize_fp_principal_nodes(db_session, contract_id=contract.id, deployment_address=None)
    db_session.rollback()

    assert [m["address"] for m in ledger["minted"]] == [timelock]
    assert ledger["budget_used"] == 1

    other = SASession(create_engine(DATABASE_URL))
    try:
        seen = (
            other.execute(select(ControlGraphNode.address).where(ControlGraphNode.contract_id == contract.id))
            .scalars()
            .all()
        )
    finally:
        other.close()
    for entry in ledger["minted"]:
        assert entry["address"] in {a.lower() for a in seen}


@pytest.mark.parametrize(
    ("second_address", "second_origin"),
    [
        # The key excludes origin, so re-minting after an origin change still finds the node.
        pytest.param(lambda t: t, "something:else", id="ignores_origin_and_label"),
        pytest.param(lambda t: "0x" + t[2:].upper(), FINITE_SET, id="checksummed_dedups_against_lowercase_node"),
    ],
)
def test_the_idempotence_key_dedups(db_session, anchor, monkeypatch, second_address, second_origin):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock", name="a")
    _mint(db_session, contract)

    _fp(db_session, contract, second_address(timelock), resolved_type="timelock", name="b", origin=second_origin)
    second, _payloads = _mint(db_session, contract)

    assert len(_nodes(db_session, contract)) == 2  # the root + the one timelock
    assert len(_nodes(db_session, contract, timelock)) == 1
    assert second["out_of_population"] == [{"address": timelock, "reason": "existing_node"}]


def test_minted_node_is_reminted_after_a_scoped_rewrite(db_session, anchor, monkeypatch):
    """The rewrite deletes the scope wholesale, so durability comes from re-minting strictly after the last rewrite."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock", count=2)

    first, _payloads = _mint(db_session, contract)
    before = _nodes(db_session, contract, timelock)[0]
    before_details = dict(before.details)
    assert first["budget_used"] == 1

    _rewrite_the_scope(db_session, contract)
    assert _nodes(db_session, contract, timelock) == []
    assert _edges(db_session, contract, EDGE_RELATION_CAPABILITY_PRINCIPAL) == []

    second, _payloads2 = _mint(db_session, contract)

    after = _nodes(db_session, contract, timelock)
    assert len(after) == 1
    assert after[0].details == before_details
    assert after[0].node_type == "contract"
    assert after[0].analyzed is False
    assert after[0].analysis_state is None
    assert after[0].depth == 1
    assert len(_edges(db_session, contract, EDGE_RELATION_CAPABILITY_PRINCIPAL)) == 1
    assert second["minted"] == first["minted"]


def test_budget_cut_is_recorded_never_silent(db_session, anchor, monkeypatch):
    """Every candidate lands in exactly one disposition."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    first, second = sorted([_addr(), _addr()])
    _fp(db_session, contract, first, resolved_type="timelock", name="a")
    _fp(db_session, contract, second, resolved_type="timelock", name="b")

    ledger, payloads = _mint(db_session, contract, budget=1)

    assert ledger["budget_used"] == 1
    assert len(_nodes(db_session, contract)) == 2  # the root + one mint
    assert ledger["queued"] == [{"address": first, "resolved_type": "timelock"}]
    assert ledger["omitted"] == [{"address": second, "reason": "budget_exhausted"}]
    assert ledger["out_of_population"] == []
    assert len(payloads) == 1

    accounted = {r["address"] for r in ledger["queued"]}
    accounted |= {r["address"] for r in ledger["omitted"]}
    accounted |= {r["address"] for r in ledger["out_of_population"]}
    assert accounted == {first, second}
    assert ledger["walked"] is True


def test_the_budget_tail_is_permanent_under_the_production_sequence(db_session, anchor, monkeypatch):
    """A budget cut is a permanent loss: every job rewrites the scope before minting, so the same tail drops forever.

    Replays the real sequence three jobs deep.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    first, second = sorted([_addr(), _addr()])
    _fp(db_session, contract, first, resolved_type="timelock", name="a")
    _fp(db_session, contract, second, resolved_type="timelock", name="b")

    ledgers = []
    for _job in range(3):
        _rewrite_the_scope(db_session, contract)
        ledger, _payloads = _mint(db_session, contract, budget=1)
        ledgers.append(ledger)

    for ledger in ledgers:
        assert ledger["queued"] == [{"address": first, "resolved_type": "timelock"}]
        assert ledger["omitted"] == [{"address": second, "reason": "budget_exhausted"}]
        assert ledger["out_of_population"] == []

    assert _nodes(db_session, contract, second) == []
    assert len(_nodes(db_session, contract, first)) == 1


def test_the_shipped_budget_leaves_no_live_tail_on_the_observed_maximum(db_session, anchor, monkeypatch):
    """The default is a backstop sized above the observed per-anchor maximum (31; none of 83 exceed 64)."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    from services.governance.control_graph_types import FP_MATERIALIZE_LIMIT

    assert FP_MATERIALIZE_LIMIT >= 31

    _protocol, contract = anchor
    principals = sorted(_addr() for _ in range(31))
    for i, principal in enumerate(principals):
        _fp(db_session, contract, principal, resolved_type="timelock", name=f"f{i}_")

    ledger, payloads = _mint(db_session, contract)

    assert ledger["omitted"] == []
    assert len(ledger["minted"]) == 31
    assert len(payloads) == 31
    assert sorted(m["address"] for m in ledger["minted"]) == principals


def test_an_earlier_gate_consumes_no_budget(db_session, anchor, monkeypatch):
    """Budget is spent only at the INSERT."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    valid = _addr()
    _fp(db_session, contract, ZERO_ADDRESS, resolved_type="timelock", name="a")
    _fp(db_session, contract, valid, resolved_type="timelock", name="b")

    ledger, _payloads = _mint(db_session, contract, budget=1)

    assert ledger["queued"] == [{"address": valid, "resolved_type": "timelock"}]
    assert ledger["out_of_population"] == [{"address": ZERO_ADDRESS, "reason": "zero_address"}]
    assert ledger["omitted"] == []


@pytest.mark.parametrize(
    ("address_of", "rows", "reason"),
    [
        pytest.param(lambda c: ZERO_ADDRESS, [("timelock", "gated")], "zero_address", id="zero_address"),
        pytest.param(lambda c: "0xdeadbeef", [("timelock", "gated")], "invalid_address", id="malformed_address"),
        # Defaulting would pick the job/no-job split by coin flip.
        pytest.param(lambda c: None, [(None, "gated")], "resolved_type_not_determined", id="undetermined_type"),
        # The types straddle the job/no-job split, so a conflict is refused, not resolved.
        pytest.param(
            lambda c: None,
            [("timelock", "a"), ("safe", "b")],
            "resolved_type_conflict",
            id="conflicting_types",
        ),
        pytest.param(lambda c: c.address, [("timelock", "gated")], "anchor_contract", id="anchor_contract"),
    ],
)
def test_a_refused_principal_never_mints(db_session, anchor, monkeypatch, address_of, rows, reason):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    principal = address_of(contract) or _addr()
    for resolved_type, name in rows:
        _fp(db_session, contract, principal, resolved_type=resolved_type, name=name)

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["out_of_population"] == [{"address": principal, "reason": reason}]
    assert len(_nodes(db_session, contract)) == 1  # the root only


def test_a_missing_chain_anchor_never_mints_a_chainless_node(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = Protocol(name=f"w5-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()
    contract = Contract(protocol_id=protocol.id, address="", chain="ethereum")
    db_session.add(contract)
    db_session.commit()
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type="timelock")

    try:
        ledger, payloads = _mint(db_session, contract)

        assert ledger["minted"] == []
        assert payloads == []
        assert ledger["out_of_population"] == [{"address": principal, "reason": "no_contract_anchor"}]
        assert _nodes(db_session, contract) == []
        assert _edges(db_session, contract) == []
    finally:
        db_session.rollback()
        db_session.query(Contract).filter_by(protocol_id=protocol.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


def test_a_disabled_chain_omits_and_mints_nothing(db_session, anchor, monkeypatch):
    """An off-allowlist chain is an OMISSION, not a carve-out."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    contract.chain = "base"
    db_session.commit()
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type="timelock")

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["omitted"] == [{"address": principal, "reason": "chain_not_enabled"}]


def test_a_null_chain_anchor_is_mainnet(db_session, anchor, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    contract.chain = None
    db_session.commit()
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type="timelock")

    ledger, _payloads = _mint(db_session, contract)

    assert ledger["queued"] == [{"address": principal, "resolved_type": "timelock"}]
    assert ledger["omitted"] == []


def test_a_deployment_scoped_mint_stays_in_its_scope(db_session, anchor, monkeypatch):
    """The mint, FP read and rewrite share one scope."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    proxy = _addr()
    principal = _addr()
    fn = EffectiveFunction(
        contract_id=contract.id, deployment_address=proxy, function_name="gated", selector="0x00000001"
    )
    db_session.add(fn)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=fn.id,
            address=principal,
            resolved_type="timelock",
            origin=FINITE_SET,
            principal_type="controller",
        )
    )
    db_session.commit()

    untagged, _payloads = _mint(db_session, contract)
    assert untagged["minted"] == []
    assert untagged["out_of_population"] == []
    assert untagged["queued"] == []

    scoped, _payloads2 = materialize_fp_principal_nodes(db_session, contract_id=contract.id, deployment_address=proxy)
    db_session.commit()
    assert [m["address"] for m in scoped["minted"]] == [principal]
    assert _nodes(db_session, contract, principal)[0].deployment_address == proxy
