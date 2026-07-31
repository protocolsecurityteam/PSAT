"""FP→control-graph materialization (W5): the INSERT half of the FP→CGN fold.

``function_principals`` was a TERMINAL plane. The graph's only two principal
ingresses are ``authority_roles[].principals`` and ``controllers[].principals``,
so an address in neither had no ``control_graph_nodes`` row — and with no node,
every node-driven spawn path was structurally blind to it.
``reconcile_control_graph_types``, the one FP→CGN fold, is UPDATE-only, so a
principal that never entered the graph could never re-enter it.

Measured on the PR-161 corpus: 73 addresses / 411 of 1,200 FP rows (34.3%) /
240 gated functions across 43 of 93 contracts, all
``origin='semantic_capability:finite_set'``, ``principal_type='controller'``.
The population splits ``contract`` 35 / ``eoa`` 32 / ``safe`` 5 / ``timelock``
1; 72 of the 73 have no ``contracts`` row at all, so raising the discovery
``analyze_limit`` could never reach the class. The largest member is the
monitored Safe ``0x2aca7102…`` (127 FP rows, 22 contracts), not the
EtherFiTimelock ``0xcd425f44…`` (53 rows, 16 contracts) that surfaced it.

The split these tests exist to pin is the counterfactual the investigation
predicted: a ``timelock`` is in ``ANALYZABLE_TYPES`` so it mints
``node_type='contract'`` and the EXISTING perimeter gates give it a job; a
``safe`` / ``eoa`` is not, so it mints ``node_type='principal'`` and the same
gates give it none. This unit adds zero job-creation logic — the assertion that
no ``create_job`` fires for the non-analyzable arm is made against a counted
monkeypatch, from both the type side and the ledger side, because a silent skip
would be indistinguishable from the defect.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import (  # noqa: E402
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
from services.discovery.perimeter import (  # noqa: E402
    ZERO_ADDRESS,
    queue_discovered_contracts,
)
from services.governance.control_graph_types import materialize_fp_principal_nodes  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]

# The corpus origin: a single constant on 1,200/1,200 FP rows, which is exactly
# why the idempotence key must never touch it.
FINITE_SET = "semantic_capability:finite_set"


def _addr() -> str:
    return ("0x" + uuid.uuid4().hex + "0" * 8).lower()


@pytest.fixture()
def anchor(db_session):
    """A protocol + one analyzed gated contract with its own graph root node.

    The root node is what gives a minted node its depth (root depth + 1) — the
    walk always writes it, so its presence is the normal case, and its absence
    is pinned separately.
    """
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
    """*count* gated functions on *contract*, each naming *address* a principal."""
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


def _edges(db_session, contract, relation=None):
    q = db_session.query(ControlGraphEdge).filter_by(contract_id=contract.id)
    if relation is not None:
        q = q.filter(ControlGraphEdge.relation == relation)
    return q.all()


# ---------------------------------------------------------------------------
# The fix: what a minted node asserts, and what it must not
# ---------------------------------------------------------------------------


def test_timelock_fp_row_mints_the_exact_witnessed_node(db_session, anchor, monkeypatch):
    """The EtherFiTimelock shape. Byte-exact: every field the node publishes is
    either witnessed by the FP row or explicitly not-determined.

    ``analyzed`` False and ``analysis_state`` NULL are the load-bearing pair —
    stamping ``analyzed=true`` would make the perimeter spawn on a node no walk
    ever produced. ``graph_max_depth`` NULL because no walk horizon covered it:
    the walk's own horizon is a completeness claim about the walk, and this node
    was never in one.
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
    assert node.label == "capability principal"
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
    """``role_principal`` asserts a WITNESSED ROLE. The population reaching this
    pass is precisely the one ``capability_role_grants`` refused to assert a role
    for (a ``_ROLE_DISSOLVING_TRACE_STEPS`` trace leaves ``authority_roles`` JSON
    null; 127 further corpus rows carry ``authority_roles == []``). Minting
    ``role_principal`` would publish the exact claim the upstream declined."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    _fp(db_session, contract, _addr(), resolved_type="timelock")

    _mint(db_session, contract)

    assert {e.relation for e in _edges(db_session, contract)} == {EDGE_RELATION_CAPABILITY_PRINCIPAL}
    assert _edges(db_session, contract, "role_principal") == []


def test_the_new_relation_is_a_control_relation(db_session):
    """It carries authority, so it belongs in the allowlist. It moves NO NEW
    value through the effects closure: ``build_authority_graph`` already folds
    ``function_principals`` in directly as principal → contract, so this edge
    duplicates a link the closure had — it makes it reachable in the TABLE plane
    that reads edges instead of FP rows."""
    from db.models import CONTROL_EDGE_RELATIONS

    assert EDGE_RELATION_CAPABILITY_PRINCIPAL in CONTROL_EDGE_RELATIONS


# ---------------------------------------------------------------------------
# Node yes, job never — pinned from both directions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("resolved_type", ["safe", "eoa"])
def test_non_analyzable_principal_mints_a_node_and_provably_no_job(db_session, anchor, monkeypatch, resolved_type):
    """``safe`` / ``eoa`` ∉ ``ANALYZABLE_TYPES``, so the node mints as
    ``principal`` and the walker's own ``node_type == 'contract'`` gate rejects
    it. Asserted three ways, because a silent skip is the defect this whole unit
    is about: (1) the type gate — ``node_type='principal'``; (2) the mint
    ledger's ``not_analyzable_type``; (3) the walker's ``not_contract_node``
    with ``create_job`` counted at zero.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type=resolved_type, count=2)

    ledger, payloads = _mint(db_session, contract)

    # (1) the type gate
    node = _nodes(db_session, contract, principal)[0]
    assert node.node_type == "principal"
    assert node.resolved_type == resolved_type
    assert node.analyzed is False

    # (2) the mint ledger — minted, and named as never-a-candidate
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

    # (3) the walker, with create_job counted
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
    )

    assert calls == []
    assert spawn["queued"] == []
    assert spawn["omitted"] == []
    assert spawn["out_of_population"] == [{"address": principal, "reason": "not_contract_node"}]
    assert db_session.query(Job).filter(Job.address == principal).all() == []


def test_end_to_end_the_timelock_gets_one_job_and_the_safe_gets_none(db_session, anchor, monkeypatch):
    """The counterfactual the investigation predicted, closed end to end.

    Both principals are invisible to the walk and both acquire nodes. Only the
    ``timelock`` reaches ``create_job`` — through the EXISTING perimeter gates,
    with no new job-creation logic anywhere in this unit.
    """
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
    )

    assert [q["address"] for q in spawn["queued"]] == [timelock]
    assert spawn["out_of_population"] == [{"address": safe, "reason": "not_contract_node"}]
    assert spawn["omitted"] == []
    assert len(db_session.query(Job).filter(Job.address == timelock).all()) == 1
    assert db_session.query(Job).filter(Job.address == safe).all() == []


def test_a_walk_node_that_is_unanalyzed_is_still_refused(db_session, anchor, monkeypatch):
    """The admission arm is scoped to the FP-mint witness, not widened.

    An ordinary walk node with ``analyzed=false`` still books
    ``not_analyzed``: the walk REACHED it and did not analyse it, which is a
    recorded decision. Only a node the walk was never offered is admitted.
    """
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


# ---------------------------------------------------------------------------
# Idempotence, and the rewrite hinge
# ---------------------------------------------------------------------------


def test_mint_is_idempotent(db_session, anchor, monkeypatch):
    """Run twice ⇒ one node, one edge. The second pass books ``existing_node``
    out-of-population, not as an omission: an address that already HAS a node
    was never dropped. It also consumes no budget, which is what lets an
    over-budget anchor drain across passes instead of stalling."""
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


def test_the_idempotence_key_ignores_origin_and_label(db_session, anchor, monkeypatch):
    """The key is ``(chain, lower(address), contract_id, deployment_scope)``.
    Re-minting after the FP rows change ORIGIN must still find the node: origin
    is a single constant on 1,200/1,200 corpus rows and keys nothing."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock", name="a")

    _mint(db_session, contract)
    _fp(db_session, contract, timelock, resolved_type="timelock", name="b", origin="something:else")
    second, _payloads = _mint(db_session, contract)

    assert len(_nodes(db_session, contract, timelock)) == 1
    assert second["out_of_population"] == [{"address": timelock, "reason": "existing_node"}]


def test_a_checksummed_fp_address_dedups_against_the_lowercase_node(db_session, anchor, monkeypatch):
    """The key lowercases. A mixed-case FP address is the same principal."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock", name="a")
    _mint(db_session, contract)

    mixed = "0x" + timelock[2:].upper()
    _fp(db_session, contract, mixed, resolved_type="timelock", name="b")
    second, _payloads = _mint(db_session, contract)

    assert len(_nodes(db_session, contract)) == 2  # the root + the one timelock
    assert second["out_of_population"] == [{"address": timelock, "reason": "existing_node"}]


def test_minted_node_is_reminted_after_a_scoped_rewrite(db_session, anchor, monkeypatch):
    """THE HINGE. ``replace_control_graph_rows`` deletes wholesale within this
    exact ``(contract_id, deployment)`` scope, so a minted row cannot be made
    durable against it — the strategy is RE-MINT, made sound by ORDERING: the
    caller runs the mint strictly after the last rewrite in the job's stage
    sequence. This pins both halves: the rewrite really does remove the node
    (so nothing here is relying on an accidental survival), and the next mint
    restores it identically.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    from services.resolution.graph_tables import replace_control_graph_rows

    _protocol, contract = anchor
    timelock = _addr()
    _fp(db_session, contract, timelock, resolved_type="timelock", count=2)

    first, _payloads = _mint(db_session, contract)
    before = _nodes(db_session, contract, timelock)[0]
    before_details = dict(before.details)
    assert first["budget_used"] == 1

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


# ---------------------------------------------------------------------------
# The budget, and the population invariant
# ---------------------------------------------------------------------------


def test_budget_cut_is_recorded_never_silent(db_session, anchor, monkeypatch):
    """Budget 1 with 2 candidates ⇒ 1 minted, 1 named. Plus the population
    invariant: every candidate lands in exactly one disposition, so the count
    of UNLOGGED omissions is zero."""
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


def test_the_budget_cut_drains_on_the_next_pass(db_session, anchor, monkeypatch):
    """A cut is a DELAY, not a loss. ``existing_node`` precedes the budget gate,
    so the already-minted address consumes none of it and the next pass reaches
    the one that was cut."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    first, second = sorted([_addr(), _addr()])
    _fp(db_session, contract, first, resolved_type="timelock", name="a")
    _fp(db_session, contract, second, resolved_type="timelock", name="b")

    _mint(db_session, contract, budget=1)
    ledger, _payloads = _mint(db_session, contract, budget=1)

    assert ledger["queued"] == [{"address": second, "resolved_type": "timelock"}]
    assert ledger["out_of_population"] == [{"address": first, "reason": "existing_node"}]
    assert ledger["omitted"] == []
    assert len(_nodes(db_session, contract)) == 3  # the root + both mints


def test_an_earlier_gate_consumes_no_budget(db_session, anchor, monkeypatch):
    """FALSIFIER: statement order is not an enforceable invariant, so the budget
    is spent at the INSERT and nowhere else. With budget 1 and a zero-address
    candidate sorting FIRST, the valid candidate must still mint."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    valid = _addr()
    _fp(db_session, contract, ZERO_ADDRESS, resolved_type="timelock", name="a")
    _fp(db_session, contract, valid, resolved_type="timelock", name="b")

    ledger, _payloads = _mint(db_session, contract, budget=1)

    assert ledger["queued"] == [{"address": valid, "resolved_type": "timelock"}]
    assert ledger["out_of_population"] == [{"address": ZERO_ADDRESS, "reason": "zero_address"}]
    assert ledger["omitted"] == []


# ---------------------------------------------------------------------------
# Fail-closed arms
# ---------------------------------------------------------------------------


def test_zero_address_never_mints(db_session, anchor, monkeypatch):
    """An unset controller resolves to 0x000…0. It is not a principal."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    _fp(db_session, contract, ZERO_ADDRESS, resolved_type="timelock")

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["out_of_population"] == [{"address": ZERO_ADDRESS, "reason": "zero_address"}]
    assert len(_nodes(db_session, contract)) == 1  # the root only


def test_malformed_address_never_mints(db_session, anchor, monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    _fp(db_session, contract, "0xdeadbeef", resolved_type="timelock")

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["out_of_population"] == [{"address": "0xdeadbeef", "reason": "invalid_address"}]


def test_a_missing_chain_anchor_never_mints_a_chainless_node(db_session, monkeypatch):
    """The join to the anchor contract is what supplies the chain. Without a
    usable anchor there is no chain to claim and no node id to hang the edge
    from, so every candidate fails closed WITH a reason — never a NULL-chain
    node and never a silent skip."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol = Protocol(name=f"w5-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()
    # A blank address is no anchor: it would mint an edge from the node id
    # ``address:``, an identity no node has.
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
    """Invariant 14. An off-allowlist chain is an OMISSION, not a carve-out: on
    an enabled deployment the same FP row would mint."""
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
    """Legacy rows persisted ``chain=NULL`` for mainnet. Coalesced, so a mainnet
    principal still mints instead of reading as a chain we cannot name."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    contract.chain = None
    db_session.commit()
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type="timelock")

    ledger, _payloads = _mint(db_session, contract)

    assert ledger["queued"] == [{"address": principal, "resolved_type": "timelock"}]
    assert ledger["omitted"] == []


def test_an_undetermined_resolved_type_refuses(db_session, anchor, monkeypatch):
    """A NULL ``resolved_type`` determines no ``node_type``. Defaulting it would
    pick the job/no-job split by coin flip."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type=None)

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["out_of_population"] == [{"address": principal, "reason": "resolved_type_not_determined"}]


def test_conflicting_resolved_types_refuse_to_guess(db_session, anchor, monkeypatch):
    """Two types for one principal at one anchor, unresolved by the FP plane. 0
    of 413 corpus anchors reach this; a first occurrence must surface as a
    refusal, not as a silently-picked winner — the two candidate types straddle
    the job / no-job split."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    principal = _addr()
    _fp(db_session, contract, principal, resolved_type="timelock", name="a")
    _fp(db_session, contract, principal, resolved_type="safe", name="b")

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["out_of_population"] == [{"address": principal, "reason": "resolved_type_conflict"}]


def test_the_anchor_contract_is_never_its_own_principal_node(db_session, anchor, monkeypatch):
    """A self-referential FP row must not mint a duplicate of the root node or a
    self-edge."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol, contract = anchor
    _fp(db_session, contract, contract.address, resolved_type="timelock")

    ledger, payloads = _mint(db_session, contract)

    assert ledger["minted"] == []
    assert payloads == []
    assert ledger["out_of_population"] == [{"address": contract.address, "reason": "anchor_contract"}]
    assert len(_nodes(db_session, contract)) == 1


def test_a_deployment_scoped_mint_stays_in_its_scope(db_session, anchor, monkeypatch):
    """The mint scope, the FP read scope and the rewrite scope are one scope by
    construction — the caller passes the same ``deployment_address`` to all
    three. An FP row tagged to a proxy deployment must not mint into the
    untagged scope."""
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


def test_an_absent_ledger_is_not_an_empty_walk(db_session, anchor, monkeypatch):
    """``walked`` is set at loop exit and nowhere else, so a ledger that never
    reached the end says so rather than reading as "considered everything,
    minted nothing"."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    from services.discovery.perimeter import new_fp_materialization_result

    fresh = new_fp_materialization_result(budget=16)
    assert fresh["walked"] is False
    assert fresh["site"] == "fp_materialization"
    assert fresh["minted"] == []

    _protocol, contract = anchor
    ledger, _payloads = _mint(db_session, contract)
    assert ledger["walked"] is True
