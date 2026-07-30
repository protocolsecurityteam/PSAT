"""``services.resolution.graph_tables.replace_control_graph_rows`` — the one
writer both the resolution stage and the policy-stage graph refresh share.

What these tests pin (the N3 divergence): the policy refresh projects
``role_principal`` edges (they need effective_permissions, absent at resolution
time), and rewriting only the artifact left them structurally unreachable in
``control_graph_edges`` while every row still asserted the walk's
``graph_max_depth``. The shared writer must (a) persist the refreshed graph's
role edges, (b) replace idempotently under the (contract, deployment) scope,
and (c) leave other deployments' and other contracts' rows alone.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = requires_postgres

PROTO_NAME = "__test_graph_tables__"

ROOT = "0x" + "11" * 20
SAFE = "0x" + "bb" * 20
ROLE_PRINCIPAL = "0x" + "ee" * 20


def _node(address: str, resolved_type: str = "contract", **overrides) -> dict:
    payload = {
        "id": f"address:{address}",
        "address": address,
        "node_type": "contract",
        "resolved_type": resolved_type,
        "label": address,
        "contract_name": None,
        "depth": 0,
        "analyzed": False,
        "analysis_state": None,
        "details": {"address": address},
        "artifacts": {},
    }
    payload.update(overrides)
    return payload


def _edge(from_addr: str, to_addr: str, relation: str, **overrides) -> dict:
    payload = {
        "from_id": f"address:{from_addr}",
        "to_id": f"address:{to_addr}",
        "relation": relation,
        "label": relation,
        "source_controller_id": None,
        "notes": [],
    }
    payload.update(overrides)
    return payload


def _resolution_graph() -> dict:
    """What the resolution stage persists: no role_principal edges yet."""
    return {
        "schema_version": "0.1",
        "root_contract_address": ROOT,
        "max_depth": 6,
        "nodes": [
            _node(ROOT, analyzed=True, analysis_state="analyzed"),
            _node(SAFE, resolved_type="safe", node_type="principal", depth=1, analysis_state="not_analyzable"),
        ],
        "edges": [_edge(ROOT, SAFE, "controller_value")],
    }


def _refreshed_graph() -> dict:
    """The policy-stage refresh: superset with a projected role principal."""
    graph = _resolution_graph()
    graph["nodes"].append(
        _node(ROLE_PRINCIPAL, resolved_type="eoa", node_type="principal", depth=1, analysis_state="not_analyzable")
    )
    graph["edges"].append(_edge(ROOT, ROLE_PRINCIPAL, "role_principal", notes=["role=1"]))
    return graph


@pytest.fixture()
def pg_session():
    from db.models import Base, Contract, Protocol

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        proto = session.execute(select(Protocol).where(Protocol.name == PROTO_NAME)).scalar_one_or_none()
        if proto:
            for contract in session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars():
                session.delete(contract)  # cascades CGN/CGE
            session.delete(proto)
            session.commit()
        session.close()
        engine.dispose()


def _contract(session, address: str):
    from db.models import Contract, Protocol

    proto = session.execute(select(Protocol).where(Protocol.name == PROTO_NAME)).scalar_one_or_none()
    if proto is None:
        proto = Protocol(name=PROTO_NAME)
        session.add(proto)
        session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=proto.id)
    session.add(contract)
    session.flush()
    return contract


def _rows(session, contract_id: int):
    from db.models import ControlGraphEdge, ControlGraphNode

    nodes = session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == contract_id)).scalars().all()
    edges = session.execute(select(ControlGraphEdge).where(ControlGraphEdge.contract_id == contract_id)).scalars().all()
    return nodes, edges


def test_refresh_rewrite_persists_role_principal_edges_and_converges(pg_session):
    """Resolution write, then policy-refresh write: the table plane must end
    equal to the refreshed graph — role_principal edge included — and a
    re-run of the same write must change nothing (idempotent replace, no
    duplicate rows)."""
    from services.resolution.graph_tables import replace_control_graph_rows

    contract = _contract(pg_session, ROOT)

    n, e = replace_control_graph_rows(
        pg_session, contract_id=contract.id, deployment_address=None, resolved_graph=_resolution_graph()
    )
    pg_session.commit()
    assert (n, e) == (2, 1)
    _nodes, edges = _rows(pg_session, contract.id)
    assert {edge.relation for edge in edges} == {"controller_value"}

    n, e = replace_control_graph_rows(
        pg_session, contract_id=contract.id, deployment_address=None, resolved_graph=_refreshed_graph()
    )
    pg_session.commit()
    assert (n, e) == (3, 2)
    nodes, edges = _rows(pg_session, contract.id)
    assert len(nodes) == 3 and len(edges) == 2
    role_edges = [edge for edge in edges if edge.relation == "role_principal"]
    assert len(role_edges) == 1
    assert role_edges[0].to_node_id == f"address:{ROLE_PRINCIPAL}"
    # graph_max_depth now describes the graph that actually contains the rows.
    assert {node.graph_max_depth for node in nodes} == {6}
    principal_node = next(node for node in nodes if node.address == ROLE_PRINCIPAL)
    assert principal_node.resolved_type == "eoa"
    assert principal_node.analysis_state == "not_analyzable"

    # Idempotence: same write again -> same row population, no dupes.
    replace_control_graph_rows(
        pg_session, contract_id=contract.id, deployment_address=None, resolved_graph=_refreshed_graph()
    )
    pg_session.commit()
    nodes2, edges2 = _rows(pg_session, contract.id)
    assert len(nodes2) == 3 and len(edges2) == 2
    assert {(e.from_node_id, e.relation, e.to_node_id) for e in edges2} == {
        (e.from_node_id, e.relation, e.to_node_id) for e in edges
    }


def test_replace_is_scoped_to_contract_and_deployment(pg_session):
    """The delete half of the replace touches ONLY the (contract, deployment)
    being rewritten: a sibling deployment's rows and another contract's rows
    survive byte-identical."""
    from services.resolution.graph_tables import replace_control_graph_rows

    contract = _contract(pg_session, ROOT)
    other_contract = _contract(pg_session, "0x" + "22" * 20)
    proxy_a = "0x" + "aa" * 20

    # Same contract, deployment-scoped rows (impl analyzed in proxy context).
    replace_control_graph_rows(
        pg_session, contract_id=contract.id, deployment_address=proxy_a, resolved_graph=_resolution_graph()
    )
    # Another contract entirely.
    replace_control_graph_rows(
        pg_session, contract_id=other_contract.id, deployment_address=None, resolved_graph=_resolution_graph()
    )
    pg_session.commit()

    # Rewrite the NULL-deployment scope of `contract`.
    replace_control_graph_rows(
        pg_session, contract_id=contract.id, deployment_address=None, resolved_graph=_refreshed_graph()
    )
    pg_session.commit()

    from db.models import ControlGraphEdge, ControlGraphNode

    proxy_nodes = (
        pg_session.execute(
            select(ControlGraphNode).where(
                ControlGraphNode.contract_id == contract.id,
                ControlGraphNode.deployment_address == proxy_a,
            )
        )
        .scalars()
        .all()
    )
    assert len(proxy_nodes) == 2, "sibling deployment's rows must survive the rewrite"
    proxy_edges = (
        pg_session.execute(
            select(ControlGraphEdge).where(
                ControlGraphEdge.contract_id == contract.id,
                ControlGraphEdge.deployment_address == proxy_a,
            )
        )
        .scalars()
        .all()
    )
    assert {e.relation for e in proxy_edges} == {"controller_value"}

    other_nodes, other_edges = _rows(pg_session, other_contract.id)
    assert len(other_nodes) == 2 and len(other_edges) == 1


def test_persisted_role_edges_reach_the_authority_closure_relations(pg_session):
    """The point of persisting: a written role_principal edge satisfies the
    exact predicate the effects value closure selects on
    (``relation.in_(CONTROL_EDGE_RELATIONS)``) — before the policy-stage
    rewrite these edges could not exist in the table at all."""
    from db.models import CONTROL_EDGE_RELATIONS, ControlGraphEdge
    from services.resolution.graph_tables import replace_control_graph_rows

    contract = _contract(pg_session, ROOT)
    replace_control_graph_rows(
        pg_session, contract_id=contract.id, deployment_address=None, resolved_graph=_refreshed_graph()
    )
    pg_session.commit()

    closure_edges = pg_session.execute(
        select(ControlGraphEdge.from_node_id, ControlGraphEdge.to_node_id, ControlGraphEdge.relation).where(
            ControlGraphEdge.contract_id == contract.id,
            ControlGraphEdge.relation.in_(CONTROL_EDGE_RELATIONS),
        )
    ).all()
    assert (f"address:{ROOT}", f"address:{ROLE_PRINCIPAL}", "role_principal") in {
        (row.from_node_id, row.to_node_id, row.relation) for row in closure_edges
    }
