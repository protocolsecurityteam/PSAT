"""§2 sub-part B: shared_deployer witnessed fact (heuristic-for-attribution).

Same-deployer is a Tier-1 on-chain fact but NOT proof of same organization
(factories defeat it) — the fact carries a heuristic marker and never mints an
org-identity label. Pure fact + DB grouping + build_principal_labels integration.
"""

import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from db.models import Contract, Protocol
from services.policy.principal_enrichment import (
    _shared_deployer_fact,
    build_principal_labels,
    load_protocol_deployer_groups,
)
from utils.concurrency import RpcExecutor

DEPLOYER = "0x" + "d" * 40
A = "0x" + "1" * 40
B = "0x" + "2" * 40
C = "0x" + "3" * 40


@pytest.fixture(autouse=True)
def _reset_executor():
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


# --- pure fact ---------------------------------------------------------------


def test_fact_emitted_for_shared_group():
    groups = {A: {"deployer": DEPLOYER, "addresses": [A, B]}, B: {"deployer": DEPLOYER, "addresses": [A, B]}}
    fact = _shared_deployer_fact(A, groups)
    assert fact == {"provenance": "deployer_read", "heuristic": True, "deployer": DEPLOYER, "addresses": [A, B]}


def test_fact_omitted_when_absent():
    assert _shared_deployer_fact(C, {A: {"deployer": DEPLOYER, "addresses": [A, B]}}) is None


# --- DB grouping -------------------------------------------------------------


def _contract(session, protocol_id, address, deployer):
    c = Contract(protocol_id=protocol_id, address=address, deployer=deployer)
    session.add(c)
    return c


def test_load_deployer_groups_shared_pair_grouped(db_session):
    protocol = Protocol(name="etherfi-deployer")
    db_session.add(protocol)
    db_session.flush()
    _contract(db_session, protocol.id, A, DEPLOYER)
    _contract(db_session, protocol.id, B, DEPLOYER.upper())  # case-insensitive same deployer
    _contract(db_session, protocol.id, C, "0x" + "e" * 40)  # singleton deployer -> omitted
    db_session.commit()

    groups = load_protocol_deployer_groups(db_session, protocol.id)
    assert set(groups) == {A, B}
    assert groups[A] == {"deployer": DEPLOYER, "addresses": [A, B]}
    assert groups[B]["addresses"] == [A, B]


def test_load_deployer_groups_null_deployer_omitted(db_session):
    protocol = Protocol(name="etherfi-null-deployer")
    db_session.add(protocol)
    db_session.flush()
    _contract(db_session, protocol.id, A, None)
    _contract(db_session, protocol.id, B, None)
    db_session.commit()

    assert load_protocol_deployer_groups(db_session, protocol.id) == {}


def test_load_deployer_groups_scoped_to_protocol(db_session):
    p1 = Protocol(name="dp1")
    p2 = Protocol(name="dp2")
    db_session.add_all([p1, p2])
    db_session.flush()
    # Same deployer across protocols must NOT group cross-protocol.
    _contract(db_session, p1.id, A, DEPLOYER)
    _contract(db_session, p2.id, B, DEPLOYER)
    db_session.commit()

    assert load_protocol_deployer_groups(db_session, p1.id) == {}
    assert load_protocol_deployer_groups(db_session, p2.id) == {}


# --- build_principal_labels integration --------------------------------------

TARGET = "0x1111111111111111111111111111111111111111"
PRINCIPAL = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
SIBLING = "0xffffffffffffffffffffffffffffffffffffffff"


def _effective_permissions():
    return {
        "contract_address": TARGET,
        "contract_name": "BoringVault",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "effect_labels": ["arbitrary_external_call"],
                "authority_public": False,
                "authority_roles": [
                    {"role": 1, "principals": [{"address": PRINCIPAL, "resolved_type": "contract", "details": {}}]}
                ],
                "direct_owner": None,
            }
        ],
    }


def _graph():
    return {
        "nodes": [
            {
                "id": f"address:{TARGET}",
                "address": TARGET,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "BoringVault",
                "depth": 0,
                "analyzed": True,
                "details": {"address": TARGET},
            },
            {
                "id": f"address:{PRINCIPAL}",
                "address": PRINCIPAL,
                "node_type": "principal",
                "resolved_type": "contract",
                "label": "manager",
                "depth": 1,
                "analyzed": False,
                "details": {"address": PRINCIPAL},
            },
        ],
        "edges": [
            {
                "from_id": f"address:{TARGET}",
                "to_id": f"address:{PRINCIPAL}",
                "relation": "controller_value",
                "label": "manager",
                "source_controller_id": "state_variable:manager",
                "notes": [],
            }
        ],
    }


def test_shared_deployer_lands_on_principal_without_org_label(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("contract", {"address": address}, True),
    )
    groups = {
        PRINCIPAL: {"deployer": DEPLOYER, "addresses": [PRINCIPAL, SIBLING]},
        SIBLING: {"deployer": DEPLOYER, "addresses": [PRINCIPAL, SIBLING]},
    }
    payload = build_principal_labels(
        _effective_permissions(),
        resolved_control_graph=_graph(),
        rpc_url="http://rpc.example",
        protocol_deployer_groups=groups,
    )
    profiles = {p["address"]: cast(Any, p) for p in payload["principals"]}
    profile = profiles[PRINCIPAL]
    fact = profile["details"]["shared_deployer"]
    assert fact["heuristic"] is True
    assert fact["provenance"] == "deployer_read"
    assert fact["deployer"] == DEPLOYER
    assert fact["addresses"] == [PRINCIPAL, SIBLING]
    # The heuristic fact must NOT leak into an org-identity label / display name.
    assert DEPLOYER not in profile["labels"]
    assert DEPLOYER not in (profile["display_name"] or "")
    assert SIBLING not in profile["labels"]


def test_shared_deployer_omitted_when_no_groups(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("contract", {"address": address}, True),
    )
    payload = build_principal_labels(
        _effective_permissions(),
        resolved_control_graph=_graph(),
        rpc_url="http://rpc.example",
        protocol_deployer_groups=None,
    )
    profiles = {p["address"]: cast(Any, p) for p in payload["principals"]}
    assert "shared_deployer" not in profiles[PRINCIPAL]["details"]
