"""C1: signer-overlap attribution fact + A4 terminal wiring in build_principal_index.

SCORING plan §2 (signer overlap) and §4 (contract-principal terminal walk). The
DB-backed test exercises the exact/lower_bound owner-quality gate in
``load_protocol_safe_owner_sets``; the pure tests exercise the overlap algebra;
the integration tests confirm the facts land in ``principal_labels.details``.
"""

from typing import Any, cast

import pytest

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Protocol
from services.concurrency import RpcExecutor
from services.policy.principal_index import (
    _compute_signer_overlap,
    build_principal_index,
    load_protocol_safe_owner_sets,
)

# Ops Safe (4/7) and pauser Safe (1/5) — the pauser's owners are a strict subset,
# the exact etherfi shape the plan cites.
OPS = "0x2aca71020de61bb532008049e1bd41e451ae8adc"
PAUSER = "0x427989bb12f4a390d11e7647d467dea02b9d2ee3"
OPS_OWNERS = [f"0x{i:040x}" for i in range(1, 8)]  # 7 owners
PAUSER_OWNERS = OPS_OWNERS[:5]  # strict subset of the ops signers
DISJOINT = "0x" + "9" * 40
DISJOINT_OWNERS = [f"0x{i:040x}" for i in range(100, 103)]


@pytest.fixture(autouse=True)
def _reset_executor():
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


def _registry(*entries):
    return {
        addr.lower(): {"owners": [o.lower() for o in owners], "membership_quality": "exact"} for addr, owners in entries
    }


# --- pure overlap algebra ----------------------------------------------------


def test_subset_relation_emitted_with_flag():
    registry = _registry((OPS, OPS_OWNERS), (PAUSER, PAUSER_OWNERS))
    fact = _compute_signer_overlap(PAUSER, registry)
    assert fact is not None
    assert fact["provenance"] == "onchain_owner_read"
    assert fact["self_owner_count"] == 5
    assert len(fact["overlaps"]) == 1
    ov = fact["overlaps"][0]
    assert ov["address"] == OPS
    assert ov["subset"] is True
    assert ov["superset"] is False
    assert ov["equal"] is False
    assert ov["shared_count"] == 5
    assert ov["jaccard"] == round(5 / 7, 4)


def test_superset_side_also_emitted():
    registry = _registry((OPS, OPS_OWNERS), (PAUSER, PAUSER_OWNERS))
    fact = _compute_signer_overlap(OPS, registry)
    assert fact is not None
    ov = fact["overlaps"][0]
    assert ov["address"] == PAUSER
    assert ov["superset"] is True
    assert ov["subset"] is False


def test_disjoint_sets_emitted_with_empty_overlap():
    registry = _registry((PAUSER, PAUSER_OWNERS), (DISJOINT, DISJOINT_OWNERS))
    fact = _compute_signer_overlap(PAUSER, registry)
    assert fact is not None
    ov = fact["overlaps"][0]
    assert ov["address"] == DISJOINT
    assert ov["shared_count"] == 0
    assert ov["shared_owners"] == []
    assert ov["subset"] is False
    assert ov["superset"] is False
    assert ov["jaccard"] == 0.0


def test_omitted_when_self_absent_from_registry():
    # A Safe not in the exact-owners registry (owners absent / non-exact) has no
    # dispositive owner set — the fact is omitted, never guessed.
    registry = _registry((OPS, OPS_OWNERS))
    assert _compute_signer_overlap(PAUSER, registry) is None


def test_omitted_when_no_other_safe_to_compare():
    registry = _registry((PAUSER, PAUSER_OWNERS))
    assert _compute_signer_overlap(PAUSER, registry) is None


# --- DB owner-quality gate ---------------------------------------------------


def _make_safe_fp(session, contract, address, details):
    ef = EffectiveFunction(contract_id=contract.id, function_name="pauseUntil", authority_public=False)
    session.add(ef)
    session.flush()
    session.add(FunctionPrincipal(function_id=ef.id, address=address, resolved_type="safe", details=details))


def test_load_protocol_safe_owner_sets_owner_quality_gate(db_session):
    protocol = Protocol(name="etherfi-test")
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address="0x" + "c" * 40)
    db_session.add(contract)
    db_session.flush()

    # exact + owners -> admitted (appears on two functions -> dedup to one entry)
    _make_safe_fp(db_session, contract, OPS, {"owners": OPS_OWNERS, "threshold": 4, "membership_quality": "exact"})
    _make_safe_fp(db_session, contract, OPS, {"owners": OPS_OWNERS, "threshold": 4, "membership_quality": "exact"})
    # lower_bound -> excluded (owner set not dispositively enumerated)
    _make_safe_fp(
        db_session, contract, PAUSER, {"owners": PAUSER_OWNERS, "threshold": 1, "membership_quality": "lower_bound"}
    )
    # exact but no owners -> excluded
    _make_safe_fp(db_session, contract, DISJOINT, {"threshold": 2, "membership_quality": "exact"})
    db_session.commit()

    registry = load_protocol_safe_owner_sets(db_session, protocol.id)
    assert set(registry) == {OPS.lower()}
    assert registry[OPS.lower()]["owners"] == sorted(o.lower() for o in OPS_OWNERS)
    assert registry[OPS.lower()]["threshold"] == 4


def test_load_protocol_safe_owner_sets_conflicting_exacts_omitted(db_session):
    # Two exact witnesses that DISAGREE on the owner set -> fail closed, omit.
    protocol = Protocol(name="etherfi-conflict")
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address="0x" + "d" * 40)
    db_session.add(contract)
    db_session.flush()
    _make_safe_fp(db_session, contract, OPS, {"owners": OPS_OWNERS, "membership_quality": "exact"})
    _make_safe_fp(db_session, contract, OPS, {"owners": OPS_OWNERS[:6], "membership_quality": "exact"})
    # A second, non-conflicting Safe stays admitted (conflict is per-Safe).
    _make_safe_fp(db_session, contract, PAUSER, {"owners": PAUSER_OWNERS, "membership_quality": "exact"})
    db_session.commit()

    registry = load_protocol_safe_owner_sets(db_session, protocol.id)
    assert set(registry) == {PAUSER.lower()}  # OPS omitted, PAUSER kept


def test_load_protocol_safe_owner_sets_exact_and_lower_bound_not_a_conflict(db_session):
    # An exact + lower_bound pair for one Safe is NOT a conflict: lower_bound is
    # skipped and the exact stands (regression guard).
    protocol = Protocol(name="etherfi-mixed-quality")
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address="0x" + "e" * 40)
    db_session.add(contract)
    db_session.flush()
    _make_safe_fp(db_session, contract, OPS, {"owners": OPS_OWNERS, "membership_quality": "exact"})
    _make_safe_fp(db_session, contract, OPS, {"owners": OPS_OWNERS[:3], "membership_quality": "lower_bound"})
    db_session.commit()

    registry = load_protocol_safe_owner_sets(db_session, protocol.id)
    assert set(registry) == {OPS.lower()}
    assert registry[OPS.lower()]["owners"] == sorted(o.lower() for o in OPS_OWNERS)


def test_load_protocol_safe_owner_sets_scoped_to_protocol(db_session):
    p1 = Protocol(name="p1")
    p2 = Protocol(name="p2")
    db_session.add_all([p1, p2])
    db_session.flush()
    c1 = Contract(protocol_id=p1.id, address="0x" + "1" * 40)
    c2 = Contract(protocol_id=p2.id, address="0x" + "2" * 40)
    db_session.add_all([c1, c2])
    db_session.flush()
    _make_safe_fp(db_session, c1, OPS, {"owners": OPS_OWNERS, "membership_quality": "exact"})
    _make_safe_fp(db_session, c2, PAUSER, {"owners": PAUSER_OWNERS, "membership_quality": "exact"})
    db_session.commit()

    assert set(load_protocol_safe_owner_sets(db_session, p1.id)) == {OPS.lower()}
    assert set(load_protocol_safe_owner_sets(db_session, p2.id)) == {PAUSER.lower()}


# --- build_principal_index integration --------------------------------------

TARGET = "0x1111111111111111111111111111111111111111"
CONTRACT_PRINCIPAL = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
TERMINAL_SAFE = "0x" + "a" * 40


def _permission_index_with_principal(principal_addr, resolved_type):
    return {
        "contract_address": TARGET,
        "contract_name": "BoringVault",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "authority_public": False,
                "authority_roles": [
                    {
                        "role": 1,
                        "principals": [{"address": principal_addr, "resolved_type": resolved_type, "details": {}}],
                    }
                ],
                "direct_owner": None,
            }
        ],
    }


def _graph_with_leaf_principal(principal_addr, resolved_type):
    return {
        "nodes": [
            {
                "id": f"address:{TARGET}",
                "address": TARGET,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "BoringVault",
                "depth": 0,
                "analysis_state": "analyzed",
                "details": {"address": TARGET},
            },
            {
                "id": f"address:{principal_addr}",
                "address": principal_addr,
                "node_type": "principal",
                "resolved_type": resolved_type,
                "label": "manager",
                "depth": 1,
                "analysis_state": None,
                "details": {"address": principal_addr},
            },
        ],
        "edges": [
            {
                "from_id": f"address:{TARGET}",
                "to_id": f"address:{principal_addr}",
                "relation": "controller_value",
                "label": "manager",
                "source_controller_id": "state_variable:manager",
                "notes": [],
            }
        ],
    }


def test_signer_overlap_lands_on_safe_profile(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_index.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )
    registry = _registry((OPS, OPS_OWNERS), (PAUSER, PAUSER_OWNERS))
    payload = build_principal_index(
        _permission_index_with_principal(PAUSER, "safe"),
        resolution_graph=_graph_with_leaf_principal(PAUSER, "safe"),
        rpc_url="http://rpc.example",
        protocol_safe_owner_sets=registry,
    )
    profiles = {p["address"]: cast(Any, p) for p in payload["principals"]}
    safe_profile = profiles[PAUSER.lower()]
    overlap = safe_profile["details"]["signer_overlap"]
    assert overlap["overlaps"][0]["subset"] is True
    assert safe_profile["details"]["terminal"] is True


def test_contract_principal_gets_terminal_chain(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_index.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("contract", {"address": address}, True),
    )

    def _resolve_controllers(address):
        if address.lower() == CONTRACT_PRINCIPAL:
            return [{"address": TERMINAL_SAFE, "resolved_type": "safe", "details": {"threshold": 3}}]
        return None

    payload = build_principal_index(
        _permission_index_with_principal(CONTRACT_PRINCIPAL, "contract"),
        resolution_graph=_graph_with_leaf_principal(CONTRACT_PRINCIPAL, "contract"),
        rpc_url="http://rpc.example",
        resolve_controllers=_resolve_controllers,
    )
    profiles = {p["address"]: cast(Any, p) for p in payload["principals"]}
    contract_profile = profiles[CONTRACT_PRINCIPAL]
    assert contract_profile["details"]["terminal"] is False  # the way-point is not a settled key
    terminal = contract_profile["details"]["terminal_principal"]
    assert terminal["terminal"] is True
    assert terminal["resolved_type"] == "safe"
    assert terminal["address"] == TERMINAL_SAFE


def test_contract_principal_without_resolver_stays_non_terminal(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_index.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("contract", {"address": address}, True),
    )
    payload = build_principal_index(
        _permission_index_with_principal(CONTRACT_PRINCIPAL, "contract"),
        resolution_graph=_graph_with_leaf_principal(CONTRACT_PRINCIPAL, "contract"),
        rpc_url="http://rpc.example",
        resolve_controllers=None,
    )
    profiles = {p["address"]: cast(Any, p) for p in payload["principals"]}
    contract_profile = profiles[CONTRACT_PRINCIPAL]
    assert contract_profile["details"]["terminal"] is False
    assert "terminal_principal" not in contract_profile["details"]
