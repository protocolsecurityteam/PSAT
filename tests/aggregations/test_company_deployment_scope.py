"""One code artifact may serve many independent deployments; reports must preserve that boundary."""

from __future__ import annotations

import uuid

import pytest

from db.models import (
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    PrincipalLabel,
)
from services.aggregations.company_overview import build_company_overview, build_functions_for_protocol
from services.aggregations.company_overview.entity_keys import _entity_key
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


@pytest.mark.parametrize("count", [2, 25])
def test_shared_code_reports_are_isolated_and_grow_linearly(db_session, count):
    protocol = _add_protocol(db_session, f"shared-code-{uuid.uuid4().hex}")
    implementation = _addr("impl")
    impl_job = _add_job(db_session, address=implementation, protocol_id=protocol.id)
    impl = _add_contract(db_session, address=implementation, job=impl_job, protocol_id=protocol.id)
    facet_address = _addr("facet")
    facet_job = _add_job(db_session, address=facet_address, protocol_id=protocol.id)
    facet = _add_contract(db_session, address=facet_address, job=facet_job, protocol_id=protocol.id)
    # A common caller has a distinct terminal walk in each deployment. NULL rows represent only the code address.
    common_caller = _addr("caller")
    proxies = []

    def facts(code, deployment, owner, function="execute"):
        fn = EffectiveFunction(
            contract_id=code.id,
            deployment_address=deployment,
            function_name=function,
            selector="0x01020304",
            authority_openness="restricted",
            state_changing=True,
        )
        db_session.add(fn)
        db_session.flush()
        db_session.add_all(
            [
                ControllerValue(
                    contract_id=code.id,
                    deployment_address=deployment,
                    controller_id="owner",
                    value=owner,
                    resolved_type="eoa",
                ),
                ControlGraphNode(
                    contract_id=code.id, deployment_address=deployment, address=owner, resolved_type="eoa"
                ),
                ControlGraphNode(
                    contract_id=code.id, deployment_address=deployment, address=common_caller, resolved_type="contract"
                ),
                ControlGraphEdge(
                    contract_id=code.id,
                    deployment_address=deployment,
                    from_node_id=f"address:{deployment or code.address}",
                    to_node_id=f"address:{owner}",
                    relation="capability_principal",
                ),
                FunctionPrincipal(function_id=fn.id, address=owner, resolved_type="eoa", principal_type="direct_owner"),
                FunctionPrincipal(
                    function_id=fn.id, address=common_caller, resolved_type="contract", principal_type="controller"
                ),
                PrincipalLabel(
                    contract_id=code.id,
                    deployment_address=deployment,
                    address=common_caller,
                    details={"terminal_principal": {"status": "resolved", "address": owner}},
                ),
            ]
        )

    legacy_owner = _addr("legacy")
    facts(impl, None, legacy_owner, "legacy")
    for i in range(count + 1):
        address, owner = _addr(str(i)), _addr("owner" + str(i))
        job = _add_job(db_session, address=address, protocol_id=protocol.id, is_proxy=True)
        proxy = _add_contract(
            db_session, address=address, job=job, protocol_id=protocol.id, is_proxy=True, implementation=implementation
        )
        proxy.secondary_implementations = [facet_address]
        proxies.append((address, owner))
        if i < count:
            db_session.add(
                ControllerValue(
                    contract_id=proxy.id,
                    controller_id="caller",
                    value=common_caller,
                    resolved_type="contract",
                    details={"proxy_marker": address},
                )
            )
            facts(impl, address, owner)
            facts(facet, address, owner, "admin")
    # A standalone deployment still reads its own untagged results.
    standalone_addr = _addr("standalone")
    standalone_job = _add_job(db_session, address=standalone_addr, protocol_id=protocol.id)
    standalone = _add_contract(db_session, address=standalone_addr, job=standalone_job, protocol_id=protocol.id)
    standalone_owner = _addr("standalone-owner")
    facts(standalone, None, standalone_owner)
    # Same byte address on another chain is a different code/runtime identity.
    twin_job = _add_job(db_session, address=proxies[0][0], protocol_id=protocol.id, request={"chain": "base"})
    twin = _add_contract(db_session, address=proxies[0][0], job=twin_job, protocol_id=protocol.id, chain="base")
    twin_owner = _addr("twin-owner")
    facts(twin, None, twin_owner)
    db_session.commit()

    functions = build_functions_for_protocol(db_session, protocol.name)
    overview = build_company_overview(db_session, protocol.name)
    entries = {_entity_key(c["chain"], c["address"]): c for c in overview["contracts"]}
    for address, owner in proxies[:-1]:
        key = _entity_key("ethereum", address)
        rows = functions[key]
        assert len(rows) == 2
        assert {row["function"] for row in rows} == {"execute", "admin"}
        assert all(row["direct_owner"]["address"] == owner for row in rows)
        for row in rows:
            caller = next(p for c in row["controllers"] for p in c["principals"] if p["address"] == common_caller)
            assert caller["details"]["terminal_principal"]["address"] == owner
            assert caller["details"]["proxy_marker"] == address
        assert owner in str(rows) and legacy_owner not in str(rows) and twin_owner not in str(rows)
        for other_address, other_owner in proxies:
            if other_address != address:
                assert other_owner not in str(rows)
        entry = entries[key]
        assert entry["owner"] == owner
        assert {n["address"] for n in entry["control_graph"]["nodes"]} <= {owner, common_caller}
        assert all(edge["to"] == owner for edge in entry["control_graph"]["edges"])
        principal = next(p for p in overview["principals"] if p["address"] == owner)
        assert set(principal["controls"]) == {address}
        assert set(principal["primary_for"]) == {address}
    missing = _entity_key("ethereum", proxies[-1][0])
    assert functions[missing] == []
    assert entries[missing]["owner"] is None
    assert entries[missing]["control_graph"] == {"nodes": [], "edges": []}
    assert functions[_entity_key("ethereum", standalone_addr)][0]["direct_owner"]["address"] == standalone_owner
    assert functions[_entity_key("base", twin.address)][0]["direct_owner"]["address"] == twin_owner
    assert sum(len(rows) for rows in functions.values()) == count * 2 + 2
    assert sum(len(c.get("control_graph", {}).get("edges", [])) for c in entries.values()) == count * 2 + 2
