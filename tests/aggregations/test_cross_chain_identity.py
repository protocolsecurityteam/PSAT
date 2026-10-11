"""The same address on two chains is two entities everywhere the company views publish: principals, Safe details,
monitoring and enrollment, /functions, and audit coverage. Each case runs its inputs in both row orders, since a
bare-address merge shows up as a result that depends on which row came first.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import select

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    ControlGraphNode,
    EffectiveFunction,
    FunctionPrincipal,
    MonitoredContract,
    Protocol,
    UpgradeEvent,
)
from services.aggregations import build_contract_audit_timeline
from services.aggregations.company_overview import (
    build_company_overview,
    build_functions_for_protocol,
    controllers_for_protocol,
    prefetch_contracts,
    resolve_company_jobs,
    resolve_implementation_contracts,
)
from services.aggregations.company_overview.governance_view import build_governance_view
from services.audits.coverage import _compute_impl_windows_batch
from services.chat import data as chat_data
from tests.conftest import SessionFactory, requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres

ORDERS = [("ethereum", "base"), ("base", "ethereum")]


def _subject(session, protocol: Protocol, chain: str, tag: str) -> Contract:
    address = _addr(tag)
    job = _add_job(
        session,
        address=address,
        protocol_id=protocol.id,
        name=tag,
        request={"address": address, "chain": chain},
    )
    job.chain_id = 1 if chain == "ethereum" else 8453
    session.commit()
    return _add_contract(session, address=address, job=job, protocol_id=protocol.id, chain=chain, contract_name=tag)


def _governed_by(session, contract: Contract, principal: str, resolved_type: str, details: dict[str, Any]) -> None:
    """``principal`` holds a gated function of ``contract`` and is read as ``resolved_type`` on its chain."""
    function = EffectiveFunction(
        contract_id=contract.id,
        function_name="upgradeTo",
        selector="0x3659cfe6",
        abi_signature="upgradeTo(address)",
        authority_public=False,
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {}}],
    )
    session.add(function)
    session.flush()
    session.add(
        FunctionPrincipal(
            function_id=function.id,
            address=principal,
            resolved_type="unknown",
            origin="semantic_capability:finite_set",
            principal_type="controller",
            details={"membership_quality": "exact"},
        )
    )
    session.add(
        ControlGraphNode(
            contract_id=contract.id,
            address=principal,
            resolved_type=resolved_type,
            label=resolved_type,
            details=details,
        )
    )
    session.commit()


def _principals(payload) -> dict[tuple[str, str], dict[str, Any]]:
    return {(p["chain"], p["address"]): p for p in payload["principals"]}


def _world(session, order: tuple[str, str], configs: dict[str, tuple[str, dict[str, Any]]]):
    protocol = _add_protocol(session, f"xchain-{uuid.uuid4().hex[:8]}")
    shared = _addr("shared")
    subjects = {}
    for chain in order:
        resolved_type, details = configs[chain]
        subjects[chain] = _subject(session, protocol, chain, f"subject-{chain}")
        _governed_by(session, subjects[chain], shared, resolved_type, details)
    return protocol, shared, subjects


EOA_AND_SAFE = {
    "ethereum": ("eoa", {}),
    "base": ("safe", {"threshold": 2, "owners": ["0x" + "b1" * 20, "0x" + "b2" * 20, "0x" + "b3" * 20]}),
}
SAFE_TWINS = {
    "ethereum": ("safe", {"threshold": 4, "owners": ["0x" + f"{i:02x}" * 20 for i in range(1, 8)]}),
    "base": ("safe", {"threshold": 1, "owners": ["0x" + "c1" * 20]}),
}


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_an_eoa_and_a_safe_at_one_address_are_two_principals_and_only_the_safe_is_monitored(db_session, order):
    protocol, shared, subjects = _world(db_session, order, EOA_AND_SAFE)

    principals = _principals(build_company_overview(db_session, protocol.name))

    eth, base = principals[("ethereum", shared)], principals[("base", shared)]
    assert (eth["type"], base["type"]) == ("eoa", "safe")
    assert "threshold" not in eth["details"] and base["details"]["threshold"] == 2
    assert (eth["controls_chains"], base["controls_chains"]) == (["ethereum"], ["base"])
    assert eth["primary_for"] == [subjects["ethereum"].address.lower()]
    assert base["primary_for"] == [subjects["base"].address.lower()]
    assert controllers_for_protocol(db_session, protocol.id) == {(shared, "base"): "safe"}


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_safe_twins_keep_their_own_owners_and_threshold(db_session, order):
    protocol, shared, _subjects = _world(db_session, order, SAFE_TWINS)

    principals = _principals(build_company_overview(db_session, protocol.name))

    eth, base = principals[("ethereum", shared)], principals[("base", shared)]
    assert (eth["details"]["threshold"], len(eth["details"]["owners"])) == (4, 7)
    assert (base["details"]["threshold"], len(base["details"]["owners"])) == (1, 1)
    assert controllers_for_protocol(db_session, protocol.id) == {(shared, "ethereum"): "safe", (shared, "base"): "safe"}


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_a_contract_on_one_chain_does_not_hide_a_safe_at_its_address_on_another(db_session, order):
    protocol = _add_protocol(db_session, f"xchain-inv-{uuid.uuid4().hex[:8]}")
    shared = _addr("shared")
    for chain in order:
        if chain == "ethereum":
            # The Ethereum copy of the Safe is in the inventory as a protocol contract.
            job = _add_job(
                db_session, address=shared, protocol_id=protocol.id, request={"address": shared, "chain": chain}
            )
            _add_contract(
                db_session, address=shared, job=job, protocol_id=protocol.id, chain=chain, contract_name="Safe"
            )
        else:
            subject = _subject(db_session, protocol, "base", "subject-base")
            _governed_by(db_session, subject, shared, "safe", SAFE_TWINS["base"][1])

    principals = _principals(build_company_overview(db_session, protocol.name))

    assert ("base", shared) in principals and ("ethereum", shared) not in principals
    assert principals[("base", shared)]["type"] == "safe"
    assert controllers_for_protocol(db_session, protocol.id) == {(shared, "base"): "safe"}


def test_shuffled_inputs_publish_the_same_principals(db_session):
    protocol, _shared, _subjects = _world(db_session, ORDERS[0], EOA_AND_SAFE)
    _protocol_row, jobs = resolve_company_jobs(db_session, protocol.name)
    contracts_by_job_id = prefetch_contracts(db_session, jobs)
    impl_job_by_entity, contracts_by_job_id = resolve_implementation_contracts(db_session, jobs, contracts_by_job_id)

    def published(seed: int) -> str:
        shuffled_jobs = list(jobs)
        random.Random(seed).shuffle(shuffled_jobs)
        shuffled_contracts = dict(
            random.Random(seed).sample(list(contracts_by_job_id.items()), len(contracts_by_job_id))
        )
        view = build_governance_view(db_session, shuffled_jobs, shuffled_contracts, impl_job_by_entity)
        return json.dumps(sorted(view.principals, key=lambda p: (p["chain"], p["address"])), sort_keys=True)

    assert len({published(seed) for seed in range(6)}) == 1


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_functions_type_a_principal_from_its_own_chain(db_session, order):
    protocol, shared, subjects = _world(db_session, order, EOA_AND_SAFE)

    functions = build_functions_for_protocol(db_session, protocol.name)

    def principal_type(chain: str) -> str:
        (entry,) = functions[f"{chain}::{subjects[chain].address.lower()}"]
        principals = [p for c in entry["controllers"] for p in c["principals"] if p["address"] == shared]
        assert principals, entry
        return principals[0]["resolved_type"]

    assert (principal_type("ethereum"), principal_type("base")) == ("eoa", "safe")


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_enrollment_watches_only_the_safe_and_retires_a_row_the_merge_created(db_session, monkeypatch, order):
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", lambda *_a, **_k: "0x100")
    protocol, shared, _subjects = _world(db_session, order, EOA_AND_SAFE)
    # The old bare-address merge enrolled the Ethereum EOA as a Safe.
    db_session.add(
        MonitoredContract(
            address=shared,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_type="safe",
            monitoring_config={},
            last_known_state={},
            is_active=True,
            enrollment_source="auto",
        )
    )
    db_session.commit()

    enroll_protocol_contracts(db_session, protocol.id, "http://rpc.test", "ethereum")
    db_session.commit()

    rows = {
        mc.chain: (mc.contract_type, mc.is_active, mc.enrollment_source)
        for mc in db_session.execute(select(MonitoredContract).where(MonitoredContract.address == shared)).scalars()
    }
    assert rows == {"base": ("safe", True, "auto"), "ethereum": ("safe", False, "auto_deprimary")}


def test_enrollment_does_not_count_a_twins_analysis(db_session, monkeypatch):
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", lambda *_a, **_k: "0x100")
    protocol = _add_protocol(db_session, f"xchain-enroll-{uuid.uuid4().hex[:8]}")
    address = _addr("twin")
    job = _add_job(
        db_session, address=address, protocol_id=protocol.id, request={"address": address, "chain": "ethereum"}
    )
    _add_contract(db_session, address=address, job=job, protocol_id=protocol.id, chain="ethereum")
    # Only the Ethereum copy was analysed; the Base row is inventory.
    base_job = _add_job(
        db_session, address=address, protocol_id=protocol.id, request={"address": address, "chain": "base"}
    )
    base_job.status = base_job.status.queued
    db_session.commit()
    _add_contract(db_session, address=address, job=base_job, protocol_id=protocol.id, chain="base")

    enrolled = enroll_protocol_contracts(
        db_session, protocol.id, "http://rpc.test", "ethereum", enroll_controllers=False
    )

    assert {(mc.address, mc.chain) for mc in enrolled} == {(address, "ethereum")}


# Audit joins --------------------------------------------------------------------------------------------------------


def _audit(session, protocol: Protocol) -> AuditReport:
    report = AuditReport(
        protocol_id=protocol.id,
        url="https://example.invalid/base-audit",
        auditor="Base auditor",
        title="Base source",
        scope_extraction_status="success",
    )
    session.add(report)
    session.commit()
    return report


def _cover(session, protocol: Protocol, contract: Contract, report: AuditReport) -> None:
    session.add(
        AuditContractCoverage(
            contract_id=contract.id,
            audit_report_id=report.id,
            protocol_id=protocol.id,
            matched_name="Impl",
            match_type="reviewed_commit",
            match_confidence="high",
            equivalence_status="proven",
            matched_commit_sha="a" * 40,
        )
    )
    session.commit()


def _proxy_and_impl_twins(session, order: tuple[str, str]):
    """An Ethereum proxy whose implementation address also exists on Base, where only the Base copy is audited."""
    protocol = _add_protocol(session, f"xchain-audit-{uuid.uuid4().hex[:8]}")
    impl = _addr("impl")
    proxy_address = _addr("proxy")
    proxy_job = _add_job(
        session, address=proxy_address, protocol_id=protocol.id, request={"address": proxy_address, "chain": "ethereum"}
    )
    proxy = _add_contract(
        session,
        address=proxy_address,
        job=proxy_job,
        protocol_id=protocol.id,
        chain="ethereum",
        is_proxy=True,
        implementation=impl,
        contract_name="Proxy",
    )
    impls = {}
    for chain in order:
        job = _add_job(session, address=impl, protocol_id=protocol.id, request={"address": impl, "chain": chain})
        impls[chain] = _add_contract(
            session, address=impl, job=job, protocol_id=protocol.id, chain=chain, contract_name=f"Impl-{chain}"
        )
    report = _audit(session, protocol)
    _cover(session, protocol, impls["base"], report)
    return protocol, proxy, impls


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_audit_coverage_never_gives_a_proxy_another_chains_implementation_audit(db_session, monkeypatch, order):
    from routers import deps
    from routers.company import company_audit_coverage

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
    protocol, proxy, impls = _proxy_and_impl_twins(db_session, order)

    coverage = {(row["chain"], row["address"]): row for row in company_audit_coverage(protocol.name)["coverage"]}

    assert coverage[("ethereum", proxy.address)]["audit_count"] == 0
    assert coverage[("base", impls["base"].address)]["audit_count"] == 1


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_audit_timeline_and_chat_scope_a_proxys_implementation_to_its_chain(db_session, monkeypatch, order):
    monkeypatch.setattr("services.audits.coverage._fetch_bytecode_keccak", lambda *_a, **_k: None)
    protocol, proxy, impls = _proxy_and_impl_twins(db_session, order)
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=impls["ethereum"].address,
            block_number=100,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
    )
    db_session.commit()

    timeline = build_contract_audit_timeline(db_session, proxy.id)
    assert timeline is not None
    assert timeline["coverage"] == []

    summary = chat_data.upgrade_summary(db_session, proxy.address, "ethereum")
    assert summary["coverage"] == []

    # The Base copy's own views still carry its audit.
    base_timeline = build_contract_audit_timeline(db_session, impls["base"].id)
    assert base_timeline is not None
    assert len(base_timeline["coverage"]) == 1


def test_chat_upgrade_summary_scopes_implementations_to_the_proxys_protocol(db_session):
    protocol, proxy, impls = _proxy_and_impl_twins(db_session, ("ethereum", "base"))
    other = _add_protocol(db_session, f"xchain-other-{uuid.uuid4().hex[:8]}")
    other_impl = impls["ethereum"]
    # Audited under another protocol only.
    other_impl.protocol_id = other.id
    db_session.commit()
    _cover(db_session, other, other_impl, _audit(db_session, other))

    assert chat_data.upgrade_summary(db_session, proxy.address, "ethereum")["coverage"] == []


@pytest.mark.parametrize("order", ORDERS, ids=["ethereum-first", "base-first"])
def test_impl_windows_come_only_from_a_proxy_on_the_implementations_chain(db_session, order):
    protocol, proxy, impls = _proxy_and_impl_twins(db_session, order)
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=impls["ethereum"].address.upper().replace("0X", "0x"),
            block_number=100,
        )
    )
    db_session.commit()

    windows = _compute_impl_windows_batch(db_session, [impls["ethereum"], impls["base"]])

    assert [w.proxy_contract_id for w in windows[impls["ethereum"].id]] == [proxy.id]
    assert windows[impls["base"].id] == []
