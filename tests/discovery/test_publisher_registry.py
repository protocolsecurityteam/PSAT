from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

from db.models import Contract, ContractCreationWitness, ContractMembershipWitness, Protocol
from services.discovery import membership_gate as gate
from services.discovery.publisher_membership import register_snapshot
from services.discovery.publisher_registry import (
    REGISTRIES,
    WITNESS_RULE,
    fetch_registries,
    parse_lido,
    parse_solidity,
    registry_evidence,
    validate_evidence,
)
from tests.conftest import requires_postgres

A = "0x" + "11" * 20
B = "0x" + "22" * 20
REVISION = "a" * 40


def snapshot(key="maple_eth", text=None):
    source = next(s for s in REGISTRIES if s.key == key)
    if text is None:
        text = f"contract MapleAddressRegistryETH {{ address public constant syrupUSDCPoolManager = {A}; }}"
    digest = hashlib.sha256(text.encode()).hexdigest()
    return {
        "registry": key,
        "protocol": source.protocol,
        "chain_id": 1,
        "url": f"https://raw.githubusercontent.com/{source.repo}/{REVISION}/{source.path}"
        if source.repo
        else source.url,
        "revision": REVISION if source.repo else f"sha256:{digest}",
        "sha256": digest,
        "retrieved_at": "2026-10-13T00:00:00+00:00",
        "content": text,
        "deployments": parse_solidity(source, text) if source.repo else parse_lido(source, text),
    }


@pytest.mark.parametrize(
    "key,content,expected",
    [
        (
            "maple_eth",
            f"""contract MapleAddressRegistryETH {{
        address public constant syrupUSDCPoolManager = {A};
        address public constant usdc = {B};
        address public constant uniswapFactory = {B};
        // address public constant syrupUSDTPoolManager = {B};
        /* address public constant poolManagerFactory = {B}; */
    }}""",
            [A],
        ),
        (
            "aave_v3_eth",
            f"""library AaveV3Ethereum {{ IPool internal constant POOL = IPool({A}); }}
        library AaveV3EthereumAssets {{ address constant USDC = {B}; }}
        library AaveV3Polygon {{ address constant POOL = {B}; }}""",
            [A],
        ),
        (
            "aave_v4_eth",
            f"""library AaveV4EthereumHubs {{ IHub constant CORE_HUB = IHub({A}); }}
        library AaveV4EthereumAssets {{ address constant USDC = {B}; }}""",
            [A],
        ),
    ],
)
def test_registry_selectors_exclude_external_networks_comments_and_assets(key, content, expected):
    assert [row["address"] for row in snapshot(key, content)["deployments"]] == expected


def test_lido_requires_core_section_and_explicit_mainnet_link():
    text = f"""<h1>Deployments</h1><h2>DAO Contracts</h2>
    <p>Admin Executor: <a href="https://etherscan.io/address/{A}">{A}</a></p>
    <p>Other chain: <a href="https://polygonscan.com/address/{B}">{B}</a></p>
    <p>Unqualified address: {B}</p>
    <h3>External integrations</h3><p>Token <a href="https://etherscan.io/address/{B}">{B}</a></p>
    <h2>Examples</h2><p>Example <a href="https://etherscan.io/address/{B}">{B}</a></p>"""
    rows = snapshot("lido_eth", text)["deployments"]
    assert [row["address"] for row in rows] == [A]


@pytest.mark.parametrize(
    "change",
    [
        {"protocol": "aave"},
        {"chain_id": 137},
        {"registry": "invented"},
        {"url": "https://untrusted.example/registry"},
        {"revision": "main"},
        {"sha256": "bad"},
        {"retrieved_at": "2026-10-13T00:00:00"},
    ],
)
def test_registry_evidence_binds_identity_chain_and_content(change):
    saved = snapshot()
    evidence = registry_evidence(saved, saved["deployments"][0])
    with pytest.raises(ValueError):
        validate_evidence(evidence | change)


def test_failed_fetch_does_not_create_a_declaration(monkeypatch):
    import services.discovery.publisher_registry as registry

    monkeypatch.setattr(registry, "_get", lambda *a, **k: b'{"sha":"main"}')
    snapshots, failures = fetch_registries("maple", "ethereum")
    assert snapshots == [] and failures[0]["registry"] == "maple_eth"
    assert fetch_registries("maple", "polygon") == ([], [])
    assert fetch_registries("unrecognized", "ethereum") == ([], [])


@pytest.mark.parametrize("name", ["aave-v3-fork", "aave-v5", "not-aave"])
def test_unreviewed_names_do_not_inherit_aave_publisher_sources(monkeypatch, name):
    def unexpected_fetch(*args, **kwargs):
        pytest.fail("An unreviewed protocol name must not select a trusted publisher")

    monkeypatch.setattr("services.discovery.publisher_registry._get", unexpected_fetch)
    assert fetch_registries(name, "ethereum") == ([], [])


def test_redirect_is_not_a_trusted_registry(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from services.discovery.publisher_registry import _get

    monkeypatch.setattr("requests.get", lambda *a, **k: nullcontext(SimpleNamespace(status_code=302)))
    with pytest.raises(ValueError, match="HTTP 302"):
        _get("https://docs.lido.fi/deployed-contracts/")


def protocol(session):
    p = Protocol(name="Maple", canonical_slug="maple")
    session.add(p)
    session.flush()
    return p


def code_witness(session, p, row, chain_id=1):
    gate.write_witness(
        session,
        contract_id=row.id,
        protocol_id=p.id,
        rule="w1_code",
        evidence=gate.w1_evidence(chain_id=chain_id, code_probe_block=123),
    )


@requires_postgres
def test_declared_core_requires_same_chain_code_and_never_revives_revocation(db_session):
    p = protocol(db_session)
    ids = register_snapshot(db_session, p, snapshot())
    assert len(ids) == 1
    row = db_session.get(Contract, ids[0])
    assert row.protocol_id is None and not gate.promote(db_session, contract=row, protocol_id=p.id)
    code_witness(db_session, p, row, chain_id=137)
    assert not gate.promote(db_session, contract=row, protocol_id=p.id)
    wrong = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == row.id, ContractMembershipWitness.rule == "w1_code"
        )
    ).scalar_one()
    gate.revoke_witness(db_session, wrong, reason="replace wrong-chain observation")
    code_witness(db_session, p, row)
    assert gate.promote(db_session, contract=row, protocol_id=p.id)
    assert register_snapshot(db_session, p, snapshot()) == []
    witness = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == row.id, ContractMembershipWitness.rule == WITNESS_RULE
        )
    ).scalar_one()
    gate.revoke_witness(db_session, witness, reason="operator rejects declaration")
    assert register_snapshot(db_session, p, snapshot()) == []
    assert witness.revoked_at is not None


@requires_postgres
def test_nomination_tag_and_forged_rows_cannot_seed_membership(db_session):
    p = protocol(db_session)
    saved = snapshot()
    saved["deployments"].append({"name": "forged", "address": B, "selector": "forged"})
    register_snapshot(db_session, p, saved)
    assert db_session.execute(select(Contract).where(Contract.address == B)).scalar_one_or_none() is None
    row = Contract(address=B, chain="ethereum", nominated_protocol_id=p.id, discovery_sources=["publisher_registry"])
    db_session.add(row)
    db_session.flush()
    code_witness(db_session, p, row)
    assert not gate.promote(db_session, contract=row, protocol_id=p.id)
    assert WITNESS_RULE not in gate.NONLINEAGE_WITNESS_RULES


@requires_postgres
def test_registry_does_not_override_absent_code_or_other_protocol(db_session):
    p = protocol(db_session)
    saved = snapshot()
    saved["content"] += "tampered"
    with pytest.raises(ValueError, match="digest"):
        register_snapshot(db_session, p, saved)
    row = db_session.get(Contract, register_snapshot(db_session, p, snapshot())[0])
    code_witness(db_session, p, row)
    db_session.add(ContractCreationWitness(chain_id=1, address=A, code_probe_block=124, code_absent_at_probe=True))
    db_session.flush()
    assert not gate.promote(db_session, contract=row, protocol_id=p.id)
    p.name = "Other"
    p.canonical_slug = "other"
    with pytest.raises(ValueError, match="protocol"):
        register_snapshot(db_session, p, snapshot())


@requires_postgres
def test_existing_code_probe_promotes_through_normal_probe_pass_without_reprobing(db_session, monkeypatch):
    from workers.discovery import run_probe_pass

    p = protocol(db_session)
    row = db_session.get(Contract, register_snapshot(db_session, p, snapshot())[0])
    code_witness(db_session, p, row)
    db_session.add(ContractCreationWitness(chain_id=1, address=A, code_probe_block=123, code_absent_at_probe=False))
    db_session.commit()
    monkeypatch.setattr("workers.discovery.needs_probe", lambda *a: False)
    monkeypatch.setattr("workers.discovery.probe_predates_revocation", lambda *a: False)
    monkeypatch.setattr("workers.discovery.gate.probe", lambda *a: pytest.fail("cached code should not be re-probed"))
    result = run_probe_pass(db_session, p.id)
    assert row.id in result.promoted_contract_ids
    assert row.protocol_id == p.id


@requires_postgres
def test_publisher_structural_descendants_do_not_bootstrap_deployer_affinity(db_session):
    from services.discovery.membership_gate.heuristics import compute_deployer_affinity

    p = protocol(db_session)
    saved = snapshot(
        text=f"""contract MapleAddressRegistryETH {{
        address public constant syrupUSDCPoolManager = {A};
        address public constant syrupUSDTPoolManager = {B};
    }}"""
    )
    roots = [db_session.get(Contract, id) for id in register_snapshot(db_session, p, saved)]
    deployer = "0x" + "dd" * 20
    for root, suffix in zip(roots, [31, 32]):
        code_witness(db_session, p, root)
        assert gate.promote(db_session, contract=root, protocol_id=p.id)
        address = "0x" + f"{suffix:040x}"
        root.implementation = address
        row = Contract(address=address, chain="ethereum", nominated_protocol_id=p.id, deployer=deployer)
        db_session.add(row)
        db_session.flush()
        code_witness(db_session, p, row)
        gate.write_witness(
            db_session,
            contract_id=row.id,
            protocol_id=p.id,
            rule="w2_structural",
            evidence=gate.w2_evidence(
                edge_kind="implementation",
                member_contract_id=root.id,
                member_address=root.address,
                resolved_pointer=row.address,
            ),
            via_address=root.address,
        )
        assert gate.promote(db_session, contract=row, protocol_id=p.id)
    db_session.flush()
    from db.models import ProtocolDeployer
    from services.discovery.membership_gate.heuristics import _attempt_w4h_admission, grant_heuristic_deployer

    affinity = compute_deployer_affinity(db_session, protocol_id=p.id, address=deployer)
    assert affinity.qualifies()  # Ordinary W2 descendants would previously qualify this deployer.
    assert (
        grant_heuristic_deployer(db_session, protocol_id=p.id, address=deployer, affinity=affinity, challenges=0)
        is None
    )
    standing = ProtocolDeployer(protocol_id=p.id, address=deployer, trust_class="H", evidence={})
    sibling = Contract(address="0x" + "ee" * 20, chain="ethereum", nominated_protocol_id=p.id, deployer=deployer)
    db_session.add_all([standing, sibling])
    db_session.flush()
    db_session.add(
        ContractCreationWitness(
            chain_id=1,
            address=sibling.address,
            code_probe_block=123,
            code_absent_at_probe=False,
            creation_tx_hash="0x" + "aa" * 32,
            creation_block=10,
        )
    )
    db_session.flush()
    assert not _attempt_w4h_admission(db_session, sibling, registry=standing, affinity=affinity)
    for witness in db_session.execute(
        select(ContractMembershipWitness).where(ContractMembershipWitness.rule == WITNESS_RULE)
    ).scalars():
        gate.revoke_witness(db_session, witness, reason="withdraw publisher source")
    assert not _attempt_w4h_admission(db_session, sibling, registry=standing, affinity=affinity)


@requires_postgres
def test_successful_refresh_withdraws_old_declaration_without_rearming_it(db_session):
    p = protocol(db_session)
    row = db_session.get(Contract, register_snapshot(db_session, p, snapshot())[0])
    code_witness(db_session, p, row)
    assert gate.promote(db_session, contract=row, protocol_id=p.id)
    new = snapshot(text=f"contract MapleAddressRegistryETH {{ address public constant syrupUSDCPoolManager = {B}; }}")
    register_snapshot(db_session, p, new)
    assert row.protocol_id is None
    assert register_snapshot(db_session, p, snapshot()) == []
    assert not gate.promote(db_session, contract=row, protocol_id=p.id)


@requires_postgres
def test_publisher_priority_bypasses_stale_research_confidence(db_session, monkeypatch):
    from db.models import JobStage
    from db.queue import create_job
    from workers.selection_worker import SelectionWorker

    p = protocol(db_session)
    row = db_session.get(Contract, register_snapshot(db_session, p, snapshot())[0])
    row.confidence = 0.01
    code_witness(db_session, p, row)
    assert gate.promote(db_session, contract=row, protocol_id=p.id)
    job = create_job(db_session, {"protocol_id": p.id, "analyze_limit": 1}, initial_stage=JobStage.selection)
    monkeypatch.setattr("workers.selection_worker.run_probe_pass", lambda *a, **k: gate.PromotionResult())
    monkeypatch.setattr(
        "workers.selection_worker.rank_contract_rows",
        lambda rows: [{"__row_address": r.address, "__row_chain": r.chain, "rank_score": 0.01} for r in rows],
    )
    seen = []
    worker = SelectionWorker()
    monkeypatch.setattr(worker, "_queue_top_n", lambda **kwargs: (seen.extend(kwargs["ranked"]) or [], []))
    monkeypatch.setattr(worker, "_finish", lambda *a, **k: None)
    worker.process(db_session, job)
    assert len(seen) == 1 and seen[0]["publisher_core_priority"] is True


@requires_postgres
def test_overlapping_sources_refresh_as_a_batch_and_failed_sources_keep_dated_evidence(db_session):
    from services.discovery.publisher_membership import register_snapshots

    p = Protocol(name="Aave", canonical_slug="aave")
    db_session.add(p)
    db_session.flush()

    def registry(key, address):
        container = "AaveV3Ethereum" if key == "aave_v3_eth" else "AaveV4Ethereum"
        return snapshot(key, f"library {container} {{ address constant RISK_COUNCIL = {address}; }}")

    register_snapshots(db_session, p, [registry("aave_v3_eth", A), registry("aave_v4_eth", B)])
    a = db_session.execute(select(Contract).where(Contract.address == A)).scalar_one()
    code_witness(db_session, p, a)
    assert gate.promote(db_session, contract=a, protocol_id=p.id)
    # The address moves between sources in one refresh: no transient revocation/no-rearm trap.
    register_snapshots(db_session, p, [registry("aave_v3_eth", B), registry("aave_v4_eth", A)])
    assert a.protocol_id == p.id
    witness = db_session.execute(
        select(ContractMembershipWitness).where(
            ContractMembershipWitness.contract_id == a.id, ContractMembershipWitness.rule == WITNESS_RULE
        )
    ).scalar_one()
    assert [item["registry"] for item in witness.evidence["assertions"]] == ["aave_v4_eth"]
    old = witness.evidence.copy()
    # V4 failed to fetch and is absent from this successful batch; do not claim a fresh V4 observation.
    register_snapshot(db_session, p, registry("aave_v3_eth", B))
    assert a.protocol_id == p.id and witness.evidence == old
    register_snapshot(db_session, p, registry("aave_v4_eth", B))
    assert a.protocol_id is None and witness.revoked_at is not None
