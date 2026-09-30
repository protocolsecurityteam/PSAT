from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from tests.conftest import requires_postgres
from tests.support.audit_coverage_builders import (
    _add_audit,
    _add_contract,
    _add_upgrade_event,
    _stub_get_code,
    _ts,
    seed_protocol,  # noqa: F401  (fixture, registered by import)
)

pytestmark = [
    requires_postgres,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # End-of-day semantics so "impl replaced on 2024-06-15" matches.
        pytest.param("2024-06-15", {"year": 2024, "month": 6, "day": 15, "hour": 23, "minute": 59}, id="full_date"),
        pytest.param("2023", {"month": 12, "day": 31}, id="year_only"),
        pytest.param(None, None, id="none"),
        pytest.param("", None, id="empty"),
        pytest.param("nonsense", None, id="garbage"),
    ],
)
def test_audit_effective_ts(raw, expected):
    from services.audits.coverage import _audit_effective_ts

    got = _audit_effective_ts(raw)
    if expected is None:
        assert got is None
        return
    assert got is not None
    for attr, value in expected.items():
        assert getattr(got, attr) == value


def test_audit_effective_ts_month_placeholder():
    from services.audits.coverage import _audit_effective_ts

    # Both the scope-extraction "YYYY-MM-00" placeholder and "YYYY-MM"
    # resolve to end of month.
    a = _audit_effective_ts("2024-06-00")
    b = _audit_effective_ts("2024-06")
    assert a == b
    assert a is not None and a.month == 6 and a.day == 30


def test_direct_match_high_when_audit_has_date(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    contract = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-15")

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    m = matches[0]
    assert m.contract_id == contract.id
    assert m.match_type == "direct"
    assert m.match_confidence == "high"
    assert m.covered_from_block is None
    assert m.covered_to_block is None
    assert m.matched_name == "Pool"


def test_direct_match_medium_without_audit_date(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date=None)

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].match_confidence == "medium"


def test_direct_match_is_case_insensitive(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="EtherFiNodesManager")
    audit = _add_audit(db_session, protocol_id, scope=["etherfinodesmanager"], date="2024-01-01")
    assert len(match_contracts_for_audit(db_session, audit.id)) == 1


def test_scope_name_not_in_protocol_yields_zero_matches(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["UnrelatedThing"], date="2024-01-01")
    assert match_contracts_for_audit(db_session, audit.id) == []


def test_duplicate_scope_names_collapse_to_single_match(db_session, seed_protocol):
    """Extraction glitches ship one contract twice under near-identical names."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool", "pool", "POOL"], date="2024-01-01")

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1


def test_impl_era_match_inside_window_is_high(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "1" * 40,
        name="Proxy",
        is_proxy=True,
        implementation="0x" + "b" * 40,  # currently pointing at Y
    )
    impl_x = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MorphoBlue")
    _add_contract(db_session, protocol_id, address="0x" + "b" * 40, name="MorphoBlueV2")

    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_x.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl="0x" + "b" * 40,
        old_impl=impl_x.address,
        block_number=200,
        timestamp=_ts(2024, 6, 1),
    )

    audit = _add_audit(db_session, protocol_id, scope=["MorphoBlue"], date="2024-03-15")
    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    m = matches[0]
    assert m.contract_id == impl_x.id
    assert m.match_type == "impl_era"
    assert m.match_confidence == "high"
    assert m.covered_from_block == 100
    assert m.covered_to_block == 200


def test_impl_era_match_open_ended_window_for_current_impl(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "1" * 40,
        name="Proxy",
        is_proxy=True,
        implementation="0x" + "a" * 40,
    )
    impl_x = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MorphoBlue")

    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_x.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )

    audit = _add_audit(db_session, protocol_id, scope=["MorphoBlue"], date="2024-06-01")
    [m] = match_contracts_for_audit(db_session, audit.id)
    assert m.covered_from_block == 100
    assert m.covered_to_block is None
    assert m.match_confidence == "high"


def test_impl_era_grace_window_gives_medium_confidence(db_session, seed_protocol):
    """An audit finalized after a remediation upgrade stays attached at 'medium'."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(db_session, protocol_id, address="0x" + "1" * 40, name="Proxy", is_proxy=True)
    impl_x = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MorphoBlue")

    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_x.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl="0x" + "b" * 40,
        old_impl=impl_x.address,
        block_number=200,
        timestamp=_ts(2024, 6, 1),
    )

    audit = _add_audit(db_session, protocol_id, scope=["MorphoBlue"], date="2024-06-11")
    [m] = match_contracts_for_audit(db_session, audit.id)
    assert m.match_confidence == "medium"
    assert m.contract_id == impl_x.id


def test_impl_era_far_outside_window_is_low(db_session, seed_protocol):
    """Never silently dropped; low confidence lets a UI hide or badge it."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(db_session, protocol_id, address="0x" + "1" * 40, name="Proxy", is_proxy=True)
    impl_x = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MorphoBlue")
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_x.address,
        block_number=100,
        timestamp=_ts(2023, 1, 1),
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl="0x" + "b" * 40,
        old_impl=impl_x.address,
        block_number=200,
        timestamp=_ts(2023, 6, 1),
    )

    audit = _add_audit(db_session, protocol_id, scope=["MorphoBlue"], date="2025-01-01")
    [m] = match_contracts_for_audit(db_session, audit.id)
    assert m.match_confidence == "low"
    assert m.contract_id == impl_x.id


def test_impl_era_with_no_audit_date_falls_to_low(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(db_session, protocol_id, address="0x" + "1" * 40, name="Proxy", is_proxy=True)
    impl_x = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MorphoBlue")
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_x.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )

    audit = _add_audit(db_session, protocol_id, scope=["MorphoBlue"], date=None)
    [m] = match_contracts_for_audit(db_session, audit.id)
    assert m.match_confidence == "low"
    assert m.match_type == "impl_era"


def test_impl_era_picks_correct_window_across_multiple_upgrades(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(db_session, protocol_id, address="0x" + "1" * 40, name="Proxy", is_proxy=True)
    impl_a = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="ImplA")

    for ts, block, new_impl, old_impl in [
        (_ts(2024, 1, 1), 100, impl_a.address, None),
        (_ts(2024, 2, 1), 200, "0x" + "b" * 40, impl_a.address),
        (_ts(2024, 3, 1), 300, impl_a.address, "0x" + "b" * 40),
        (_ts(2024, 4, 1), 400, "0x" + "c" * 40, impl_a.address),
    ]:
        _add_upgrade_event(
            db_session,
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=new_impl,
            old_impl=old_impl,
            block_number=block,
            timestamp=ts,
        )

    audit = _add_audit(db_session, protocol_id, scope=["ImplA"], date="2024-03-15")
    [m] = match_contracts_for_audit(db_session, audit.id)
    assert m.covered_from_block == 300
    assert m.covered_to_block == 400
    assert m.match_confidence == "high"


def test_proxy_and_impl_share_name_only_impl_gets_row(db_session, seed_protocol):
    """The proxy view still shows coverage via audit_timeline's union over historical impls."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "1" * 40,
        name="SharedName",
        is_proxy=True,
    )
    impl = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="SharedName")
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    audit = _add_audit(db_session, protocol_id, scope=["SharedName"], date="2024-03-01")
    matches = match_contracts_for_audit(db_session, audit.id)
    by_id = {m.contract_id: m for m in matches}
    assert set(by_id) == {impl.id}
    assert by_id[impl.id].match_type == "impl_era"


def test_proxy_direct_match_on_own_name_skipped(db_session, seed_protocol):
    """A generic proxy scope-name match ("UUPSProxy") is the false-positive class; proxy coverage flows via the impl."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    # Mirrors KING Distributor / CumulativeMerkleDrop: the impl name is not in the audit scope.
    _add_contract(
        db_session,
        protocol_id,
        address="0x" + "a" * 40,
        name="UUPSProxy",
        is_proxy=True,
        implementation="0x" + "b" * 40,
    )
    _add_contract(
        db_session,
        protocol_id,
        address="0x" + "b" * 40,
        name="Distributor",
    )
    audit = _add_audit(
        db_session,
        protocol_id,
        scope=["UUPSProxy", "SomeOtherContract"],
        date="2024-06-01",
    )

    matches = match_contracts_for_audit(db_session, audit.id)
    assert matches == []


def test_proxy_direct_match_skipped_but_impl_still_matches(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "1" * 40,
        name="UUPSProxy",
        is_proxy=True,
        implementation="0x" + "2" * 40,
    )
    impl = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "2" * 40,
        name="LiquidityPool",
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    audit = _add_audit(
        db_session,
        protocol_id,
        scope=["UUPSProxy", "LiquidityPool"],
        date="2024-06-01",
    )

    matches = match_contracts_for_audit(db_session, audit.id)
    by_id = {m.contract_id: m for m in matches}
    assert set(by_id) == {impl.id}
    assert by_id[impl.id].match_type == "impl_era"
    assert by_id[impl.id].matched_name == "LiquidityPool"


def test_non_proxy_contract_named_proxy_still_matches_directly(db_session, seed_protocol):
    """The skip keys on is_proxy, not the name string."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    c = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "c" * 40,
        name="UUPSProxy",
        is_proxy=False,
    )
    audit = _add_audit(db_session, protocol_id, scope=["UUPSProxy"], date="2024-06-01")
    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == c.id
    assert matches[0].match_type == "direct"


def test_proxy_with_windows_is_still_excluded_from_matching(db_session, seed_protocol):
    """A proxy-behind-proxy has impl windows and used to slip past the no-windows is_proxy guard."""
    from db.models import Contract
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    inner_proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "a" * 40,
        name="UUPSProxy",
        is_proxy=True,
        implementation="0x" + "b" * 40,
    )
    # The upgrade gives the inner proxy a window despite being a proxy.
    outer_proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "c" * 40,
        name="OuterProxy",
        is_proxy=True,
        implementation=inner_proxy.address,
    )
    _add_upgrade_event(
        db_session,
        contract_id=outer_proxy.id,
        proxy_address=outer_proxy.address,
        new_impl=inner_proxy.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    audit = _add_audit(db_session, protocol_id, scope=["UUPSProxy"], date="2024-06-01")

    matches = match_contracts_for_audit(db_session, audit.id)
    by_id = {m.contract_id: m for m in matches}
    assert inner_proxy.id not in by_id, (
        "Proxy with windows must be excluded from coverage candidates even "
        "though the impl_era path would have matched it"
    )
    assert outer_proxy.id not in by_id
    assert db_session.get(Contract, inner_proxy.id).is_proxy is True


def test_match_audits_for_contract_skips_proxies_own_name(db_session, seed_protocol):
    from services.audits.coverage import match_audits_for_contract

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "a" * 40,
        name="UUPSProxy",
        is_proxy=True,
        implementation="0x" + "b" * 40,
    )
    _add_audit(
        db_session,
        protocol_id,
        scope=["UUPSProxy"],
        date="2024-06-01",
    )
    assert match_audits_for_contract(db_session, proxy.id) == []


def test_match_audits_for_contract_is_symmetric(db_session, seed_protocol):
    from services.audits.coverage import match_audits_for_contract, match_contracts_for_audit

    protocol_id, _ = seed_protocol
    impl = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")

    m_from_audit = match_contracts_for_audit(db_session, audit.id)
    m_from_contract = match_audits_for_contract(db_session, impl.id)
    assert len(m_from_audit) == 1
    assert len(m_from_contract) == 1
    assert m_from_audit[0].contract_id == m_from_contract[0].contract_id == impl.id
    assert m_from_audit[0].audit_report_id == m_from_contract[0].audit_report_id == audit.id
    assert m_from_audit[0].match_type == m_from_contract[0].match_type


def test_match_audits_for_contract_ignores_non_success_scope(db_session, seed_protocol):
    from services.audits.coverage import match_audits_for_contract

    protocol_id, _ = seed_protocol
    contract = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01", status="skipped")
    _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01", status="failed")
    _add_audit(db_session, protocol_id, scope=None, date="2024-06-01", status=None)

    assert match_audits_for_contract(db_session, contract.id) == []


def test_upsert_coverage_for_audit_is_idempotent(db_session, seed_protocol):
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")

    n1 = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    n2 = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert n1 == n2 == 1
    rows = (
        db_session.execute(select(AuditContractCoverage).where(AuditContractCoverage.audit_report_id == audit.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1


def test_upsert_drops_stale_rows_after_scope_change(db_session, seed_protocol):
    from db.models import AuditContractCoverage, AuditReport
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    pool = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    vault = _add_contract(db_session, protocol_id, address="0x" + "b" * 40, name="Vault")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    rows = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).all()
    assert {r.contract_id for r in rows} == {pool.id}

    ar = db_session.get(AuditReport, audit.id)
    ar.scope_contracts = ["Vault"]
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    rows = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).all()
    assert {r.contract_id for r in rows} == {vault.id}


def test_upsert_skipped_audit_wipes_rows(db_session, seed_protocol):
    """Stale coverage must not outlive extraction."""
    from db.models import AuditContractCoverage, AuditReport
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")
    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).count() == 1

    ar = db_session.get(AuditReport, audit.id)
    ar.scope_extraction_status = "skipped"
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).count() == 0


def test_upsert_coverage_for_protocol_batches(db_session, seed_protocol):
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_protocol

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    _add_contract(db_session, protocol_id, address="0x" + "b" * 40, name="Vault")
    _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")
    _add_audit(db_session, protocol_id, scope=["Vault"], date="2024-07-01")
    _add_audit(db_session, protocol_id, scope=["Pool", "Vault"], date="2024-08-01")

    inserted = upsert_coverage_for_protocol(db_session, protocol_id)
    db_session.commit()
    assert inserted == 4  # 1 + 1 + 2
    assert db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).count() == 4


def test_upsert_on_audit_with_no_matches_inserts_nothing(db_session, seed_protocol):
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    audit = _add_audit(db_session, protocol_id, scope=["NoSuchContract"], date="2024-06-01")
    assert upsert_coverage_for_audit(db_session, audit.id) == 0
    db_session.commit()
    assert db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).count() == 0


def test_extract_reviewed_commits_pulls_git_shas():
    from services.audits.source_equivalence import extract_reviewed_commits

    text = "Initial Commit Hash: 3b6b81b a643d24f2 7fc5100\nThe audit reviewed src/LiquidityPool.sol at commit abc1234."
    got = extract_reviewed_commits(text)
    assert got == ["3b6b81b", "a643d24f2", "7fc5100", "abc1234"]


def test_extract_reviewed_commits_filters_all_digit_and_palette_tokens():
    from services.audits.source_equivalence import extract_reviewed_commits

    # All-digit tokens (block numbers, issue ids) and repeated-char tokens are rejected.
    text = "issue 1234567 placeholder 0000000 real commit deadbeefcafe01"
    assert extract_reviewed_commits(text) == ["deadbeefcafe01"]


def test_extract_reviewed_commits_empty_input_safe():
    from services.audits.source_equivalence import extract_reviewed_commits

    assert extract_reviewed_commits("") == []
    assert extract_reviewed_commits(None) == []  # pyright: ignore[reportArgumentType]


def test_source_equivalence_proves_coverage_when_hashes_match(db_session, seed_protocol, monkeypatch):
    """A sha match upgrades to reviewed_commit/high regardless of temporal fit."""
    import hashlib

    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol

    # Outside all windows: temporal matching alone gives at most direct/medium.
    impl = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2099-01-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    content = "contract MyPool {}"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    def fake_etherscan(address, **_kw):
        return source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="MyPool",
                compiler_version="0.8.27",
                files={"src/MyPool.sol": content_hash},
            ),
            status="ok",
            detail="",
        )

    def fake_github(repo, commit, path, *, token=None):
        if path == "src/MyPool.sol":
            return source_equivalence.GithubHashResult(sha256=content_hash, status="ok", detail="")
        return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="not found")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", fake_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    n = upsert_coverage_for_audit(db_session, audit.id, verify_source_equivalence=True)
    db_session.commit()
    assert n == 1

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.contract_id == impl.id
    assert row.match_type == "reviewed_commit"
    assert row.match_confidence == "high"
    assert row.equivalence_status == "proven"


def test_source_equivalence_leaves_temporal_match_when_hashes_differ(db_session, seed_protocol, monkeypatch):
    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    def fake_etherscan(address, **_kw):
        return source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="MyPool", compiler_version="0.8", files={"src/MyPool.sol": "aaa"}
            ),
            status="ok",
            detail="",
        )

    def fake_github(repo, commit, path, *, token=None):
        return source_equivalence.GithubHashResult(sha256="bbb", status="ok", detail="")  # different sha

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", fake_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    upsert_coverage_for_audit(db_session, audit.id, verify_source_equivalence=True)
    db_session.commit()
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "hash_mismatch"


def test_source_equivalence_prefers_db_source_files(db_session, seed_protocol, monkeypatch):
    """Saves an HTTP call and works when rate-limited."""
    import hashlib
    import uuid as _uuid

    from db.models import AuditContractCoverage, Job, JobStage, JobStatus, SourceFile
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    impl = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"

    job = Job(id=_uuid.uuid4(), status=JobStatus.completed, stage=JobStage.done)
    db_session.add(job)
    db_session.flush()
    impl.job_id = job.id

    content = "contract MyPool {}"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    db_session.add(SourceFile(job_id=job.id, path="src/MyPool.sol", content=content))
    db_session.commit()

    etherscan_calls = {"count": 0}

    def boom_etherscan(address, **_kw):
        etherscan_calls["count"] += 1
        raise AssertionError("Etherscan should not be called when DB source is available")

    def fake_github(repo, commit, path, *, token=None):
        if path == "src/MyPool.sol":
            return source_equivalence.GithubHashResult(sha256=content_hash, status="ok", detail="")
        return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="not found")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    upsert_coverage_for_audit(db_session, audit.id, verify_source_equivalence=True)
    db_session.commit()

    assert etherscan_calls["count"] == 0, "DB path must short-circuit Etherscan"
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "reviewed_commit"
    assert row.match_confidence == "high"

    # Detach so contract teardown doesn't cascade-delete a job other tests may use.
    db_session.query(SourceFile).filter_by(job_id=job.id).delete()
    impl.job_id = None
    db_session.commit()
    db_session.query(Job).filter_by(id=job.id).delete()
    db_session.commit()


def test_source_equivalence_falls_back_to_etherscan_when_no_db_source(db_session, seed_protocol, monkeypatch):
    import hashlib

    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    content = "contract MyPool {}"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    etherscan_calls = {"count": 0}

    def fake_etherscan(address, **_kw):
        etherscan_calls["count"] += 1
        return source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="MyPool",
                compiler_version="0.8",
                files={"src/MyPool.sol": content_hash},
            ),
            status="ok",
            detail="",
        )

    def fake_github(repo, commit, path, *, token=None):
        if path == "src/MyPool.sol":
            return source_equivalence.GithubHashResult(sha256=content_hash, status="ok", detail="")
        return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="not found")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", fake_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    upsert_coverage_for_audit(db_session, audit.id, verify_source_equivalence=True)
    db_session.commit()

    assert etherscan_calls["count"] == 1, "Etherscan must be the fallback when DB is empty"
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "reviewed_commit"


def test_source_equivalence_skipped_when_audit_missing_commits(db_session, seed_protocol, monkeypatch):
    """A config error can't pound GitHub."""
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    db_session.commit()

    called = {"etherscan": 0, "github": 0}

    def boom_etherscan(address, **_kw):
        called["etherscan"] += 1
        return None

    def boom_github(*args, **kwargs):
        called["github"] += 1
        return None

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", boom_github)

    upsert_coverage_for_audit(db_session, audit.id, verify_source_equivalence=True)
    db_session.commit()
    assert called == {"etherscan": 0, "github": 0}


def test_verify_source_equivalence_off_by_default(db_session, seed_protocol, monkeypatch):
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    called = {"etherscan": 0, "github": 0}

    def boom_etherscan(address, **_kw):
        called["etherscan"] += 1
        return None

    def boom_github(*args, **kwargs):
        called["github"] += 1
        return None

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", boom_github)

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert called == {"etherscan": 0, "github": 0}


def test_deferred_path_stamps_pending_when_audit_is_verifiable(db_session, seed_protocol, monkeypatch):
    """CoverageVerifyWorker drains 'pending'; no HTTP here."""
    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    called = {"etherscan": 0, "github": 0}

    def boom_etherscan(address, **_kw):
        called["etherscan"] += 1
        raise AssertionError("etherscan must not be called on the deferred path")

    def boom_github(*args, **kwargs):
        called["github"] += 1
        raise AssertionError("github must not be called on the deferred path")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", boom_github)

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "pending"
    assert row.equivalence_checked_at is None
    assert called == {"etherscan": 0, "github": 0}


def test_deferred_path_stamps_no_reviewed_commit_when_audit_lacks_commits(db_session, seed_protocol):
    """Terminal, so the verify worker stops polling."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "no_reviewed_commit"


def test_deferred_path_stamps_no_source_repo_when_repo_missing(db_session, seed_protocol):
    """Terminal too: nowhere to fetch from."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "no_source_repo"


def test_deferred_path_for_contract_stamps_pending(db_session, seed_protocol, monkeypatch):
    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_contract

    protocol_id, _ = seed_protocol
    contract = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: (_ for _ in ()).throw(AssertionError("must not call etherscan")),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not call github")),
    )

    n = upsert_coverage_for_contract(db_session, contract.id)
    db_session.commit()
    assert n == 1

    row = db_session.query(AuditContractCoverage).filter_by(contract_id=contract.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "pending"


def test_verify_one_coverage_row_proves_when_hashes_match(db_session, seed_protocol, monkeypatch):
    import hashlib

    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit, verify_one_coverage_row

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    audit.classified_commits = [{"sha": "abc1234", "label": "reviewed", "context": ""}]
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.equivalence_status == "pending"

    content = "contract MyPool {}"
    h = hashlib.sha256(content.encode()).hexdigest()

    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="MyPool",
                compiler_version="0.8",
                files={"src/MyPool.sol": h},
            ),
            status="ok",
            detail="",
        ),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda _repo, _commit, path, token=None: source_equivalence.GithubHashResult(
            sha256=h if path == "src/MyPool.sol" else None,
            status="ok" if path == "src/MyPool.sol" else "http_404",
            detail="",
        ),
    )

    status = verify_one_coverage_row(db_session, row.id)
    db_session.commit()
    assert status == "proven"

    db_session.expire_all()
    row = db_session.get(AuditContractCoverage, row.id)
    assert row.equivalence_status == "proven"
    assert row.match_type == "reviewed_commit"
    assert row.match_confidence == "high"
    assert row.proof_kind == "clean"
    assert row.matched_commit_sha == "abc1234"
    assert row.equivalence_checked_at is not None


def test_verify_one_coverage_row_writes_hash_mismatch_when_hashes_differ(db_session, seed_protocol, monkeypatch):
    """Failed proofs annotate but never delete."""
    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit, verify_one_coverage_row

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.equivalence_status == "pending"

    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="MyPool",
                compiler_version="0.8",
                files={"src/MyPool.sol": "aaa"},
            ),
            status="ok",
            detail="",
        ),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda *_a, **_k: source_equivalence.GithubHashResult(sha256="bbb", status="ok", detail=""),
    )

    status = verify_one_coverage_row(db_session, row.id)
    db_session.commit()
    assert status == "hash_mismatch"

    db_session.expire_all()
    row = db_session.get(AuditContractCoverage, row.id)
    assert row.match_type == "direct"
    assert row.equivalence_status == "hash_mismatch"
    assert row.proof_kind is None
    assert row.matched_commit_sha is None


def test_verify_one_coverage_row_returns_none_when_row_vanished(db_session, seed_protocol):
    """A coverage rebuild can race the claim."""
    from services.audits.coverage import verify_one_coverage_row

    status = verify_one_coverage_row(db_session, 999_999_999)
    assert status is None


def test_verify_one_coverage_row_etherscan_unverified(db_session, seed_protocol, monkeypatch):
    """Permanent, not retried, still visible to the UI."""
    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit, verify_one_coverage_row

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()

    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: source_equivalence.EtherscanFetch(
            source=None,
            status="unverified",
            detail="no verified source for 0xaaaa…",
        ),
    )

    status = verify_one_coverage_row(db_session, row.id)
    db_session.commit()
    assert status == "etherscan_unverified"


def test_source_equivalence_uses_referenced_repos_when_source_repo_missing(
    db_session,
    seed_protocol,
    monkeypatch,
):
    import hashlib

    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "7" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = None
    audit.referenced_repos = ["etherfi-protocol/smart-contracts"]
    db_session.commit()

    content = "contract MyPool {}"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    fetched_repos: list[str] = []

    def fake_etherscan(address, **_kw):
        return source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="MyPool",
                compiler_version="0.8.27",
                files={"src/MyPool.sol": content_hash},
            ),
            status="ok",
            detail="",
        )

    def fake_github(repo, commit, path, *, token=None):
        fetched_repos.append(repo)
        if path == "src/MyPool.sol":
            return source_equivalence.GithubHashResult(sha256=content_hash, status="ok", detail="")
        return source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="not found")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", fake_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    upsert_coverage_for_audit(db_session, audit.id, verify_source_equivalence=True)
    db_session.commit()

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "reviewed_commit"
    assert row.equivalence_status == "proven"
    assert fetched_repos == ["etherfi-protocol/smart-contracts"]


def test_match_contracts_for_audit_is_not_n_plus_one(db_session, seed_protocol):
    """It was K+1 queries per candidate."""
    from sqlalchemy import event

    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol

    n_candidates = 8
    scope_name = "SharedImpl"
    for i in range(n_candidates):
        impl = _add_contract(
            db_session,
            protocol_id,
            address="0x" + f"{i:02x}" + "a" * 38,
            name=scope_name,
        )
        proxy = _add_contract(
            db_session,
            protocol_id,
            address="0x" + f"{i:02x}" + "1" * 38,
            name="Proxy",
            is_proxy=True,
            implementation=impl.address,
        )
        _add_upgrade_event(
            db_session,
            contract_id=proxy.id,
            proxy_address=proxy.address,
            new_impl=impl.address,
            block_number=100 + i,
            timestamp=_ts(2024, 1, 1),
        )

    audit = _add_audit(db_session, protocol_id, scope=[scope_name], date="2024-03-01")

    # Counting every SELECT is a conservative upper bound.
    queries: list[str] = []

    def before_cursor_execute(conn, cursor, statement, params, context, executemany):
        s = statement.strip().lower()
        if s.startswith("select"):
            queries.append(statement)

    event.listen(db_session.bind, "before_cursor_execute", before_cursor_execute)
    try:
        matches = match_contracts_for_audit(db_session, audit.id)
    finally:
        event.remove(db_session.bind, "before_cursor_execute", before_cursor_execute)

    assert len(matches) == n_candidates
    # Unbatched this is ~18 SELECTs for 8 candidates.
    assert len(queries) <= 5, f"expected ≤ 5 SELECTs for {n_candidates} candidates, got {len(queries)}:\n" + "\n".join(
        queries
    )


def test_match_contracts_for_audit_per_contract_dedupe_prefers_reviewed_commit(db_session, seed_protocol):
    """Keep the reviewed_commit candidate, not whichever spelling iterated first."""
    # Mixed types can't occur today; seeding the helper directly guards the ranking against a refactor.
    from services.audits.coverage import CoverageMatch, _row_score

    impl_era_high = CoverageMatch(
        audit_report_id=1,
        contract_id=1,
        protocol_id=1,
        matched_name="Pool",
        match_type="impl_era",
        match_confidence="high",
    )
    reviewed_high = CoverageMatch(
        audit_report_id=1,
        contract_id=1,
        protocol_id=1,
        matched_name="Pool",
        match_type="reviewed_commit",
        match_confidence="high",
    )
    direct_high = CoverageMatch(
        audit_report_id=1,
        contract_id=1,
        protocol_id=1,
        matched_name="Pool",
        match_type="direct",
        match_confidence="high",
    )
    assert _row_score(reviewed_high) > _row_score(impl_era_high)
    assert _row_score(reviewed_high) > _row_score(direct_high)
    assert _row_score(impl_era_high) > _row_score(direct_high)
    reviewed_low = CoverageMatch(
        audit_report_id=1,
        contract_id=1,
        protocol_id=1,
        matched_name="Pool",
        match_type="reviewed_commit",
        match_confidence="low",
    )
    assert _row_score(direct_high) > _row_score(reviewed_low)


# ---------------------------------------------------------------------------
# Bytecode anchor
# ---------------------------------------------------------------------------


def test_fetch_bytecode_keccak_returns_hex_hash(monkeypatch):
    from services.audits import coverage as cov

    addr = "0x" + "ab" * 20
    monkeypatch.setattr(
        cov,
        "get_code" if hasattr(cov, "get_code") else "_dummy",
        lambda *a, **k: "0x1234",
        raising=False,
    )
    # ``_fetch_bytecode_keccak`` imports get_code at call time.
    from services.clients import rpc

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({addr: "0x1234"}))

    got = cov._fetch_bytecode_keccak(addr, "ethereum")
    assert got is not None
    assert got.startswith("0x")
    assert len(got) == 66  # 0x + 64 hex chars


def _boom_get_code(_rpc_url, _addr):
    raise RuntimeError("RPC down")


@pytest.mark.parametrize(
    ("addr", "get_code"),
    [
        pytest.param("0x" + "cd" * 20, _stub_get_code({}), id="empty_code"),
        # Drift unknown, not drift detected.
        pytest.param("0x" + "ef" * 20, _boom_get_code, id="rpc_error"),
    ],
)
def test_fetch_bytecode_keccak_none(monkeypatch, addr, get_code):
    from services.audits import coverage as cov
    from services.clients import rpc

    monkeypatch.setattr(rpc, "get_code", get_code)
    assert cov._fetch_bytecode_keccak(addr, "ethereum") is None


def test_upsert_coverage_keccak_null_when_rpc_fails(db_session, seed_protocol, monkeypatch):
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit
    from services.clients import rpc

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "bb" * 20, name="Treasury")
    audit = _add_audit(db_session, protocol_id, date="2024-06-15", scope=["Treasury"])

    def always_fail(_rpc_url, _addr):
        raise RuntimeError("network down")

    monkeypatch.setattr(rpc, "get_code", always_fail)

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    cov_row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert cov_row.bytecode_keccak_at_match is None
    assert cov_row.verified_at is None


def test_scope_entry_address_produces_reviewed_address_match(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    addr = "0x" + "a" * 40
    c = _add_contract(db_session, protocol_id, address=addr, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")
    audit.scope_entries = [{"name": "Pool", "address": addr, "commit": "abc1234", "chain": "ethereum"}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    m = matches[0]
    assert m.match_type == "reviewed_address"
    assert m.match_confidence == "high"
    assert m.contract_id == c.id
    assert m.pinned_commit == "abc1234"


def test_scope_entry_address_can_match_global_shared_contract(db_session, seed_protocol):
    from db.models import Protocol
    from services.audits.coverage import match_contracts_for_audit

    audit_protocol_id, _ = seed_protocol
    owner = Protocol(name=f"shared-owner-{uuid.uuid4().hex[:8]}")
    db_session.add(owner)
    db_session.commit()

    addr = "0x" + "9" * 40
    shared = _add_contract(db_session, owner.id, address=addr, name="StETH")
    audit = _add_audit(db_session, audit_protocol_id, scope=[], date="2024-06-01")
    audit.scope_entries = [{"name": "StETH", "address": addr, "commit": "abc1234", "chain": "ethereum"}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == shared.id
    assert matches[0].protocol_id == audit_protocol_id
    assert matches[0].match_type == "reviewed_address"


def test_scope_entry_proxy_address_resolves_to_impl(db_session, seed_protocol):
    """The db trigger rejects the proxy, so it is resolved before insert."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy_addr = "0x" + "b" * 40
    impl_addr = "0x" + "c" * 40
    _add_contract(
        db_session,
        protocol_id,
        address=proxy_addr,
        name="WeETHProxy",
        is_proxy=True,
        implementation=impl_addr,
    )
    impl = _add_contract(db_session, protocol_id, address=impl_addr, name="WeETH")
    audit = _add_audit(db_session, protocol_id, scope=["WeETH"], date="2024-06-01")
    audit.scope_entries = [{"name": "WeETH", "address": proxy_addr, "commit": None, "chain": None}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == impl.id  # impl, not proxy
    assert matches[0].match_type == "reviewed_address"


def test_scope_entry_proxy_address_uses_impl_active_at_audit_date(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy_addr = "0x" + "d" * 40
    impl_a = _add_contract(db_session, protocol_id, address="0x" + "e" * 40, name="ImplA")
    impl_b = _add_contract(db_session, protocol_id, address="0x" + "f" * 40, name="ImplB")
    proxy = _add_contract(
        db_session,
        protocol_id,
        address=proxy_addr,
        name="Proxy",
        is_proxy=True,
        implementation=impl_b.address,
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_a.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        old_impl=impl_a.address,
        new_impl=impl_b.address,
        block_number=200,
        timestamp=_ts(2024, 7, 1),
    )
    audit = _add_audit(db_session, protocol_id, scope=[], date="2024-03-15")
    audit.scope_entries = [{"name": "Pool", "address": proxy_addr, "commit": None, "chain": "ethereum"}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == impl_a.id
    assert matches[0].match_type == "reviewed_address"


def test_scope_entry_suppresses_duplicate_name_match(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    addr = "0x" + "d" * 40
    _add_contract(db_session, protocol_id, address=addr, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")
    audit.scope_entries = [{"name": "Pool", "address": addr, "commit": None, "chain": None}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].match_type == "reviewed_address"


def test_scope_entry_match_survives_unmatched_leftover_scope_names(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    addr = "0x" + "1" * 40
    c = _add_contract(db_session, protocol_id, address=addr, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool", "MadeUpAlias"], date="2024-06-01")
    audit.scope_entries = [{"name": "Pool", "address": addr, "commit": None, "chain": None}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == c.id
    assert matches[0].match_type == "reviewed_address"


def test_scope_entry_address_honors_chain(db_session, seed_protocol):
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    addr = "0x" + "2" * 40
    _add_contract(db_session, protocol_id, address=addr, name="PoolEth", chain="ethereum")
    arb = _add_contract(db_session, protocol_id, address=addr, name="PoolArb", chain="arbitrum")
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01")
    audit.scope_entries = [{"name": "Pool", "address": addr, "commit": None, "chain": "arbitrum"}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == arb.id
    assert matches[0].match_type == "reviewed_address"


def test_match_audits_for_contract_finds_address_anchored(db_session, seed_protocol):
    from services.audits.coverage import match_audits_for_contract

    protocol_id, _ = seed_protocol
    addr = "0x" + "e" * 40
    c = _add_contract(db_session, protocol_id, address=addr, name="SomeContract")
    audit = _add_audit(db_session, protocol_id, scope=[], date="2024-06-01")
    audit.scope_entries = [{"name": "OtherNameInAudit", "address": addr, "commit": "cafebab", "chain": None}]
    db_session.commit()

    matches = match_audits_for_contract(db_session, c.id)
    assert len(matches) == 1
    m = matches[0]
    assert m.match_type == "reviewed_address"
    assert m.matched_name == "OtherNameInAudit"
    assert m.pinned_commit == "cafebab"


def test_match_audits_for_contract_proxy_scope_entry_uses_historical_impl(db_session, seed_protocol):
    """An upgrade must not rebind a historical proxy-address audit to the current impl."""
    from services.audits.coverage import match_audits_for_contract

    protocol_id, _ = seed_protocol
    proxy_addr = "0x" + "3" * 40
    impl_a = _add_contract(db_session, protocol_id, address="0x" + "4" * 40, name="ImplA")
    impl_b = _add_contract(db_session, protocol_id, address="0x" + "5" * 40, name="ImplB")
    proxy = _add_contract(
        db_session,
        protocol_id,
        address=proxy_addr,
        name="Proxy",
        is_proxy=True,
        implementation=impl_b.address,
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        new_impl=impl_a.address,
        block_number=100,
        timestamp=_ts(2024, 1, 1),
    )
    _add_upgrade_event(
        db_session,
        contract_id=proxy.id,
        proxy_address=proxy.address,
        old_impl=impl_a.address,
        new_impl=impl_b.address,
        block_number=200,
        timestamp=_ts(2024, 7, 1),
    )
    audit = _add_audit(db_session, protocol_id, scope=[], date="2024-03-15")
    audit.scope_entries = [{"name": "Pool", "address": proxy_addr, "commit": None, "chain": "ethereum"}]
    db_session.commit()

    old_matches = match_audits_for_contract(db_session, impl_a.id)
    new_matches = match_audits_for_contract(db_session, impl_b.id)
    assert len(old_matches) == 1
    assert old_matches[0].audit_report_id == audit.id
    assert old_matches[0].match_type == "reviewed_address"
    assert new_matches == []


def test_match_audits_for_contract_address_anchor_honors_chain(db_session, seed_protocol):
    from services.audits.coverage import match_audits_for_contract

    protocol_id, _ = seed_protocol
    addr = "0x" + "6" * 40
    eth = _add_contract(db_session, protocol_id, address=addr, name="Pool", chain="ethereum")
    arb = _add_contract(db_session, protocol_id, address=addr, name="Pool", chain="arbitrum")
    audit = _add_audit(db_session, protocol_id, scope=[], date="2024-06-01")
    audit.scope_entries = [{"name": "Pool", "address": addr, "commit": None, "chain": "arbitrum"}]
    db_session.commit()

    assert match_audits_for_contract(db_session, eth.id) == []
    matches = match_audits_for_contract(db_session, arb.id)
    assert len(matches) == 1
    assert matches[0].audit_report_id == audit.id
    assert matches[0].match_type == "reviewed_address"


class TestComputeProofKind:
    def _call(self, matched: list[str], classified: list[dict] | None):
        from services.audits.coverage import _compute_proof_kind

        return _compute_proof_kind({m.lower() for m in matched}, classified)

    _REVIEWED = {"sha": "abc1234", "label": "reviewed", "context": "review"}
    _FIX = {"sha": "def5678", "label": "fix", "context": "fix L-01"}

    @pytest.mark.parametrize(
        ("matched", "classified", "expected"),
        [
            pytest.param(["abc1234"], None, "unclassified", id="unclassified_none"),
            pytest.param(["abc1234"], [], "unclassified", id="unclassified_empty"),
            pytest.param(
                ["abc1234"],
                [{"sha": "abc1234", "label": "reviewed", "context": "audited at abc1234"}],
                "clean",
                id="clean_reviewed_no_fix_commits",
            ),
            pytest.param(["abc1234", "def5678"], [_REVIEWED, _FIX], "clean", id="clean_reviewed_and_fix"),
            pytest.param(["def5678"], [_REVIEWED, _FIX], "post_fix", id="post_fix_matched_only_fix"),
            # Deployed matches reviewed, fix commits exist, and deployed matches none: the findings are still live.
            pytest.param(
                ["abc1234"],
                [_REVIEWED, _FIX, {"sha": "ffa9876", "label": "fix", "context": "fix L-02"}],
                "pre_fix_unpatched",
                id="pre_fix_unpatched",
            ),
            # A 'cited' commit is historical context, so the match is coincidence.
            pytest.param(
                ["def5678"],
                [_REVIEWED, {"sha": "def5678", "label": "cited", "context": "baseline"}],
                "cited_only",
                id="cited_only_cited_label",
            ),
            pytest.param(
                ["def5678"],
                [_REVIEWED, {"sha": "def5678", "label": "unclear", "context": "?"}],
                "cited_only",
                id="cited_only_unclear_label",
            ),
            # Compared on the shared 7-char prefix.
            pytest.param(["abc1234" + "f" * 33], [_REVIEWED], "clean", id="prefix_match_abbreviated_shas"),
        ],
    )
    def test_proof_kind(self, matched, classified, expected):
        assert self._call(matched, classified) == expected
