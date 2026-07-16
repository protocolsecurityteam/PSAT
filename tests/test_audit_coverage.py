"""Unit tests for the audit-coverage matcher.

Focus: the *rules* — direct vs. impl_era matching, temporal window
selection, confidence downgrade on boundary misses, proxy resolution,
date parsing quirks (partial months, null dates). Integration with the
scope worker + live API is covered separately in
``test_audit_coverage_integration.py``.

Requires a real test Postgres (matcher queries UpgradeEvent / Contract /
AuditReport) — skipped cleanly on a dev box without TEST_DATABASE_URL.
Object storage is NOT required here; we never touch the scope artifact
bucket.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [
    requires_postgres,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def seed_protocol(db_session):
    """Fresh, unique-named Protocol + cascading cleanup."""
    from db.models import AuditContractCoverage, AuditReport, Contract, Protocol, UpgradeEvent

    name = f"cov-test-{uuid.uuid4().hex[:12]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id
    try:
        yield protocol_id, name
    finally:
        # Cascade order matters: coverage refs contract+audit, upgrade
        # refs contract, so delete children first.
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        contract_ids = [c.id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all()]
        if contract_ids:
            db_session.query(UpgradeEvent).filter(UpgradeEvent.contract_id.in_(contract_ids)).delete(
                synchronize_session=False
            )
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _add_contract(
    session,
    protocol_id: int,
    *,
    address: str,
    name: str,
    is_proxy: bool = False,
    implementation: str | None = None,
    chain: str = "ethereum",
):
    """Create a Contract row and return it (already committed)."""
    from db.models import Contract

    c = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        contract_name=name,
        is_proxy=is_proxy,
        implementation=implementation.lower() if implementation else None,
        chain=chain,
    )
    session.add(c)
    session.commit()
    return c


def _add_audit(
    session,
    protocol_id: int,
    *,
    auditor: str = "TestFirm",
    title: str = "Audit",
    date: str | None = None,
    scope: list[str] | None = None,
    status: str | None = "success",
):
    """Create an AuditReport with scope_contracts + status='success' by default."""
    from db.models import AuditReport

    ar = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor=auditor,
        title=title,
        date=date,
        confidence=0.9,
        scope_extraction_status=status,
        scope_contracts=scope or [],
    )
    session.add(ar)
    session.commit()
    return ar


def _add_upgrade_event(
    session,
    *,
    contract_id: int,
    proxy_address: str,
    new_impl: str,
    old_impl: str | None = None,
    block_number: int,
    timestamp: datetime | None = None,
    tx_hash: str | None = None,
):
    """Append an UpgradeEvent row on the proxy's contract_id."""
    from db.models import UpgradeEvent

    ev = UpgradeEvent(
        contract_id=contract_id,
        proxy_address=proxy_address.lower(),
        old_impl=old_impl.lower() if old_impl else None,
        new_impl=new_impl.lower(),
        block_number=block_number,
        timestamp=timestamp,
        tx_hash=tx_hash or f"0x{uuid.uuid4().hex[:64]}",
    )
    session.add(ev)
    session.commit()
    return ev


def _ts(year: int, month: int = 1, day: int = 1) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# 1. Date parser — the foundation every confidence call depends on
# ---------------------------------------------------------------------------


def test_audit_effective_ts_full_date():
    from services.audits.coverage import _audit_effective_ts

    got = _audit_effective_ts("2024-06-15")
    assert got is not None
    # End-of-day semantics so "impl replaced on 2024-06-15" matches.
    assert got.year == 2024 and got.month == 6 and got.day == 15
    assert got.hour == 23 and got.minute == 59


def test_audit_effective_ts_month_placeholder():
    from services.audits.coverage import _audit_effective_ts

    # Both the scope-extraction "YYYY-MM-00" placeholder and "YYYY-MM"
    # resolve to end of month.
    a = _audit_effective_ts("2024-06-00")
    b = _audit_effective_ts("2024-06")
    assert a == b
    assert a is not None and a.month == 6 and a.day == 30


def test_audit_effective_ts_year_only():
    from services.audits.coverage import _audit_effective_ts

    got = _audit_effective_ts("2023")
    assert got is not None
    assert got.month == 12 and got.day == 31


def test_audit_effective_ts_none_and_garbage():
    from services.audits.coverage import _audit_effective_ts

    assert _audit_effective_ts(None) is None
    assert _audit_effective_ts("") is None
    assert _audit_effective_ts("nonsense") is None


# ---------------------------------------------------------------------------
# 2. Direct match — no proxy history
# ---------------------------------------------------------------------------


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
    # Name in scope doesn't exist in this protocol's contracts.
    audit = _add_audit(db_session, protocol_id, scope=["UnrelatedThing"], date="2024-01-01")
    assert match_contracts_for_audit(db_session, audit.id) == []


def test_duplicate_scope_names_collapse_to_single_match(db_session, seed_protocol):
    """Extraction glitches sometimes ship the same contract twice under
    near-identical names (e.g. 'EtherFiNodesManager' + 'EtherFiNodeManager').
    Only one coverage row should emerge for the single Contract row.
    """
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    audit = _add_audit(db_session, protocol_id, scope=["Pool", "pool", "POOL"], date="2024-01-01")

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# 3. impl_era match — the proxy-aware path
# ---------------------------------------------------------------------------


def test_impl_era_match_inside_window_is_high(db_session, seed_protocol):
    """Proxy was X (block 100) → Y (block 200). Audit on X dated between
    those blocks lands in X's window → high confidence, range set."""
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
    """An audit dated AFTER the latest upgrade covers the still-current
    impl — covered_to_block is NULL because the impl hasn't been replaced."""
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
    """Audit published 10 days AFTER the impl was replaced should still
    attach to that impl at 'medium' — typical 'audit finalized after
    remediation upgrade shipped' pattern."""
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

    # 10 days after replacement — within the 14-day grace.
    audit = _add_audit(db_session, protocol_id, scope=["MorphoBlue"], date="2024-06-11")
    [m] = match_contracts_for_audit(db_session, audit.id)
    assert m.match_confidence == "medium"
    assert m.contract_id == impl_x.id


def test_impl_era_far_outside_window_is_low(db_session, seed_protocol):
    """Audit dated years after the impl was replaced — name matches but
    timing is clearly off. Still emits a row (don't silently drop) but
    marks it low so a UI can hide or badge it."""
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
    """Proxy: A (block 100) → B (200) → A (300) → C (400). Audit dated
    in the [300,400) window matches A again with THAT window, not the
    earlier [100,200) one."""
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    proxy = _add_contract(db_session, protocol_id, address="0x" + "1" * 40, name="Proxy", is_proxy=True)
    impl_a = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="ImplA")

    # A active [100, 200), then B [200, 300), then A again [300, 400), then C.
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
    # Audit lands in the SECOND active window of A: [300, 400).
    assert m.covered_from_block == 300
    assert m.covered_to_block == 400
    assert m.match_confidence == "high"


# ---------------------------------------------------------------------------
# 4. Proxy that shares a name with its impl
# ---------------------------------------------------------------------------


def test_proxy_and_impl_share_name_only_impl_gets_row(db_session, seed_protocol):
    """Proxy and impl share a scope name. Under is_proxy-aware matching,
    only the impl gets a coverage row — the proxy's direct match on its
    own name is dropped regardless of the spelling. The proxy view still
    shows coverage through ``audit_timeline``'s union over historical
    impls.
    """
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


# ---------------------------------------------------------------------------
# 4b. Proxy-aware matching — generic proxy names shouldn't create coverage
# ---------------------------------------------------------------------------


def test_proxy_direct_match_on_own_name_skipped(db_session, seed_protocol):
    """A Contract whose ``is_proxy`` is True shouldn't get a direct
    coverage row on its own scope-name match. Scope like "UUPSProxy"
    matches generic proxy Contract rows verbatim, and attributing audit
    coverage on that alone is the false-positive class we want gone.
    Coverage for the proxy, when legitimate, flows via the impl's own
    Contract row + audit_timeline's union, not via a direct match on the
    proxy name.
    """
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    # Proxy whose DB name is a generic OZ pattern. Impl name is NOT in
    # the audit scope — mirrors the KING Distributor / CumulativeMerkleDrop
    # shape where the audit reviewed core etherfi contracts but not the
    # distributor's impl.
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
    # Proxy row must not emit a coverage row — its ``is_proxy`` tells us
    # the meaningful name is the impl's, and the impl's name isn't in
    # scope here. Impl row's own name ("Distributor") also isn't in
    # scope, so no coverage anywhere. Before the fix this returned a
    # direct/high row for the proxy.
    assert matches == []


def test_proxy_direct_match_skipped_but_impl_still_matches(db_session, seed_protocol):
    """The etherfi-style case: proxy named generically, impl has the
    protocol-specific name the audit actually scopes. The impl gets a
    direct coverage row on its own name; the proxy still appears
    covered in audit_timeline through the impl_era union, but the
    matcher doesn't emit a redundant direct row on the proxy's generic
    name.
    """
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
    # Only the impl gets a coverage row; the proxy's generic-name match
    # is dropped in favor of the impl-sourced signal.
    assert set(by_id) == {impl.id}
    assert by_id[impl.id].match_type == "impl_era"
    assert by_id[impl.id].matched_name == "LiquidityPool"


def test_non_proxy_contract_named_proxy_still_matches_directly(db_session, seed_protocol):
    """Defensive: skipping only triggers on ``is_proxy=True``. A
    protocol could have a Contract legitimately named "Proxy" or
    "UUPSProxy" that isn't actually a delegator (``is_proxy=False`` per
    the static analyzer). Those must still get a direct match — the
    rule is about the behavior flag, not the string.
    """
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    # Named "UUPSProxy" but classifier said is_proxy=False — treat as a
    # regular contract.
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
    """Regression for the pre-architectural-filter shape: a proxy that
    has impl windows (because another proxy was upgraded to point at it
    — a proxy-behind-proxy chain) could previously slip through the
    ``else: if c.is_proxy: continue`` guard, since that guard only
    applies in the no-windows branch. The architectural filter at the
    candidate query must exclude is_proxy=True rows regardless of
    window status.
    """
    from db.models import Contract
    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol
    # Inner proxy (target of the audit scope name) that has is_proxy=True.
    inner_proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "a" * 40,
        name="UUPSProxy",
        is_proxy=True,
        implementation="0x" + "b" * 40,
    )
    # Outer proxy that was once upgraded to point at the inner_proxy —
    # which gives the inner_proxy a "window" despite being a proxy itself.
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
    # Neither proxy should appear. Pre-fix: inner_proxy would have slipped
    # through as an impl_era match because it has a window.
    by_id = {m.contract_id: m for m in matches}
    assert inner_proxy.id not in by_id, (
        "Proxy with windows must be excluded from coverage candidates even "
        "though the impl_era path would have matched it"
    )
    assert outer_proxy.id not in by_id
    # Sanity: confirm is_proxy really is True on the DB side.
    assert db_session.get(Contract, inner_proxy.id).is_proxy is True


def test_match_audits_for_contract_skips_proxies_own_name(db_session, seed_protocol):
    """Symmetric: querying by proxy_id must not surface audits that only
    matched on the proxy's own generic name. The audit_timeline endpoint
    will still show coverage for the proxy through impl-era rows on
    historical impls — that path is separate.
    """
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


# ---------------------------------------------------------------------------
# 5. Symmetry — match_audits_for_contract returns the same thing
# ---------------------------------------------------------------------------


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
    # A failed/skipped/pending extraction shouldn't contribute coverage.
    _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01", status="skipped")
    _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-06-01", status="failed")
    _add_audit(db_session, protocol_id, scope=None, date="2024-06-01", status=None)

    assert match_audits_for_contract(db_session, contract.id) == []


# ---------------------------------------------------------------------------
# 6. Upsert helpers — idempotency + scope re-extraction invalidation
# ---------------------------------------------------------------------------


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
    """Simulates a re-extraction where scope_contracts changes from
    ['Pool'] to ['Vault']. The prior Pool coverage row must disappear;
    a fresh Vault row must appear."""
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

    # Re-extraction result: scope now says Vault instead of Pool.
    ar = db_session.get(AuditReport, audit.id)
    ar.scope_contracts = ["Vault"]
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    rows = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).all()
    assert {r.contract_id for r in rows} == {vault.id}


def test_upsert_skipped_audit_wipes_rows(db_session, seed_protocol):
    """If an audit transitions from success → skipped (e.g. a
    reextract_scope that later failed), coverage rows for it must
    clear. Otherwise stale data outlives the extraction."""
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


# ---------------------------------------------------------------------------
# 7. Reviewed-commit extraction — regex over PDF text
# ---------------------------------------------------------------------------


def test_extract_reviewed_commits_pulls_git_shas():
    from services.audits.source_equivalence import extract_reviewed_commits

    text = "Initial Commit Hash: 3b6b81b a643d24f2 7fc5100\nThe audit reviewed src/LiquidityPool.sol at commit abc1234."
    got = extract_reviewed_commits(text)
    # All four plus the 7-char abc1234 — deduped, lowercase, order preserved.
    assert got == ["3b6b81b", "a643d24f2", "7fc5100", "abc1234"]


def test_extract_reviewed_commits_filters_all_digit_and_palette_tokens():
    from services.audits.source_equivalence import extract_reviewed_commits

    # 7 digits with no hex-letters → rejected (block number / issue ID).
    # Repeated-char token (0x000000..0) → rejected.
    # Real commit → kept.
    text = "issue 1234567 placeholder 0000000 real commit deadbeefcafe01"
    assert extract_reviewed_commits(text) == ["deadbeefcafe01"]


def test_extract_reviewed_commits_empty_input_safe():
    from services.audits.source_equivalence import extract_reviewed_commits

    assert extract_reviewed_commits("") == []
    assert extract_reviewed_commits(None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 8. Source-equivalence matcher — synthetic GitHub / Etherscan stubs
# ---------------------------------------------------------------------------


def test_source_equivalence_proves_coverage_when_hashes_match(db_session, seed_protocol, monkeypatch):
    """When audit.reviewed_commits[0] has a src file whose sha matches the
    impl's Etherscan source, the upsert path upgrades the match to
    ``reviewed_commit`` / ``high`` — regardless of temporal fit.
    """
    import hashlib

    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol

    # Seed an impl + an audit whose date falls OUTSIDE all temporal windows.
    # If only temporal matching applied, we'd get 'direct'/'medium' at best.
    impl = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2099-01-01")
    # Manually set the source-equivalence inputs (would be populated by
    # scope extraction in production).
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    content = "contract MyPool {}"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    # Stub Etherscan: return a single source file whose sha matches.
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

    # Stub GitHub: same hash → equivalence proven.
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
    """Source hashes don't match → match stays at its original type/confidence.
    Proof failure must never DOWNGRADE a match the temporal matcher already
    emitted.
    """
    from db.models import AuditContractCoverage
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()

    # Stubs return mismatching hashes.
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
    # Original temporal match stands — 'direct' because no proxy history.
    assert row.match_type == "direct"
    # But equivalence_status reflects the mismatch.
    assert row.equivalence_status == "hash_mismatch"


def test_source_equivalence_prefers_db_source_files(db_session, seed_protocol, monkeypatch):
    """When a Contract's Job has SourceFile rows, source-equivalence reads
    them instead of hitting Etherscan. Saves one HTTP call per impl and
    keeps the matcher usable when Etherscan is rate-limited.
    """
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

    # Attach a Job + SourceFile so fetch_db_source_files finds content
    # without needing Etherscan.
    job = Job(id=_uuid.uuid4(), status=JobStatus.completed, stage=JobStage.done)
    db_session.add(job)
    db_session.flush()
    impl.job_id = job.id

    content = "contract MyPool {}"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    db_session.add(SourceFile(job_id=job.id, path="src/MyPool.sol", content=content))
    db_session.commit()

    # Etherscan stub blows up loudly — if the DB path fails, we'll know.
    etherscan_calls = {"count": 0}

    def boom_etherscan(address, **_kw):
        etherscan_calls["count"] += 1
        raise AssertionError("Etherscan should not be called when DB source is available")

    # GitHub stub returns the matching hash.
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

    # Cleanup — the autouse teardown doesn't know about the Job we created.
    db_session.query(SourceFile).filter_by(job_id=job.id).delete()
    # Detach the job_id from the contract so the contract teardown doesn't
    # cascade-delete a job that other tests may depend on (Job has no FK
    # back here but keeping clean is nice).
    impl.job_id = None
    db_session.commit()
    db_session.query(Job).filter_by(id=job.id).delete()
    db_session.commit()


def test_source_equivalence_falls_back_to_etherscan_when_no_db_source(db_session, seed_protocol, monkeypatch):
    """Contract has no Job → no SourceFile rows → DB path returns None →
    matcher falls through to Etherscan. Proves the fallback is wired,
    not just a happy-path optimization.
    """
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
    """No reviewed_commits populated → equivalence short-circuits without
    any HTTP calls. Protects us from a config error pounding GitHub."""
    from services.audits import source_equivalence
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    # reviewed_commits is None (not set).
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
    """verify_source_equivalence=False (the default) must not reach GitHub /
    Etherscan at all, even when reviewed_commits is populated."""
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


# ---------------------------------------------------------------------------
# 8.1 Deferred verification — pending stamping for the verify worker
# ---------------------------------------------------------------------------


def test_deferred_path_stamps_pending_when_audit_is_verifiable(db_session, seed_protocol, monkeypatch):
    """verify_source_equivalence=False on a verifiable audit must write
    ``equivalence_status='pending'`` so ``CoverageVerifyWorker`` can later
    drain it. No HTTP calls happen here.
    """
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
    # Heuristic match still emitted synchronously…
    assert row.match_type == "direct"
    # …with verification deferred.
    assert row.equivalence_status == "pending"
    assert row.equivalence_checked_at is None
    assert called == {"etherscan": 0, "github": 0}


def test_deferred_path_stamps_no_reviewed_commit_when_audit_lacks_commits(db_session, seed_protocol):
    """Audits without reviewed_commits can never be verified — write a
    terminal status immediately so the verify worker doesn't keep
    polling them."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    # No reviewed_commits, no source_repo.
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "no_reviewed_commit"


def test_deferred_path_stamps_no_source_repo_when_repo_missing(db_session, seed_protocol):
    """reviewed_commits without source_repo / referenced_repos is also a
    terminal — there's nowhere to fetch the file from."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="MyPool")
    audit = _add_audit(db_session, protocol_id, scope=["MyPool"], date="2024-06-01")
    audit.reviewed_commits = ["abc1234"]
    # source_repo + referenced_repos both missing.
    db_session.commit()

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert row.match_type == "direct"
    assert row.equivalence_status == "no_source_repo"


def test_deferred_path_for_contract_stamps_pending(db_session, seed_protocol, monkeypatch):
    """Symmetric: ``upsert_coverage_for_contract`` (called by
    CoverageWorker.process) on a verifiable audit must also write
    ``pending`` rather than blocking on inline HTTP."""
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


# ---------------------------------------------------------------------------
# 8.2 verify_one_coverage_row — the per-row entry point the verify worker uses
# ---------------------------------------------------------------------------


def test_verify_one_coverage_row_proves_when_hashes_match(db_session, seed_protocol, monkeypatch):
    """End-to-end one-row verify: pending row → proven, with match_type
    upgraded to ``reviewed_commit`` and the audit's classified_commits
    feeding ``proof_kind``."""
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

    # Land a pending row first.
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
    """Files exist on both sides, content differs → hash_mismatch.
    match_type stays at the heuristic 'direct' — failed proofs annotate
    but never delete."""
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
    # Heuristic match preserved on a non-proven verdict.
    assert row.match_type == "direct"
    assert row.equivalence_status == "hash_mismatch"
    # Non-proven rows must not carry stale proven-only fields.
    assert row.proof_kind is None
    assert row.matched_commit_sha is None


def test_verify_one_coverage_row_returns_none_when_row_vanished(db_session, seed_protocol):
    """If the row has been deleted between claim and verify (e.g. a
    coverage rebuild raced), the verify entry point must no-op cleanly."""
    from services.audits.coverage import verify_one_coverage_row

    # Deliberately use an id that won't exist.
    status = verify_one_coverage_row(db_session, 999_999_999)
    assert status is None


def test_verify_one_coverage_row_etherscan_unverified(db_session, seed_protocol, monkeypatch):
    """Etherscan returns the empty-source sentinel → permanent
    ``etherscan_unverified``. The verify worker won't retry a row in
    this state, but the row stays visible to the UI as "no verified
    source"."""
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
    """Coverage refresh must still verify rows when source_repo is NULL but
    referenced_repos contains the real code repo."""
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


# ---------------------------------------------------------------------------
# 9. Perf: N+1 query explosion in the matcher is avoided
# ---------------------------------------------------------------------------


def test_match_contracts_for_audit_is_not_n_plus_one(db_session, seed_protocol):
    """With N scope-name candidate Contracts × K proxies each, the old
    implementation fired (K+1) queries per candidate inside
    ``_compute_impl_windows_for_contract``. The batched path must keep the
    count bounded regardless of N, proving we don't scale queries with
    candidate count.
    """
    from sqlalchemy import event

    from services.audits.coverage import match_contracts_for_audit

    protocol_id, _ = seed_protocol

    # Seed a handful of impl candidates (all sharing the same scope name)
    # and a proxy history per impl. The more candidates, the more the
    # per-candidate helper would amplify the query count.
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

    # Count real SQL statements emitted during the call (filter out SAVEPOINT /
    # BEGIN / COMMIT noise). We only care about proxy-window lookups — but
    # counting all SELECTs is a conservative upper bound.
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
    # Without batching: ~1 audit lookup + 1 candidate query + N*(1+1) window
    # queries = N=8 -> ~18+ SELECTs. With batching we expect ≤ 5.
    assert len(queries) <= 5, f"expected ≤ 5 SELECTs for {n_candidates} candidates, got {len(queries)}:\n" + "\n".join(
        queries
    )


# ---------------------------------------------------------------------------
# 8. /api/contracts/{id}/audit_timeline dedupe — match_type-aware ranking
# ---------------------------------------------------------------------------


def test_audit_timeline_dedupe_prefers_reviewed_commit_over_impl_era(db_session, seed_protocol):
    """``best_by_audit`` in api.contract_audit_timeline must prefer a
    ``reviewed_commit`` row over an ``impl_era`` row when the audit
    matched both at the same confidence. Source-equivalence is
    cryptographic proof; impl_era is a temporal heuristic — the proof
    should always win.

    Regression: pre-fix, the dedupe ranked only on ``match_confidence``,
    so two rows tied at 'high' fell through to first-iterated-wins (no
    SQL ORDER BY). On EtherFi's LiquidityPool that flipped audits like
    Certora "Priority Queue" off the current impl in the UI even though
    the DB had a reviewed_commit row pinning it there — top banner said
    "audited", per-impl chip said "no audit coverage" for the current
    impl.
    """
    from fastapi.testclient import TestClient

    import api as api_module
    from db.models import AuditContractCoverage, UpgradeEvent
    from tests.conftest import SessionFactory

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "1" * 40,
        name="Proxy",
        is_proxy=True,
        implementation="0x" + "a" * 40,
    )
    impl_a = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    impl_b = _add_contract(db_session, protocol_id, address="0x" + "b" * 40, name="Pool")
    # Two upgrade events: impl_b first, then upgraded to impl_a (current).
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=None,
            new_impl=impl_b.address,
            block_number=100,
            timestamp=_ts(2024, 1, 1),
            tx_hash="0x" + "1" * 64,
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=impl_b.address,
            new_impl=impl_a.address,
            block_number=200,
            timestamp=_ts(2024, 6, 1),
            tx_hash="0x" + "2" * 64,
        )
    )
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-08-01")

    # Two coverage rows at SAME confidence. With the buggy ranker, whichever
    # row hits the cov_rows iteration first wins. We insert impl_b's
    # impl_era row FIRST so the bug pins the chip to impl_b — the fix must
    # still pick impl_a's reviewed_commit despite iteration order.
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_b.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="impl_era",
            match_confidence="high",
            covered_from_block=100,
            covered_to_block=200,
        )
    )
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_a.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="reviewed_commit",
            match_confidence="high",
        )
    )
    db_session.commit()

    # Hit the API on the proxy — it unions coverage from proxy + impls.
    from routers import deps as routers_deps

    SessionLocal_orig = routers_deps.SessionLocal
    routers_deps.SessionLocal = SessionFactory(db_session)
    try:
        client = TestClient(api_module.app)
        r = client.get(f"/api/contracts/{proxy.id}/audit_timeline")
    finally:
        routers_deps.SessionLocal = SessionLocal_orig

    assert r.status_code == 200, r.text
    body = r.json()
    rows_for_audit = [c for c in body["coverage"] if c["audit_id"] == audit.id]
    assert len(rows_for_audit) == 1, f"audit must dedupe to one row, got {rows_for_audit}"
    chosen = rows_for_audit[0]
    assert chosen["match_type"] == "reviewed_commit", (
        f"Source-equivalence proof must beat impl_era at equal confidence; got {chosen['match_type']!r}. "
        f"Full row: {chosen!r}"
    )
    assert chosen["impl_address"].lower() == impl_a.address.lower(), (
        f"Chip must point to current impl (reviewed_commit target), got {chosen['impl_address']!r}"
    )


def test_audit_timeline_dedupe_prefers_impl_era_over_direct(db_session, seed_protocol):
    """At equal confidence, ``impl_era`` (temporal window) beats
    ``direct`` (pure name match) — impl_era carries strictly more
    information. Defense-in-depth so the type-aware ranker remains
    consistent across all three match types.
    """
    from fastapi.testclient import TestClient

    import api as api_module
    from db.models import AuditContractCoverage, UpgradeEvent
    from tests.conftest import SessionFactory

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "3" * 40,
        name="Proxy2",
        is_proxy=True,
        implementation="0x" + "c" * 40,
    )
    impl_c = _add_contract(db_session, protocol_id, address="0x" + "c" * 40, name="Pool")
    impl_d = _add_contract(db_session, protocol_id, address="0x" + "d" * 40, name="Pool")
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=None,
            new_impl=impl_d.address,
            block_number=300,
            timestamp=_ts(2024, 1, 1),
            tx_hash="0x" + "3" * 64,
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=impl_d.address,
            new_impl=impl_c.address,
            block_number=400,
            timestamp=_ts(2024, 6, 1),
            tx_hash="0x" + "4" * 64,
        )
    )
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-04-01")

    # direct on current impl (no temporal info), impl_era on past impl
    # (window match). impl_era should win.
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_c.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="direct",
            match_confidence="high",
        )
    )
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_d.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="impl_era",
            match_confidence="high",
            covered_from_block=300,
            covered_to_block=400,
        )
    )
    db_session.commit()

    from routers import deps as routers_deps

    SessionLocal_orig = routers_deps.SessionLocal
    routers_deps.SessionLocal = SessionFactory(db_session)
    try:
        client = TestClient(api_module.app)
        r = client.get(f"/api/contracts/{proxy.id}/audit_timeline")
    finally:
        routers_deps.SessionLocal = SessionLocal_orig

    assert r.status_code == 200, r.text
    rows_for_audit = [c for c in r.json()["coverage"] if c["audit_id"] == audit.id]
    assert len(rows_for_audit) == 1
    assert rows_for_audit[0]["match_type"] == "impl_era"


def test_match_contracts_for_audit_per_contract_dedupe_prefers_reviewed_commit(db_session, seed_protocol):
    """Symmetric ranking inside the matcher: ``by_contract`` in
    match_contracts_for_audit must use the same (confidence, match_type)
    ranking. Same audit + same contract from two scope-name matches
    should keep the ``reviewed_commit`` candidate, not whichever
    spelling iterated first.
    """
    # NOTE: ``match_contracts_for_audit`` itself only emits one match
    # type per (audit, contract) — it picks impl_era when windows exist
    # and direct otherwise, never both. The (confidence, match_type)
    # rank applies when two scope-name spellings produce candidates of
    # different match types... which can't happen in current code (the
    # branch is per-contract, not per-name). But we still want the
    # ranker future-proofed against a refactor that could mix types.
    # This test seeds two CoverageMatch outputs directly via the dedup
    # helper to confirm the ranking semantics.
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
    # Reviewed_commit must outrank both.
    assert _row_score(reviewed_high) > _row_score(impl_era_high)
    assert _row_score(reviewed_high) > _row_score(direct_high)
    # impl_era beats direct.
    assert _row_score(impl_era_high) > _row_score(direct_high)
    # Confidence still dominates: reviewed_commit/low loses to direct/high.
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
# Bytecode anchor (Phase 2)
# ---------------------------------------------------------------------------


def _stub_get_code(code_map: dict[str, str]):
    """Return a ``get_code(rpc_url, address)`` stand-in served from a dict.

    Lets tests exercise ``_fetch_bytecode_keccak`` / ``_apply_bytecode_anchor``
    without an RPC. Keys are lowercased addresses; value is the code hex
    string the RPC would return (including ``'0x'`` for EOAs).
    """

    def fake_get_code(rpc_url, addr):
        return code_map.get((addr or "").lower(), "0x")

    return fake_get_code


def test_fetch_bytecode_keccak_returns_hex_hash(monkeypatch):
    """Runtime bytecode → keccak256 hex string with ``0x`` prefix."""
    from services.audits import coverage as cov

    addr = "0x" + "ab" * 20
    # Known input → known keccak. "0x1234" runtime bytes, keccak256 is
    # deterministic so a stable assert is possible.
    monkeypatch.setattr(
        cov,
        "get_code" if hasattr(cov, "get_code") else "_dummy",
        lambda *a, **k: "0x1234",
        raising=False,
    )
    # Patch through the import site (utils.rpc.get_code) since that's what
    # _fetch_bytecode_keccak imports at call time.
    from utils import rpc

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({addr: "0x1234"}))

    got = cov._fetch_bytecode_keccak(addr, "ethereum")
    assert got is not None
    assert got.startswith("0x")
    assert len(got) == 66  # 0x + 64 hex chars


def test_fetch_bytecode_keccak_none_on_empty_code(monkeypatch):
    """EOA or selfdestructed address returns ``None`` not a zero hash."""
    from services.audits import coverage as cov
    from utils import rpc

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({}))
    assert cov._fetch_bytecode_keccak("0x" + "cd" * 20, "ethereum") is None


def test_fetch_bytecode_keccak_none_on_rpc_error(monkeypatch):
    """RPC exception → NULL propagates (drift-unknown, not drift-detected)."""
    from services.audits import coverage as cov
    from utils import rpc

    def boom(_rpc_url, _addr):
        raise RuntimeError("RPC down")

    monkeypatch.setattr(rpc, "get_code", boom)
    assert cov._fetch_bytecode_keccak("0x" + "ef" * 20, "ethereum") is None


def test_upsert_coverage_stamps_bytecode_keccak(db_session, seed_protocol, monkeypatch):
    """End-to-end: after upsert, coverage rows carry ``bytecode_keccak_at_match``."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit
    from utils import rpc

    protocol_id, _ = seed_protocol
    pool_addr = "0x" + "aa" * 20
    _add_contract(db_session, protocol_id, address=pool_addr, name="Pool")
    audit = _add_audit(db_session, protocol_id, date="2024-06-15", scope=["Pool"])

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({pool_addr: "0xdeadbeef"}))

    rows_written = upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    assert rows_written == 1

    cov_row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    assert cov_row.bytecode_keccak_at_match is not None
    assert cov_row.bytecode_keccak_at_match.startswith("0x")
    assert len(cov_row.bytecode_keccak_at_match) == 66
    assert cov_row.verified_at is not None


def test_upsert_coverage_keccak_null_when_rpc_fails(db_session, seed_protocol, monkeypatch):
    """Row still writes, keccak/verified_at stay NULL — drift unknown."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit
    from utils import rpc

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


# ---------------------------------------------------------------------------
# Findings / live_findings filter (Phase 3a)
# ---------------------------------------------------------------------------


def test_findings_filter_excludes_fixed_status(db_session, api_client, seed_protocol, monkeypatch):
    """Timeline endpoint exposes non-'fixed' findings, hides 'fixed' ones."""
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    addr = "0x" + "cc" * 20
    contract = _add_contract(db_session, protocol_id, address=addr, name="Vault")
    audit = _add_audit(db_session, protocol_id, date="2024-06-15", scope=["Vault"])

    # Write a coverage row directly (bypass upsert to keep this test
    # focused on the findings filter rather than the whole match path).
    from db.models import AuditContractCoverage

    db_session.add(
        AuditContractCoverage(
            contract_id=contract.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Vault",
            match_type="direct",
            match_confidence="high",
        )
    )
    # Set findings on the audit row — must update via SQLAlchemy so the
    # JSONB serialization path runs.
    audit_row = db_session.query(AuditReport).filter_by(id=audit.id).one()
    audit_row.findings = [
        {"title": "Fixed issue", "severity": "medium", "status": "fixed", "contract_hint": "Vault"},
        {"title": "Acknowledged issue", "severity": "high", "status": "acknowledged", "contract_hint": "Vault"},
        {"title": "Still mitigating", "severity": "low", "status": "mitigated", "contract_hint": "Vault"},
    ]
    db_session.commit()

    from utils import rpc

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({addr: "0xbeef"}))

    resp = api_client.get(f"/api/contracts/{contract.id}/audit_timeline")
    assert resp.status_code == 200
    payload = resp.json()

    assert len(payload["coverage"]) == 1
    live = payload["coverage"][0]["live_findings"]
    # 'fixed' dropped, the other two survive.
    titles = {f["title"] for f in live}
    assert "Fixed issue" not in titles
    assert "Acknowledged issue" in titles
    assert "Still mitigating" in titles


# ---------------------------------------------------------------------------
# Phase F: address-anchored matching via scope_entries
# ---------------------------------------------------------------------------


def test_scope_entry_address_produces_reviewed_address_match(db_session, seed_protocol):
    """Audit with an address-pinned scope entry emits match_type='reviewed_address'
    at the Contract row sharing that address. No name matching needed."""
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
    """Address-pinned audits can target the one global Contract row for a shared dependency."""
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
    """Audit's scope table names the PROXY address; coverage row targets
    the impl contract_id (proxy rejected by db trigger, resolved before insert)."""
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
    # Audit lists the PROXY address (user-facing), not the impl.
    audit.scope_entries = [{"name": "WeETH", "address": proxy_addr, "commit": None, "chain": None}]
    db_session.commit()

    matches = match_contracts_for_audit(db_session, audit.id)
    assert len(matches) == 1
    assert matches[0].contract_id == impl.id  # impl, not proxy
    assert matches[0].match_type == "reviewed_address"


def test_scope_entry_proxy_address_uses_impl_active_at_audit_date(db_session, seed_protocol):
    """A proxy-address scope entry must resolve to the impl active when the
    audit happened, not the proxy's current implementation pointer."""
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
    """Audit has BOTH a scope_entry with address AND the name in
    scope_contracts[]. Matcher emits a single reviewed_address row,
    not a redundant direct/impl_era row on the same contract."""
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
    """Address-pinned matches must survive even when leftover scope names
    don't match any Contract rows."""
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
    """Same-address contracts on different chains must not collide."""
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
    """Dual-entry contract→audits matcher honors scope_entries by address."""
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
    # matched_name comes from the audit entry's name, not our contract_name
    assert m.matched_name == "OtherNameInAudit"
    assert m.pinned_commit == "cafebab"


def test_match_audits_for_contract_proxy_scope_entry_uses_historical_impl(db_session, seed_protocol):
    """Reverse lookup must not rebind a historical proxy-address audit to
    the proxy's current impl after an upgrade."""
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
    """Reverse address-anchored matching must respect chain as well as address."""
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


def test_pinned_commit_overrides_reviewed_commits_in_verification(monkeypatch):
    """specific_commit narrows verify_audit_covers_impl to exactly that SHA;
    other commits in reviewed_commits are not attempted."""
    from services.audits import source_equivalence

    fetched_commits = []

    def fake_github(repo, commit, path, *, token=None):
        fetched_commits.append(commit)
        return source_equivalence.GithubHashResult(sha256="matching", status="ok", detail="")

    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", fake_github)

    impl = source_equivalence.VerifiedSource(
        contract_name="Pool", compiler_version="v0.8", files={"src/Pool.sol": "matching"}
    )
    out = source_equivalence.verify_audit_covers_impl(
        reviewed_commits=["abc1234", "def5678", "fed9876"],
        scope_name="Pool",
        impl_source=impl,
        source_repo="r/n",
        specific_commit="def5678",  # narrow to this one
    )
    assert out.status == "proven"
    # Only the specific commit was fetched, not the full list.
    assert fetched_commits == ["def5678"]


def test_reviewed_address_match_type_in_order_ranking():
    """_MATCH_TYPE_ORDER: reviewed_address beats impl_era, loses to reviewed_commit."""
    from services.audits.coverage import _MATCH_TYPE_ORDER

    assert _MATCH_TYPE_ORDER["direct"] < _MATCH_TYPE_ORDER["impl_era"]
    assert _MATCH_TYPE_ORDER["impl_era"] < _MATCH_TYPE_ORDER["reviewed_address"]
    assert _MATCH_TYPE_ORDER["reviewed_address"] < _MATCH_TYPE_ORDER["reviewed_commit"]


# ---------------------------------------------------------------------------
# Phase C: _compute_proof_kind — one test per taxonomy case
# ---------------------------------------------------------------------------


class TestComputeProofKind:
    """Covers the five proof_kind values the Phase C rules produce.

    The function is pure: it doesn't hit the DB or network. Each test
    feeds a matched-commit set + a classified_commits list and asserts
    the returned kind.
    """

    def _call(self, matched: list[str], classified: list[dict] | None):
        from services.audits.coverage import _compute_proof_kind

        return _compute_proof_kind({m.lower() for m in matched}, classified)

    def test_unclassified_when_no_classification_data(self):
        """NULL classified_commits → we can't judge strength → ``unclassified``."""
        assert self._call(["abc1234"], None) == "unclassified"
        assert self._call(["abc1234"], []) == "unclassified"

    def test_clean_when_matched_reviewed_and_no_fix_commits(self):
        """Audit has no fix commits; deployed matches the reviewed one.
        Canonical happy path."""
        classified = [{"sha": "abc1234", "label": "reviewed", "context": "audited at abc1234"}]
        assert self._call(["abc1234"], classified) == "clean"

    def test_clean_when_matched_reviewed_and_fix(self):
        """Deployed matches both reviewed and fix commits — file was stable
        across the fix window. Still clean."""
        classified = [
            {"sha": "abc1234", "label": "reviewed", "context": "review"},
            {"sha": "def5678", "label": "fix", "context": "fix L-01"},
        ]
        assert self._call(["abc1234", "def5678"], classified) == "clean"

    def test_post_fix_when_matched_only_fix(self):
        """Deployed matches fix but not reviewed — audit reviewed older
        code, fix was shipped. Audit's findings are addressed."""
        classified = [
            {"sha": "abc1234", "label": "reviewed", "context": "review"},
            {"sha": "def5678", "label": "fix", "context": "fix L-01"},
        ]
        assert self._call(["def5678"], classified) == "post_fix"

    def test_pre_fix_unpatched_when_reviewed_matches_but_fix_doesnt(self):
        """DANGER: deployed matches reviewed AND fix commits exist AND
        deployed doesn't match any fix. Audit's findings are still
        present in the deployed code."""
        classified = [
            {"sha": "abc1234", "label": "reviewed", "context": "review"},
            {"sha": "def5678", "label": "fix", "context": "fix L-01"},
            {"sha": "ffa9876", "label": "fix", "context": "fix L-02"},
        ]
        assert self._call(["abc1234"], classified) == "pre_fix_unpatched"

    def test_cited_only_when_match_hits_cited_label(self):
        """Matched only a commit labeled as 'cited' (historical context,
        not the reviewed commit) — coincidence. Weak signal."""
        classified = [
            {"sha": "abc1234", "label": "reviewed", "context": "review"},
            {"sha": "def5678", "label": "cited", "context": "baseline"},
        ]
        assert self._call(["def5678"], classified) == "cited_only"

    def test_cited_only_when_match_hits_unclear_label(self):
        """Matched only a commit labeled 'unclear' — same semantics as cited."""
        classified = [
            {"sha": "abc1234", "label": "reviewed", "context": "review"},
            {"sha": "def5678", "label": "unclear", "context": "?"},
        ]
        assert self._call(["def5678"], classified) == "cited_only"

    def test_prefix_match_tolerates_abbreviated_shas(self):
        """Matched commit is 40-char full SHA; classified is 7-char abbrev.
        Proof kind computation compares on the shared 7-char prefix."""
        full = "abc1234" + "f" * 33
        classified = [{"sha": "abc1234", "label": "reviewed", "context": "review"}]
        assert self._call([full], classified) == "clean"
