"""NULL-chain Contract lookups in ``services.discovery.upgrade_history``
(MULTICHAIN_INVARIANTS.md 1/6/12).

``project_to_events`` (proxy-row lookup) and
``backfill_historical_impl_contracts`` (impl-row dedup + current-impl anchor)
resolved Contract rows with a raw ``chain == <value>`` / ``chain IS NULL``
predicate that ignored the NULL≡mainnet convention. A subject/proxy persisted
with a legacy ``chain=NULL`` was invisible to a mainnet lookup, so events were
skipped and impls were re-minted as duplicate rows.

Both directions are proven: a mainnet lookup finds legacy NULL rows, and a
non-mainnet lookup stays isolated. Etherscan is stubbed (offline).
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_postgres  # noqa: E402


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture()
def proto_id(db_session):
    from db.models import Protocol

    p = Protocol(name=f"uh-coalesce-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


@pytest.fixture()
def stub_etherscan(monkeypatch):
    """``get_contract_info`` returns a deterministic name; nothing leaves the box."""
    import utils.etherscan as etherscan_mod

    monkeypatch.setattr(etherscan_mod, "get_contract_info", lambda address, **_kw: (f"Impl-{address[2:6]}", {}))


# ---------------------------------------------------------------------------
# project_to_events — proxy-row lookup
# ---------------------------------------------------------------------------


@requires_postgres
def test_project_events_keys_to_legacy_null_proxy_row_on_mainnet_subject(db_session, proto_id):
    """The proxy Contract row is a legacy ``chain=NULL`` mainnet row while the
    subject reports ``chain='ethereum'``. The coalesced lookup keys the events
    to that proxy; the old ``chain == 'ethereum'`` predicate skipped it."""
    from db.models import Contract, UpgradeEvent
    from services.discovery.upgrade_history import project_to_events

    proxy_addr = _addr()
    impl_addr = _addr()
    proxy = Contract(address=proxy_addr, chain=None, protocol_id=proto_id, is_proxy=True)
    db_session.add(proxy)
    db_session.commit()

    artifact = {
        "proxies": {
            proxy_addr: {
                "proxy_address": proxy_addr,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_addr,
                        "block_number": 100,
                        "tx_hash": "0x" + "a" * 64,
                    }
                ],
            }
        }
    }

    stats = project_to_events(
        db_session,
        subject_contract_id=proxy.id,
        subject_chain="ethereum",
        artifact_data=artifact,
    )
    db_session.commit()

    assert stats["proxies_projected"] == 1
    assert stats["proxies_skipped_no_contract"] == 0
    events = db_session.query(UpgradeEvent).filter_by(contract_id=proxy.id).all()
    assert len(events) == 1 and events[0].new_impl == impl_addr


@requires_postgres
def test_project_events_skips_mainnet_proxy_row_for_l2_subject(db_session, proto_id):
    """A Base subject must not key its events onto a mainnet (NULL/ethereum)
    proxy row at the same address — no cross-chain bleed."""
    from db.models import Contract, UpgradeEvent
    from services.discovery.upgrade_history import project_to_events

    proxy_addr = _addr()
    impl_addr = _addr()
    # Only a mainnet (legacy NULL) proxy row exists for this address.
    mainnet_proxy = Contract(address=proxy_addr, chain=None, protocol_id=proto_id, is_proxy=True)
    db_session.add(mainnet_proxy)
    db_session.commit()

    artifact = {
        "proxies": {
            proxy_addr: {
                "proxy_address": proxy_addr,
                "events": [
                    {
                        "event_type": "upgraded",
                        "implementation": impl_addr,
                        "block_number": 100,
                        "tx_hash": "0x" + "b" * 64,
                    }
                ],
            }
        }
    }

    stats = project_to_events(
        db_session,
        subject_contract_id=mainnet_proxy.id,
        subject_chain="base",
        artifact_data=artifact,
    )
    db_session.commit()

    assert stats["proxies_skipped_no_contract"] == 1
    # The mainnet proxy row keeps zero events — the Base subject didn't touch it.
    assert db_session.query(UpgradeEvent).filter_by(contract_id=mainnet_proxy.id).count() == 0


# ---------------------------------------------------------------------------
# backfill_historical_impl_contracts — impl-row dedup
# ---------------------------------------------------------------------------


@requires_postgres
def test_backfill_adopts_legacy_null_impl_row_on_mainnet(db_session, proto_id, stub_etherscan):
    """A legacy ``chain=NULL`` orphan impl row is adopted by a mainnet backfill
    (coalesced dedup) rather than duplicated into a fresh ``'ethereum'`` row."""
    from db.models import Contract
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    impl_addr = _addr()
    db_session.add(Contract(address=impl_addr, chain=None, protocol_id=None, contract_name="ExistingImpl"))
    db_session.commit()

    backfill_historical_impl_contracts(
        db_session,
        protocol_id=proto_id,
        chain="ethereum",
        impl_addrs={impl_addr},
        parent_proxy_sources=["inventory"],  # HIGH → ownership asserted
    )

    rows = db_session.query(Contract).filter(Contract.address == impl_addr).all()
    assert len(rows) == 1  # adopted, not duplicated
    row = rows[0]
    assert row.chain is None  # no backfill of the legacy value
    assert row.protocol_id == proto_id
    assert "upgrade_history" in (row.discovery_sources or [])
    assert row.contract_name == "ExistingImpl"  # existing name preserved


@requires_postgres
def test_backfill_base_does_not_adopt_legacy_null_mainnet_impl_row(db_session, proto_id, stub_etherscan):
    """A Base backfill must create a fresh Base row rather than adopt the legacy
    mainnet (NULL) row at the same address."""
    from db.models import Contract
    from services.discovery.upgrade_history import backfill_historical_impl_contracts

    impl_addr = _addr()
    db_session.add(Contract(address=impl_addr, chain=None, protocol_id=None, contract_name="MainnetImpl"))
    db_session.commit()

    backfill_historical_impl_contracts(
        db_session,
        protocol_id=proto_id,
        chain="base",
        impl_addrs={impl_addr},
        parent_proxy_sources=["inventory"],
    )

    rows = db_session.query(Contract).filter(Contract.address == impl_addr).all()
    assert {r.chain for r in rows} == {None, "base"}
    # The mainnet (NULL) row was left an orphan; only the Base row is owned.
    by_chain = {r.chain: r for r in rows}
    assert by_chain[None].protocol_id is None
    assert by_chain["base"].protocol_id == proto_id
