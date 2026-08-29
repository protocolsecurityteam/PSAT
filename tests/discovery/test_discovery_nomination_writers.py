"""Discovery-write nomination conversion (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.2).

Invariant 1 at the persistence boundary: ``db.queue`` discovery upserts —
the funnel for every discovery writer, the exa/spa/two-pass ``run_discovery``
entries included — record nominations via the membership gate and never write
``Contract.protocol_id``, whatever the source tag.
"""

from __future__ import annotations

import uuid

import pytest

from db.models import Contract, Protocol
from db.queue import bulk_upsert_discovered_contracts, upsert_discovered_contract
from services.discovery.membership_gate import membership_state
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]


@pytest.fixture()
def proto_id(db_session):
    row = Protocol(name=f"nom-writers-{uuid.uuid4().hex[:12]}")
    db_session.add(row)
    db_session.commit()
    return row.id


def _row(session, addr: str) -> Contract:
    return session.query(Contract).filter_by(address=addr).one()


class TestBulkUpsertNominates:
    def test_new_row_is_nominated_candidate_not_member(self, db_session, proto_id):
        addr = ADDR(0x1A01)
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=proto_id,
            entries=[{"address": addr, "chain": "ethereum", "new_sources": ["defillama"]}],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.protocol_id is None
        assert row.nominated_protocol_id == proto_id
        assert membership_state(row) == "candidate"
        assert "defillama" in (row.discovery_sources or [])

    def test_high_confidence_tags_no_longer_stamp(self, db_session, proto_id):
        # The retired HIGH tier: each tag used to write protocol_id at the
        # persistence boundary; all are nominations now.
        for i, tag in enumerate(["deployer_expansion", "defillama", "ai_inventory", "exa_deep_research", "inventory"]):
            addr = ADDR(0x1B00 + i)
            bulk_upsert_discovered_contracts(
                db_session,
                protocol_id=proto_id,
                entries=[{"address": addr, "chain": "ethereum", "new_sources": [tag]}],
            )
            db_session.commit()
            row = _row(db_session, addr)
            assert row.protocol_id is None, tag
            assert row.nominated_protocol_id == proto_id, tag

    def test_existing_orphan_gains_nomination(self, db_session, proto_id):
        # Orphan amnesia fix: the re-write records WHICH protocol nominated.
        addr = ADDR(0x1C01)
        db_session.add(Contract(address=addr, chain="ethereum", discovery_sources=["dapp_crawl"]))
        db_session.commit()
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=proto_id,
            entries=[{"address": addr, "chain": "ethereum", "new_sources": ["dapp_crawl"]}],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.protocol_id is None
        assert row.nominated_protocol_id == proto_id

    def test_no_protocol_id_writes_no_nomination(self, db_session):
        addr = ADDR(0x1D01)
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=None,
            entries=[{"address": addr, "chain": "ethereum", "new_sources": ["dapp_crawl"]}],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.nominated_protocol_id is None
        assert membership_state(row) == "unclaimed"

    def test_first_nominator_wins(self, db_session, proto_id):
        other = Protocol(name=f"nom-writers-2-{uuid.uuid4().hex[:12]}")
        db_session.add(other)
        db_session.commit()
        addr = ADDR(0x1E01)
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=proto_id,
            entries=[{"address": addr, "chain": "ethereum", "new_sources": ["defillama"]}],
        )
        db_session.commit()
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=other.id,
            entries=[{"address": addr, "chain": "ethereum", "new_sources": ["exa_deep_research"]}],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.nominated_protocol_id == proto_id
        # The late nominator's tag stays as provenance.
        assert set(row.discovery_sources or []) >= {"defillama", "exa_deep_research"}

    def test_member_row_is_never_reclaimed(self, db_session, proto_id):
        other = Protocol(name=f"nom-writers-3-{uuid.uuid4().hex[:12]}")
        db_session.add(other)
        db_session.commit()
        addr = ADDR(0x1F01)
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=proto_id))
        db_session.commit()
        bulk_upsert_discovered_contracts(
            db_session,
            protocol_id=other.id,
            entries=[{"address": addr, "chain": "ethereum", "new_sources": ["defillama"]}],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.protocol_id == proto_id
        # The member's empty nomination slot belongs to its own protocol
        # (demotion provenance), never a foreign nominator.
        assert row.nominated_protocol_id == proto_id


class TestSingleUpsertNominates:
    def test_new_row_is_nominated_candidate(self, db_session, proto_id):
        addr = ADDR(0x2A01)
        upsert_discovered_contract(
            db_session,
            address=addr,
            chain="ethereum",
            protocol_id=proto_id,
            new_sources=["ai_inventory"],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.protocol_id is None
        assert row.nominated_protocol_id == proto_id
        assert membership_state(row) == "candidate"

    def test_existing_row_gains_nomination_never_protocol_id(self, db_session, proto_id):
        addr = ADDR(0x2B01)
        db_session.add(Contract(address=addr, chain="ethereum", discovery_sources=["upgrade_history"]))
        db_session.commit()
        upsert_discovered_contract(
            db_session,
            address=addr,
            chain="ethereum",
            protocol_id=proto_id,
            new_sources=["deployer_expansion"],
        )
        db_session.commit()
        row = _row(db_session, addr)
        assert row.protocol_id is None
        assert row.nominated_protocol_id == proto_id
        assert set(row.discovery_sources or []) >= {"upgrade_history", "deployer_expansion"}

    def test_unknown_chain_row_nominates_but_stays_candidate(self, db_session, proto_id):
        # The exa resolve-later bucket: a nomination is recorded; membership
        # is impossible until the chain resolves and W1 lands (invariant 3).
        addr = ADDR(0x2C01)
        upsert_discovered_contract(
            db_session,
            address=addr,
            chain="unknown",
            protocol_id=proto_id,
            new_sources=["exa_deep_research"],
        )
        db_session.commit()
        row = db_session.query(Contract).filter_by(address=addr, chain="unknown").one()
        assert row.protocol_id is None
        assert row.nominated_protocol_id == proto_id
        assert membership_state(row) == "candidate"
