"""D1 — node enumeration: one fold, one cursor, and a set that is a lower bound.

The fold proves a node EXISTS. It can never prove one does not, so every arm
below asserts the absence side stays unclaimed: no cursor on an unresolved
creation block, no complete node set, and no earned negative anywhere.
"""

from __future__ import annotations

import pathlib

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import select

from db.models import Contract, IndexedEventCursor, IndexedEventLog, Protocol
from services.monitoring import restaking_enrollment
from services.monitoring.restaking_enrollment import (
    PUBKEY_LINKED_SIGNATURE,
    PUBKEY_LINKED_TOPIC0,
    discover_emitters,
    enroll_restaking_fold,
    node_addresses_from_fold,
    protocol_contract_addresses,
)
from tests.conftest import requires_postgres

# The measured emitter: the EtherFiNodesManager PROXY. Its ``contracts`` row is
# keyed at the implementation (0xcf5928ea…), which emits nothing — the same
# implementation-vs-proxy keying defect the balance plane documents.
EFNM_PROXY = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
EFNM_IMPLEMENTATION = "0xcf5928ea7d7f164ec868ceda7a69e08a102b5e05"
EFNM_CREATION_BLOCK = 17174453

NODE_A = "0x05b1e40339823e1af30a8ed70c3fbf7f1d0ce9ae"
NODE_B = "0x53e1eb2fa5ec3c5097e67265e33ea4e53ab61b79"


def _topic(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _log(node: str, *, address: str = EFNM_PROXY) -> dict:
    return {
        "address": address,
        "topics": ["0x" + "11" * 32, PUBKEY_LINKED_TOPIC0, _topic(node)],
    }


class TestTopic:
    def test_topic0_is_derived_from_the_signature(self):
        assert PUBKEY_LINKED_TOPIC0 == "0x" + keccak(text=PUBKEY_LINKED_SIGNATURE).hex()
        # Reproduced against the chain at block 25643300.
        assert PUBKEY_LINKED_TOPIC0 == "0x5e525a525cf73653f769c8305dc71a68b85b0e62e3cc5258fe187ff9fd3e5cb9"


class TestEmitterDiscovery:
    def test_emitter_is_the_address_that_actually_emitted(self):
        captured: dict = {}

        def fetch(addresses, topic0, from_block, to_block):
            captured.update(addresses=addresses, topic0=topic0, from_block=from_block, to_block=to_block)
            return [_log(NODE_A), _log(NODE_B)]

        emitters = discover_emitters(
            [EFNM_PROXY, EFNM_IMPLEMENTATION],
            from_block=25443300,
            to_block=25643300,
            fetch_logs=fetch,
        )
        assert emitters == {EFNM_PROXY}
        # One request carrying the whole address set, not one probe per address.
        assert captured["addresses"] == [EFNM_PROXY, EFNM_IMPLEMENTATION]
        assert captured["topic0"] == PUBKEY_LINKED_TOPIC0

    def test_no_logs_yields_no_emitters_and_no_claim(self):
        assert discover_emitters([EFNM_PROXY], from_block=1, to_block=2, fetch_logs=lambda *a: []) == set()

    def test_fetch_failure_propagates_rather_than_narrowing_the_set(self):
        def fetch(*_args):
            raise RuntimeError("transport")

        with pytest.raises(RuntimeError):
            discover_emitters([EFNM_PROXY], from_block=1, to_block=2, fetch_logs=fetch)

    def test_empty_address_list_issues_no_request(self):
        def fetch(*_args):  # pragma: no cover - must not run
            raise AssertionError("no request expected")

        assert discover_emitters([], from_block=1, to_block=2, fetch_logs=fetch) == set()


@requires_postgres
class TestEnrollment:
    def test_cursor_seeded_one_below_creation(self, db_session, monkeypatch):
        monkeypatch.setattr(
            restaking_enrollment, "get_contract_creation_block", lambda addr, *, chain_id: EFNM_CREATION_BLOCK
        )
        assert enroll_restaking_fold(db_session, chain_id=1, emitters=[EFNM_PROXY]) == 1
        cursor = db_session.execute(
            select(IndexedEventCursor).where(
                IndexedEventCursor.chain_id == 1,
                IndexedEventCursor.event_address == EFNM_PROXY,
                IndexedEventCursor.topic0 == PUBKEY_LINKED_TOPIC0,
            )
        ).scalar_one()
        assert cursor.last_indexed_block == EFNM_CREATION_BLOCK - 1
        assert cursor.backfill_complete is False
        db_session.rollback()

    def test_unresolved_creation_block_enrolls_nothing(self, db_session, monkeypatch):
        monkeypatch.setattr(restaking_enrollment, "get_contract_creation_block", lambda addr, *, chain_id: None)
        assert enroll_restaking_fold(db_session, chain_id=1, emitters=[EFNM_PROXY]) == 0
        assert db_session.execute(select(IndexedEventCursor)).all() == []
        db_session.rollback()

    def test_creation_lookup_raise_defers_rather_than_seeding_genesis(self, db_session, monkeypatch):
        def boom(addr, *, chain_id):
            raise RuntimeError("etherscan")

        monkeypatch.setattr(restaking_enrollment, "get_contract_creation_block", boom)
        assert enroll_restaking_fold(db_session, chain_id=1, emitters=[EFNM_PROXY]) == 0
        assert db_session.execute(select(IndexedEventCursor)).all() == []
        db_session.rollback()

    def test_warm_siblings_never_regress_and_stay_complete(self, db_session, monkeypatch):
        """The measured deferral: a cold cursor joins warm ones, and
        ``index_event_group_step`` takes ``min(last_indexed_block)``, dragging the shared
        window back 8,468,848 blocks (17 windows at 500,000). A sibling must not lose ground
        or have its completeness reset by the enrollment itself."""
        warm_topics = [
            "0x1bb6cfc6cc765f48d6e1b6b8c5e5503c0d2ee684bdd46f53e0785cc966e20fab",
            "0x2a1547b8c4fcc5c564373b299ab7eecb2d5013083f2fe08a64698fe5198e1930",
        ]
        for topic0 in warm_topics:
            db_session.add(
                IndexedEventCursor(
                    chain_id=1,
                    event_address=EFNM_PROXY,
                    topic0=topic0,
                    last_indexed_block=25641245,
                    backfill_complete=True,
                )
            )
        db_session.flush()

        monkeypatch.setattr(
            restaking_enrollment, "get_contract_creation_block", lambda addr, *, chain_id: EFNM_CREATION_BLOCK
        )
        enroll_restaking_fold(db_session, chain_id=1, emitters=[EFNM_PROXY])

        for topic0 in warm_topics:
            cursor = db_session.execute(
                select(IndexedEventCursor).where(
                    IndexedEventCursor.chain_id == 1,
                    IndexedEventCursor.event_address == EFNM_PROXY,
                    IndexedEventCursor.topic0 == topic0,
                )
            ).scalar_one()
            assert cursor.last_indexed_block == 25641245
            assert cursor.backfill_complete is True
        db_session.rollback()

    def test_protocol_addresses_include_proxy_and_implementation_rows(self, db_session):
        protocol = Protocol(name="fold-scope")
        db_session.add(protocol)
        db_session.flush()
        db_session.add_all(
            [
                Contract(protocol_id=protocol.id, address=EFNM_PROXY, implementation=EFNM_IMPLEMENTATION),
                Contract(protocol_id=protocol.id, address=EFNM_IMPLEMENTATION),
            ]
        )
        db_session.flush()
        assert sorted(protocol_contract_addresses(db_session, protocol_id=protocol.id)) == sorted(
            [EFNM_PROXY, EFNM_IMPLEMENTATION]
        )
        db_session.rollback()


@requires_postgres
class TestNodeSet:
    def _log_row(self, session, node, *, block, log_index):
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=EFNM_PROXY,
                topic0=PUBKEY_LINKED_TOPIC0,
                tx_hash=bytes([log_index]) * 32,
                log_index=log_index,
                block_number=block,
                block_hash=bytes([block % 251]) * 32,
                transaction_index=0,
                topics=["0x" + "11" * 32, PUBKEY_LINKED_TOPIC0, _topic(node)],
                data_words=[],
            )
        )

    def test_node_set_is_distinct_topic2(self, db_session):
        self._log_row(db_session, NODE_A, block=25473872, log_index=1)
        self._log_row(db_session, NODE_B, block=25473873, log_index=2)
        self._log_row(db_session, NODE_A, block=25473874, log_index=3)
        db_session.flush()
        assert node_addresses_from_fold(db_session, chain_id=1) == sorted([NODE_A, NODE_B])
        db_session.rollback()

    def test_short_topic_list_is_skipped_not_guessed(self, db_session):
        db_session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=EFNM_PROXY,
                topic0=PUBKEY_LINKED_TOPIC0,
                tx_hash=b"\x09" * 32,
                log_index=9,
                block_number=25473875,
                block_hash=b"\x09" * 32,
                transaction_index=0,
                topics=["0x" + "11" * 32, PUBKEY_LINKED_TOPIC0],
                data_words=[],
            )
        )
        db_session.flush()
        assert node_addresses_from_fold(db_session, chain_id=1) == []
        db_session.rollback()

    def test_other_chain_logs_do_not_leak(self, db_session):
        self._log_row(db_session, NODE_A, block=25473872, log_index=1)
        db_session.flush()
        assert node_addresses_from_fold(db_session, chain_id=8453) == []
        db_session.rollback()


def test_no_module_outside_the_plane_imports_the_position_model():
    """Makes "zero readers modified" self-enforcing: the plane is invisible to spot-balance
    readers only structurally (a node has no ``contracts`` row), so the import surface is asserted."""
    root = pathlib.Path(__file__).resolve().parents[2]
    allowed = {
        # The model's home and the package re-export surface.
        root / "db" / "models" / "balances.py",
        root / "db" / "models" / "__init__.py",
        root / "tests" / "monitoring" / "test_restaking_position.py",
        root / "services" / "monitoring" / "restaking_reads.py",
        root / "services" / "monitoring" / "restaking_enrollment.py",
        # The scorer's value plane: SCORER_INTEGRATION_STRATEGY §7.1 mandates a fold read keyed
        # by the positions' OWN entity keys, which cannot use spot-balance readers.
        root / "services" / "scoring" / "planes" / "value.py",
        root / "services" / "scoring" / "planes" / "provenance.py",
        # The scorer's P4 universe builder: an ADDRESS-ONLY read (no quantity, share basis or
        # dollar), so it cannot double-count or mis-key like a value reader. Kept outside the
        # plane because its source-literal arm reads object storage, which the fold may not.
        root / "services" / "scoring" / "distill" / "universe.py",
        # This file: the needle appears in the assertion below.
        pathlib.Path(__file__).resolve(),
        # Metadata-registration guard: carries the table NAME in its snapshot
        # of ``Base.metadata`` but reads no rows and imports no model.
        root / "tests" / "storage" / "test_models_metadata.py",
    }
    offenders = []
    for path in root.rglob("*.py"):
        # Exclude on REPO-RELATIVE parts: a worktree checkout lives under
        # .claude/worktrees/, so matching absolute parts would skip every file
        # and pass this guard vacuously there.
        if any(
            part in {".venv", "node_modules", "alembic", ".claude", ".local-compute", "analysis"}
            for part in path.relative_to(root).parts
        ):
            continue
        if path in allowed:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Both the mapped identifier AND the table name: a raw-SQL consumer
        # (``FROM restaking_positions_latest``) never mentions the class, and the
        # table name is the substring both relations share.
        if any(needle in text for needle in ("RestakingPosition", "restaking_positions")):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []
