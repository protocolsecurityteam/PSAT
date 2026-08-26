"""Downgrade of b3d7e1f05a92 (W4-H heuristic layer) on populated data.

The vocabulary narrows only after nothing rests on it: the downgrade must
unwind heuristic-derived W2 rows and memberships whose only admission was
heuristic BEFORE deleting the w4h rows and narrowing the CHECK constraints —
otherwise a heuristic_via W2 row becomes indistinguishable from a proven one,
and a heuristic-admitted member survives with zero witnesses.

Runs the real alembic round-trip against a THROWAWAY database (created and
dropped here) so the shared test DB's schema and data are never touched.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.conftest import DATABASE_URL, requires_postgres, run_alembic_upgrade

pytestmark = requires_postgres

_REVISION = "b3d7e1f05a92"
_DOWN_REVISION = "a1c94f2e6b73"


def _alembic_downgrade(url: str, target: str) -> None:
    from alembic.config import Config

    from alembic import command

    repo_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.downgrade(cfg, target)


@pytest.fixture()
def throwaway_db_url():
    admin_engine = sa.create_engine(DATABASE_URL, isolation_level="AUTOCOMMIT")
    dbname = f"psat_mig_w4h_{os.getpid()}"
    with admin_engine.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{dbname}"'))
        conn.execute(sa.text(f'CREATE DATABASE "{dbname}"'))
    url = sa.engine.make_url(DATABASE_URL).set(database=dbname)
    yield url.render_as_string(hide_password=False)
    with admin_engine.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)'))
    admin_engine.dispose()


def test_w4h_downgrade_unwinds_heuristic_membership(throwaway_db_url):
    run_alembic_upgrade(throwaway_db_url)
    engine = sa.create_engine(throwaway_db_url)

    deployer = "0x" + "d1" * 20
    with engine.begin() as conn:
        protocol_id = conn.execute(
            sa.text("INSERT INTO protocols (name) VALUES ('w4h-downgrade-proto') RETURNING id")
        ).scalar_one()
        conn.execute(
            sa.text(
                "INSERT INTO protocol_deployers (protocol_id, address, trust_class, evidence) "
                "VALUES (:p, :a, 'H', '{}'::jsonb)"
            ),
            {"p": protocol_id, "a": deployer},
        )

        def add_contract(tag: str) -> int:
            return conn.execute(
                sa.text(
                    "INSERT INTO contracts (address, chain, protocol_id, nominated_protocol_id) "
                    "VALUES (:a, 'ethereum', :p, :p) RETURNING id"
                ),
                {"a": "0x" + tag * 20, "p": protocol_id},
            ).scalar_one()

        def add_witness(contract_id: int, rule: str, evidence: str, via: str | None = None) -> None:
            conn.execute(
                sa.text(
                    "INSERT INTO contract_membership_witnesses "
                    "(contract_id, protocol_id, rule, via_address, evidence) "
                    "VALUES (:c, :p, :r, :v, CAST(:e AS JSONB))"
                ),
                {"c": contract_id, "p": protocol_id, "r": rule, "v": via, "e": evidence},
            )

        # A: admitted only by the heuristic rule (w1 is a precondition, never
        # an admission).
        contract_a = add_contract("aa")
        add_witness(contract_a, "w1_code", '{"code_present": true}')
        add_witness(contract_a, "w4h_deployer_affinity", '{"deployer": "' + deployer + '"}', via=deployer)
        # B: admitted by a W2 edge derived from the heuristic member A.
        contract_b = add_contract("bb")
        add_witness(
            contract_b,
            "w2_structural",
            '{"edge_kind": "implementation", "heuristic_via": true}',
            via="0x" + "aa" * 20,
        )
        # C: proven member — a plain W2 admission that must survive.
        contract_c = add_contract("cc")
        add_witness(contract_c, "w2_structural", '{"edge_kind": "implementation"}', via="0x" + "ee" * 20)

    _alembic_downgrade(throwaway_db_url, _DOWN_REVISION)

    with engine.connect() as conn:
        rules = set(conn.execute(sa.text("SELECT DISTINCT rule FROM contract_membership_witnesses")).scalars())
        assert "w4h_deployer_affinity" not in rules
        heuristic_w2 = conn.execute(
            sa.text(
                "SELECT count(*) FROM contract_membership_witnesses "
                "WHERE rule = 'w2_structural' AND evidence->>'heuristic_via' = 'true'"
            )
        ).scalar_one()
        assert heuristic_w2 == 0, "heuristic-derived W2 rows must not survive the vocabulary narrowing"

        orphan_members = conn.execute(
            sa.text(
                "SELECT count(*) FROM contracts c WHERE c.protocol_id IS NOT NULL AND NOT EXISTS ("
                "  SELECT 1 FROM contract_membership_witnesses w"
                "  WHERE w.contract_id = c.id AND w.protocol_id = c.protocol_id AND w.revoked_at IS NULL"
                "    AND w.rule IN ('w2_structural', 'w3_control', 'w4_deployer', "
                "'w4_factory', 'w5_human', 'w6_llama_seed'))"
            )
        ).scalar_one()
        assert orphan_members == 0, "no member row may lack an admitting witness after downgrade"

        rows = {
            r.id: r
            for r in conn.execute(sa.text("SELECT id, protocol_id, nominated_protocol_id FROM contracts ORDER BY id"))
        }
        assert rows[contract_a].protocol_id is None
        assert rows[contract_b].protocol_id is None
        assert rows[contract_c].protocol_id == protocol_id
        # Gate invariant 4: nomination is never a membership claim and is
        # preserved through the unwind.
        for cid in (contract_a, contract_b, contract_c):
            assert rows[cid].nominated_protocol_id == protocol_id

        trust_classes = set(conn.execute(sa.text("SELECT DISTINCT trust_class FROM protocol_deployers")).scalars())
        assert "H" not in trust_classes

    # Round-trip back to head must succeed on the unwound data.
    run_alembic_upgrade(throwaway_db_url)
    engine.dispose()
