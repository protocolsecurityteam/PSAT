"""Migration a3f7c9d21e08: chain-token normalization on populated data.

Exercises the collision-safe re-key logic directly (``_normalize_chain_tokens``)
rather than driving the whole alembic run: a name-keyed row moves to its decimal
id token, and a row whose target key is already occupied is left on its stale key
(a cache miss, not corruption — invariant 11).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import select

from db.models import ContractMaterialization  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

_MIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "a3f7c9d21e08_materialization_source_hash_and_chain_token.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("_mig_a3f7c9d21e08", _MIG_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def _clean_cm(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


def _row(chain, keccak, addr, **kw):
    return ContractMaterialization(
        chain=chain,
        bytecode_keccak=keccak,
        address=addr,
        status="ready",
        analysis_schema_version=1,
        **kw,
    )


@requires_postgres
def test_normalize_chain_tokens_rekeys_and_skips_collisions(_clean_cm):
    mig = _load_migration()

    k1 = "0x" + "11" * 32
    k2 = "0x" + "22" * 32
    a1 = "0x" + "a1" * 20
    a2 = "0x" + "a2" * 20
    a3 = "0x" + "a3" * 20

    # X: plain mainnet name → moves to "1".
    _clean_cm.add(_row("ethereum", k1, a1))
    # Y (name "ethereum", keccak k2) collides with pre-existing Z ("1", keccak k2)
    # on the (chain, bytecode_keccak) PK → Y must be left on "ethereum".
    _clean_cm.add(_row("ethereum", k2, a2))
    _clean_cm.add(_row("1", k2, a3))
    _clean_cm.commit()

    mig._normalize_chain_tokens(_clean_cm.connection())

    _clean_cm.expire_all()
    rows = {
        (r.bytecode_keccak, r.address): r.chain
        for r in _clean_cm.execute(select(ContractMaterialization)).scalars().all()
    }
    assert rows[(k1, a1)] == "1", "non-colliding name row re-keyed to decimal id"
    assert rows[(k2, a2)] == "ethereum", "colliding row left on stale key"
    assert rows[(k2, a3)] == "1", "pre-existing id row untouched"


@requires_postgres
def test_normalize_chain_tokens_maps_base_name(_clean_cm):
    mig = _load_migration()
    k = "0x" + "33" * 32
    a = "0x" + "b1" * 20
    _clean_cm.add(_row("base", k, a))
    _clean_cm.commit()

    mig._normalize_chain_tokens(_clean_cm.connection())

    _clean_cm.expire_all()
    row = _clean_cm.execute(select(ContractMaterialization)).scalars().one()
    assert row.chain == "8453"
