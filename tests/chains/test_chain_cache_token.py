"""One cache-key token format everywhere.

The mapping-enumeration cache once keyed one contract by chain name and by ``str(chain_id)``;
``chain_cache_token`` collapses both onto the decimal chain id so L1 (``mapping_enumerator._chain_key``)
and L2 (``db.mapping_enumeration_cache``) hit the same row.
"""

from __future__ import annotations

from tests.conftest import requires_postgres


def test_token_name_id_and_none_converge_on_mainnet():
    from utils.chains import chain_cache_token

    assert (
        chain_cache_token("ethereum")
        == chain_cache_token("mainnet")
        == chain_cache_token("1")
        == chain_cache_token(1)
        == chain_cache_token(None)
        == chain_cache_token("")
        == "1"
    )


def test_token_unknown_name_is_isolated_not_aliased_to_mainnet():
    """A miss is safe; a cross-chain collision is not."""
    from utils.chains import chain_cache_token

    assert chain_cache_token("nonexistent-chain") == "nonexistent-chain"
    assert chain_cache_token("nonexistent-chain") != chain_cache_token("ethereum")


@requires_postgres
def test_l2_name_and_decimal_id_hit_same_row(db_session, monkeypatch):
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from db import mapping_enumeration_cache as db_cache
    from db.models import MappingEnumerationCache

    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(db_cache, "SessionLocal", sessionmaker(bind=engine))
    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()

    addr = "0x" + "ab" * 20
    h = "specshash-token-test"
    payload = {
        "principals": [
            {"address": "0x" + "cd" * 20, "mapping_name": "wards", "direction_history": ["add"], "last_seen_block": 5}
        ],
        "status": "complete",
        "pages_fetched": 1,
        "last_block_scanned": 42,
        "error": None,
    }

    db_cache.upsert(chain="ethereum", address=addr, specs_hash=h, result=payload)

    hit = db_cache.find_fresh(chain="1", address=addr, specs_hash=h)
    assert hit is not None and hit["last_block_scanned"] == 42

    assert db_cache.find_fresh(chain="base", address=addr, specs_hash=h) is None

    rows = db_session.query(MappingEnumerationCache).filter(MappingEnumerationCache.address == addr).all()
    assert len(rows) == 1
    assert rows[0].chain == "1"

    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()
