"""M0.2 item 2 — one cache-key token format everywhere (invariant 11).

The mapping-enumeration cache used to key the same contract two ways: a chain
*name* (``"ethereum"``) from one code path and ``str(chain_id)`` (``"1"``) from
another. ``chain_cache_token`` collapses both onto the decimal-string chain id,
so the L1 (``mapping_enumerator._chain_key``) and L2
(``db.mapping_enumeration_cache``) layers agree and hit the same row.
"""

from __future__ import annotations

from tests.conftest import requires_postgres

# ---------------------------------------------------------------------------
# chain_cache_token — pure normalizer
# ---------------------------------------------------------------------------


def test_token_name_id_and_none_converge_on_mainnet():
    from utils.chains import chain_cache_token

    # Name, alias, decimal string, int, and None all collapse to "1".
    assert (
        chain_cache_token("ethereum")
        == chain_cache_token("mainnet")
        == chain_cache_token("1")
        == chain_cache_token(1)
        == chain_cache_token(None)
        == chain_cache_token("")
        == "1"
    )


def test_token_non_mainnet_name_and_id_converge():
    from utils.chains import chain_cache_token

    assert chain_cache_token("base") == chain_cache_token("8453") == chain_cache_token(8453) == "8453"
    assert chain_cache_token("arbitrum") == "42161"


def test_token_unknown_name_is_isolated_not_aliased_to_mainnet():
    """An unregistered non-numeric name gets its own bucket rather than silently
    colliding with mainnet — a miss is safe, a cross-chain collision is not."""
    from utils.chains import chain_cache_token

    assert chain_cache_token("nonexistent-chain") == "nonexistent-chain"
    assert chain_cache_token("nonexistent-chain") != chain_cache_token("ethereum")


def test_l1_chain_key_uses_the_token():
    """The L1 key (``mapping_enumerator._chain_key``) yields the decimal token so
    a name-keyed caller and an id-keyed caller share the same cache entry."""
    from services.resolution.mapping_enumerator import _chain_key

    assert _chain_key("ethereum") == _chain_key("1") == _chain_key(None) == "1"
    assert _chain_key("base") == _chain_key("8453") == "8453"


# ---------------------------------------------------------------------------
# L2 durable cache — name and decimal id resolve to the same row
# ---------------------------------------------------------------------------


@requires_postgres
def test_l2_name_and_decimal_id_hit_same_row(db_session, monkeypatch):
    """upsert keyed by the chain *name* is found by a lookup keyed by the decimal
    chain id, and a different chain misses."""
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from db import mapping_enumeration_cache as db_cache
    from db.models import MappingEnumerationCache

    # Point the module's own SessionLocal at the test DB (mirrors
    # tests/resolution/test_mapping_enumeration_db_cache.py).
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

    # Decimal-id lookup hits the name-keyed row (one token format).
    hit = db_cache.find_fresh(chain="1", address=addr, specs_hash=h)
    assert hit is not None and hit["last_block_scanned"] == 42

    # A genuinely different chain misses.
    assert db_cache.find_fresh(chain="base", address=addr, specs_hash=h) is None

    # Exactly one row was written (name and decimal id did not fork the key).
    rows = db_session.query(MappingEnumerationCache).filter(MappingEnumerationCache.address == addr).all()
    assert len(rows) == 1
    assert rows[0].chain == "1"

    db_session.query(MappingEnumerationCache).delete()
    db_session.commit()
