"""``services.resolution.creation_block_floor.resolve_scan_floor`` — the floor a
log scan may start from.

The floor is what keeps a backfill from asking an upstream for the whole chain,
and its three answers are distinct: a durable cursor (free, and preferred), a
creation block from Etherscan (paid, memoized per address), or DEFER. It never
fails open to block 0 — a scan that started at 0 because the floor was unknown
would read downstream as a scan that covered everything.

The module's collaborators are monkeypatched or seeded, so nothing here touches the Etherscan wire.
"""

from __future__ import annotations

from tests.conftest import requires_postgres


def test_resolve_scan_floor_caches_per_address(monkeypatch):
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    calls: list[str] = []

    def fake_lookup(addr, **_k):
        calls.append(addr)
        return 6_000_000

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", fake_lookup)
    addr = "0x" + "ab" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) == 6_000_000 - 1
    assert floor_mod.resolve_scan_floor(addr, 1) == 6_000_000 - 1
    assert calls == [addr]  # second call served from cache


@requires_postgres
def test_resolve_scan_floor_prefers_durable_cursor(db_session, monkeypatch):
    # A witnessed cursor floor (its first_indexed_block, not its frontier) is preferred over an Etherscan call.
    import services.resolution.creation_block_floor as floor_mod
    from db.models import FIRST_INDEXED_BASIS_CREATION, IndexedEventCursor

    addr = "0x" + "cd" * 20
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=addr,
            topic0="0x" + "12" * 32,
            last_indexed_block=9_000_000,
            backfill_complete=True,
            first_indexed_block=5_000_000,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        )
    )
    db_session.commit()
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 7_000_000)
    assert floor_mod.resolve_scan_floor(addr, 1, session=db_session) == 5_000_000


def test_resolve_scan_floor_defers_on_a_failed_witness(monkeypatch):
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: "defer")
    calls: list[str] = []

    def lookup(addr, **_k):
        calls.append(addr)
        return 6_000_000

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lookup)
    assert floor_mod.resolve_scan_floor("0x" + "ce" * 20, 1) is None
    assert calls == []


def test_resolve_scan_floor_none_for_zero_or_missing_address(monkeypatch):
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(
        floor_mod,
        "_floor_from_cursor",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not query for zero/invalid")),
    )
    assert floor_mod.resolve_scan_floor("0x" + "0" * 40, 1) is None
    assert floor_mod.resolve_scan_floor(None, 1) is None
    assert floor_mod.resolve_scan_floor("not-an-address", 1) is None
