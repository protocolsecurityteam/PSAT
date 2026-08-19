"""Canonical-slug deduplication for the Protocol table.

Regression test for the prod incident where two rows existed for ether.fi:
the audit-discovery path created ``protocol_id=3`` ("etherfi") while the
dapp-crawl/TVL path created ``protocol_id=2`` ("ether fi"). Both reached
``get_or_create_protocol`` with different free-text strings, so the
exact-name lookup missed and a duplicate row was inserted.

The fix is canonical external IDs: every caller resolves the input to a
DefiLlama slug first, and ``get_or_create_protocol`` keys on slug when
one is provided. The fallback name-based path stays so protocols with no
DefiLlama match (the resolver returns ``slug=None``) still work.

Tests run against the real Postgres test DB (``db_session`` fixture in
``tests/conftest.py``). The DefiLlama HTTP call is stubbed at the
``resolve_protocol`` boundary — that's the seam the workers cross.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Protocol  # noqa: E402
from db.queue import get_or_create_protocol  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# Resolver stub
# ---------------------------------------------------------------------------

# All three free-text spellings of ether.fi must resolve to the same family
# slug — that's the whole point of routing through DefiLlama. The stub mirrors
# the real resolver's output shape (slug + name + url + chains + all_slugs).
_ETHERFI = {
    "slug": "ether.fi-stake",
    "name": "Ether.fi",
    "url": "https://ether.fi",
    "chains": ["Ethereum"],
    "all_slugs": ["ether.fi-cash", "ether.fi-stake", "etherfi-liquid"],
}

_YEARN_V2 = {
    "slug": "yearn-finance",
    "name": "Yearn Finance",
    "url": "https://yearn.finance",
    "chains": ["Ethereum"],
    "all_slugs": ["yearn-finance"],
}

_YEARN_V3 = {
    "slug": "yearn-v3",
    "name": "Yearn V3",
    "url": "https://v3.yearn.finance",
    "chains": ["Ethereum"],
    "all_slugs": ["yearn-v3"],
}

_NO_MATCH = {"slug": None, "url": None, "name": None, "chains": [], "all_slugs": []}

_RESOLVER_TABLE = {
    "ether fi": _ETHERFI,
    "etherfi": _ETHERFI,
    "EtherFi": _ETHERFI,
    "Yearn V2": _YEARN_V2,
    "Yearn V3": _YEARN_V3,
}


@pytest.fixture()
def stub_resolver(monkeypatch):
    """Replace ``resolve_protocol`` with a deterministic in-memory table.

    The real resolver fetches DefiLlama over HTTP; integration tests can't
    rely on that. The stub returns the same dict shape, keyed off the input
    string, so the worker glue (resolve → pick family slug → upsert) works
    end-to-end.
    """

    def _fake_resolve(name: str) -> dict:
        return _RESOLVER_TABLE.get(name, _NO_MATCH)

    monkeypatch.setattr("services.discovery.protocol_resolver.resolve_protocol", _fake_resolve)
    return _fake_resolve


def _resolve_and_create(session, name: str, official_domain: str | None = None) -> Protocol:
    """Mirror what discovery workers do: resolve → pick family slug → upsert.

    Workers receive free-text input (a user-typed company name, a github
    org, a hostname). They resolve it to a DefiLlama family slug, then
    hand both name and slug to ``get_or_create_protocol``. This helper
    bundles those two steps so the integration tests exercise the full
    code path the prod incident took.
    """
    from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol

    resolved = resolve_protocol(name)
    slug = pick_family_slug(resolved)
    return get_or_create_protocol(session, name, canonical_slug=slug, official_domain=official_domain)


def _count_protocols(session) -> int:
    return len(session.execute(select(Protocol)).scalars().all())


# ---------------------------------------------------------------------------
# (a) Idempotent same-input — happy-path regression guard.
# ---------------------------------------------------------------------------


def test_same_input_twice_yields_one_row(db_session, stub_resolver):
    p1 = _resolve_and_create(db_session, "etherfi", official_domain="ether.fi")
    db_session.commit()
    p2 = _resolve_and_create(db_session, "etherfi", official_domain="ether.fi")
    db_session.commit()

    assert p1.id == p2.id
    assert _count_protocols(db_session) == 1


# ---------------------------------------------------------------------------
# (b) Whitespace variant — THE prod-incident reproduction.
# ---------------------------------------------------------------------------


def test_whitespace_variants_dedupe_via_slug(db_session, stub_resolver):
    """``ether fi`` (TVL/dapp-crawl path) and ``etherfi`` (github-org path)
    must collapse to ONE row. Pre-fix this produced two rows — protocol_id=2
    and protocol_id=3 in prod, with audits and contracts split across them.
    """
    p1 = _resolve_and_create(db_session, "ether fi", official_domain="ether.fi")
    db_session.commit()
    p2 = _resolve_and_create(db_session, "etherfi", official_domain="ether.fi")
    db_session.commit()

    assert p1.id == p2.id
    assert _count_protocols(db_session) == 1


# ---------------------------------------------------------------------------
# (c) Case variant — same family, different capitalization.
# ---------------------------------------------------------------------------


def test_case_variants_dedupe_via_slug(db_session, stub_resolver):
    p1 = _resolve_and_create(db_session, "EtherFi")
    db_session.commit()
    p2 = _resolve_and_create(db_session, "etherfi")
    db_session.commit()

    assert p1.id == p2.id
    assert _count_protocols(db_session) == 1


# ---------------------------------------------------------------------------
# (d) Distinct protocols with similar names must NOT merge.
# ---------------------------------------------------------------------------


def test_distinct_slugs_keep_protocols_separate(db_session, stub_resolver):
    """Yearn V2 and Yearn V3 share a brand but are independent DefiLlama
    entries with distinct slugs. Slug-based lookup must keep them apart —
    this is why naive normalization (lowercase / strip-punct) was rejected.
    """
    p_v2 = _resolve_and_create(db_session, "Yearn V2")
    db_session.commit()
    p_v3 = _resolve_and_create(db_session, "Yearn V3")
    db_session.commit()

    assert p_v2.id != p_v3.id
    assert _count_protocols(db_session) == 2


# ---------------------------------------------------------------------------
# (e) No-slug fallback — protocol with no DefiLlama match still creates a row.
# ---------------------------------------------------------------------------


def test_no_slug_fallback_uses_name_lookup(db_session, stub_resolver):
    """When the resolver returns ``slug=None`` (no DefiLlama match), the
    function must fall back to the legacy name-keyed lookup. This is the
    'long-tail / private protocol' path — without it those discoveries
    can't be persisted at all.
    """
    p1 = _resolve_and_create(db_session, "obscure-private-protocol")
    db_session.commit()
    p2 = _resolve_and_create(db_session, "obscure-private-protocol")
    db_session.commit()

    assert p1.id == p2.id
    assert p1.canonical_slug is None
    assert _count_protocols(db_session) == 1


def test_no_slug_then_slug_backfills_canonical(db_session, stub_resolver):
    """A row first persisted name-only (resolver miss) should be reused
    when a later resolution succeeds for the same display name. Avoids
    double-rowing protocols whose DefiLlama listing arrives later.
    """
    # First call: resolver returns no match, row keyed by name.
    p1 = _resolve_and_create(db_session, "Ether.fi")  # not in RESOLVER_TABLE → no slug
    db_session.commit()
    assert p1.canonical_slug is None

    # Second call: same display name, but now the slug is known. The same
    # row is reused and ``canonical_slug`` is filled in.
    p2 = get_or_create_protocol(
        db_session,
        "Ether.fi",
        canonical_slug="ether.fi-cash",
        official_domain="ether.fi",
    )
    db_session.commit()

    assert p2.id == p1.id
    assert p2.canonical_slug == "ether.fi-cash"
    assert _count_protocols(db_session) == 1
