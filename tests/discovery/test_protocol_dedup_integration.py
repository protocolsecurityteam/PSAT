"""Free-text names once gave ether.fi two Protocol rows; callers now key on the DefiLlama slug, with the name path
for ``slug=None``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from db.models import Protocol
from db.queue import get_or_create_protocol
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


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

    def _fake_resolve(name: str) -> dict:
        return _RESOLVER_TABLE.get(name, _NO_MATCH)

    monkeypatch.setattr("services.discovery.protocol_resolver.resolve_protocol", _fake_resolve)
    return _fake_resolve


def _resolve_and_create(session, name: str, official_domain: str | None = None) -> Protocol:
    from services.discovery.protocol_resolver import pick_family_slug, resolve_protocol

    resolved = resolve_protocol(name)
    slug = pick_family_slug(resolved)
    return get_or_create_protocol(session, name, canonical_slug=slug, official_domain=official_domain)


def _count_protocols(session) -> int:
    return len(session.execute(select(Protocol)).scalars().all())


@pytest.mark.parametrize(
    ("first", "second", "official_domain"),
    [
        pytest.param("etherfi", "etherfi", "ether.fi", id="same-input-twice"),
        # The prod-incident reproduction: pre-fix these were two rows with audits and contracts split.
        pytest.param("ether fi", "etherfi", "ether.fi", id="whitespace-variants"),
        pytest.param("EtherFi", "etherfi", None, id="case-variants"),
    ],
)
def test_spelling_variants_dedupe_via_slug(db_session, stub_resolver, first, second, official_domain):
    p1 = _resolve_and_create(db_session, first, official_domain=official_domain)
    db_session.commit()
    p2 = _resolve_and_create(db_session, second, official_domain=official_domain)
    db_session.commit()

    assert p1.id == p2.id
    assert _count_protocols(db_session) == 1


def test_distinct_slugs_keep_protocols_separate(db_session, stub_resolver):
    """Yearn V2 and V3 are separate DefiLlama entries, which is why naive normalization was rejected."""
    p_v2 = _resolve_and_create(db_session, "Yearn V2")
    db_session.commit()
    p_v3 = _resolve_and_create(db_session, "Yearn V3")
    db_session.commit()

    assert p_v2.id != p_v3.id
    assert _count_protocols(db_session) == 2


def test_no_slug_fallback_uses_name_lookup(db_session, stub_resolver):
    """The long-tail / private protocol path."""
    p1 = _resolve_and_create(db_session, "obscure-private-protocol")
    db_session.commit()
    p2 = _resolve_and_create(db_session, "obscure-private-protocol")
    db_session.commit()

    assert p1.id == p2.id
    assert p1.canonical_slug is None
    assert _count_protocols(db_session) == 1
