"""Offline tests for chain-qualified address labels (F5) via ``routers/address_labels.py``.

Global rows keep the historical address-keyed shape, chain-qualified rows override per network,
and the three can coexist at one address.
"""

from __future__ import annotations

import pytest

from db.models import AddressLabel
from tests.cache_helpers import requires_postgres

ADDR = "0x00000000000000000000000000000000deadbeef"


@pytest.fixture()
def clean_labels(db_session):
    db_session.query(AddressLabel).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(AddressLabel).delete()
    db_session.commit()


@requires_postgres
def test_global_roundtrip_backcompat(api_client, clean_labels):
    r = api_client.put(f"/api/address_labels/{ADDR}", json={"name": "Treasury"})
    assert r.status_code == 200
    body = r.json()
    assert body["address"] == ADDR and body["chain"] is None and body["name"] == "Treasury"

    listing = api_client.get("/api/address_labels").json()
    assert listing["labels"][ADDR]["name"] == "Treasury"
    assert listing["chain_labels"] == {}


@requires_postgres
def test_chain_qualified_roundtrip(api_client, clean_labels):
    r = api_client.put(f"/api/address_labels/{ADDR}?chain=base", json={"name": "Base Vault"})
    assert r.status_code == 200 and r.json()["chain"] == "base"

    listing = api_client.get("/api/address_labels").json()
    assert listing["labels"] == {}
    assert listing["chain_labels"]["base"][ADDR]["name"] == "Base Vault"


@requires_postgres
def test_three_rows_coexist(api_client, clean_labels):
    api_client.put(f"/api/address_labels/{ADDR}", json={"name": "Global"})
    api_client.put(f"/api/address_labels/{ADDR}?chain=ethereum", json={"name": "L1 Contract"})
    api_client.put(f"/api/address_labels/{ADDR}?chain=base", json={"name": "L2 Contract"})

    listing = api_client.get("/api/address_labels").json()
    assert listing["labels"][ADDR]["name"] == "Global"
    assert listing["chain_labels"]["ethereum"][ADDR]["name"] == "L1 Contract"
    assert listing["chain_labels"]["base"][ADDR]["name"] == "L2 Contract"
    assert clean_labels.query(AddressLabel).count() == 3


@requires_postgres
def test_upsert_is_idempotent_per_slot(api_client, clean_labels):
    api_client.put(f"/api/address_labels/{ADDR}?chain=base", json={"name": "First"})
    api_client.put(f"/api/address_labels/{ADDR}?chain=base", json={"name": "Second"})
    listing = api_client.get("/api/address_labels").json()
    assert listing["chain_labels"]["base"][ADDR]["name"] == "Second"
    assert clean_labels.query(AddressLabel).count() == 1


@requires_postgres
def test_delete_targets_the_right_row(api_client, clean_labels):
    api_client.put(f"/api/address_labels/{ADDR}", json={"name": "Global"})
    api_client.put(f"/api/address_labels/{ADDR}?chain=base", json={"name": "Base"})

    r = api_client.delete(f"/api/address_labels/{ADDR}")
    assert r.status_code == 200 and r.json()["chain"] is None

    listing = api_client.get("/api/address_labels").json()
    assert listing["labels"] == {}
    assert listing["chain_labels"]["base"][ADDR]["name"] == "Base"

    r = api_client.delete(f"/api/address_labels/{ADDR}?chain=base")
    assert r.status_code == 200 and r.json()["chain"] == "base"
    assert clean_labels.query(AddressLabel).count() == 0


@requires_postgres
def test_delete_missing_row_404(api_client, clean_labels):
    # Deleting a missing base override is a 404, not a silent hit on the global row.
    api_client.put(f"/api/address_labels/{ADDR}", json={"name": "Global"})
    assert api_client.delete(f"/api/address_labels/{ADDR}?chain=base").status_code == 404


@requires_postgres
def test_chain_alias_normalized(api_client, clean_labels):
    r = api_client.put(f"/api/address_labels/{ADDR}?chain=mainnet", json={"name": "Aliased"})
    assert r.status_code == 200 and r.json()["chain"] == "ethereum"
    listing = api_client.get("/api/address_labels").json()
    assert listing["chain_labels"]["ethereum"][ADDR]["name"] == "Aliased"


@requires_postgres
def test_unknown_chain_400(api_client, clean_labels):
    r = api_client.put(f"/api/address_labels/{ADDR}?chain=notachain", json={"name": "x"})
    assert r.status_code == 400 and "notachain" in r.json()["detail"]
    # The "unknown" discovery sentinel is not a labelable chain either.
    assert api_client.delete(f"/api/address_labels/{ADDR}?chain=unknown").status_code == 400
