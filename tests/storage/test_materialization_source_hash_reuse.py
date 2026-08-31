"""Cross-chain code-plane reuse (invariant 1) + chain-token normalization
(invariant 11) for ``contract_materializations``.

The ``(chain, bytecode_keccak)`` key reuses a bundle only across byte-identical
deployments. Per-chain immutables make the same source compile to different
bytecode, so a genuine cross-chain deployment misses on keccak. The
``source_content_hash`` reuse path closes that gap: the static_facts /
observation_plan / predicate_trees bundle is a pure function of the verified
source, so a ready row for the same source hash on any chain is copied into the
new deployment's row instead of paying the forge+Slither build again. State
(owner/roles/proxy impl/balances) is never shared — it stays per
``(chain, address)`` and is resolved separately.
"""

from __future__ import annotations

from typing import Any

import pytest

from db import contract_materializations as cm
from db.contract_materializations import STATIC_FACTS_SCHEMA_VERSION
from db.models import ContractMaterialization
from services.discovery.fetch import source_content_hash
from tests.conftest import requires_postgres

ADDR_MAINNET = "0x" + "a1" * 20
ADDR_BASE = "0x" + "b2" * 20
KECCAK_MAINNET = "0x" + "11" * 32
KECCAK_BASE = "0x" + "22" * 32  # different bytecode: immutables differ per chain


# ---------------------------------------------------------------------------
# Fixtures (mirror the pattern in test_contract_materializations_*)
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_cm(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()


@pytest.fixture()
def _route_to_test_db(monkeypatch):
    import os

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")

    engine = create_engine(test_url)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.contract_materializations.SessionLocal", factory)
    monkeypatch.setattr("db.contract_materializations.get_storage_client", lambda: None)
    yield
    engine.dispose()


def _bundle(name: str = "C") -> dict[str, Any]:
    return {
        "contract_name": name,
        "static_facts": {"subject": {"address": "0xwhatever", "name": name}, "functions": []},
        "observation_plan": {"contract_address": "0xwhatever", "controllers": []},
        "predicate_trees": {"schema_version": "semantic", "trees": {"pause()": {"node_type": "caller"}}},
    }


# ---------------------------------------------------------------------------
# source_content_hash — determinism + what it does and does not cover
# ---------------------------------------------------------------------------


def _flat_result(
    src: str = "contract C {}", *, name: str = "C", evm: str = "shanghai", opt: str = "1", runs: str = "200"
):
    return {"ContractName": name, "SourceCode": src, "EVMVersion": evm, "OptimizationUsed": opt, "Runs": runs}


def test_source_hash_is_deterministic():
    r = _flat_result()
    assert source_content_hash(r) == source_content_hash(dict(r))
    h = source_content_hash(r)
    assert h.startswith("0x") and len(h) == 66


def test_source_hash_order_independent_for_multi_file_bundle():
    import json

    def bundle(order):
        files = {"A.sol": {"content": "contract A {}"}, "B.sol": {"content": "contract B {}"}}
        sources = {k: files[k] for k in order}
        payload = {"language": "Solidity", "sources": sources, "settings": {"remappings": ["p=q", "x=y"]}}
        # Etherscan's standard-json double-brace wrapper: one extra brace each side.
        return {"ContractName": "A", "SourceCode": "{" + json.dumps(payload) + "}", "EVMVersion": "shanghai"}

    assert source_content_hash(bundle(["A.sol", "B.sol"])) == source_content_hash(bundle(["B.sol", "A.sol"]))


def test_source_hash_changes_with_source_and_compiler_inputs():
    base = source_content_hash(_flat_result())
    assert source_content_hash(_flat_result(src="contract C { uint x; }")) != base
    assert source_content_hash(_flat_result(evm="cancun")) != base
    assert source_content_hash(_flat_result(opt="0")) != base
    assert source_content_hash(_flat_result(runs="999")) != base


def test_source_hash_ignores_non_code_fields():
    """Deployment-specific metadata that is not a source-pipeline input must not
    change the hash — otherwise cross-chain reuse would never fire."""
    r = _flat_result()
    r2 = dict(r)
    r2["ContractCreationCode"] = "0xdeadbeef"  # constructor/immutable bytecode
    r2["ABI"] = "[]"
    assert source_content_hash(r2) == source_content_hash(r)


# ---------------------------------------------------------------------------
# Cross-chain reuse
# ---------------------------------------------------------------------------


@requires_postgres
def test_cross_chain_reuse_copies_bundle_and_skips_builder(_route_to_test_db, _clean_cm):
    src_hash = "0x" + "de" * 32

    built = {"n": 0}

    def build1() -> dict[str, Any]:
        built["n"] += 1
        return _bundle("Vault")

    row1 = cm.materialize_or_wait(
        chain="ethereum",
        address=ADDR_MAINNET,
        bytecode_keccak=KECCAK_MAINNET,
        builder=build1,
        source_hash_fn=lambda: src_hash,
    )
    assert row1.status == "ready"
    assert row1.chain == "1"
    assert row1.source_content_hash == src_hash
    assert built["n"] == 1

    def build2() -> dict[str, Any]:
        raise AssertionError("cross-chain reuse must skip the forge+Slither build")

    # Same source, Base deployment: different bytecode_keccak (immutables), so
    # keccak misses — reuse must fire off the source hash.
    row2 = cm.materialize_or_wait(
        chain="base",
        address=ADDR_BASE,
        bytecode_keccak=KECCAK_BASE,
        builder=build2,
        source_hash_fn=lambda: src_hash,
    )
    assert row2.status == "ready"
    assert row2.chain == "8453"
    assert row2.bytecode_keccak == KECCAK_BASE
    assert row2.address == ADDR_BASE
    assert row2.source_content_hash == src_hash
    # The CODE plane is reused byte-for-byte.
    assert cm.hydrate_static_facts(row2) == row1.static_facts
    assert cm.hydrate_observation_plan(row2) == row1.observation_plan
    assert cm.hydrate_predicate_trees(row2) == row1.predicate_trees
    # Two distinct rows: state stays per (chain, address).
    assert cm.find_by_keccak(_clean_cm, chain="base", bytecode_keccak=KECCAK_BASE) is not None
    assert cm.find_by_keccak(_clean_cm, chain="ethereum", bytecode_keccak=KECCAK_BASE) is None


@requires_postgres
def test_reuse_ignores_old_schema_version_donor(_route_to_test_db, _clean_cm):
    """A ready row with the same source hash but an OLDER static_facts_schema_version
    is not a reuse donor — the bundle shape may have changed, so we rebuild."""
    src_hash = "0x" + "ee" * 32
    stale = ContractMaterialization(
        chain="1",
        bytecode_keccak=KECCAK_MAINNET,
        address=ADDR_MAINNET,
        contract_name="Old",
        static_facts={"old": True},
        observation_plan={"old": True},
        source_content_hash=src_hash,
        status="ready",
        static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION + 1000,
    )
    _clean_cm.add(stale)
    _clean_cm.commit()

    built = {"n": 0}

    def build() -> dict[str, Any]:
        built["n"] += 1
        return _bundle("Fresh")

    row = cm.materialize_or_wait(
        chain="base",
        address=ADDR_BASE,
        bytecode_keccak=KECCAK_BASE,
        builder=build,
        source_hash_fn=lambda: src_hash,
    )
    assert built["n"] == 1, "old-version donor must not be reused"
    assert row.static_facts_schema_version == STATIC_FACTS_SCHEMA_VERSION
    assert row.contract_name == "Fresh"


@requires_postgres
def test_find_reusable_only_returns_ready(_route_to_test_db, _clean_cm):
    src_hash = "0x" + "ab" * 32
    for i, status in enumerate(("building", "failed")):
        _clean_cm.add(
            ContractMaterialization(
                chain="1",
                bytecode_keccak="0x" + status.encode().hex().ljust(64, "0")[:64],
                address="0x" + f"c{i}" * 20,
                source_content_hash=src_hash,
                status=status,
                static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
            )
        )
    _clean_cm.commit()
    assert cm.find_reusable_by_source_hash(_clean_cm, source_content_hash=src_hash) is None


@requires_postgres
def test_no_source_hash_fn_preserves_keccak_only_behaviour(_route_to_test_db, _clean_cm):
    """Without source_hash_fn (or when it returns None) the layer is the
    pre-reuse keccak cache: the row carries a NULL source hash and no
    cross-key reuse happens."""
    row = cm.materialize_or_wait(
        chain="ethereum",
        address=ADDR_MAINNET,
        bytecode_keccak=KECCAK_MAINNET,
        builder=lambda: _bundle("Plain"),
    )
    assert row.source_content_hash is None
    assert row.status == "ready"


# ---------------------------------------------------------------------------
# Invariant 11: one cache-key token format (decimal chain id)
# ---------------------------------------------------------------------------


@requires_postgres
def test_chain_key_normalized_to_decimal_id(_route_to_test_db, _clean_cm):
    row = cm.materialize_or_wait(
        chain="ethereum",
        address=ADDR_MAINNET,
        bytecode_keccak=KECCAK_MAINNET,
        builder=lambda: _bundle(),
    )
    assert row.chain == "1", "mainnet must be stored under the decimal-id token"

    # A name, an alias, the id string, and the int all resolve to the same row.
    for variant in ("ethereum", "mainnet", "1", 1):
        assert cm.find_by_keccak(_clean_cm, chain=variant, bytecode_keccak=KECCAK_MAINNET) is not None, variant
        assert cm.find_by_address(_clean_cm, chain=variant, address=ADDR_MAINNET) is not None, variant


@requires_postgres
def test_base_chain_name_and_id_agree(_route_to_test_db, _clean_cm):
    cm.materialize_or_wait(
        chain="base",
        address=ADDR_BASE,
        bytecode_keccak=KECCAK_BASE,
        builder=lambda: _bundle(),
    )
    by_name = cm.find_by_keccak(_clean_cm, chain="base", bytecode_keccak=KECCAK_BASE)
    by_id = cm.find_by_keccak(_clean_cm, chain="8453", bytecode_keccak=KECCAK_BASE)
    assert by_name is not None and by_id is not None
    assert by_name.chain == "8453"
