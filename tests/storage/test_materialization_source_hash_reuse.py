"""Cross-chain code-plane reuse + chain-token normalization for
``contract_materializations``.

The ``(chain, bytecode_keccak)`` key reuses a bundle only across byte-identical deployments, but
per-chain immutables make one source compile to different bytecode. The ``source_content_hash``
path closes that gap: the analysis / tracking_plan / predicate_trees bundle is a pure function of
the verified source, so a ready row for the same hash on any chain is copied instead of rebuilt.
State (owner/roles/proxy impl/balances) is never shared; it stays per ``(chain, address)``.
"""

from __future__ import annotations

from typing import Any

import pytest

from db import contract_materializations as cm
from services.discovery.fetch import source_content_hash
from tests.conftest import requires_postgres
from tests.support.materializations import _clean_cm  # noqa: F401  (fixture, registered by import)

ADDR_MAINNET = "0x" + "a1" * 20
ADDR_BASE = "0x" + "b2" * 20
KECCAK_MAINNET = "0x" + "11" * 32
KECCAK_BASE = "0x" + "22" * 32  # different bytecode: immutables differ per chain


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
        "analysis": {"subject": {"address": "0xwhatever", "name": name}, "functions": []},
        "tracking_plan": {"contract_address": "0xwhatever", "controllers": []},
        "predicate_trees": {"schema_version": "semantic", "trees": {"pause()": {"node_type": "caller"}}},
    }


def _flat_result(
    src: str = "contract C {}", *, name: str = "C", evm: str = "shanghai", opt: str = "1", runs: str = "200"
):
    return {"ContractName": name, "SourceCode": src, "EVMVersion": evm, "OptimizationUsed": opt, "Runs": runs}


def test_source_hash_changes_with_source_and_compiler_inputs():
    base = source_content_hash(_flat_result())
    assert source_content_hash(_flat_result(src="contract C { uint x; }")) != base
    assert source_content_hash(_flat_result(evm="cancun")) != base
    assert source_content_hash(_flat_result(opt="0")) != base
    assert source_content_hash(_flat_result(runs="999")) != base


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
    assert cm.hydrate_analysis(row2) == row1.analysis
    assert cm.hydrate_tracking_plan(row2) == row1.tracking_plan
    assert cm.hydrate_predicate_trees(row2) == row1.predicate_trees
    assert cm.find_by_keccak(_clean_cm, chain="base", bytecode_keccak=KECCAK_BASE) is not None
    assert cm.find_by_keccak(_clean_cm, chain="ethereum", bytecode_keccak=KECCAK_BASE) is None


# ---------------------------------------------------------------------------
# One cache-key token format (decimal chain id)
# ---------------------------------------------------------------------------
