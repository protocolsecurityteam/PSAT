"""A build that failed deterministically is remembered per (chain, address, source hash, analyzer version), so later
callers get the failure without rebuilding; any other failure is rebuilt on the next request.
"""

from __future__ import annotations

from typing import Any

import pytest

from db import contract_materializations as cm
from db.models import ContractMaterialization
from tests.conftest import requires_postgres
from tests.support.materializations import cm_db  # noqa: F401  (fixture, registered by import)

CHAIN = "1"
ADDRESS = "0x" + "c4" * 20
KECCAK = "0x" + "4c" * 32
SOURCE_HASH = "0x" + "5d" * 32


class _Builder:
    def __init__(self, exc: Exception | None = None) -> None:
        self.calls = 0
        self.exc = exc

    def __call__(self) -> dict[str, Any]:
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return {
            "contract_name": "C",
            "analysis": {"subject": {"name": "C"}},
            "tracking_plan": {"contract_address": ADDRESS},
            "predicate_trees": {"schema_version": "semantic", "trees": {}},
        }


def _materialize(builder, *, address: str = ADDRESS, source_hash: str | None = SOURCE_HASH):
    return cm.materialize_or_wait(
        chain=CHAIN, address=address, bytecode_keccak=KECCAK, builder=builder, source_hash_fn=lambda: source_hash
    )


def _row(session) -> ContractMaterialization:
    session.expire_all()
    return session.query(ContractMaterialization).filter_by(chain=CHAIN, bytecode_keccak=KECCAK).one()


@requires_postgres
def test_a_deterministic_failure_is_served_without_rebuilding(cm_db):  # noqa: F811
    builder = _Builder(cm.DeterministicBuildFailure("ParserError 7858"))
    with pytest.raises(cm.DeterministicBuildFailure):
        _materialize(builder)
    row = _row(cm_db)
    assert (row.status, row.deterministic_failure, row.source_content_hash) == ("failed", True, SOURCE_HASH)

    with pytest.raises(cm.RememberedBuildFailure, match="ParserError 7858"):
        _materialize(builder)
    assert builder.calls == 1
    assert _row(cm_db).status == "failed"


@requires_postgres
def test_a_transient_failure_is_rebuilt(cm_db):  # noqa: F811
    builder = _Builder(RuntimeError("etherscan rate limited"))
    for _ in range(2):
        with pytest.raises(RuntimeError, match="rate limited"):
            _materialize(builder)
    assert builder.calls == 2
    assert _row(cm_db).deterministic_failure is False


@pytest.mark.parametrize(
    "second_call",
    [
        pytest.param({"source_hash": "0x" + "6e" * 32}, id="source_changed"),
        pytest.param({"source_hash": None}, id="source_not_determined"),
        pytest.param({"address": "0x" + "d5" * 20}, id="other_address"),
    ],
)
@requires_postgres
def test_a_remembered_failure_needs_the_same_key(cm_db, second_call):  # noqa: F811
    with pytest.raises(cm.DeterministicBuildFailure):
        _materialize(_Builder(cm.DeterministicBuildFailure("boom")))
    rebuilt = _Builder()
    row = _materialize(rebuilt, **second_call)
    assert rebuilt.calls == 1
    assert (row.status, row.deterministic_failure) == ("ready", False)


@requires_postgres
def test_a_new_analyzer_version_rebuilds(cm_db, monkeypatch):  # noqa: F811
    with pytest.raises(cm.DeterministicBuildFailure):
        _materialize(_Builder(cm.DeterministicBuildFailure("boom")))
    monkeypatch.setattr(cm, "ANALYSIS_SCHEMA_VERSION", cm.ANALYSIS_SCHEMA_VERSION + 1)
    rebuilt = _Builder()
    assert _materialize(rebuilt).status == "ready"
    assert rebuilt.calls == 1
