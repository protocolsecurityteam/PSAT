"""A SQL null test over JSONB is also true for the jsonb scalar ``null``, inflating "has evidence" filters (five
offenders before this). The scan resolves columns by attribute name, so ``col = Model.x; col.is_not(None)`` is
invisible to it; ``alembic/versions/`` is out of scope.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest
from sqlalchemy import JSON, select
from sqlalchemy.orm import Session

from db.jsonb import jsonb_has_payload, jsonb_state
from db.models import Base, ContractMaterialization

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# A fixture asserting an inflated count is as wrong as code producing one.
SCANNED_DIRS = ("services", "routers", "workers", "db", "scripts", "tests")

NULL_TEST_METHODS = frozenset({"is_", "isnot", "is_not"})


def _jsonb_column_names() -> frozenset[str]:
    names = {c.name for t in Base.metadata.tables.values() for c in t.columns if isinstance(c.type, JSON)}
    assert "conditions" in names and "witness" in names, "metadata scan found no known JSONB columns"
    return frozenset(names)


def _sql_null_test_pattern(columns: frozenset[str]) -> re.Pattern[str]:
    return re.compile(r"\b(?:\w+\.)?(" + "|".join(sorted(columns)) + r")\s+is\s+(?:not\s+)?null\b", re.IGNORECASE)


def _typeof_guarded(sql: str, column: str) -> bool:
    """Flagging the correct long form would train readers to ignore the check."""
    return re.search(r"jsonb_typeof\(\s*(?:\w+\.)?" + column + r"\b", sql, re.IGNORECASE) is not None


def _scan() -> list[str]:
    columns = _jsonb_column_names()
    sql_pattern = _sql_null_test_pattern(columns)
    findings: list[str] = []
    for directory in SCANNED_DIRS:
        for path in sorted((REPO_ROOT / directory).rglob("*.py")):
            source = path.read_text()
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            rel = path.relative_to(REPO_ROOT)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in NULL_TEST_METHODS
                    and len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value is None
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr in columns
                ):
                    findings.append(f"{rel}:{node.lineno}: {ast.unparse(node)}")
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    for match in sql_pattern.finditer(node.value):
                        if _typeof_guarded(node.value, match.group(1)):
                            continue
                        findings.append(f"{rel}:{node.lineno}: {match.group(0).strip()}")
    return findings


def test_no_sql_null_test_over_a_jsonb_column() -> None:
    findings = _scan()
    assert not findings, (
        "A SQL null test over a JSONB column also matches the jsonb scalar null, "
        "which is what a write of a Python None stores. Use db.jsonb.jsonb_has_payload "
        "(payload only) or jsonb_state (all three states):\n  " + "\n  ".join(findings)
    )


def test_scan_detects_a_planted_offender(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Assembled so this file doesn't contain a literal finding.
    bad_sql = "conditions " + "is not " + "null"
    planted = tmp_path / "services" / "planted.py"
    planted.parent.mkdir(parents=True)
    planted.write_text(
        "from db.models import EffectiveFunction\n"
        "orm = EffectiveFunction.conditions.isnot(None)\n"
        f'raw = "select 1 from effective_functions where {bad_sql}"\n'
    )
    monkeypatch.setitem(globals(), "REPO_ROOT", tmp_path)
    monkeypatch.setitem(globals(), "SCANNED_DIRS", ("services",))
    findings = _scan()
    assert len(findings) == 2, findings
    assert any("isnot(None)" in f for f in findings)
    assert any(bad_sql in f for f in findings)


@pytest.fixture()
def _materializations(db_session: Session):
    """Production has all three states here (75 written-null, 6 unset, 1 payload) and no foreign keys."""
    from sqlalchemy import null

    rows = [
        ContractMaterialization(
            chain="w0-5-payload", bytecode_keccak="0x" + "1" * 64, address="0x" + "1" * 40, analysis={"trees": 1}
        ),
        # ``none_as_null=False`` stores the jsonb scalar null; that's how 5770/5770 ``artifacts.data`` rows got theirs.
        ContractMaterialization(
            chain="w0-5-written-null", bytecode_keccak="0x" + "2" * 64, address="0x" + "2" * 40, analysis=None
        ),
        ContractMaterialization(
            chain="w0-5-unset", bytecode_keccak="0x" + "3" * 64, address="0x" + "3" * 40, analysis=null()
        ),
    ]
    db_session.add_all(rows)
    db_session.commit()
    chains = [r.chain for r in rows]
    try:
        yield chains
    finally:
        db_session.rollback()
        db_session.query(ContractMaterialization).filter(ContractMaterialization.chain.in_(chains)).delete(
            synchronize_session=False
        )
        db_session.commit()


def test_jsonb_state_separates_three_states_and_has_payload_selects_one(
    db_session: Session, _materializations: list[str]
) -> None:
    scoped = ContractMaterialization.chain.in_(_materializations)
    rows = db_session.execute(
        select(ContractMaterialization.chain, jsonb_state(ContractMaterialization.analysis)).where(scoped)
    ).all()
    states = {row[0]: row[1] for row in rows}
    assert states == {
        "w0-5-payload": "object",
        "w0-5-written-null": "null",
        "w0-5-unset": "unset",
    }

    selected = db_session.scalars(
        select(ContractMaterialization.chain).where(scoped, jsonb_has_payload(ContractMaterialization.analysis))
    ).all()
    assert list(selected) == ["w0-5-payload"]
