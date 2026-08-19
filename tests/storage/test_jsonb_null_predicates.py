"""The jsonb-null audit, as an enforced invariant rather than a one-off sweep.

Two halves:

1. :func:`test_no_sql_null_test_over_a_jsonb_column` re-runs the audit on every
   commit. A SQL null test over a JSONB column is true for the jsonb scalar
   ``null`` as well as for a real payload, so any "does this row carry
   evidence?" filter written that way is inflated. Before this module landed the
   scan reported five offenders (two in ``deferred_reconciler``, two in
   ``company_overview``, one in ``coverage``).

2. :func:`test_jsonb_state_separates_all_three_states` pins the behaviour the
   fix depends on against a real Postgres round-trip: the three states exist,
   ``db.jsonb`` separates them, and the predicate it replaces does not.

Known limits of the scan, stated rather than papered over:

* It resolves a column by *attribute name*, so ``col = Model.conditions``
  followed by ``col.is_not(None)`` is invisible to it. The DB test below uses
  exactly that form on purpose, to hold the naive predicate for comparison.
* ``alembic/versions/`` is out of scope. Those files are applied history; a
  migration's predicate described the database as it was on the day it ran.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest
from sqlalchemy import JSON, select
from sqlalchemy.orm import Session

from db.jsonb import JSONB_UNSET, JSONB_WRITTEN_NULL, jsonb_has_payload, jsonb_state
from db.models import Base, ContractMaterialization

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# The audited scope, plus ``tests`` — a fixture that asserts an
# inflated count is as wrong as production code that produces one.
SCANNED_DIRS = ("services", "routers", "workers", "db", "scripts", "tests")

# SQLAlchemy spells the ORM-side null test three ways; all compile identically.
NULL_TEST_METHODS = frozenset({"is_", "isnot", "is_not"})


def _jsonb_column_names() -> frozenset[str]:
    """Every JSONB column name in the schema, from the metadata.

    Read off the mapper rather than hardcoded, so a new JSONB column is covered
    the day it is added instead of the day someone remembers to list it.
    """
    names = {c.name for t in Base.metadata.tables.values() for c in t.columns if isinstance(c.type, JSON)}
    assert "conditions" in names and "witness" in names, "metadata scan found no known JSONB columns"
    return frozenset(names)


def _sql_null_test_pattern(columns: frozenset[str]) -> re.Pattern[str]:
    """Raw-SQL form: an optionally table-qualified column followed by a null test."""
    return re.compile(r"\b(?:\w+\.)?(" + "|".join(sorted(columns)) + r")\s+is\s+(?:not\s+)?null\b", re.IGNORECASE)


def _typeof_guarded(sql: str, column: str) -> bool:
    """Does this statement already discriminate the jsonb scalar null itself?

    ``x is null or jsonb_typeof(x) = 'null'`` is the correct long form of
    :func:`db.jsonb.jsonb_has_payload`'s negation. Flagging it would train
    readers to ignore the check.
    """
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
    """The scan is not vacuous — it fires on both forms it claims to catch."""
    # Assembled, not written out whole: a literal offending statement in this
    # file would be a real finding for the scan above, and silencing that with
    # a self-exemption would blind the scan to the rest of the file.
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
    """Three rows, one per state of a JSONB column, then clean up.

    ``contract_materializations`` is the fixture table because production holds
    all three states in it today (75 written-null, 6 unset, 1 payload) and
    because it has no foreign keys, so the rows stand alone.
    """
    from sqlalchemy import null

    rows = [
        ContractMaterialization(
            chain="w0-5-payload", bytecode_keccak="0x" + "1" * 64, address="0x" + "1" * 40, analysis={"trees": 1}
        ),
        # A Python ``None`` into a JSONB column: SQLAlchemy's default
        # ``none_as_null=False`` stores the jsonb scalar null, not SQL NULL.
        # This is how 5770/5770 ``artifacts.data`` rows got their value.
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


def test_jsonb_state_separates_all_three_states(db_session: Session, _materializations: list[str]) -> None:
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


def test_jsonb_has_payload_selects_the_payload_row(db_session: Session, _materializations: list[str]) -> None:
    """The positive case: a row that really carries a tree stays selected."""
    scoped = ContractMaterialization.chain.in_(_materializations)
    selected = db_session.scalars(
        select(ContractMaterialization.chain).where(scoped, jsonb_has_payload(ContractMaterialization.analysis))
    ).all()
    assert list(selected) == ["w0-5-payload"]


def test_written_null_and_unset_are_separately_addressable(db_session: Session, _materializations: list[str]) -> None:
    """R1: the two empty states are different facts and stay distinguishable.

    "A writer ran and recorded no value" is evidence about the writer; "nothing
    was ever written here" is not. Collapsing them is how an unpopulated column
    reads as a proven absence.
    """
    scoped = ContractMaterialization.chain.in_(_materializations)
    written_null = db_session.scalars(
        select(ContractMaterialization.chain).where(
            scoped, jsonb_state(ContractMaterialization.analysis) == JSONB_WRITTEN_NULL
        )
    ).all()
    unset = db_session.scalars(
        select(ContractMaterialization.chain).where(
            scoped, jsonb_state(ContractMaterialization.analysis) == JSONB_UNSET
        )
    ).all()
    assert list(written_null) == ["w0-5-written-null"]
    assert list(unset) == ["w0-5-unset"]


def test_the_replaced_predicate_over_counts(db_session: Session, _materializations: list[str]) -> None:
    """The defect being fixed, pinned so a revert is loud.

    Bound through a local name so the scan above does not flag this file; that
    binding is also the scan's documented blind spot.
    """
    column = ContractMaterialization.analysis
    scoped = ContractMaterialization.chain.in_(_materializations)
    naive = db_session.scalars(select(ContractMaterialization.chain).where(scoped, column.is_not(None))).all()
    assert sorted(naive) == ["w0-5-payload", "w0-5-written-null"]
