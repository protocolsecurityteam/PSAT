"""``authority_roles`` keeps its three states across BOTH published surfaces.

``effective_functions.authority_roles`` is three-state (see
``schemas/effective_permissions.EffectiveFunctionPermission``): a non-empty list
is a WITNESSED role requirement, jsonb ``null`` is role-gated with the role NOT
determined, ``[]`` is proven not role-gated. ``[]`` is the NEGATION of what
``null`` asserts, not a coarsening of it.

Two endpoints publish the same rows and disagreed. ``/api/analyses/{job}``
(``services/aggregations/analysis_detail``) passed the column through;
``/api/company/{name}/functions``
(``services/governance/principals._build_company_function_entry``) seeded its
result with ``list(authority_roles_by_key.values())`` — a list on every path,
including the "witnessed nothing" one that every row takes
(``function_principals.principal_type`` is ``controller`` on 100% of rows) — so
the column's ``null`` could not reach the payload. On the ether.fi preview the
company endpoint served 0 nulls over 1,109 rows whose pool holds 324.

These tests pin the POSITIVE case of all three states on both endpoints, and
that the two endpoints agree row-for-row.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import text

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Job, JobStage, JobStatus, Protocol

COMPANY = "three_state_roles_co"
ADDR = "0x" + "5a" * 20
ROLE_MEMBER = "0x" + "b1" * 20

# The three column values under test, keyed by the function that carries each.
COLUMN_BY_FUNCTION: dict[str, Any] = {
    "roleGated()": None,  # role-gated, role NOT determined
    "ownerOnly()": [],  # proven not role-gated
    "witnessed()": [{"role": 7, "principals": [{"address": ROLE_MEMBER, "details": {}}]}],
}


@pytest.fixture
def three_state_rows(db_session):
    protocol = Protocol(name=COMPANY)
    db_session.add(protocol)
    db_session.flush()

    job = Job(
        id=uuid.uuid4(),
        address=ADDR,
        company=COMPANY,
        name="ThreeState",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"chain": "ethereum"},
        protocol_id=protocol.id,
    )
    db_session.add(job)
    db_session.flush()

    contract = Contract(
        job_id=job.id,
        protocol_id=protocol.id,
        address=ADDR,
        chain="ethereum",
        contract_name="ThreeState",
        is_proxy=False,
        source_verified=True,
    )
    db_session.add(contract)
    db_session.flush()

    for signature, column_value in COLUMN_BY_FUNCTION.items():
        ef = EffectiveFunction(
            contract_id=contract.id,
            function_name=signature.rstrip("()"),
            selector="0x" + f"{abs(hash(signature)) % (16**8):08x}",
            abi_signature=signature,
            effect_labels=[],
            effect_targets=[],
            action_summary="Performs a contract action.",
            authority_public=False,
            authority_roles=column_value,
        )
        db_session.add(ef)
        db_session.flush()
        # A controller principal on every row: ``principal_type='controller'``
        # is what 100% of production rows carry, and it is the shape that made
        # the company endpoint's role fold witness nothing and fall through to
        # the column. Without it the test would exercise a path production
        # never takes.
        db_session.add(
            FunctionPrincipal(
                function_id=ef.id,
                address="0x" + "c0" * 20,
                resolved_type="contract",
                origin="roleRegistry",
                principal_type="controller",
                details={},
            )
        )
    db_session.commit()
    try:
        yield job, contract
    finally:
        db_session.rollback()
        db_session.execute(text("DELETE FROM contracts WHERE protocol_id = :p"), {"p": protocol.id})
        db_session.execute(text("DELETE FROM jobs WHERE company = :c"), {"c": COMPANY})
        db_session.execute(text("DELETE FROM protocols WHERE id = :p"), {"p": protocol.id})
        db_session.commit()


def _by_signature(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["function"]: entry for entry in entries}


def test_company_functions_serves_all_three_authority_roles_states(api_client, three_state_rows):
    """The POSITIVE case for each state, not just the hedge: the ``null`` row
    must serve ``null``, the ``[]`` row must serve ``[]``, and the witnessed row
    must serve its grant. Collapsing any pair passes only one of these."""
    _job, _contract = three_state_rows

    body = api_client.get(f"/api/company/{COMPANY}/functions")
    assert body.status_code == 200
    entries = _by_signature(body.json()["functions"][f"ethereum::{ADDR.lower()}"])
    assert set(entries) == set(COLUMN_BY_FUNCTION)

    assert entries["roleGated()"]["authority_roles"] is None
    assert entries["ownerOnly()"]["authority_roles"] == []
    witnessed = entries["witnessed()"]["authority_roles"]
    assert isinstance(witnessed, list) and [g["role"] for g in witnessed] == [7]
    assert [p["address"] for g in witnessed for p in g["principals"]] == [ROLE_MEMBER]


def test_analyses_detail_serves_all_three_authority_roles_states(api_client, three_state_rows):
    job, _contract = three_state_rows

    body = api_client.get(f"/api/analyses/{job.id}")
    assert body.status_code == 200
    entries = _by_signature(body.json()["effective_permissions"]["functions"])

    assert entries["roleGated()"]["authority_roles"] is None
    assert entries["ownerOnly()"]["authority_roles"] == []
    assert [g["role"] for g in entries["witnessed()"]["authority_roles"]] == [7]


def test_the_two_surfaces_agree_on_every_row(api_client, three_state_rows):
    """The contradiction this file exists for: the same DB row served two ways.
    Compared as the three STATES rather than by deep equality — the company
    endpoint enriches a witnessed grant's principals with their classified type,
    which analysis_detail does not do."""
    job, _contract = three_state_rows

    company = _by_signature(api_client.get(f"/api/company/{COMPANY}/functions").json()["functions"][
        f"ethereum::{ADDR.lower()}"
    ])
    analyses = _by_signature(api_client.get(f"/api/analyses/{job.id}").json()["effective_permissions"]["functions"])

    def state(value: Any) -> str:
        if value is None:
            return "not_determined"
        return "proven_absent" if value == [] else "witnessed"

    for signature in COLUMN_BY_FUNCTION:
        assert state(company[signature]["authority_roles"]) == state(analyses[signature]["authority_roles"]), signature
        # …and each equals the state the column itself holds.
        assert state(company[signature]["authority_roles"]) == state(COLUMN_BY_FUNCTION[signature]), signature


# ---------------------------------------------------------------------------
# The storage encoding the column comment asserts. Both halves are load-bearing:
# a query written against the wrong one returns an empty result that reads as
# "nothing is undetermined".
# ---------------------------------------------------------------------------


def test_undetermined_roles_are_jsonb_null_not_sql_null(db_session, three_state_rows):
    """``mapped_column(JSONB)`` without ``none_as_null`` writes a Python ``None``
    as the jsonb SCALAR ``null``, so ``IS NULL`` never finds the undetermined
    rows. This is what the column comment tells a reader to use instead."""
    _job, contract = three_state_rows

    sql_null = db_session.execute(
        text("SELECT count(*) FROM effective_functions WHERE contract_id = :c AND authority_roles IS NULL"),
        {"c": contract.id},
    ).scalar_one()
    jsonb_null = db_session.execute(
        text(
            "SELECT count(*) FROM effective_functions "
            "WHERE contract_id = :c AND jsonb_typeof(authority_roles) = 'null'"
        ),
        {"c": contract.id},
    ).scalar_one()

    assert sql_null == 0
    assert jsonb_null == 1


@pytest.mark.parametrize("column", ["authority_public", "authority_roles", "authority_openness"])
def test_authority_columns_carry_their_column_comment(db_session, column):
    """The three-state semantics live in the DB, where an operator reading the
    schema meets them. ``authority_openness`` was commented and the two columns
    a consumer actually folds were not."""
    comment = db_session.execute(
        text(
            "SELECT col_description(a.attrelid, a.attnum) FROM pg_attribute a "
            "WHERE a.attrelid = 'effective_functions'::regclass AND a.attname = :n"
        ),
        {"n": column},
    ).scalar_one()
    assert comment, f"effective_functions.{column} carries no column comment"
