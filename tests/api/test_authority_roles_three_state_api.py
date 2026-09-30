"""``authority_roles`` is three-state on both published surfaces: a list is witnessed, jsonb ``null`` is
role-gated with the role not determined, ``[]`` is proven not role-gated.

``/functions`` used to seed a list on every path, so ``null`` never reached it.
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

# The three states plus an unreadable shape, which both surfaces must serve as not-determined.
COLUMN_BY_FUNCTION: dict[str, Any] = {
    "roleGated()": None,  # role-gated, role NOT determined
    "ownerOnly()": [],  # proven not role-gated
    "witnessed()": [{"role": 7, "principals": [{"address": ROLE_MEMBER, "details": {}}]}],
    "unreadable()": ["admin"],  # non-object members: unreadable, NOT witnessed
}

EXPECTED_STATE: dict[str, str] = {
    "roleGated()": "not_determined",
    "ownerOnly()": "proven_absent",
    "witnessed()": "witnessed",
    "unreadable()": "not_determined",
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
        # ``principal_type='controller'`` is on 100% of production rows and makes the role fold fall through to the
        # column.
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
    """Collapsing any pair of states passes only one of these."""
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
    assert entries["unreadable()"]["authority_roles"] is None


def test_the_two_surfaces_agree_on_every_row(api_client, three_state_rows):
    """Compared as states, since the company endpoint also enriches principals with their type."""
    job, _contract = three_state_rows

    company = _by_signature(
        api_client.get(f"/api/company/{COMPANY}/functions").json()["functions"][f"ethereum::{ADDR.lower()}"]
    )
    analyses = _by_signature(api_client.get(f"/api/analyses/{job.id}").json()["effective_permissions"]["functions"])

    def state(value: Any) -> str:
        if value is None:
            return "not_determined"
        return "proven_absent" if value == [] else "witnessed"

    for signature in COLUMN_BY_FUNCTION:
        assert state(company[signature]["authority_roles"]) == state(analyses[signature]["authority_roles"]), signature
        assert state(company[signature]["authority_roles"]) == EXPECTED_STATE[signature], signature


def test_undetermined_roles_are_jsonb_null_not_sql_null(db_session, three_state_rows):
    """Without ``none_as_null`` a Python ``None`` is stored as jsonb ``null``, so ``IS NULL`` never finds it."""
    _job, contract = three_state_rows

    sql_null, jsonb_null = db_session.execute(
        text(
            "SELECT count(*) FILTER (WHERE authority_roles IS NULL),"
            "       count(*) FILTER (WHERE jsonb_typeof(authority_roles) = 'null') "
            "FROM effective_functions WHERE contract_id = :c"
        ),
        {"c": contract.id},
    ).one()

    assert sql_null == 0
    assert jsonb_null == 1
