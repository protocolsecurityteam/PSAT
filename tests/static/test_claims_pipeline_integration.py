"""End-to-end integration for the Plane-1 claims plumbing.

Drives the real production stack — the static pipeline
(``collect_static_inputs``, i.e. Slither -> effects ->
authority labels -> the new claims phase in ``core.py``), the effective-
permissions dual-write, the row writer, and the API serializers — on a real
compiled factory fixture, and asserts a ``contract_deployment`` claim survives
onto the ``EffectiveFunction.claims`` column and out through the payloads. Only
the solc binary + Postgres are external; nothing under test is faked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("slither")

from tests.conftest import requires_postgres
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts"


def _has_deploy_claim(claims: object) -> bool:
    return isinstance(claims, list) and any(
        isinstance(c, dict) and c.get("claim_id") == "contract_deployment" and c.get("tier") == "standard_exact"
        for c in claims
    )


@requires_postgres
def test_claims_flow_from_static_pipeline_to_effective_function_row(tmp_path, db_session):
    from db.models import Contract, EffectiveFunction
    from services.governance.principals import _build_company_function_entry
    from services.policy.permission_index import build_permission_index
    from services.policy.permission_index_writer import write_permission_rows
    from services.static.static_analysis import collect_static_inputs

    source = (FIXTURES_DIR / "composed" / "upgrade_factory_uups.sol").read_text()
    project_dir = write_foundry_project(tmp_path, "UpgradeFactory", source)

    # (1) The static pipeline's claims phase minted a claim onto the effects
    #     facts carrier (the real core.py invocation, not a stub).
    analysis, predicate_trees, effects = collect_static_inputs(project_dir)
    assert effects is not None
    create_effect = effects["functions"]["createChild()"]
    assert _has_deploy_claim(create_effect.get("claims")), create_effect.get("claims")
    # A non-deploying function carries an (empty) claims list — the field is
    # always present, never a KeyError downstream.
    assert all("claims" in rec for rec in effects["functions"].values())

    # (2) The permission index carries claims per function.
    payload = build_permission_index(analysis, effects=effects, predicate_trees=predicate_trees)
    create_record = next(r for r in payload["functions"] if r["function"] == "createChild()")
    assert _has_deploy_claim(create_record.get("claims"))

    # (3) The writer round-trips claims onto the real EffectiveFunction column.
    contract = Contract(
        address=analysis["subject"]["address"],
        chain="ethereum",
        contract_name=analysis["subject"]["name"],
    )
    db_session.add(contract)
    db_session.commit()

    write_permission_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast(list[dict[str, Any]], payload["functions"]),
    )
    db_session.commit()

    row = (
        db_session.query(EffectiveFunction)
        .filter(EffectiveFunction.contract_id == contract.id, EffectiveFunction.function_name == "createChild")
        .one()
    )
    assert _has_deploy_claim(row.claims)

    # (4) API pass-throughs expose the field on both serializers.
    company_entry = _build_company_function_entry(row, list(row.principals or []))
    assert _has_deploy_claim(company_entry["claims"])
