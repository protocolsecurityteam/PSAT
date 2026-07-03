"""End-to-end integration for the Plane-1 claims plumbing.

Drives the real production stack — the static pipeline
(``collect_contract_analysis_with_artifacts``, i.e. Slither -> effects ->
authority labels -> the new claims phase in ``core.py``), the effective-
permissions dual-write, the row writer, and the API serializers — on a real
compiled factory fixture, and asserts a ``contract_deployment`` claim survives
onto the ``EffectiveFunction.claims`` column and out through the payloads. Only
the solc binary + Postgres are external; nothing under test is faked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("slither")

from tests.conftest import requires_postgres  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "contracts"


def _write_project(tmp_path: Path, contract_name: str, source_code: str) -> Path:
    """Minimal Foundry scaffold the static pipeline can compile (mirrors the
    ``test_contract_analysis`` helper: solc 0.8.19, no build output)."""
    project_dir = tmp_path / contract_name
    (project_dir / "src").mkdir(parents=True)
    (project_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "src" / f"{contract_name}.sol").write_text(source_code)
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x1111111111111111111111111111111111111111",
                "contract_name": contract_name,
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
        + "\n"
    )
    (project_dir / "slither_results.json").write_text(json.dumps({"results": {"detectors": []}}) + "\n")
    return project_dir


def _has_deploy_claim(claims: object) -> bool:
    return isinstance(claims, list) and any(
        isinstance(c, dict) and c.get("claim_id") == "contract_deployment" and c.get("tier") == "standard_exact"
        for c in claims
    )


@requires_postgres
def test_claims_flow_from_static_pipeline_to_effective_function_row(tmp_path, db_session):
    from db.models import Contract, EffectiveFunction
    from services.aggregations.analysis_detail import _serialize_effective_functions
    from services.governance.principals import _build_company_function_entry
    from services.policy.effective_permissions import build_effective_permissions
    from services.policy.effective_permissions_writer import write_effective_function_rows
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    source = (FIXTURES_DIR / "composed" / "upgrade_factory_uups.sol").read_text()
    project_dir = _write_project(tmp_path, "UpgradeFactory", source)

    # (1) The static pipeline's claims phase minted a claim onto the effects
    #     facts carrier (the real core.py invocation, not a stub).
    analysis, predicate_trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None
    create_effect = effects["functions"]["createChild()"]
    assert _has_deploy_claim(create_effect.get("claims")), create_effect.get("claims")
    # A non-deploying function carries an (empty) claims list — the field is
    # always present, never a KeyError downstream.
    assert all("claims" in rec for rec in effects["functions"].values())

    # (2) Dual-write: build_effective_permissions carries claims per function
    #     alongside the untouched legacy effect_labels.
    payload = build_effective_permissions(analysis, effects=effects, predicate_trees=predicate_trees)
    create_record = next(r for r in payload["functions"] if r["function"] == "createChild()")
    assert _has_deploy_claim(create_record.get("claims"))
    assert "contract_deployment" in create_record["effect_labels"]  # legacy label unchanged

    # (3) The writer round-trips claims onto the real EffectiveFunction column.
    contract = Contract(
        address=analysis["subject"]["address"],
        chain="ethereum",
        contract_name=analysis["subject"]["name"],
    )
    db_session.add(contract)
    db_session.commit()

    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast(list[dict[str, Any]], payload["functions"]),
        capability_by_function=None,
    )
    db_session.commit()

    row = (
        db_session.query(EffectiveFunction)
        .filter(EffectiveFunction.contract_id == contract.id, EffectiveFunction.function_name == "createChild")
        .one()
    )
    assert _has_deploy_claim(row.claims)

    # (4) API pass-throughs expose the field on both serializers.
    detail_entry = next(e for e in _serialize_effective_functions([row]) if e["function"].startswith("createChild"))
    assert _has_deploy_claim(detail_entry["claims"])

    company_entry = _build_company_function_entry(row, list(row.principals or []))
    assert _has_deploy_claim(company_entry["claims"])
