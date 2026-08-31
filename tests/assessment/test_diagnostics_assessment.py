"""Pipeline failures live in analysis receipts rather than claims."""

from __future__ import annotations

from types import SimpleNamespace

from services.assessment import add_stage_errors, build_static_assessment


def test_stage_error_adds_no_claim() -> None:
    assessment = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash=None,
        static_facts={"controller_tracking": []},
        effects={"schema_version": "semantic", "functions": {}},
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    before = set(assessment["claims"])
    enriched = add_stage_errors(
        assessment,
        [
            SimpleNamespace(
                stage="static",
                severity="degraded",
                exc_type="UnsupportedAssembly",
                message="could not lower pause gate",
            )
        ],
    )

    assert set(enriched["claims"]) == before
    receipt = enriched["analyses"][-1]
    assert receipt["detector"] == "stage.static"
    assert receipt["status"] == "partial"
    assert receipt["diagnostics"][0]["code"] == "UnsupportedAssembly"
