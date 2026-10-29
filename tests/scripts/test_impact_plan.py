import copy

import pytest

from services.clients.jev import JevClient
from services.logic.expansion import Selection
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import JudgmentCache
from services.resolution.logic_selection import selections_from_report
from tests.logic.test_impact import Session, inputs


def rated(tmp_path):
    _, artifact, report = inputs()
    result = assess_formulas(
        artifact, cache=JudgmentCache(tmp_path), client=JevClient("test-secret", session=Session())
    )
    return artifact, result


def test_reviewed_impact_plan_is_explicit_and_source_bound(tmp_path):
    artifact, report = rated(tmp_path)
    before = copy.deepcopy((artifact, report))
    assert selections_from_report(artifact, report) == {"change(uint256)": Selection(False, (0,))}
    assert (artifact, report) == before
    assert report["automatic_execution"] is False


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(block=999),
        lambda r: r["suggested_expansions"][0].update(formula_hash="stale"),
        lambda r: r["rows"][0].update(decision="review"),
        lambda r: r["suggested_expansions"][0].update(callers=True),
        lambda r: r["rows"].append(copy.deepcopy(r["rows"][0])),
    ],
)
def test_changed_or_unreviewed_targets_cannot_be_executed(tmp_path, change):
    artifact, report = rated(tmp_path)
    change(report)
    with pytest.raises(ValueError):
        selections_from_report(artifact, report)


def test_cli_executes_only_the_explicit_plan_and_preserves_inputs(tmp_path, monkeypatch):
    import json
    from contextlib import nullcontext

    from scripts.logic import main

    artifact, report = rated(tmp_path / "cache")
    source, plan, output = (tmp_path / name for name in ("formulas.json", "impact.json", "addresses.json"))
    source.write_text(json.dumps(artifact))
    plan.write_text(json.dumps(report))
    before = (source.read_bytes(), plan.read_bytes())
    calls = []
    monkeypatch.setattr("db.models.SessionLocal", lambda: nullcontext(None))

    def expand(session, saved, rpc_url, selections, *, limits):
        calls.append(selections)
        assert saved == artifact
        return {"kind": "address_expansions"}

    monkeypatch.setattr("services.logic.deployment.deployment_expansions", expand)
    args = ["enumerate", str(source), "--assessment", str(plan), "--rpc-url", "unused", "--output", str(output)]
    main(args)
    assert calls == [{"change(uint256)": Selection(False, (0,))}]
    assert (source.read_bytes(), plan.read_bytes()) == before
    assert json.loads(output.read_text())["kind"] == "address_expansions"
    report["block"] += 1
    plan.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        main(args)
    assert len(calls) == 1  # Invalid plans fail before the expansion provider is invoked.
