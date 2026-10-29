import json

import pytest

from scripts.logic_select import main
from services.logic.model import Effect, Formula, encode
from services.logic.terms import CALLER, const, mk_cmp


def test_offline_cli_only_writes_a_selection_report(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("selection performed a side effect")

    monkeypatch.setattr("services.logic.expansion.expand_formula", forbidden)
    monkeypatch.setattr("services.logic.deployment._deployment_inputs", forbidden)
    f = Formula(
        1,
        123,
        "f()",
        0,
        (),
        mk_cmp("eq", CALLER, const(7)),
        (Effect("write", (const(1, "address"), "x", ()), const(1), mk_cmp("eq", CALLER, const(7))),),
        (),
    )
    data = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "block": 123,
        "address": "0x1",
        "functions": {"f()": encode(f)},
    }
    source, dest = tmp_path / "formulas.json", tmp_path / "selection.json"
    source.write_text(json.dumps(data))
    original = source.read_bytes()
    main([str(source), "--output", str(dest)])
    report = json.loads(dest.read_text())
    assert report["kind"] == "expansion_selection" and report["automatic_execution"] is False
    assert report["rows"][0]["access"]["status"] == "restricted"
    assert source.read_bytes() == original


def test_cli_cannot_replace_its_formulas(tmp_path):
    p = str(tmp_path / "input.json")
    with pytest.raises(SystemExit) as error:
        main([p, "--output", p])
    assert error.value.code == 2


def test_missing_block_cannot_trigger_a_latest_state_query(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("invalid artifact reached provider creation")

    monkeypatch.setattr("services.logic.deployment._deployment_inputs", forbidden)
    source = tmp_path / "bad.json"
    source.write_text(json.dumps({"schema": 2, "kind": "formulas", "chain_id": 1, "address": "0x1", "functions": {}}))
    with pytest.raises(ValueError, match="block"):
        main([str(source), "--rpc-url", "unused", "--output", str(tmp_path / "out.json")])
