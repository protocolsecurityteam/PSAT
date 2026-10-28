"""The expansion process requires an explicit selection and a separate output."""

import pytest

from scripts.logic_expand import main


def test_selected_job_writes_a_separate_artifact(monkeypatch, tmp_path):
    import json
    from contextlib import nullcontext

    from services.logic.expansion import Selection

    source = tmp_path / "formulas.json"
    output = tmp_path / "addresses.json"
    source.write_text('{"kind":"formulas"}')
    before = source.read_bytes()
    monkeypatch.setattr("db.models.SessionLocal", lambda: nullcontext(None))

    def expand(session, artifact, rpc_url, selections, *, limits):
        assert artifact == {"kind": "formulas"}
        assert selections == {"f()": Selection(True, (0,)), "g()": Selection(False, (1,))}
        assert limits.members == 5
        return {"kind": "address_expansions"}

    monkeypatch.setattr("services.logic.deployment.deployment_expansions", expand)
    main(
        [
            str(source),
            "--rpc-url",
            "unused",
            "--output",
            str(output),
            "--function",
            "f()",
            "--effect",
            "f():0",
            "--effect",
            "g():1",
            "--members",
            "5",
        ]
    )
    assert source.read_bytes() == before
    assert json.loads(output.read_text()) == {"kind": "address_expansions"}


def test_no_selection_does_not_start_a_job(tmp_path):
    with pytest.raises(SystemExit) as error:
        main([str(tmp_path / "missing.json"), "--rpc-url", "unused", "--output", str(tmp_path / "out.json")])
    assert error.value.code == 2


def test_output_cannot_replace_source_artifact(tmp_path):
    filename = str(tmp_path / "formulas.json")
    with pytest.raises(SystemExit) as error:
        main([filename, "--function", "f()", "--rpc-url", "unused", "--output", filename])
    assert error.value.code == 2
