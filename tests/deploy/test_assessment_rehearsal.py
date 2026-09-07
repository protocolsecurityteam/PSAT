"""The restored-copy rehearsal refuses unsafe targets and reconciles import."""

import pytest

from deploy import assessment_rehearsal as rehearsal


def test_refuses_same_database(tmp_path):
    with pytest.raises(ValueError, match="different databases"):
        rehearsal.rehearse("postgresql://db.example/psat", "postgresql://db.example/psat", tmp_path / "x.dump")


def test_refuses_nonempty_scratch_without_running_commands(monkeypatch, tmp_path):
    monkeypatch.setattr(rehearsal, "_scalar", lambda *_a: 3)
    calls = []
    monkeypatch.setattr(rehearsal, "_run", lambda *args, **kwargs: calls.append((args, kwargs)))
    with pytest.raises(RuntimeError, match="not empty"):
        rehearsal.rehearse(
            "postgresql://db.example/source",
            "postgresql://db.example/scratch",
            tmp_path / "x.dump",
        )
    assert calls == []


def test_rehearsal_orders_restore_import_contraction_and_check(monkeypatch, tmp_path):
    counts = iter([0, 2, 0, 2])
    monkeypatch.setattr(rehearsal, "_scalar", lambda *_a: next(counts))
    commands = []
    backup = tmp_path / "assessment.dump"

    def run(args, *, database_url=None, pg_url=None):
        commands.append((args, database_url))
        if args[0] == "pg_dump":
            backup.write_bytes(b"backup")

    monkeypatch.setattr(rehearsal, "_run", run)
    result = rehearsal.rehearse(
        "postgresql://db.example/source",
        "postgresql://db.example/scratch",
        backup,
    )

    assert [command[0][0] for command in commands] == ["pg_dump", "pg_restore", "uv", "uv", "uv", "uv"]
    assert "services.assessment.migrate" in commands[3][0]
    assert "assessment_cutover=stopped" in commands[4][0]
    assert commands[5][0][-1] == "check"
    assert result["source_artifacts"] == result["import_manifests"] == 2
    assert result["remaining_legacy_artifacts"] == 0
    assert result["backup_sha256"] == "54d00d867758cef816bc4685f58e327b949712b07ebd17c3485f3ffc9e9f5133"
