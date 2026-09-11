"""The maintenance command cannot migrate while an old machine remains."""

import json

import pytest

from deploy import assessment_cutover as cutover


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "fly.toml"
    path.write_text('app = "psat"\n[deploy]\nrelease_command = "uv run --no-sync alembic upgrade head"\n')
    return path


def machine(**config):
    return {"id": "abc123", "config": {"metadata": {"fly_process_group": "web"}, **config}}


def test_build_then_remove_then_migrate_and_restore_config(monkeypatch, config):
    calls = []
    inventories = iter([[machine()], []])
    original = config.read_text()

    def fly(*args):
        calls.append(args)
        if args[:2] == ("machines", "list"):
            return json.dumps(next(inventories))
        if args[0] == "deploy" and "--image" in args:
            release = config.read_text()
            assert "alembic upgrade f6a1c2d3e4b5" in release
            assert "services.assessment.migrate" in release
            assert "assessment_cutover=stopped" in release
        return ""

    monkeypatch.setattr(cutover, "fly", fly)
    cutover.cutover(config, "a" * 40, "snapshot-test")
    assert "--build-only" in calls[0]
    assert calls[2][:2] == ("machine", "destroy")
    assert calls[3][:2] == ("machines", "list")
    assert "--image" in calls[4]
    assert config.read_text() == original


@pytest.mark.parametrize("remaining", [True, False])
def test_no_migration_with_old_machines_or_persistent_volumes(monkeypatch, config, remaining):
    inventories = iter([[machine()] if remaining else [machine(mounts=[{"volume": "vol_test"}])], [machine()]])
    calls = []

    def fly(*args):
        calls.append(args)
        return json.dumps(next(inventories)) if args[:2] == ("machines", "list") else ""

    monkeypatch.setattr(cutover, "fly", fly)
    with pytest.raises(RuntimeError):
        cutover.cutover(config, "a" * 40, "snapshot-test")
    assert not any("--image" in args for args in calls)
    if not remaining:
        assert not any(args[:2] == ("machine", "destroy") for args in calls)
