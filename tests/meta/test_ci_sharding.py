"""Exercise the pytest handoff and reject incomplete coverage before combining."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from coverage import CoverageData
from coverage.exceptions import CoverageException

from tests.ci_sharding import MAPPING_HASH, SHARDS, shard_for, verify

pytest_plugins = ["pytester"]
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def artifacts(tmp_path):
    universe = [f"tests/{areas[0]}/test_example.py::test_ok" for areas in SHARDS.values()]
    for shard, nodeid in enumerate(universe, 1):
        manifest = {
            "version": 1,
            "shard": shard,
            "revision": "revision-a",
            "mapping_hash": MAPPING_HASH,
            "exit_code": 0,
            "universe": universe,
            "selected": [nodeid],
            "completed": [nodeid],
        }
        (tmp_path / f"shard-{shard}.json").write_text(json.dumps(manifest))
        data = CoverageData(basename=str(tmp_path / f".coverage.{shard}"))
        data.add_lines({"api.py": {shard}})
        data.write()
    return tmp_path


def edit_manifest(directory, **changes):
    path = directory / "shard-1.json"
    manifest = json.loads(path.read_text())
    manifest.update(changes)
    path.write_text(json.dumps(manifest))


def test_complete_artifacts_can_be_verified_and_combined(artifacts):
    assert verify(artifacts, "revision-a") == 4
    # Real data from disjoint executions combines as a union, not an average.
    combined = CoverageData(basename=str(artifacts / "combined"))
    for shard in SHARDS:
        data = CoverageData(basename=str(artifacts / f".coverage.{shard}"))
        data.read()
        combined.update(data)
    assert set(combined.lines("api.py") or []) == {1, 2, 3, 4}


@pytest.mark.parametrize("filename", ["shard-1.json", ".coverage.1"])
def test_missing_artifact_is_rejected(artifacts, filename):
    (artifacts / filename).unlink()
    with pytest.raises(ValueError, match="Missing"):
        verify(artifacts, "revision-a")


@pytest.mark.parametrize("filename", ["shard-5.json", ".coverage.5"])
def test_extra_artifact_is_rejected(artifacts, filename):
    (artifacts / filename).write_text("unexpected")
    with pytest.raises(ValueError, match="unexpected"):
        verify(artifacts, "revision-a")


@pytest.mark.parametrize(
    "changes",
    [
        {"version": 2},
        {"shard": 2},
        {"revision": "another-commit"},
        {"mapping_hash": "another-mapping"},
        {"exit_code": 1},
        {"universe": ["tests/static/test_other.py::test_ok"]},
        {"selected": []},
        {"completed": []},
        {"completed": ["tests/static/test_example.py::test_ok"] * 2},
        {"selected": ["tests/monitoring/test_example.py::test_ok"]},
        {"completed": ["tests/static/test_other.py::test_ok"]},
    ],
)
def test_invalid_manifest_is_rejected(artifacts, changes):
    edit_manifest(artifacts, **changes)
    with pytest.raises(ValueError):
        verify(artifacts, "revision-a")


@pytest.mark.parametrize("contents", ["not json", "[]", "null"])
def test_malformed_manifest_is_rejected(artifacts, contents):
    (artifacts / "shard-1.json").write_text(contents)
    with pytest.raises(ValueError):
        verify(artifacts, "revision-a")


@pytest.mark.parametrize("kind", ["corrupt", "empty", "absolute", "parent", "branch"])
def test_unusable_coverage_is_rejected(artifacts, kind):
    path = artifacts / ".coverage.1"
    path.unlink()
    if kind == "corrupt":
        path.write_bytes(b"not a coverage database")
    else:
        data = CoverageData(basename=str(path))
        if kind == "branch":
            data.add_arcs({"api.py": {(1, 2)}})
        else:
            name = {"absolute": "/other/checkout/api.py", "parent": "../api.py"}.get(kind, "api.py")
            data.add_lines({name: set() if kind == "empty" else {1}})
        data.write()
    with pytest.raises((ValueError, CoverageException)):
        verify(artifacts, "revision-a")


@pytest.fixture
def mini_suite(pytester, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    pytester.makeini("[pytest]\nmarkers = live\n")
    for area in ("static", "monitoring", "storage", "crawlers", "live"):
        directory = pytester.path / "tests" / area
        directory.mkdir(parents=True)
        (directory / f"test_{area}.py").write_text(
            "import pytest\n"
            "@pytest.fixture(scope='module')\n"
            "def shared():\n    return []\n"
            "def test_first(shared):\n    shared.append(1)\n"
            "def test_second(shared):\n    assert shared == [1]\n"
        )
    (pytester.path / "tests/live/conftest.py").write_text(
        "import pytest\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        if '/live/' in str(item.path):\n"
        "            item.add_marker(pytest.mark.live)\n"
    )
    return pytester


def run_shard(pytester, shard, *args):
    return pytester.runpytest_subprocess(
        "-p", "tests.ci_sharding", "-m", "not live", f"--ci-shard={shard}", "--ci-revision=revision-a", "-q", *args
    )


def test_real_collection_preserves_fixtures_and_filters_live_before_sharding(mini_suite):
    all_selected = []
    for shard in SHARDS:
        run_shard(mini_suite, shard).assert_outcomes(passed=2, deselected=8)
        manifest = json.loads((mini_suite.path / f"ci-results/shard-{shard}.json").read_text())
        assert len(manifest["universe"]) == 8
        assert manifest["selected"] == manifest["completed"]
        assert manifest["exit_code"] == 0
        assert all(shard_for(node) == shard for node in manifest["selected"])
        assert manifest["file_seconds"]
        all_selected.extend(manifest["selected"])
    assert len(all_selected) == len(set(all_selected)) == 8


def test_new_test_area_fails_collection_instead_of_disappearing(mini_suite):
    directory = mini_suite.path / "tests/new_area"
    directory.mkdir()
    (directory / "test_new.py").write_text("def test_new():\n    pass\n")
    result = run_shard(mini_suite, 1)
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*Offline test has no CI shard*new_area*"])


def test_manifest_records_test_failure(mini_suite):
    (mini_suite.path / "tests/static/test_failure.py").write_text("def test_failure():\n    assert False\n")
    result = run_shard(mini_suite, 1)
    result.assert_outcomes(passed=2, failed=1)
    manifest = json.loads((mini_suite.path / "ci-results/shard-1.json").read_text())
    assert manifest["exit_code"] == 1
    assert any(outcome.get("call") == "failed" for outcome in manifest["outcomes"].values())


def test_manifest_captures_sessionfinish_guard_failure(mini_suite):
    # Mimics local_netguard/conftest changing a successful session into a failure.
    mini_suite.makeconftest("def pytest_sessionfinish(session):\n    session.exitstatus = 1\n")
    result = run_shard(mini_suite, 1)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    manifest = json.loads((mini_suite.path / "ci-results/shard-1.json").read_text())
    assert manifest["exit_code"] == 1


def test_empty_shard_is_an_error(mini_suite):
    result = run_shard(mini_suite, 1, "tests/monitoring")
    assert result.ret == pytest.ExitCode.USAGE_ERROR


@pytest.mark.parametrize("nodeid", ["tests/new_area/test_new.py::test_ok", "tests/test_root.py::test_ok"])
def test_unknown_directory_has_no_implicit_fallback(nodeid):
    with pytest.raises(ValueError, match="no CI shard"):
        shard_for(nodeid)


def test_new_files_in_existing_areas_are_included():
    assert shard_for("tests/static/nested/test_new.py::test_ok") == 1
    areas = [area for group in SHARDS.values() for area in group]
    assert len(areas) == len(set(areas))


@pytest.mark.parametrize(
    "overrides,success",
    [
        ({}, True),
        ({"COVERAGE_RESULT": "failure"}, False),
        ({"COVERAGE_RESULT": "skipped"}, False),
        ({"TEST_RESULT": "failure", "COVERAGE_RESULT": "skipped"}, False),
        ({"TEST_RESULT": "cancelled", "COVERAGE_RESULT": "skipped"}, False),
        ({"CHANGES_RESULT": "failure"}, False),
        ({"FRONTEND_RESULT": "skipped"}, False),
        ({"FRONTEND_REQUIRED": "false", "FRONTEND_RESULT": "skipped"}, True),
        (
            {
                "PYTHON_REQUIRED": "false",
                "LINT_RESULT": "skipped",
                "TYPECHECK_RESULT": "skipped",
                "TEST_RESULT": "skipped",
                "COVERAGE_RESULT": "skipped",
            },
            True,
        ),
        ({"PYTHON_REQUIRED": "false", "COVERAGE_RESULT": "failure"}, False),
    ],
)
def test_actual_workflow_gate_handles_required_and_optional_results(overrides, success):
    workflow = yaml.safe_load((ROOT / ".github/workflows/_ci-checks.yml").read_text())
    jobs = workflow["jobs"]
    assert jobs["test"]["strategy"]["matrix"]["shard"] == list(SHARDS)
    assert {"test", "coverage"} <= set(jobs["ci-pass"]["needs"])
    env = dict(os.environ, PYTHON_REQUIRED="true", FRONTEND_REQUIRED="true")
    env.update({name: "success" for name in jobs["ci-pass"]["steps"][0]["env"] if name.endswith("_RESULT")})
    env.update(overrides)
    result = subprocess.run(["bash", "-eu", "-c", jobs["ci-pass"]["steps"][0]["run"]], env=env, capture_output=True)
    assert (result.returncode == 0) is success, result.stdout.decode()
