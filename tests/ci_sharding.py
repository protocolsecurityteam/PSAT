from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from coverage import CoverageData
from coverage.exceptions import CoverageException

# Measured directory groups; keep module/class fixtures on the same runner.
SHARDS = {
    1: ("static", "audits", "meta", "deploy"),
    2: ("monitoring", "workers", "api", "rpc", "policy"),
    3: ("storage", "resolution", "scoring", "aggregations"),
    4: ("discovery", "crawlers", "indexer", "effects", "chains", "observability"),
}
MAPPING_HASH = hashlib.sha256(json.dumps(SHARDS, sort_keys=True).encode()).hexdigest()


def shard_for(nodeid: str) -> int:
    """Fail closed for a new test area, while automatically including new files."""
    parts = PurePosixPath(nodeid.split("::", 1)[0]).parts
    if len(parts) >= 3 and parts[0] == "tests":
        for shard, areas in SHARDS.items():
            if parts[1] in areas:
                return shard
    raise ValueError(f"Offline test has no CI shard: {nodeid}; update SHARDS in tests/ci_sharding.py")


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("ci-sharding")
    group.addoption("--ci-shard", type=int, choices=tuple(SHARDS))
    group.addoption("--ci-output-dir", default="ci-results")
    group.addoption("--ci-revision", help="Revision under test (defaults to git HEAD)")


def pytest_configure(config: pytest.Config) -> None:
    shard = config.getoption("ci_shard")
    if shard is None:
        return
    if config.getoption("markexpr").strip() != "not live":
        raise pytest.UsageError('CI sharding requires -m "not live"')
    if config.getoption("numprocesses", default=None):
        raise pytest.UsageError("CI shards use one pytest process; do not combine them with xdist")
    revision = (
        config.getoption("ci_revision")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=config.rootpath, text=True).strip()
    )
    output = Path(config.getoption("ci_output_dir"))
    config.pluginmanager.register(ShardRecorder(shard, revision, output), "ci-shard-recorder")


class ShardRecorder:
    def __init__(self, shard: int, revision: str, output: Path) -> None:
        self.shard = shard
        self.revision = revision
        self.output = output
        self.universe: list[str] = []
        self.selected: list[str] = []
        self.completed: list[str] = []
        self.outcomes: dict[str, dict[str, str]] = defaultdict(dict)
        self.durations: dict[str, float] = defaultdict(float)

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]):
        # Run after marker filtering, including tests/live/conftest.py's tags.
        result = yield
        self.universe = sorted(item.nodeid for item in items)
        selected, deselected = [], []
        for item in items:
            try:
                owner = shard_for(item.nodeid)
            except ValueError as exc:
                raise pytest.UsageError(str(exc)) from exc
            (selected if owner == self.shard else deselected).append(item)
        self.selected = [item.nodeid for item in selected]
        if not selected:
            raise pytest.UsageError(f"CI shard {self.shard} selected no tests")
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected
        return result

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        outcome = report.outcome
        if getattr(report, "wasxfail", None):
            outcome = "xfailed" if report.skipped else "xpassed"
        self.outcomes[report.nodeid][report.when] = outcome
        self.durations[report.nodeid.split("::", 1)[0]] += report.duration
        if report.when == "teardown":
            self.completed.append(report.nodeid)

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session):
        # Both offline guards may change exitstatus during sessionfinish.
        result = yield
        self.output.mkdir(parents=True, exist_ok=True)
        manifest = {
            "version": 1,
            "shard": self.shard,
            "revision": self.revision,
            "mapping_hash": MAPPING_HASH,
            "universe": self.universe,
            "selected": self.selected,
            "completed": self.completed,
            "outcomes": self.outcomes,
            "file_seconds": self.durations,
            "exit_code": int(session.exitstatus),
        }
        (self.output / f"shard-{self.shard}.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return result


def _nodeids(manifest: dict[str, Any], key: str) -> list[str]:
    value = manifest.get(key)
    if not isinstance(value, list) or not value or any(not isinstance(node, str) for node in value):
        raise ValueError(f"Invalid or empty {key} in shard {manifest.get('shard')}")
    if len(set(value)) != len(value):
        raise ValueError(f"Duplicate node IDs in {key} for shard {manifest.get('shard')}")
    return value


def verify(directory: Path, revision: str) -> int:
    """Validate every input before coverage combine (which can skip bad files)."""
    expected_manifests = {f"shard-{shard}.json" for shard in SHARDS}
    expected_coverage = {f".coverage.{shard}" for shard in SHARDS}
    if {p.name for p in directory.glob("shard-*.json")} != expected_manifests:
        raise ValueError("Missing or unexpected shard manifests")
    if {p.name for p in directory.glob(".coverage.*")} != expected_coverage:
        raise ValueError("Missing or unexpected coverage files")
    universe: list[str] | None = None
    executed: Counter[str] = Counter()
    for shard in SHARDS:
        manifest = json.loads((directory / f"shard-{shard}.json").read_text())
        if not isinstance(manifest, dict):
            raise ValueError(f"Invalid manifest for shard {shard}")
        expected = {"version": 1, "shard": shard, "revision": revision, "mapping_hash": MAPPING_HASH, "exit_code": 0}
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise ValueError(f"Shard {shard}: invalid {key}: {manifest.get(key)!r}, expected {value!r}")
        collected = _nodeids(manifest, "universe")
        if universe is None:
            universe = collected
        elif collected != universe:
            raise ValueError(f"Shard {shard}: inconsistent offline test collection")
        selected = _nodeids(manifest, "selected")
        completed = _nodeids(manifest, "completed")
        if set(selected) != {node for node in collected if shard_for(node) == shard}:
            raise ValueError(f"Shard {shard}: selection does not match its directory assignment")
        if Counter(completed) != Counter(selected):
            raise ValueError(f"Shard {shard}: missing or unexpected completed tests")
        executed.update(completed)
        data = CoverageData(basename=str(directory / f".coverage.{shard}"))
        data.read()
        files = data.measured_files()
        if not files or not any(data.lines(file) for file in files):
            raise ValueError(f"Shard {shard}: empty coverage data")
        if data.has_arcs():
            raise ValueError(f"Shard {shard}: expected line coverage, found branch coverage")
        if any(PurePosixPath(file).is_absolute() or ".." in PurePosixPath(file).parts for file in files):
            raise ValueError(f"Shard {shard}: coverage paths must be relative to the checkout")
    if executed != Counter(universe):
        raise ValueError("Offline tests were omitted or executed more than once")
    return len(executed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    try:
        count = verify(args.directory, args.revision)
    except (ValueError, OSError, CoverageException) as exc:
        parser.exit(1, f"Invalid CI shard results: {exc}\n")
    print(f"Verified {count} offline tests, each completed once across {len(SHARDS)} shards.")


if __name__ == "__main__":
    main()
