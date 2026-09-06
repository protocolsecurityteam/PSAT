"""Fail visibly when production publishers, child producers, or threads change."""

import ast
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("publisher_census.json")
WATCHED = {
    "commit",
    "create_job",
    "Job",
    "advance_job",
    "complete_job",
    "requeue_job",
    "fail_job_terminal",
    "Thread",
    "ThreadPoolExecutor",
    "ContextThreadPoolExecutor",
    "Popen",
    "reactivate_terminal_job",
}


def source_files():
    paths = {p for directory in ("db", "workers", "services", "routers") for p in (ROOT / directory).rglob("*.py")}
    scripts = subprocess.check_output(["git", "ls-files", "scripts/*.py"], cwd=ROOT, text=True).splitlines()
    return sorted(paths | {ROOT / path for path in scripts})


def census():
    result = Counter()
    producers = []
    for path in source_files():
        scope = []

        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                scope.append(node.name)
                self.generic_visit(node)
                scope.pop()

            visit_AsyncFunctionDef = visit_FunctionDef
            visit_ClassDef = visit_FunctionDef

            def visit_Call(self, node):
                name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                if name in WATCHED:
                    result[f"{path.relative_to(ROOT)}:{'.'.join(scope)}:{name}"] += 1
                if name == "create_job":
                    producers.append((str(path.relative_to(ROOT)), node.lineno, {arg.arg for arg in node.keywords}))
                self.generic_visit(node)

        Visitor().visit(ast.parse(path.read_text()))
    return dict(sorted(result.items())), producers


def test_publisher_and_lifecycle_census_requires_review():
    actual, _ = census()
    assert actual == json.loads(MANIFEST.read_text())


def test_every_job_producer_declares_parent_or_cloud_root():
    _, producers = census()
    assert producers
    assert not [
        (path, line) for path, line, keys in producers if not keys.intersection({"routing_from", "compute_target"})
    ]


def test_every_session_commit_has_the_attempt_guard():
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    from db.attempts import _fence_commit

    assert event.contains(Session, "before_commit", _fence_commit)


def test_topology_has_exactly_four_local_workers():
    from services.compute.runtime import WORKER_MODULES

    assert WORKER_MODULES == (
        "workers.static_worker",
        "workers.resolution_worker",
        "workers.policy_worker",
        "workers.effects_worker",
    )
    script = (ROOT / "deploy/start_local_compute.sh").read_text()
    assert "alembic" not in script and "docker" not in script
    production = (ROOT / "deploy/start_workers.sh").read_text()
    assert production.count("workers.event_log_indexer") == 1
    assert production.count("workers.protocol_monitor --reconcile") == 1
