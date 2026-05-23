"""Static guardrail for the WARNING-degraded-with-record_degraded contract.

The level contract in ``utils/logging.py`` says: any worker emitting
``logger.warning`` (or ``logger.exception``) inside a swallowed-exception
path must also call ``record_degraded(...)`` in the same except block, so
the partial outcome shows up in the ``stage_errors`` artifact downstream.

This test parses each pipeline-worker module with ``ast`` and flags any
``logger.warning`` / ``logger.exception`` call inside an ``except``
handler that:

  * does not end with ``raise`` (i.e. the exception is swallowed), AND
  * does not call ``record_degraded(...)`` anywhere in the same handler.

Approximate by design: doesn't reason about call-chains (a helper that
wraps the logger call hides its site from this check) and doesn't try to
classify control-flow patterns. Catches the common regression where a new
``except → logger.warning → continue`` lands without a paired
``record_degraded``. Per-file allow-list below covers the few intentional
exceptions; every entry has a one-line reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Pipeline workers (BaseWorker subclasses that drive the jobs queue).
# Narrowed per the handoff: these are where degradation tracking matters
# most. Audit-row workers + monitoring loops are intentionally excluded —
# they don't bind ``degraded_errors_var`` so ``record_degraded`` is a no-op
# there and the contract doesn't apply.
PIPELINE_WORKERS: tuple[str, ...] = (
    "workers/discovery.py",
    "workers/static_worker.py",
    "workers/resolution_worker.py",
    "workers/policy_worker.py",
    "workers/coverage_worker.py",
)

# {file: {line_of_logger_call: reason}}
# Sites where WARNING in a swallowed except is *intentionally* not paired
# with record_degraded. Each entry needs justification — when in doubt,
# prefer adding record_degraded to silence the test.
ALLOW_LIST: dict[str, dict[int, str]] = {
    "workers/policy_worker.py": {
        # Reanalysis-completion notifier: the reanalysis itself completed
        # before the notifier ran, so its failure is a side-effect that
        # doesn't change the job's stage output. record_degraded would
        # mislead callers of /api/jobs/{id}/errors into thinking the
        # reanalysis was degraded.
        595: "Notifier side-effect; reanalysis already completed before this fired.",
    },
}


def _attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]


def _enclosing_handler(node: ast.AST) -> ast.ExceptHandler | None:
    cur: ast.AST | None = node
    while cur is not None:
        cur = getattr(cur, "parent", None)
        if isinstance(cur, ast.ExceptHandler):
            return cur
    return None


def _is_logger_warning_or_exception(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in ("warning", "exception"):
        return False
    return isinstance(func.value, ast.Name) and func.value.id == "logger"


def _handler_calls_record_degraded(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "record_degraded":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "record_degraded":
            return True
    return False


def _handler_ends_with_raise(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return False
    return isinstance(handler.body[-1], ast.Raise)


def _find_violations(rel_path: str, source: str) -> list[int]:
    tree = ast.parse(source)
    _attach_parents(tree)
    violations: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_logger_warning_or_exception(node)):
            continue
        handler = _enclosing_handler(node)
        if handler is None:
            continue  # Not inside an except block — contract doesn't apply.
        if _handler_ends_with_raise(handler):
            continue  # Re-raises; BaseWorker's failure path will log + record.
        if _handler_calls_record_degraded(handler):
            continue
        violations.append(node.lineno)
    return violations


def test_warning_in_swallowed_except_pairs_with_record_degraded() -> None:
    repo_root = Path(__file__).parent.parent
    failures: list[str] = []
    for rel in PIPELINE_WORKERS:
        path = repo_root / rel
        for line in _find_violations(rel, path.read_text()):
            allowed = ALLOW_LIST.get(rel, {})
            if line in allowed:
                continue
            failures.append(f"{rel}:{line}")
    assert not failures, (
        "logger.warning / logger.exception inside a swallowed except handler "
        "without a paired record_degraded() — see utils/logging.py level "
        "contract. Sites: " + ", ".join(failures)
    )


def test_allow_list_entries_still_present() -> None:
    """If an allow-listed line moves or disappears, the entry rots silently —
    fail loudly so the next maintainer re-evaluates the exemption."""
    repo_root = Path(__file__).parent.parent
    stale: list[str] = []
    for rel, lines in ALLOW_LIST.items():
        path = repo_root / rel
        if not path.exists():
            stale.extend(f"{rel}:{line} (file missing)" for line in lines)
            continue
        violations = set(_find_violations(rel, path.read_text()))
        for line in lines:
            if line not in violations:
                stale.append(f"{rel}:{line}")
    assert not stale, (
        "ALLOW_LIST entries no longer match a violation — the call site "
        "either moved, was deleted, or now pairs with record_degraded. "
        "Update ALLOW_LIST: " + ", ".join(stale)
    )
