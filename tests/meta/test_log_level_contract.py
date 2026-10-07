"""A swallowing ``except`` that logs WARNING must also ``record_degraded`` so the outcome reaches ``stage_errors``.

Approximate by design; the allow-list carries a reason per exception.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Audit-row workers and monitoring loops bind no accumulator, so the contract doesn't apply.
PIPELINE_WORKERS: tuple[str, ...] = (
    "workers/discovery.py",
    "workers/static_worker.py",
    "workers/resolution_worker.py",
    "workers/policy_worker.py",
    "workers/coverage_worker.py",
    "workers/effects_worker.py",
    "workers/selection_worker.py",
    "workers/dapp_crawl_worker.py",
    "workers/defillama_worker.py",
)

# Service modules that execute *under* those workers' job contexts, so the
# accumulator is bound and ``record_degraded`` is not a no-op. Globs rather
# than file lists, so a new module landing in one of these packages inherits
# the contract instead of silently opting out.
#
# Deliberately outside the perimeter:
#   * ``services/scoring/planes/`` and ``loop.py`` — monitor thread / CLI
#     only; no accumulator is ever bound, and the scoring plane loaders' WARNINGs are
#     documented deliberate no-pairs.
#   * ``services/monitoring/**`` other than ``balance_reads.py`` — daemon
#     loops with no accumulator. ``balance_reads`` is in because the
#     resolution worker calls it per job.
PIPELINE_SERVICE_GLOBS: tuple[str, ...] = (
    "services/effects/**/*.py",
    "services/scoring/distill/*.py",
    "services/discovery/**/*.py",
    "services/policy/*.py",
    "services/static/contract_analysis_pipeline/**/*.py",
    "services/resolution/**/*.py",
    "services/monitoring/balance_reads.py",
)

# {file: {line: reason}}. Line-pinned, so re-pin in the same commit as any edit above; stale entries fail
# ``test_allow_list_entries_still_present``.
ALLOW_LIST: dict[str, dict[int, str]] = {
    "services/resolution/indexer_scheduler.py": {
        103: "Indexer daemon has no job accumulator; failed enrollment remains in its durable retry queue.",
        129: "Indexer daemon has no job accumulator; a failed witness retry pass leaves every candidate due.",
        195: "Indexer daemon has no job accumulator; failed reconciliation remains in its durable retry queue.",
    },
    "workers/discovery.py": {
        1151: "Boot-time sweep failure; runs before any job context exists.",
    },
    "workers/policy_worker.py": {
        # The reanalysis completed before the notifier; recording would mark it degraded.
        923: "Notifier side-effect; reanalysis already completed before this fired.",
    },
    "workers/effects_worker.py": {
        # A resource side-effect, not a degraded verdict.
        480: "Fork-close cleanup side-effect; does not degrade the stage's verdict output.",
    },
    "services/effects/anvil.py": {
        714: "Fork-close cleanup side-effect; SIGKILL escalation does not degrade the verdicts.",
        723: "Fork-close cleanup side-effect; an unreaped pid does not degrade the verdicts.",
    },
    "services/resolution/repos/event_logs_rpc.py": {
        # A process-level misconfiguration would stamp every job's stage_errors.
        42: "Process-level env parse; a bad cap is a misconfiguration, not a per-job degradation.",
    },
}


def _attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # pyright: ignore[reportAttributeAccessIssue]


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


def _recording_helper_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_is_record_degraded_call(inner) for inner in ast.walk(node) if isinstance(inner, ast.Call)):
            names.add(node.name)
    names.discard("record_degraded")
    return names


def _is_record_degraded_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "record_degraded"
    if isinstance(func, ast.Attribute):
        return func.attr == "record_degraded"
    return False


def _handler_calls_record_degraded(handler: ast.ExceptHandler, helpers: set[str]) -> bool:
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        if _is_record_degraded_call(node):
            return True
        func = node.func
        if isinstance(func, ast.Name) and func.id in helpers:
            return True
        if isinstance(func, ast.Attribute) and func.attr in helpers:
            return True
    return False


def _handler_ends_with_raise(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return False
    return isinstance(handler.body[-1], ast.Raise)


def _find_violations(rel_path: str, source: str) -> list[int]:
    tree = ast.parse(source)
    _attach_parents(tree)
    helpers = _recording_helper_names(tree)
    violations: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_logger_warning_or_exception(node)):
            continue
        handler = _enclosing_handler(node)
        if handler is None:
            continue  # Not inside an except block — contract doesn't apply.
        if _handler_ends_with_raise(handler):
            continue  # Re-raises; BaseWorker's failure path will log + record.
        if _handler_calls_record_degraded(handler, helpers):
            continue
        violations.append(node.lineno)
    return violations


def _enforced_paths(repo_root: Path) -> list[str]:
    paths = list(PIPELINE_WORKERS)
    for pattern in PIPELINE_SERVICE_GLOBS:
        paths.extend(sorted(str(p.relative_to(repo_root)) for p in repo_root.glob(pattern)))
    return paths


def test_service_globs_still_match_files() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    empty = [pattern for pattern in PIPELINE_SERVICE_GLOBS if not list(repo_root.glob(pattern))]
    assert not empty, "PIPELINE_SERVICE_GLOBS entries match nothing: " + ", ".join(empty)


def test_warning_in_swallowed_except_pairs_with_record_degraded() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    failures: list[str] = []
    for rel in _enforced_paths(repo_root):
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
    repo_root = Path(__file__).resolve().parents[2]
    enforced = set(_enforced_paths(repo_root))
    outside = sorted(rel for rel in ALLOW_LIST if rel not in enforced)
    assert not outside, "ALLOW_LIST exempts files the check no longer covers, so the entries do nothing: " + ", ".join(
        outside
    )
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
