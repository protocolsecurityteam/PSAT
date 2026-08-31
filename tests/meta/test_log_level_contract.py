"""Static guardrail for the WARNING-degraded-with-record_degraded contract.

The level contract in ``utils/logging.py`` says: any worker emitting
``logger.warning`` (or ``logger.exception``) inside a swallowed-exception
path must also call ``record_degraded(...)`` in the same except block, so
the partial outcome shows up in the ``stage_errors`` artifact downstream.

This test parses each in-perimeter module with ``ast`` and flags any
``logger.warning`` / ``logger.exception`` call inside an ``except``
handler that:

  * does not end with ``raise`` (i.e. the exception is swallowed), AND
  * does not call ``record_degraded(...)`` anywhere in the same handler.

Approximate by design: it resolves one level of module-local indirection
(a handler calling a helper defined in the same module that itself calls
``record_degraded`` counts as paired) but doesn't chase call-chains
further, and doesn't try to classify control-flow patterns. Catches the
common regression where a new ``except → logger.warning → continue``
lands without a paired ``record_degraded``. Per-file allow-list below
covers the few intentional exceptions; every entry has a one-line reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Pipeline workers (BaseWorker subclasses that drive the jobs queue).
# Audit-row workers + monitoring loops are intentionally excluded — they
# don't bind ``degraded_errors_var`` so ``record_degraded`` is a no-op
# there and the contract doesn't apply.
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
#   * ``services/scoring/planes.py`` and ``loop.py`` — monitor thread / CLI
#     only; no accumulator is ever bound, and planes.py's loader WARNINGs are
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

# {file: {line_of_logger_call: reason}}
# Sites where WARNING in a swallowed except is *intentionally* not paired
# with record_degraded. Each entry needs justification — when in doubt,
# prefer adding record_degraded to silence the test.
# The keys are LINE-PINNED, so any edit above a listed call site shifts them and
# this file must be re-pinned in the same commit.
# ``test_allow_list_entries_still_present`` below fails loudly when an entry
# stops matching a real violation.
ALLOW_LIST: dict[str, dict[int, str]] = {
    "workers/discovery.py": {
        # Boot-time chain-enable sweep in main(): no job is claimed yet, so no
        # accumulator is bound and record_degraded would be a no-op.
        1242: "Boot-time sweep failure; runs before any job context exists.",
    },
    "workers/policy_worker.py": {
        # Reanalysis-completion notifier: the reanalysis itself completed
        # before the notifier ran, so its failure is a side-effect that
        # doesn't change the job's stage output. record_degraded would
        # mislead callers of /api/jobs/{id}/errors into thinking the
        # reanalysis was degraded.
        1119: "Notifier side-effect; reanalysis already completed before this fired.",
    },
    "workers/effects_worker.py": {
        # Fork-close cleanup: the anvil subprocess close failing is a resource
        # side-effect (port/memory), not a degradation of the stage's verdict
        # output. record_degraded would mislead /monitor into flagging a healthy
        # job's effects stage as degraded.
        629: "Fork-close cleanup side-effect; does not degrade the stage's verdict output.",
    },
    "services/effects/anvil.py": {
        # Same fork-close-cleanup exemption class as the effects_worker entry
        # above: SubprocessAnvil.close() escalating SIGTERM → SIGKILL is a
        # resource outcome (port/pid), not a change to the stage's verdicts.
        850: "Fork-close cleanup side-effect; SIGKILL escalation does not degrade the verdicts.",
        861: "Fork-close cleanup side-effect; an unreaped pid does not degrade the verdicts.",
    },
    "services/resolution/repos/event_logs_rpc.py": {
        # Env-var parse, evaluated per call on every job of every worker in the
        # process. A malformed cap is a deployment misconfiguration, not a
        # per-job partial outcome, and recording it would stamp every job's
        # stage_errors with the same process-level fact.
        60: "Process-level env parse; a bad cap is a misconfiguration, not a per-job degradation.",
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
    """Functions in this module that themselves call ``record_degraded``.

    A module that funnels its degraded records through a local wrapper (to
    attach a fixed phase prefix, say) still honours the contract; without
    this the check would read the wrapper as an unpaired swallow.
    """
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
    """A renamed package would empty a glob and silently drop the perimeter."""
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
    """If an allow-listed line moves or disappears, the entry rots silently —
    fail loudly so the next maintainer re-evaluates the exemption."""
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
