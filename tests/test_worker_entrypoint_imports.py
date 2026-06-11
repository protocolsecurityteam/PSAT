"""Fresh-interpreter import smoke for order-sensitive entrypoints.

A services.policy↔services.resolution package-init cycle (introduced with
``capability_surface`` → ``permissionless_shapes``) import-crashed any process
that touched ``services.policy`` FIRST. The offline suite never saw it —
pytest's collection order happens to initialize ``services.resolution``
before ``services.policy`` — but ``workers.policy_worker`` starts with the
policy package, so on deploy it died at import and ``start_workers.sh``'s
exit-on-first-death took the entire worker pool down with it, in a loop.

These tests import in a FRESH interpreter per case (the only way import
order is actually exercised; in-process imports are no-ops once
``sys.modules`` is warm).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _import_in_fresh_interpreter(module: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"import {module} crashed a fresh interpreter:\n{proc.stderr[-2000:]}"


@pytest.mark.parametrize(
    "module",
    [
        # The entrypoint that died in psat-pr-132: its first services import is
        # the policy package.
        "workers.policy_worker",
        # The policy-first package order itself (minimal reproducer of the cycle).
        "services.policy",
    ],
)
def test_policy_first_import_order(module):
    _import_in_fresh_interpreter(module)
