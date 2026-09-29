"""Fresh-interpreter import smoke for order-sensitive entrypoints.

A services.policy↔services.resolution package-init cycle import-crashed any process that touched ``services.policy``
FIRST. The offline suite missed it (pytest collection initializes ``services.resolution`` first), but
``workers.policy_worker`` starts with policy, so deploy died at import and ``start_workers.sh`` looped the whole pool.
Each case runs in a FRESH interpreter, since in-process imports are no-ops once ``sys.modules`` is warm.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


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
