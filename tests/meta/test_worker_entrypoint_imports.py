"""A policy/resolution init cycle crashed any process importing ``services.policy`` first; pytest collection hid it.

Each case runs in a fresh interpreter.
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
        "workers.policy_worker",
        "services.policy",
        "workers.company_pages",
        "workers.web_runtime",
    ],
)
def test_policy_first_import_order(module):
    _import_in_fresh_interpreter(module)
