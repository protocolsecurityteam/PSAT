"""Matcher auto-discovery: importing a module runs its ``@claim_matcher`` decorator."""

from __future__ import annotations

import importlib
import pkgutil

_discovered = False


def discover() -> None:
    """Import every matcher module. Idempotent."""
    global _discovered
    if _discovered:
        return
    for module in pkgutil.iter_modules(__path__):
        if module.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{module.name}")
    _discovered = True
