"""Matcher auto-discovery.

Importing a matcher module runs its ``@claim_matcher`` decorator, so populating
the registry is just "import every sibling module here". :func:`discover` does
that once; a matcher agent adds a module and needs no other wiring.
"""

from __future__ import annotations

import importlib
import pkgutil

_discovered = False


def discover() -> None:
    """Import every matcher module so its claim registration runs. Idempotent."""
    global _discovered
    if _discovered:
        return
    for module in pkgutil.iter_modules(__path__):
        if module.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{module.name}")
    _discovered = True
