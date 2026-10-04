from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import collect_contract_analysis, collect_contract_analysis_with_artifacts

__all__ = [
    "collect_contract_analysis",
    "collect_contract_analysis_with_artifacts",
]


# Lazy so importing a light submodule (``predicate_types``) doesn't load Slither.
def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import core

        return getattr(core, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
