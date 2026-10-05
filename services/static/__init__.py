from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .contract_analysis import collect_contract_analysis

__all__ = ["collect_contract_analysis"]


# Lazy so importing the claims vocabulary doesn't load Slither into processes that never analyze.
def __getattr__(name: str) -> Any:
    if name == "collect_contract_analysis":
        from .contract_analysis import collect_contract_analysis

        return collect_contract_analysis
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
