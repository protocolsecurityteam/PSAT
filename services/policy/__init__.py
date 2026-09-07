"""Policy package."""

from .permission_index import build_permission_index
from .principal_index import build_principal_index

__all__ = [
    "build_permission_index",
    "build_principal_index",
]
