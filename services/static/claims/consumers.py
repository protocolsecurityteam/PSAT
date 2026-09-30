"""Claim ids downstream consumers branch on; CI asserts they stay within the registry.

Empty until a consumer reads claim ids.
"""

from __future__ import annotations

CONSUMER_REFERENCED_CLAIM_IDS: frozenset[str] = frozenset()
