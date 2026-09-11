"""Resolve transient function spellings to canonical Assessment functions."""

from __future__ import annotations

from collections.abc import Mapping

from schemas.assessment import Assessment


def resolve_function(assessment: Assessment, permission: Mapping[str, object]) -> tuple[str | None, str | None]:
    """Return the unique Assessment function named by a permission row.

    Static analysis keys functions by their source-level signature while the
    permission index also carries the canonical ABI signature. Prefer the
    original source identity, then exact ABI identity, then a unique selector.
    A selector collision is not a license to choose one candidate.
    """

    functions = assessment["functions"]
    source_signature = permission.get("function")
    abi_signature = permission.get("abi_signature")
    selector = permission.get("selector")

    if isinstance(source_signature, str) and source_signature in functions:
        recorded_selector = functions[source_signature].get("selector")
        if not isinstance(selector, str) or not isinstance(recorded_selector, str) or selector == recorded_selector:
            return source_signature, None
        return None, f"selector_mismatch:{source_signature}:{selector}:{recorded_selector}"

    if isinstance(abi_signature, str):
        abi_matches = [
            signature
            for signature, function in functions.items()
            if signature == abi_signature or function.get("abi_signature") == abi_signature
        ]
        if len(abi_matches) == 1:
            return abi_matches[0], None
        if len(abi_matches) > 1:
            return None, f"ambiguous_abi_signature:{abi_signature}"

    if isinstance(selector, str):
        selector_matches = [
            signature for signature, function in functions.items() if function.get("selector") == selector
        ]
        if len(selector_matches) == 1:
            return selector_matches[0], None
        if len(selector_matches) > 1:
            return None, f"ambiguous_selector:{selector}"

    identity = source_signature if isinstance(source_signature, str) else abi_signature
    return None, f"function_not_found:{identity or selector or 'unknown'}"


__all__ = ["resolve_function"]
