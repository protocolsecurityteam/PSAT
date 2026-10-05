"""Carry per-effect authority into claims without borrowing another branch's controller or public path."""

from __future__ import annotations

from copy import deepcopy

from .capability_surface import capability_surface_openness, project_capability_surface


def principal_identity(address, details):
    details = details or {}
    return address.lower(), details.get("threshold"), tuple(sorted(details.get("owners") or []))


def authority_identity(cap):
    surface = project_capability_surface(cap)
    return (
        capability_surface_openness(cap, surface),
        tuple(
            sorted(
                (principal_identity(row["address"], row.get("details")) for row in surface.principal_rows),
                key=lambda p: (p[0], str(p[1]), p[2]),
            )
        ),
    )


def scope_claim_authority(claims, capability):
    scopes = (capability or {}).get("effect_capabilities")
    if not scopes:
        return claims
    out = deepcopy(claims)
    for claim in out:
        witness = claim.setdefault("witness", {})
        sink_ids = witness.get("sink_ids")
        candidates = [s for s in scopes if s.get("origin") == "body"]
        scope_ids = witness.get("authority_scope_ids")
        if "authority_scope_ids" in witness:
            candidates = [s for s in candidates if s["id"] in (scope_ids or [])]
        elif sink_ids:
            candidates = [s for s in candidates if set(s.get("sink_ids") or []) & set(sink_ids)]
        caps = [s["capability"] for s in candidates]
        identities = {authority_identity(c) for c in caps}
        # A claim spanning differently controlled sites cannot publish one controller as if it governed them all.
        if len(identities) != 1:
            cap = {
                "kind": "unsupported",
                "unsupported_reason": "claim_effect_authority_not_determined",
                "confidence": "check_only",
            }
        else:
            cap = caps[0]
        surface = project_capability_surface(cap)
        witness["effect_authority"] = {
            "scope_ids": [s["id"] for s in candidates],
            "capability": cap,
            "openness": capability_surface_openness(cap, surface),
            "principal_addresses": sorted({r["address"] for r in surface.principal_rows}),
            "principal_specs": [
                {"address": r["address"], "details": r.get("details") or {}} for r in surface.principal_rows
            ],
        }
    return out
