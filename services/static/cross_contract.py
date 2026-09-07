"""Cross-contract policy-derived claims (Plane-1 policy tier).

Some claims about a contract are only provable once a sibling's facts are in
hand — evidence that does not exist at single-contract static time:

1. **value-flow propagation** — a body call the caller resolves at runtime lands
   on a token/vault selector the callee proved carries a ``flow.*``/``supply.*``
   claim;
2. **transfer_policy.configure** — a setter here writes an allow/deny mapping and
   a sibling routes its runtime transfer hook back to this contract;
3. **beacon upgrade** — the caller invokes an ``upgradeTo`` the callee proved is
   an ``upgrade.implementation``;
4. **provenance upgrade** — the classifier confirms this deployment's live
   EIP-1967 implementation slot, so an upgrade selector here governs a real
   proxy.

Each is minted as a ``policy_derived`` claim through the registry. This replaces
the former propagate-every-effect-label rule: a control-plane claim never rides
across a call boundary (only the four typed derivations here do), and the
emitted objects are claims, not legacy label strings — so a mislabel on one
deployment can no longer contaminate the functions of another.
"""

from __future__ import annotations

import logging
from typing import Any

from eth_utils.crypto import keccak

from utils.evm import EIP1967_IMPL_SLOT

from .claims import (
    EffectMatch,
    RegistryEntry,
    discover,
    emit_claim,
    is_registered,
    register,
    registry,
    resolve_claim_precedence,
)
from .claims.matchers._gates import UPGRADE_SELECTORS

logger = logging.getLogger(__name__)

TRANSFER_POLICY_CONFIGURE = "transfer_policy.configure"
UPGRADE_IMPLEMENTATION = "upgrade.implementation"
CALLEE_POINTER_ROTATE = "callee_pointer.rotate"

# proxy_type values whose implementation the classifier reads from a storage
# slot (the "confirms the linked slot" evidence for the provenance upgrade).
_SLOT_CONFIRMED_PROXY_TYPES = frozenset({"eip1967", "eip1822", "beacon_proxy", "oz_legacy"})


def _no_static_gate(_ctx: Any) -> bool:
    # A policy-tier claim has no single-contract evidence, so the static
    # build_claims pass must never mint it; it is registered only so emit_claim
    # can mint it at the policy stage (the registry stays the sole id source).
    return False


def _no_static_trigger(_ctx: Any, _function: str) -> None:
    return None


if not is_registered(TRANSFER_POLICY_CONFIGURE):
    register(
        RegistryEntry(
            claim_id=TRANSFER_POLICY_CONFIGURE,
            sentence="changes another contract's transfer gating",
            gate=_no_static_gate,
            trigger=_no_static_trigger,
            consumer_family="control_plane",
        )
    )


def _compute_selector(signature: str) -> str | None:
    """The 4-byte selector for a canonical ABI signature (fallback when the
    callee's effect record did not record one)."""
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _var_to_address(controller_values: Any) -> dict[str, str]:
    """``{state-var name (lowered) -> resolved on-chain address}`` from a
    control snapshot's ``controller_values``."""
    out: dict[str, str] = {}
    if not isinstance(controller_values, dict):
        return out
    for controller_id, cv in controller_values.items():
        if not isinstance(cv, dict):
            continue
        val = cv.get("value", "")
        if not isinstance(val, str) or not val.startswith("0x"):
            continue
        parts = str(controller_id).split(":", 1)
        if len(parts) == 2:
            out[parts[1].lower()] = val.lower()
    return out


def _is_flow_family(claim_id: str) -> bool:
    entry = registry().get(claim_id)
    return entry is not None and entry.consumer_family == "flow"


def _propagatable(claim: Any) -> bool:
    """A callee claim eligible to ride across a resolved call boundary.

    Only standard_exact value-flow/supply claims (derivation 1) and the beacon
    ``upgrade.implementation`` (derivation 3) qualify. A structural/policy-tier
    callee claim is not strong enough to carry, and no control-plane claim other
    than the explicit beacon upgrade ever propagates."""
    if not isinstance(claim, dict) or claim.get("tier") != "standard_exact":
        return False
    claim_id = claim.get("claim_id")
    if not isinstance(claim_id, str):
        return False
    return claim_id == UPGRADE_IMPLEMENTATION or _is_flow_family(claim_id)


def build_callee_claim_map(
    effects_by_address: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, list[EffectMatch]]]:
    """``{callee_address -> {selector -> [propagatable claims]}}`` from siblings.

    Reads the ``claims`` list the static plane attached to each sibling
    ``effects`` record, keeping only the standard-tier flow/supply/upgrade
    claims a caller may inherit."""
    discover()  # the policy process may not have run build_claims; register the matchers
    callee_map: dict[str, dict[str, list[EffectMatch]]] = {}
    for address, effects_artifact in (effects_by_address or {}).items():
        if not isinstance(address, str) or not isinstance(effects_artifact, dict):
            continue
        selector_claims: dict[str, list[EffectMatch]] = {}
        for fn_sig, fn_record in (effects_artifact.get("functions") or {}).items():
            if not isinstance(fn_record, dict):
                continue
            claims = [c for c in (fn_record.get("claims") or []) if _propagatable(c)]
            if not claims:
                continue
            # Join keys, canonical first. The caller's sink records the
            # CANONICAL dispatch selector (its ``_callee_signature`` lowers
            # interface/enum/struct params), while the record's own
            # ``selector`` is keccak of the DECLARED signature — not a real
            # selector when a parameter is user-typed, which made every such
            # callee invisible to this join (AssetRecovery
            # ``sweepTo(IERC20,address,uint256)`` keyed 0x38541c00, sink says
            # 0x0aeef8c8). ``abi_selector`` is the canonical value stamped by
            # ``attach_claims_to_effects``; its ABSENCE (older artifact,
            # unlowerable signature) is not-determined, so the declared-form
            # key is kept as the fallback that preserves the elementary-
            # signature joins those artifacts still support.
            keys: set[str] = set()
            abi_selector = fn_record.get("abi_selector")
            if isinstance(abi_selector, str) and abi_selector.startswith("0x"):
                keys.add(abi_selector.lower())
            raw_selector = fn_record.get("selector")
            selector = (
                raw_selector
                if isinstance(raw_selector, str) and raw_selector.startswith("0x")
                else _compute_selector(str(fn_sig))
            )
            if selector:
                keys.add(selector.lower())
            for key in keys:
                selector_claims.setdefault(key, []).extend(claims)
        if selector_claims:
            callee_map[address.lower()] = selector_claims
    return callee_map


def _body_external_calls(target_effects: Any) -> dict[str, list[dict[str, Any]]]:
    """Per-function body-origin ``external_call`` sinks that carry a
    ``var.method`` target and a selector. Guard-origin calls are excluded — a
    permission check is not a value flow."""
    functions = target_effects.get("functions") if isinstance(target_effects, dict) else None
    if not isinstance(functions, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for fn_sig, record in functions.items():
        if not isinstance(fn_sig, str) or not isinstance(record, dict):
            continue
        sinks = [
            s
            for s in (record.get("sinks") or [])
            if isinstance(s, dict)
            and s.get("kind") == "external_call"
            and s.get("origin") == "body"
            and isinstance(s.get("target"), str)
            and "." in str(s.get("target"))
            and isinstance(s.get("selector"), str)
            and str(s.get("selector")).startswith("0x")
        ]
        if sinks:
            out[fn_sig] = sinks
    return out


def _derive_value_flow_claims(
    target_effects: Any,
    controller_values: Any,
    callee_claim_map: dict[str, dict[str, list[EffectMatch]]],
) -> dict[str, list[EffectMatch]]:
    """Derivations 1 (value flow) + 3 (beacon upgrade): a body call resolved via
    ``controller_values`` inherits the callee's propagatable standard-tier claims
    at ``policy_derived``."""
    var_to_address = _var_to_address(controller_values)
    enriched: dict[str, list[EffectMatch]] = {}
    for fn_sig, sinks in _body_external_calls(target_effects).items():
        new_claims: list[EffectMatch] = []
        for sink in sinks:
            var_name = str(sink.get("target", "")).lower().split(".", 1)[0]
            callee_addr = var_to_address.get(var_name)
            if not callee_addr:
                continue
            selector = str(sink.get("selector", "")).lower()
            for source in callee_claim_map.get(callee_addr, {}).get(selector, []):
                claim_id = source["claim_id"]
                new_claims.append(
                    emit_claim(
                        claim_id,
                        "policy_derived",
                        {
                            "kind": "cross_contract_join",
                            "callee": callee_addr,
                            "selector": selector,
                            "sink_id": sink.get("id"),
                            "source_tier": source.get("tier"),
                        },
                    )
                )
                logger.info(
                    "Cross-contract: %s calls %s (%s); deriving policy claim %s",
                    fn_sig.split("(")[0],
                    var_name,
                    selector,
                    claim_id,
                )
        if new_claims:
            enriched[fn_sig] = new_claims
    return enriched


def _is_bool_mapping(declared_type: Any) -> bool:
    """A ``mapping(... => bool)`` allow/deny list — the transfer-gating set shape.
    Nested maps keying to a bool leaf still qualify."""
    if not isinstance(declared_type, str):
        return False
    normalized = declared_type.replace(" ", "")
    return normalized.startswith("mapping(") and normalized.endswith("=>bool)")


def _derive_transfer_policy_claims(
    target_effects: Any,
    sibling_transfer_hooks: list[dict[str, str]] | None,
) -> dict[str, list[EffectMatch]]:
    """Derivation 2 (``transfer_policy.configure``).

    ``sibling_transfer_hooks`` are the siblings whose runtime transfer-hook
    pointer resolves to THIS contract. When such a link exists, a function here
    that writes a normal-hygiene ``address => bool`` allow/deny mapping is
    configuring that sibling's transfer gating.

    The written set-var stands in for the spec's "read by the hook fn": the
    engine records writes, not reads, so the discriminating evidence is the
    sibling→here hook link plus the allow/deny map shape."""
    if not sibling_transfer_hooks:
        return {}
    functions = target_effects.get("functions") if isinstance(target_effects, dict) else None
    if not isinstance(functions, dict):
        return {}
    enriched: dict[str, list[EffectMatch]] = {}
    for fn_sig, record in functions.items():
        if not isinstance(fn_sig, str) or not isinstance(record, dict):
            continue
        set_vars = sorted(
            {
                str(w.get("var"))
                for w in (record.get("state_writes") or [])
                if isinstance(w, dict)
                and w.get("hygiene_class") == "normal"
                and w.get("origin") == "body"
                and _is_bool_mapping(w.get("declared_type"))
            }
        )
        if not set_vars:
            continue
        claims = [
            emit_claim(
                TRANSFER_POLICY_CONFIGURE,
                "policy_derived",
                {
                    "kind": "transfer_policy",
                    "configures": hook.get("sibling_address"),
                    "hook_pointer": hook.get("pointer_var"),
                    "set_vars": set_vars,
                },
            )
            for hook in sorted(sibling_transfer_hooks, key=lambda h: h.get("sibling_address", ""))
        ]
        if claims:
            enriched[fn_sig] = claims
    return enriched


def _derive_provenance_upgrade_claims(
    target_effects: Any,
    proxy_provenance: dict[str, str] | None,
) -> dict[str, list[EffectMatch]]:
    """Derivation 4 (upgrade provenance).

    When the classifier confirms this deployment's EIP-1967 implementation slot,
    a function carrying a canonical upgrade selector governs a live proxy. The
    per-function precedence rule keeps a static standard_exact ``upgrade.*`` claim
    if one already exists — this surfaces only the upgrade entries static could
    not gate on its own."""
    if not proxy_provenance:
        return {}
    functions = target_effects.get("functions") if isinstance(target_effects, dict) else None
    if not isinstance(functions, dict):
        return {}
    enriched: dict[str, list[EffectMatch]] = {}
    for fn_sig, record in functions.items():
        if not isinstance(fn_sig, str) or not isinstance(record, dict):
            continue
        selector = record.get("selector")
        if not (isinstance(selector, str) and selector.lower() in UPGRADE_SELECTORS):
            continue
        enriched[fn_sig] = [
            emit_claim(
                UPGRADE_IMPLEMENTATION,
                "policy_derived",
                {
                    "kind": "proxy_provenance",
                    "proxy": proxy_provenance.get("proxy"),
                    "implementation": proxy_provenance.get("implementation"),
                    "slot": proxy_provenance.get("slot"),
                },
            )
        ]
    return enriched


def _callee_pointer_vars(effects_artifact: Any) -> set[str]:
    """State-var names a contract treats as a runtime code pointer, per its
    ``callee_pointer.rotate`` claim witnesses."""
    out: set[str] = set()
    functions = effects_artifact.get("functions") if isinstance(effects_artifact, dict) else None
    if not isinstance(functions, dict):
        return out
    for record in functions.values():
        if not isinstance(record, dict):
            continue
        for claim in record.get("claims") or []:
            if not isinstance(claim, dict) or claim.get("claim_id") != CALLEE_POINTER_ROTATE:
                continue
            witness = claim.get("witness")
            links = witness.get("links") if isinstance(witness, dict) else None
            for link in links or []:
                pointer = link.get("pointer") if isinstance(link, dict) else None
                if isinstance(pointer, str) and pointer:
                    out.add(pointer)
    return out


def sibling_transfer_hook_links(
    target_address: str,
    sibling_effects_by_address: dict[str, dict[str, Any]],
    sibling_snapshots_by_address: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    """Siblings whose runtime transfer-hook pointer resolves to ``target_address``.

    A sibling's ``callee_pointer.rotate`` claim names the state var it invokes as
    a runtime hook; when that var's resolved controller value equals this
    contract, the sibling routes transfers through us — the ``Teller`` hook that
    ``BoringVault`` points at."""
    target = (target_address or "").lower()
    if not target:
        return []
    links: list[dict[str, str]] = []
    for address, effects_artifact in (sibling_effects_by_address or {}).items():
        if not isinstance(address, str):
            continue
        pointer_vars = _callee_pointer_vars(effects_artifact)
        if not pointer_vars:
            continue
        snapshot = sibling_snapshots_by_address.get(address) or sibling_snapshots_by_address.get(address.lower())
        var_to_address = _var_to_address(snapshot.get("controller_values") if isinstance(snapshot, dict) else None)
        for pointer_var in sorted(pointer_vars):
            if var_to_address.get(pointer_var.lower()) == target:
                links.append({"sibling_address": address.lower(), "pointer_var": pointer_var})
    return links


def proxy_provenance_from_classifications(
    deployment_address: str,
    classifications_artifact: Any,
) -> dict[str, str] | None:
    """The classifier's confirmation that ``deployment_address`` is a live proxy
    whose implementation it read from a storage slot. Returns ``None`` when the
    deployment is not a slot-confirmed proxy."""
    if not deployment_address:
        return None
    classifications = (
        classifications_artifact.get("classifications") if isinstance(classifications_artifact, dict) else None
    )
    if not isinstance(classifications, dict):
        return None
    info = classifications.get(deployment_address.lower()) or classifications.get(deployment_address)
    if not isinstance(info, dict) or info.get("type") != "proxy":
        return None
    if str(info.get("proxy_type") or "") not in _SLOT_CONFIRMED_PROXY_TYPES:
        return None
    implementation = info.get("implementation")
    if not isinstance(implementation, str) or not implementation.startswith("0x"):
        return None
    return {
        "proxy": deployment_address.lower(),
        "implementation": implementation.lower(),
        "proxy_type": str(info.get("proxy_type")),
        "slot": EIP1967_IMPL_SLOT,
    }


def derive_cross_contract_claims(
    target_effects: Any,
    controller_values: Any,
    callee_claim_map: dict[str, dict[str, list[EffectMatch]]],
    *,
    sibling_transfer_hooks: list[dict[str, str]] | None = None,
    proxy_provenance: dict[str, str] | None = None,
) -> dict[str, list[EffectMatch]]:
    """Run the four policy-tier derivations and merge their claims per function.

    Returns ``{function_signature -> [policy_derived claims]}`` for functions that
    gained at least one; the policy stage merges these onto each function's
    existing claim list (precedence-resolved)."""
    discover()  # ensure flow/supply/upgrade ids are registered before emit_claim
    merged: dict[str, list[EffectMatch]] = {}
    for derivation in (
        _derive_value_flow_claims(target_effects, controller_values, callee_claim_map),
        _derive_transfer_policy_claims(target_effects, sibling_transfer_hooks),
        _derive_provenance_upgrade_claims(target_effects, proxy_provenance),
    ):
        for fn_sig, claims in derivation.items():
            merged.setdefault(fn_sig, []).extend(claims)
    return {fn_sig: resolve_claim_precedence(claims) for fn_sig, claims in merged.items() if claims}
