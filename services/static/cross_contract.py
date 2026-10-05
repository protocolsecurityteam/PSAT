"""Cross-contract ``policy_derived`` claims that need a sibling's facts: a resolved body call inheriting the callee's
proven ``flow.*``/``supply.*`` claims; ``transfer_policy.configure`` for a setter writing an allow/deny map a
sibling's transfer hook routes back to; a beacon ``upgradeTo`` on a proven ``upgrade.implementation``; and an
upgrade selector on a deployment whose EIP-1967 slot the classifier confirmed. Control-plane claims never cross a
call boundary otherwise.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from eth_utils.crypto import keccak

from utils import claim_ids as C
from utils.evm import EIP1967_IMPL_SLOT

from .claims import (
    Claim,
    discover,
    emit_claim,
    registry,
    resolve_claim_precedence,
)
from .claims.matchers._gates import UPGRADE_SELECTORS

logger = logging.getLogger(__name__)


# Proxy types whose implementation the classifier reads from a storage slot.
_SLOT_CONFIRMED_PROXY_TYPES = frozenset({"eip1967", "eip1822", "beacon_proxy", "oz_legacy"})


def _compute_selector(signature: str) -> str | None:
    """Selector of a canonical signature (when the callee record lacks one)."""
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _var_to_address(controller_values: Any) -> dict[str, str]:
    """``{state var (lowered): resolved address}`` from a control snapshot's ``controller_values``."""
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


def controller_addresses(controller_values: Any) -> set[str]:
    """Every address a control snapshot's state variables hold: what its derivations can join on."""
    return set(_var_to_address(controller_values).values())


def _is_flow_family(claim_id: str) -> bool:
    entry = registry().get(claim_id)
    return entry is not None and entry.consumer_family == "flow"


def _propagatable(claim: Any) -> bool:
    """Only standard_exact flow/supply claims and the beacon ``upgrade.implementation`` may cross a call boundary."""
    if not isinstance(claim, dict) or claim.get("tier") != "standard_exact":
        return False
    claim_id = claim.get("claim_id")
    if not isinstance(claim_id, str):
        return False
    return claim_id == C.UPGRADE_IMPLEMENTATION or _is_flow_family(claim_id)


def build_callee_claim_map(
    effects_by_address: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, list[Claim]]]:
    """``{callee_address: {selector: [propagatable claims]}}`` from siblings' effects records."""
    discover()  # the policy process may not have run build_claims; register the matchers
    callee_map: dict[str, dict[str, list[Claim]]] = {}
    for address, effects_artifact in (effects_by_address or {}).items():
        if not isinstance(address, str) or not isinstance(effects_artifact, dict):
            continue
        selector_claims: dict[str, list[Claim]] = {}
        for fn_sig, fn_record in (effects_artifact.get("functions") or {}).items():
            if not isinstance(fn_record, dict):
                continue
            claims = [c for c in (fn_record.get("claims") or []) if _propagatable(c)]
            if not claims:
                continue
            # The caller's sink records the canonical selector; the record's own ``selector`` hashes the declared
            # signature (``sweepTo(IERC20,...)`` keyed wrong). Use the stamped ``abi_selector`` first; the declared form
            # stays as a fallback for artifacts without it.
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
    """Body-origin ``external_call`` sinks with a ``var.method`` target and selector; guard calls aren't value flows."""
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
    callee_claim_map: dict[str, dict[str, list[Claim]]],
) -> dict[str, list[Claim]]:
    """Value flow and beacon upgrade: a body call resolved via ``controller_values`` inherits the callee's
    propagatable claims.
    """
    var_to_address = _var_to_address(controller_values)
    enriched: dict[str, list[Claim]] = {}
    for fn_sig, sinks in _body_external_calls(target_effects).items():
        new_claims: list[Claim] = []
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


def unresolved_callees(
    target_effects: Any,
    controller_values: Any,
    callees_with_facts: set[str],
    *,
    target_address: str,
) -> dict[str, list[dict[str, Any]]]:
    """Body calls whose callee resolves to an address with no facts to derive from: ``{function_signature: [{sink_id,
    selector, callee}]}``. Value-flow claims for these calls are not determined, which is not "none".
    """
    var_to_address = _var_to_address(controller_values)
    target = (target_address or "").lower()
    out: dict[str, list[dict[str, Any]]] = {}
    for fn_sig, sinks in _body_external_calls(target_effects).items():
        gaps = []
        for sink in sinks:
            callee = var_to_address.get(str(sink.get("target", "")).lower().split(".", 1)[0])
            # The zero address is a burn sentinel, not a contract that could have facts.
            if not callee or callee == target or callee in callees_with_facts or not callee[2:].strip("0"):
                continue
            selector = str(sink.get("selector", "")).lower()
            gaps.append({"sink_id": sink.get("id"), "selector": selector, "callee": callee})
        if gaps:
            out[fn_sig] = gaps
    return out


def _is_bool_mapping(declared_type: Any) -> bool:
    """A ``mapping(... => bool)`` allow/deny list (nested maps to bool count)."""
    if not isinstance(declared_type, str):
        return False
    normalized = declared_type.replace(" ", "")
    return normalized.startswith("mapping(") and normalized.endswith("=>bool)")


def _derive_transfer_policy_claims(
    target_effects: Any,
    sibling_transfer_hooks: list[dict[str, str]] | None,
) -> dict[str, list[Claim]]:
    """``transfer_policy.configure``: when a sibling's transfer-hook pointer resolves here, a function writing a
    normal-hygiene ``address => bool`` map configures that sibling's gating (the hook link stands in for proving
    the hook reads it).
    """
    if not sibling_transfer_hooks:
        return {}
    functions = target_effects.get("functions") if isinstance(target_effects, dict) else None
    if not isinstance(functions, dict):
        return {}
    enriched: dict[str, list[Claim]] = {}
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
                C.TRANSFER_POLICY_CONFIGURE,
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
) -> dict[str, list[Claim]]:
    """When the classifier confirms this deployment's EIP-1967 slot, upgrade-selector functions govern a live proxy;
    existing standard_exact upgrade claims win.
    """
    if not proxy_provenance:
        return {}
    functions = target_effects.get("functions") if isinstance(target_effects, dict) else None
    if not isinstance(functions, dict):
        return {}
    enriched: dict[str, list[Claim]] = {}
    for fn_sig, record in functions.items():
        if not isinstance(fn_sig, str) or not isinstance(record, dict):
            continue
        selector = record.get("selector")
        if not (isinstance(selector, str) and selector.lower() in UPGRADE_SELECTORS):
            continue
        enriched[fn_sig] = [
            emit_claim(
                C.UPGRADE_IMPLEMENTATION,
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
    """State vars used as runtime code pointers, from ``callee_pointer.rotate`` witnesses."""
    out: set[str] = set()
    functions = effects_artifact.get("functions") if isinstance(effects_artifact, dict) else None
    if not isinstance(functions, dict):
        return out
    for record in functions.values():
        if not isinstance(record, dict):
            continue
        for claim in record.get("claims") or []:
            if not isinstance(claim, dict) or claim.get("claim_id") != C.CALLEE_POINTER_ROTATE:
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
    """Siblings whose transfer-hook pointer resolves to ``target_address`` (the Teller hook BoringVault points at)."""
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
    """The classifier's confirmation that ``deployment_address`` is a slot-confirmed proxy, or ``None``."""
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
    callee_claim_map: dict[str, dict[str, list[Claim]]],
    *,
    sibling_transfer_hooks: list[dict[str, str]] | None = None,
    proxy_provenance: dict[str, str] | None = None,
) -> dict[str, list[Claim]]:
    """Run the four derivations: ``{function_signature: [policy_derived claims]}`` for functions that gained any."""
    discover()  # ensure flow/supply/upgrade ids are registered before emit_claim
    merged: dict[str, list[Claim]] = {}
    for derivation in (
        _derive_value_flow_claims(target_effects, controller_values, callee_claim_map),
        _derive_transfer_policy_claims(target_effects, sibling_transfer_hooks),
        _derive_provenance_upgrade_claims(target_effects, proxy_provenance),
    ):
        for fn_sig, claims in derivation.items():
            merged.setdefault(fn_sig, []).extend(claims)
    # Sorted so equal-tier ties don't depend on sink or sibling order.
    return {
        fn_sig: resolve_claim_precedence(sorted(claims, key=claim_sort_key))
        for fn_sig, claims in merged.items()
        if claims
    }


def claim_sort_key(claim: Claim) -> str:
    return json.dumps(claim, sort_keys=True, default=str)
