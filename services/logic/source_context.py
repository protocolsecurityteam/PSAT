"""Source sidecars for judgment, captured from compiler inputs without additional chain reads."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .expansion import formula_hash
from .model import Formula
from .terms import subterms


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


class ContextContracts(Mapping):
    """Record which verified contracts the compiler actually accesses."""

    def __init__(self, contracts, address: int, contract):
        self.contracts = contracts
        self.used = {address: contract}

    def get(self, address, default=None):
        contract = self.contracts.get(address, default)
        if contract is not None and contract is not default:
            self.used[address] = contract
        return contract

    def __getitem__(self, address):
        result = self.get(address)
        if result is None:
            raise KeyError(address)
        return result

    def __iter__(self):
        return iter(self.used)

    def __len__(self):
        return len(self.used)


def build_context(formula: Formula, function, contracts: Mapping, *, max_chars: int = 48_000) -> dict:
    """Preserve the target, helpers, declarations, inheritance and already-loaded callees.

    Completeness means only the collected source scope, not complete economic understanding.
    Each unit has a source hash. Cuts are explicit; an older formula without this sidecar is
    not silently joined to newly fetched source for a model judgment.
    """
    units, seen, original_chars, remaining = [], set(), 0, max_chars
    missing = []

    def add(obj, label):
        nonlocal original_chars, remaining
        text = getattr(getattr(obj, "source_mapping", None), "content", "") or ""
        if not text:
            return
        source_hash = hashlib.sha256(text.encode()).hexdigest()
        if source_hash in seen:
            return
        seen.add(source_hash)
        original_chars += len(text)
        supplied = text[: max(remaining, 0)]
        remaining -= len(supplied)
        if supplied:
            units.append(
                {
                    "label": label,
                    "source_hash": source_hash,
                    "source": supplied,
                    "truncated": len(supplied) != len(text),
                }
            )
        if len(supplied) != len(text):
            missing.append(f"source truncated: {label}")

    if not (getattr(getattr(function, "source_mapping", None), "content", "") or "").strip():
        missing.append("entry source unavailable")
    add(function, f"entry point {formula.signature}")
    for modifier in getattr(function, "modifiers", ()):
        add(modifier, f"modifier {modifier.canonical_name}")
    for address, contract in sorted(contracts.items()):
        for c in [contract, *getattr(contract, "inheritance", ())]:
            add(c, f"contract {c.name} at {address:#x}")
            for fn in getattr(c, "functions", ()):
                for call in fn.all_library_calls():
                    library_fn = getattr(call, "function", None)
                    library = getattr(library_fn, "contract", None)
                    if library is not None:
                        add(library, f"library {library.name}")
                for call in fn.all_internal_calls():
                    inner = getattr(call, "function", None)
                    if inner is not None and getattr(inner, "contract", None) is None:
                        add(inner, f"internal helper {getattr(inner, 'canonical_name', '')}")
    terms = [formula.success, *(e.guard for e in formula.effects)]
    analysis_gaps = sorted(
        {str(t[1]) for term in terms for kind in ("unknown", "opaque", "assumed") for t in subterms(term, kind)}
    )
    missing.extend(gap for gap in analysis_gaps if gap.startswith(("unverified:", "unresolved:", "budget:callee")))
    if not units:
        missing.append("entry source unavailable")
    action_sites, write_sites = {}, {}
    nodes = function.all_nodes() if hasattr(function, "all_nodes") else []
    for node in nodes:
        text = getattr(node.source_mapping, "content", "") or ""
        if not text:
            continue
        for ir in node.irs:
            action_sites[id(ir)] = text
        for var in node.state_variables_written:
            write_sites.setdefault(var.name, []).append(text)
    sites, site_chars = {}, 0
    for index, effect in enumerate(formula.effects):
        labels = [str(t[1]) for t in subterms(effect.target, "assumed")]
        ids = {int(label.rsplit(":", 1)[1]) for label in labels if label.rsplit(":", 1)[-1].isdigit()}
        statements = [action_sites[i] for i in ids if i in action_sites]
        exact = bool(statements)
        if effect.kind == "write" and isinstance(effect.target[1], str):
            statements += write_sites.get(effect.target[1], [])
        kept = []
        for statement in dict.fromkeys(statements):
            if len(statement) + site_chars > 8000:
                missing.append("effect source sites truncated")
                break
            kept.append(statement)
            site_chars += len(statement)
        sites[str(index)] = {
            "statements": kept,
            "basis": "action_ir_identity" if exact else "write_candidates" if kept else "unlocated",
        }
    context = {
        "schema": 1,
        "formula_hash": formula_hash(formula),
        "signature": formula.signature,
        "units": units,
        "source_complete": not missing,
        "source_gaps": sorted(set(missing)),
        "analysis_gaps": analysis_gaps,
        "source_chars": original_chars,
        "supplied_chars": max_chars - remaining,
        "scope": "compiler inputs; no assertion of economic completeness",
        "effect_sites": sites,
        "site_chars": site_chars,
    }
    return {**context, "context_hash": digest(context)}


def validate_context(context: dict, formula: Formula) -> None:
    if context.get("schema") != 1 or context.get("formula_hash") != formula_hash(formula):
        raise ValueError("source context does not match saved formula")
    if context.get("context_hash") != digest({k: v for k, v in context.items() if k != "context_hash"}):
        raise ValueError("source context hash mismatch")
    if not isinstance(context.get("units"), list) or not context["units"]:
        raise ValueError("source context has no code")
    for unit in context["units"]:
        if not isinstance(unit.get("source"), str) or not unit["source"].strip():
            raise ValueError("invalid source unit")
        if not unit.get("truncated") and hashlib.sha256(unit["source"].encode()).hexdigest() != unit.get("source_hash"):
            raise ValueError("source unit hash mismatch")
