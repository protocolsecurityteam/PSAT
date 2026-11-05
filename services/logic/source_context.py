"""One complete compiler-source bundle per deployment, with per-function references.

Source is stored once and truncated only when constructing a bounded model request.
Compilation-unit files include top-level constants, types, errors, and helper functions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .expansion import formula_hash
from .model import Formula
from .terms import subterms


def digest(value: Any) -> str:
    result = hashlib.sha256()
    for part in json.JSONEncoder(sort_keys=True, ensure_ascii=False, separators=(",", ":")).iterencode(value):
        result.update(part.encode())
    return result.hexdigest()


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class ContextContracts(Mapping):
    def __init__(self, contracts, address, contract):
        self.contracts, self.used, self.missing = contracts, {address: contract}, set()
        self.code_contexts = {}
        self.own_sources = {}

    def record_code(self, address, code, contract):
        if contract is None:
            self.missing.add(code)
        else:
            self.code_contexts[address, code] = contract
            self.own_sources[code] = contract
            self.missing.discard(code)

    def get(self, address, default=None):
        contract = self.contracts.get(address, default)
        if contract is not None and contract is not default:
            self.used[address] = contract
        elif isinstance(address, int):
            self.missing.add(address)
        return contract

    def own_code(self, address):
        if address in self.own_sources:
            return self.own_sources[address]
        own = getattr(self.contracts, "own_code", None)
        contract = own(address) if own is not None else self.contracts.get(address)
        self.record_code(address, address, contract)
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


def build_bundle(
    contracts: Mapping, *, max_chars=48_000, missing_sources=(), code_addresses=None, code_contexts=None
) -> dict:
    if type(max_chars) is not int or max_chars <= 0:
        raise ValueError("positive context size required")
    files, deployments, missing = {}, [], list(missing_sources)
    entries = [
        (address, (code_addresses or {}).get(address, address), contract, None)
        for address, contract in sorted(contracts.items())
    ]
    present = {(address, code) for address, code, _, _ in entries}
    entries += [
        (address, code, contract, "dispatcher" if address == code else "implementation")
        for (address, code), contract in sorted((code_contexts or {}).items())
        if (address, code) not in present
    ]
    for address, code, contract, role in entries:
        sources = contract.compilation_unit.core.source_code
        refs = []
        if not sources:
            missing.append(f"compiler source unavailable:{address:#x}")
        for path, text in sorted(sources.items()):
            key = _hash(text)
            files.setdefault(key, {"name": str(path), "source": text})
            refs.append(key)
        deployments.append(
            {
                "address": f"0x{address:040x}",
                "code_address": f"0x{code:040x}",
                **({"role": role} if role else {}),
                "contract": contract.name,
                "files": sorted(set(refs)),
            }
        )
    body = {
        "schema": 2,
        "files": files,
        "deployments": deployments,
        "source_gaps": sorted(set(missing)),
        "max_chars": max_chars,
        "scope": "captured compiler files; not a complete economic dependency graph",
    }
    return {**body, "bundle_hash": digest(body)}


def build_context(formula: Formula, function, bundle: dict) -> dict:
    source = function.source_mapping
    text = function.compilation_unit.core.source_code.get(source.filename.absolute)
    ref = _hash(text) if text is not None else None
    terms = [formula.success, *(e.guard for e in formula.effects), *(e.value for e in formula.effects)]
    gaps = sorted(
        {str(t[1]) for term in terms for kind in ("unknown", "opaque", "assumed") for t in subterms(term, kind)}
        | ({"unsupported:numeric_memory_address"} if any(subterms(t, "memory_address") for t in terms) else set())
    )
    body = {
        "schema": 2,
        "formula_hash": formula_hash(formula),
        "bundle_hash": bundle["bundle_hash"],
        "entry": {"file": ref, "start": source.start, "length": source.length},
        "analysis_gaps": gaps,
    }
    return {**body, "context_hash": digest(body)}


def validate_bundle(bundle: dict) -> None:
    if bundle.get("schema") != 2 or bundle.get("bundle_hash") != digest(
        {k: v for k, v in bundle.items() if k != "bundle_hash"}
    ):
        raise ValueError("source bundle hash mismatch; regenerate legacy source contexts")
    if type(bundle.get("max_chars")) is not int or bundle["max_chars"] <= 0:
        raise ValueError("invalid context size")
    for key, value in bundle["files"].items():
        if not isinstance(value.get("source"), str) or _hash(value["source"]) != key:
            raise ValueError("source file hash mismatch")
    if any(ref not in bundle["files"] for deployment in bundle["deployments"] for ref in deployment["files"]):
        raise ValueError("source deployment references missing file")


def materialize_context(context: dict, formula: Formula, bundle: dict) -> dict:
    """Resolve one entry into the shared source, preserving byte offsets and explicit cuts."""
    validate_bundle(bundle)
    if (
        context.get("schema") != 2
        or context.get("formula_hash") != formula_hash(formula)
        or context.get("bundle_hash") != bundle["bundle_hash"]
    ):
        raise ValueError("source context does not match formula/bundle")
    if context.get("context_hash") != digest({k: v for k, v in context.items() if k != "context_hash"}):
        raise ValueError("source context hash mismatch")
    entry = context["entry"]
    start, length, ref = entry["start"], entry["length"], entry["file"]
    gaps = list(bundle["source_gaps"])
    gaps.extend(g for g in context["analysis_gaps"] if g.startswith(("unverified:", "unresolved:", "budget:callee")))
    if type(start) is not int or type(length) is not int or min(start, length) < 0:
        raise ValueError("invalid source span")
    if ref not in bundle["files"]:
        gaps.append("entry source unavailable")
    else:
        raw = bundle["files"][ref]["source"].encode()
        if start + length > len(raw):
            raise ValueError("source span outside file")
    # Keep the complete entry's file first; do not duplicate the entrypoint or modifier text.
    units, remaining = [], bundle["max_chars"]
    for key in sorted(bundle["files"], key=lambda k: (k != ref, k)):
        file = bundle["files"][key]
        text = file["source"][:remaining]
        remaining -= len(text)
        truncated = len(text) != len(file["source"])
        if text:
            units.append({"source_hash": key, "name": file["name"], "source": text, "truncated": truncated})
        if truncated:
            gaps.append(f"source truncated:{file['name']}:{key}")
    return {
        "units": units,
        "entry": entry,
        "deployments": bundle["deployments"],
        "analysis_gaps": context["analysis_gaps"],
        "source_gaps": sorted(set(gaps)),
        "source_complete": not gaps,
        "context_hash": context["context_hash"],
    }


def artifact_hash(artifact: dict) -> str:
    """Bind selection to all formulas and assessment context, not just one function's formula."""
    return digest(
        {
            key: artifact.get(key)
            for key in (
                "schema",
                "kind",
                "chain_id",
                "address",
                "block",
                "status",
                "functions",
                "pending_functions",
                "generation_scope",
                "code_locations",
                "entry_code_addresses",
                "contexts",
                "source_bundle",
            )
        }
    )
