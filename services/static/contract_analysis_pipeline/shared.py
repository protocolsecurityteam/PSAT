"""Shared helpers for contract analysis."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from slither.slither import Slither

from schemas.contract_analysis import Evidence


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return default


def _select_subject_contract(slither: Slither, contract_name: str | None):
    candidates = [
        contract
        for contract in slither.contracts
        if not getattr(contract, "is_interface", False) and not getattr(contract, "is_library", False)
    ]
    if contract_name:
        exact = [contract for contract in candidates if contract.name == contract_name]
        if exact:
            return exact[0]

    concrete = [contract for contract in candidates if not getattr(contract, "is_abstract", False)]
    pool = concrete or candidates
    if not pool:
        return None
    return max(
        pool,
        key=lambda contract: (
            len(_contract_functions(contract)),
            len(_all_state_variables(contract)),
            len(getattr(contract, "inheritance", [])),
        ),
    )


def _contract_functions(contract) -> list:
    return [
        function
        for function in getattr(contract, "functions", [])
        if getattr(function, "name", "") and not getattr(function, "name", "").startswith("slither")
    ]


def _entry_points(contract) -> list:
    return [
        function
        for function in getattr(contract, "functions_entry_points", [])
        if getattr(function, "name", "") and not getattr(function, "name", "").startswith("slither")
    ]


def _all_state_variables(contract) -> list:
    variables = []
    seen = set()
    for current in [contract, *getattr(contract, "inheritance", [])]:
        for variable in getattr(current, "state_variables", []):
            key = getattr(variable, "canonical_name", f"{current.name}.{variable.name}")
            if key in seen:
                continue
            seen.add(key)
            variables.append(variable)
    return variables


def _all_modifiers(contract) -> list:
    modifiers = []
    seen = set()
    for current in [contract, *getattr(contract, "inheritance", [])]:
        for modifier in getattr(current, "modifiers", []):
            key = getattr(modifier, "canonical_name", f"{current.name}.{modifier.name}")
            if key in seen:
                continue
            seen.add(key)
            modifiers.append(modifier)
    return modifiers


def _contract_events(contract) -> set[str]:
    names = set()
    for event in getattr(contract, "events", []) or getattr(contract, "events_declared", []):
        name = getattr(event, "name", None)
        if name:
            names.add(name)
    return names


def _contract_signatures(contract) -> set[str]:
    signatures = set()
    for function in _contract_functions(contract):
        signature = getattr(function, "full_name", None)
        if signature:
            signatures.add(signature)
    return signatures


def _source_evidence(item, project_dir: Path, detail: str | None = None) -> Evidence:
    mapping = getattr(item, "source_mapping", None)
    file_info = getattr(mapping, "filename", None)
    absolute = getattr(file_info, "absolute", None) if file_info else None
    lines = list(getattr(mapping, "lines", []) or [])

    evidence: Evidence = {}
    if absolute:
        path = Path(str(absolute))
        try:
            evidence["file"] = str(path.relative_to(project_dir))
        except ValueError:
            evidence["file"] = str(path)
    if lines:
        evidence["line"] = lines[0]
    if detail:
        evidence["detail"] = detail
    return evidence


def _declaring_contract_name(item, default_contract_name: str) -> str:
    declaring_contract = getattr(item, "contract_declarer", None) or getattr(item, "contract", None)
    return getattr(declaring_contract, "name", default_contract_name)


def _dedupe_strings(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def _call_or_value(item, attr_name: str) -> list[Any]:
    value = getattr(item, attr_name, [])
    resolved = value() if callable(value) else value
    if resolved is None:
        return []
    if isinstance(resolved, list):
        return resolved
    if isinstance(resolved, (tuple, set)):
        return list(resolved)
    if isinstance(resolved, Iterable) and not isinstance(resolved, (str, bytes, dict)):
        return list(resolved)
    return []
