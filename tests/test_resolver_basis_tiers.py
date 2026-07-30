"""A3 — the basis rename must not detach the strength gate that reads it.

``scorer_v3`` is the only consumer that reads ``authority_getter_basis``, via
``WEAK_RESOLVER_BASES``. Splitting ``internal_accessor_convention`` into
``standard_namespaced_accessor`` / ``deunderscore_convention`` and renaming
``auto_getter`` → ``abi_auto_getter`` would, on its own, mean newly-written rows
match NEITHER literal — the weak-tier note would silently disappear and a
name-bound principal would read as full strength. That is the "strength gate
published separately from its payload" defect, reintroduced by a rename.

So both vocabulary epochs are seated, and this test asserts that every literal
the producer can emit is classified — enumerated from the producer itself, so a
future arm added there fails here rather than silently defaulting.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _scorer_constants() -> dict[str, object]:
    """Read the module's constants without importing it (it opens a DB at
    import-adjacent scope and is a CLI, not a library)."""
    tree = ast.parse((ROOT / "scoring_prototype" / "scorer_v3.py").read_text())
    out: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ("WEAK_RESOLVER_BASES", "RESOLVER_BASIS_TIERS", "WEAKEST_RESOLVER_BASIS_TIER"):
                out[name] = ast.literal_eval(node.value)
    return out


def _producer_basis_literals() -> set[str]:
    """Every basis literal ``predicate_evaluator`` can stamp into a trace: the
    ``bases=[...]`` list at the state-variable site and the ``candidate_basis``
    map at the view-call site."""
    source = (ROOT / "services" / "resolution" / "predicate_evaluator.py").read_text()
    tree = ast.parse(source)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "bases" and isinstance(node.value, ast.List):
            found.update(e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str))
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in ("candidate_basis", "canonical_basis") for t in node.targets
        ):
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value:
                    found.add(sub.value)
    return found


def test_the_producer_emits_the_expected_vocabulary():
    """Pins the split itself: the conflated label is gone from the producer and
    the two arms it hid are both emitted."""
    assert _producer_basis_literals() == {
        "abi_auto_getter",
        "deunderscore_convention",
        "standard_namespaced_accessor",
        "slot_name_keyword",
        "callee_selector",
    }
    assert "internal_accessor_convention" not in _producer_basis_literals()
    assert "auto_getter" not in _producer_basis_literals()


def test_every_shipped_label_is_classified():
    tiers = _scorer_constants()["RESOLVER_BASIS_TIERS"]
    assert isinstance(tiers, dict)
    for basis in _producer_basis_literals():
        assert basis in tiers, f"{basis} is emitted by the resolver but unclassified by the scorer"


def test_both_vocabulary_epochs_are_seated_in_the_weak_tier():
    """33 persisted rows carry the legacy literal and every row written from now
    on carries a new one. Dropping either side un-weakens that side silently."""
    weak = _scorer_constants()["WEAK_RESOLVER_BASES"]
    assert isinstance(weak, set)
    assert weak == {
        "internal_accessor_convention",  # legacy
        "standard_namespaced_accessor",
        "deunderscore_convention",
        "slot_name_keyword",
    }


def test_the_namespaced_arm_is_seated_in_the_weak_tier():
    """It is an EXACT-name match against the standard's accessor table, so its
    label reads authoritative — but an exact name match is still a name match,
    and it is not ranked against the de-underscore arm."""
    consts = _scorer_constants()
    tiers = consts["RESOLVER_BASIS_TIERS"]
    assert isinstance(tiers, dict)
    assert "standard_namespaced_accessor" in consts["WEAK_RESOLVER_BASES"]  # type: ignore[operator]
    assert tiers["standard_namespaced_accessor"] == tiers["deunderscore_convention"] == "accessor_name_matched"


def test_only_the_abi_forced_arm_is_ranked_above_the_name_matched_ones():
    tiers = _scorer_constants()["RESOLVER_BASIS_TIERS"]
    assert isinstance(tiers, dict)
    assert tiers["abi_auto_getter"] == "abi_forced"
    assert tiers["auto_getter"] == "abi_forced"  # legacy spelling of the same arm
    name_matched = {b for b, t in tiers.items() if t == "accessor_name_matched"}
    assert name_matched == {
        "standard_namespaced_accessor",
        "deunderscore_convention",
        "slot_name_keyword",
        "internal_accessor_convention",
    }


def test_an_unknown_label_defaults_to_the_weakest_tier():
    """A basis this scorer cannot recognise is one it cannot vouch for."""
    consts = _scorer_constants()
    assert consts["WEAKEST_RESOLVER_BASIS_TIER"] == "accessor_name_matched"
    tiers = consts["RESOLVER_BASIS_TIERS"]
    assert isinstance(tiers, dict)
    assert "some_future_arm" not in tiers
