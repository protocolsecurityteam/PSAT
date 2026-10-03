"""What a privilege grants is answered once, by the claims registry: consumers name claim ids through
``utils.claim_ids`` and decide privilege over grant classes, never with their own id strings, id prefixes or
effect-label sets.

Approximate by design (string constants, collection literals and comparisons); the allow-lists carry a reason per
exception.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from services.static.claims import CONSUMER_REFERENCED_CLAIM_IDS, GRANT_CLASSES, claim_ids_of_class
from services.static.contract_analysis_pipeline.effects.types import _SPECIFIC_EFFECT_LABELS

_ROOT = Path(__file__).resolve().parents[2]

# Where the vocabulary is defined, so where its strings may be spelled.
VOCABULARY_HOMES: tuple[str, ...] = (
    "services/static/claims/",
    "utils/claim_ids.py",
)

# Effect labels are produced and described here; everywhere else they are display data.
LABEL_PRODUCERS: tuple[str, ...] = ("services/static/contract_analysis_pipeline/",)

# Supply-sign words that are also labels; alone they don't mark a label set.
_GENERIC_LABELS = frozenset({"mint", "burn"})
PRIVILEGE_LABELS: frozenset[str] = frozenset(_SPECIFIC_EFFECT_LABELS) - _GENERIC_LABELS

# {file: {string: reason}} for another vocabulary's word that is spelled like a claim id.
SHARED_STRINGS: dict[str, dict[str, str]] = {
    "services/static/contract_analysis_pipeline/effects/value_flow.py": {
        "value_router": "Flow direction the effects pass produces; the value_router claim is named after it.",
    },
    "services/static/contract_analysis_pipeline/effects/build.py": {
        "value_router": "Flow direction the effects pass produces; the value_router claim is named after it.",
    },
    "services/static/contract_analysis_pipeline/effects/types.py": {
        "contract_deployment": "Effect label in the label vocabulary, not the claim.",
    },
    "services/static/contract_analysis_pipeline/summaries.py": {
        "contract_deployment": "Effect label the summaries produce and describe, not the claim.",
    },
    "services/effects/calldata/flows.py": {
        "value_router": "Flow direction read from the effect facts, not the claim.",
    },
    "services/scoring/distill/claims.py": {
        "value_router": "Flow direction on a value-flow witness, not the claim.",
    },
}

# {file: {sorted labels: reason}} for label uses that decide display, not privilege.
DISPLAY_LABEL_USES: dict[str, dict[tuple[str, ...], str]] = {
    "services/aggregations/company_overview/governance_view.py": {
        ("asset_pull", "asset_send"): "Value-handler role and controls_value lane are display classification.",
    },
    "services/aggregations/action_summary.py": {
        ("arbitrary_external_call",): "Summary wording names the label still on the row.",
    },
}


def _tracked_sources() -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.py"], cwd=_ROOT, capture_output=True, text=True, check=True).stdout
    return [path for path in out.split() if not path.startswith("tests/")]


def _consumer_sources() -> list[str]:
    return [path for path in _tracked_sources() if not path.startswith(VOCABULARY_HOMES)]


def _claim_ids() -> frozenset[str]:
    return claim_ids_of_class(*GRANT_CLASSES)


def _id_prefixes(claim_ids: frozenset[str]) -> frozenset[str]:
    return frozenset(claim_id.split(".", 1)[0] + "." for claim_id in claim_ids if "." in claim_id)


def _claim_id_literals(source: str, claim_ids: frozenset[str]) -> list[tuple[int, str]]:
    """``(line, string)`` for every string constant spelling a claim id or a claim-id family prefix."""
    spelled = claim_ids | _id_prefixes(claim_ids)
    return sorted(
        (node.lineno, node.value)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in spelled
    )


def _privilege_label_uses(source: str) -> list[tuple[int, tuple[str, ...]]]:
    """``(line, labels)`` for each collection literal or comparison that names a privilege-bearing effect label."""
    found: list[tuple[int, tuple[str, ...]]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
            elements = list(node.elts)
        elif isinstance(node, ast.Dict):
            elements = [key for key in node.keys if key is not None]
        elif isinstance(node, ast.Compare):
            elements = [node.left, *node.comparators]
        else:
            continue
        labels = {
            element.value
            for element in elements
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        }
        named = tuple(sorted(labels & PRIVILEGE_LABELS))
        if named:
            found.append((node.lineno, named))
    return sorted(found)


def _referenced_claim_id_constants(source: str) -> set[str]:
    """Names read from ``utils.claim_ids``, through a module alias or a direct import."""
    tree = ast.parse(source)
    aliases: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "utils":
            aliases |= {alias.asname or alias.name for alias in node.names if alias.name == "claim_ids"}
        elif isinstance(node, ast.ImportFrom) and node.module == "utils.claim_ids":
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.Import):
            aliases |= {alias.asname for alias in node.names if alias.name == "utils.claim_ids" and alias.asname}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            names.add(node.attr)
    return names


def _read(path: str) -> str:
    return (_ROOT / path).read_text()


def test_no_consumer_spells_a_claim_id():
    claim_ids = _claim_ids()
    offenders = [
        f"{path}:{line}: {value!r}"
        for path in _consumer_sources()
        for line, value in _claim_id_literals(_read(path), claim_ids)
        if value not in SHARED_STRINGS.get(path, {})
    ]
    assert not offenders, (
        "Claim ids and id prefixes are named through utils.claim_ids and grant classes, not spelled:\n  "
        + "\n  ".join(offenders)
    )


def test_no_consumer_decides_privilege_on_effect_labels():
    offenders = [
        f"{path}:{line}: {labels}"
        for path in _consumer_sources()
        if not path.startswith(LABEL_PRODUCERS)
        for line, labels in _privilege_label_uses(_read(path))
        if labels not in DISPLAY_LABEL_USES.get(path, {})
    ]
    assert not offenders, (
        "Effect labels are display-only; decide privilege over claims and grant classes:\n  " + "\n  ".join(offenders)
    )


def test_every_named_claim_id_is_a_listed_consumer_reference():
    from utils import claim_ids

    named = {
        getattr(claim_ids, name)
        for path in _consumer_sources()
        for name in _referenced_claim_id_constants(_read(path))
        if isinstance(getattr(claim_ids, name, None), str)
    }
    assert named <= CONSUMER_REFERENCED_CLAIM_IDS, sorted(named - CONSUMER_REFERENCED_CLAIM_IDS)


def test_allow_list_entries_still_present():
    claim_ids = _claim_ids()
    stale = [
        f"{path}: {value!r}"
        for path, values in SHARED_STRINGS.items()
        for value in values
        if value not in {spelled for _line, spelled in _claim_id_literals(_read(path), claim_ids)}
    ]
    stale += [
        f"{path}: {labels}"
        for path, uses in DISPLAY_LABEL_USES.items()
        for labels in uses
        if labels not in {named for _line, named in _privilege_label_uses(_read(path))}
    ]
    assert not stale, "Allow-list entries that no longer match; remove them:\n  " + "\n  ".join(stale)


def test_detectors_catch_planted_violations():
    claim_ids = _claim_ids()
    planted = 'ADMIN = frozenset({"ownership.transfer"})\nFAMILIES = ("roles.", "timelock.")\n'
    assert _claim_id_literals(planted, claim_ids) == [(1, "ownership.transfer"), (2, "roles."), (2, "timelock.")]
    assert _claim_id_literals("from utils import claim_ids as C\nADMIN = {C.OWNERSHIP_TRANSFER}\n", claim_ids) == []

    labels = 'PRIVILEGED = frozenset({"pause_toggle", "mint"})\nif "authority_update" in labels:\n    pass\n'
    assert _privilege_label_uses(labels) == [(1, ("pause_toggle",)), (2, ("authority_update",))]
    assert _privilege_label_uses('SIGNS = ("mint", "burn")\n') == []

    aliased = "from utils import claim_ids as C\nfrom utils.claim_ids import FLOW_IN\nX = {C.PAUSE_SET, FLOW_IN}\n"
    assert _referenced_claim_id_constants(aliased) == {"PAUSE_SET", "FLOW_IN"}
