"""End-to-end Solmate resolution on 100% real data.

Drives the actual resolver dispatch (``evaluate_tree_with_registry`` →
``AdapterRegistry`` → ``SolmateRolesAuthorityAdapter``) using:
  * the REAL predicate trees of ``TellerWithMultiAssetSupport`` 0xe2acf9f8…
    (``tests/fixtures/solmate/teller_predicate_trees.json``), and
  * the REAL RolesAuthority 0x3994741a… event logs
    (``tests/fixtures/solmate/roles_authority_3994741a.json``).

Pins the under-resolution fix end-to-end: ``pause`` (role-gated) resolves to
the governing 4/6 Safe; ``setShareLockPeriod`` (no role, owner renounced) does
not — a true negative, not a heuristic guess.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution.adapters import AdapterRegistry, CallFrame, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.adapters.solmate_roles import SolmateRolesAuthorityAdapter  # noqa: E402
from services.resolution.capabilities import CapabilityExpr  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree_with_registry  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "solmate"
SAFE_4_6 = "0xcea8039076e35a825854c5c2f85659430b06ec96"
ZERO = "0x" + "00" * 20
PAUSE = "0x8456cb59"
SET_SHARE_LOCK = "0x12056e2d"


def _event_rows() -> list[SimpleNamespace]:
    fixture = json.loads((FIXTURES / "roles_authority_3994741a.json").read_text())
    rows: list[SimpleNamespace] = []
    for log in fixture["logs"]:
        body = log["data"][2:] if isinstance(log["data"], str) and log["data"].startswith("0x") else ""
        data_words = ["0x" + body[i : i + 64] for i in range(0, len(body), 64)] if body else []
        rows.append(SimpleNamespace(topic0=log["topics"][0], topics=log["topics"], data_words=data_words))
    return rows


class FixtureRepo:
    def __init__(self, rows):
        self.rows = rows

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        del chain_id, event_address, block
        wanted = {t.lower() for t in topic0s}
        return [r for r in self.rows if str(r.topic0).lower() in wanted]

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        del chain_id, event_address, topic0s
        return 21_000_000


def _trees() -> dict:
    return json.loads((FIXTURES / "teller_predicate_trees.json").read_text())


def _members(cap: CapabilityExpr) -> set[str]:
    out: set[str] = set()
    for member in cap.members or []:
        out.add(member.lower())
    for child in cap.children or []:
        out |= _members(child)
    if cap.signer is not None:
        out |= _members(cap.signer)
    return out


def _resolve(tree_key: str, selector: str) -> CapabilityExpr:
    data = _trees()
    registry = AdapterRegistry()
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EventIndexedAdapter)
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=data["contract"],
        meta={"event_log_repo": FixtureRepo(_event_rows())},
        # authority resolved (RolesAuthority), owner renounced.
        state_var_values={"authority": "0x3994741a5b29c60d0ab318de1024f9256fe959dc", "owner": ZERO},
        call_frame=CallFrame.root(
            contract_address=data["contract"], function_signature=tree_key, function_selector=selector
        ),
    )
    return evaluate_tree_with_registry(data["trees"][tree_key], registry, ctx)


def test_teller_pause_resolves_to_governing_safe_end_to_end():
    cap = _resolve("pause()", PAUSE)
    assert SAFE_4_6 in _members(cap), (
        f"expected 4/6 Safe in resolved callers, got kind={cap.kind} members={_members(cap)}"
    )


def test_teller_set_share_lock_period_is_not_attributed_to_safe():
    # No role capability for this selector + owner renounced => the Safe must
    # NOT be attributed as a caller (would be a false positive).
    cap = _resolve("setShareLockPeriod(uint64)", SET_SHARE_LOCK)
    assert SAFE_4_6 not in _members(cap)
