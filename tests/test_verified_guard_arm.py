"""W2's verified-guard satisfier — ``verified_guard_verdicts``.

The arm exists to close one fail-open: a reentrancy guard var declared on a
contract must never license a function that does not carry the guard. Every
refusal fixture below removes exactly one conjunct of the §2.4 proof and is
paired with a positive sibling differing in that one construct, so a
``not_determined`` cannot pass because the analysis never reached the code.

Assertions are on the whole verdict dict — ``{"state": "not_determined", ...}``
is as truthy as a proof.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    W2_REASON_AMBIGUOUS_DECLARATION,
    W2_REASON_GUARD_NOT_APPLIED,
    W2_REASON_NO_VERIFIED_GUARD,
    W2_VERIFIED_GUARD_BASIS,
    ReentrancyAnalyzer,
    live_declarations,
    reentrancy_guard_modifiers,
    verified_guard_verdicts,
)


def _compile(tmp_path: Path, source: str, name: str = "C.sol") -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / name
    f.write_text(src)
    return Slither(str(f))


def _contract(tmp_path: Path, source: str, name: str):
    sl = _compile(tmp_path, source)
    for contract in sl.contracts:
        if contract.name == name:
            return contract
    raise AssertionError(f"no contract {name} in fixture")


def _refusal(reason: str, declaration: str | None = None) -> dict:
    return {
        "state": "not_determined",
        "basis": None,
        "reason": reason,
        "declaration": declaration,
        "guard_vars": [],
        "guard_modifiers": [],
    }


# ---------------------------------------------------------------------------
# Positive: OZ v4 single-modifier form
# ---------------------------------------------------------------------------

_OZ_V4 = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier nonReentrant() {
        require(_status != 2);
        _status = 2;
        _;
        _status = 1;
    }
    function withdraw() external nonReentrant {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }
}
"""


def test_oz_v4_guard_is_proven(tmp_path):
    verdicts = verified_guard_verdicts(_contract(tmp_path, _OZ_V4, "C"))
    assert verdicts["withdraw()"] == {
        "state": "proven",
        "basis": W2_VERIFIED_GUARD_BASIS,
        "reason": None,
        "declaration": "C.withdraw()",
        "guard_vars": ["_status"],
        "guard_modifiers": ["C.nonReentrant()"],
    }


# ---------------------------------------------------------------------------
# Positive: OZ v5 split form (the callee-following path)
# ---------------------------------------------------------------------------

_OZ_V5 = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    function _nonReentrantBefore() private {
        require(_status != 2);
        _status = 2;
    }
    function _nonReentrantAfter() private {
        _status = 1;
    }
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }
    function withdraw() external nonReentrant {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }
}
"""


def test_oz_v5_split_guard_is_proven(tmp_path):
    """The pre/post writes live in private helpers; the revert lives in one of
    them. Neither is visible in the modifier's own IRs."""
    verdicts = verified_guard_verdicts(_contract(tmp_path, _OZ_V5, "C"))
    assert verdicts["withdraw()"] == {
        "state": "proven",
        "basis": W2_VERIFIED_GUARD_BASIS,
        "reason": None,
        "declaration": "C.withdraw()",
        "guard_vars": ["_status"],
        "guard_modifiers": ["C.nonReentrant()"],
    }


# ---------------------------------------------------------------------------
# Positive: the guard inherited from a base contract
# ---------------------------------------------------------------------------

_INHERITED = """
pragma solidity ^0.8.19;
abstract contract Guard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status != 2);
        _status = 2;
        _;
        _status = 1;
    }
}
contract C is Guard {
    mapping(address => uint256) public bal;
    function withdraw() external nonReentrant {
        bal[msg.sender] = 0;
    }
}
"""


def test_inherited_guard_modifier_is_proven(tmp_path):
    """The join is ``id()``-identity; Slither hands the derived contract its own
    copy of an inherited modifier, and that copy is what the function lists."""
    verdicts = verified_guard_verdicts(_contract(tmp_path, _INHERITED, "C"))
    assert verdicts["withdraw()"]["state"] == "proven"
    assert verdicts["withdraw()"]["guard_modifiers"] == ["Guard.nonReentrant()"]


# ---------------------------------------------------------------------------
# A12 — the fail-open this unit exists to close
# ---------------------------------------------------------------------------

_A12_GUARD_VAR_BUT_NO_MODIFIER = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier nonReentrant() {
        require(_status != 2);
        _status = 2;
        _;
        _status = 1;
    }
    function guardedWithdraw() external nonReentrant {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }
    function payout() external {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }
}
"""


def test_a12_contract_guard_var_does_not_license_an_unguarded_function(tmp_path):
    contract = _contract(tmp_path, _A12_GUARD_VAR_BUT_NO_MODIFIER, "C")
    verdicts = verified_guard_verdicts(contract)
    assert verdicts["payout()"] == _refusal(W2_REASON_GUARD_NOT_APPLIED, "C.payout()")
    # Paired positive: the sibling differs in exactly one construct — it carries
    # the modifier — so the refusal is not the analysis failing to run.
    assert verdicts["guardedWithdraw()"]["state"] == "proven"
    # And the guard var IS contract-scoped, which is precisely why the
    # per-function join is load-bearing.
    assert "_status" in ReentrancyAnalyzer(contract).run()


# ---------------------------------------------------------------------------
# A13 — set/restore without a revert reading the var is not a guard
# ---------------------------------------------------------------------------

_A13_FAKE_GUARD_NO_REVERT = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier notAGuard() {
        _status = 2;
        _;
        _status = 1;
    }
    function payout() external notAGuard {
        bal[msg.sender] = 0;
    }
}
"""

_A13_SIBLING_WITH_REVERT = _A13_FAKE_GUARD_NO_REVERT.replace(
    "        _status = 2;\n        _;",
    "        require(_status != 2);\n        _status = 2;\n        _;",
)


def test_a13_set_restore_without_revert_refuses(tmp_path):
    verdicts = verified_guard_verdicts(_contract(tmp_path, _A13_FAKE_GUARD_NO_REVERT, "C"))
    assert verdicts["payout()"] == _refusal(W2_REASON_NO_VERIFIED_GUARD, "C.payout()")


def test_a13_sibling_adding_only_the_revert_is_proven(tmp_path):
    """One added ``require`` — the removed conjunct — flips the same fixture."""
    verdicts = verified_guard_verdicts(_contract(tmp_path, _A13_SIBLING_WITH_REVERT, "C"))
    assert verdicts["payout()"]["state"] == "proven"
    assert verdicts["payout()"]["guard_vars"] == ["_status"]


# ---------------------------------------------------------------------------
# A14 — no name drives an effect (invariant 1)
# ---------------------------------------------------------------------------

_A14_NAME_ONLY_GUARD = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _reentrancyLock = 1;
    mapping(address => uint256) public bal;
    modifier reentrancyGuard() {
        require(_reentrancyLock != 2);
        _reentrancyLock = 2;
        _;
    }
    function payout() external reentrancyGuard {
        bal[msg.sender] = 0;
    }
}
"""


def test_a14_name_only_guard_refuses(tmp_path):
    """``_reentrancyLock`` under a modifier named ``reentrancyGuard`` — every
    identifier says guard, and the post-placeholder write is missing, so there
    is no placeholder split to prove. ``effects.py``'s name fallback would
    admit this var; nothing on this arm can reach that fallback."""
    verdicts = verified_guard_verdicts(_contract(tmp_path, _A14_NAME_ONLY_GUARD, "C"))
    assert verdicts["payout()"] == _refusal(W2_REASON_NO_VERIFIED_GUARD, "C.payout()")


def test_a14_sibling_adding_only_the_post_placeholder_write_is_proven(tmp_path):
    source = _A14_NAME_ONLY_GUARD.replace(
        "        _reentrancyLock = 2;\n        _;",
        "        _reentrancyLock = 2;\n        _;\n        _reentrancyLock = 1;",
    )
    verdicts = verified_guard_verdicts(_contract(tmp_path, source, "C"))
    assert verdicts["payout()"]["state"] == "proven"


def test_a14_renamed_equivalent_of_the_real_guard_is_still_proven(tmp_path):
    """The mirror of A14: strip every guard-suggesting identifier from the OZ v4
    shape and it must still prove. Names neither earn nor deny."""
    source = _OZ_V4.replace("_status", "q").replace("nonReentrant", "m")
    verdicts = verified_guard_verdicts(_contract(tmp_path, source, "C"))
    assert verdicts["withdraw()"]["state"] == "proven"
    assert verdicts["withdraw()"]["guard_vars"] == ["q"]


# ---------------------------------------------------------------------------
# A15 — transient-storage guards are invisible to the write walk
# ---------------------------------------------------------------------------

_A15_TRANSIENT_GUARD = """
pragma solidity ^0.8.24;
contract C {
    uint256 private constant SLOT = 0;
    mapping(address => uint256) public bal;
    modifier tguard() {
        assembly {
            if tload(SLOT) { revert(0, 0) }
            tstore(SLOT, 1)
        }
        _;
        assembly { tstore(SLOT, 0) }
    }
    function payout() external tguard {
        bal[msg.sender] = 0;
    }
}
"""


def test_a15_transient_guard_refuses(tmp_path):
    """``tstore``/``tload`` lower to ``SolidityCall`` IRs, not state-variable
    writes, so the pre/post walk sees nothing. The guard is real and the verdict
    is still ``not_determined`` — fail-closed on storage we cannot read."""
    verdicts = verified_guard_verdicts(_contract(tmp_path, _A15_TRANSIENT_GUARD, "C"))
    assert verdicts["payout()"] == _refusal(W2_REASON_NO_VERIFIED_GUARD, "C.payout()")


def test_a15_same_shape_in_persistent_storage_is_proven(tmp_path):
    """Identical control flow written to a state variable instead of a transient
    slot — the refusal above is about visibility, not about the shape."""
    source = """
    pragma solidity ^0.8.24;
    contract C {
        uint256 private _slot;
        mapping(address => uint256) public bal;
        modifier tguard() {
            require(_slot == 0);
            _slot = 1;
            _;
            _slot = 0;
        }
        function payout() external tguard {
            bal[msg.sender] = 0;
        }
    }
    """
    verdicts = verified_guard_verdicts(_contract(tmp_path, source, "C"))
    assert verdicts["payout()"]["state"] == "proven"


# ---------------------------------------------------------------------------
# Function identity — a signature does not name a body in an inheritance chain
# ---------------------------------------------------------------------------

_SHADOWED_OVERRIDE = """
pragma solidity ^0.8.19;
contract Base {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier nonReentrant() {
        require(_status != 2);
        _status = 2;
        _;
        _status = 1;
    }
    function payout() external virtual nonReentrant {
        bal[msg.sender] = 0;
    }
    function helper() internal virtual nonReentrant {
        bal[msg.sender] = 0;
    }
}
contract Mid is Base {
    function payout() external virtual override {
        bal[msg.sender] = 0;
    }
    function helper() internal virtual override {
        bal[msg.sender] = 0;
    }
}
contract C is Mid {}
"""


def test_shadowed_base_declaration_does_not_publish_the_overrides_verdict(tmp_path):
    """``C``'s live ``payout`` is ``Mid``'s, which dropped the guard; ``Base``'s
    guarded body is still in ``contract.functions`` and must not answer for it.
    Keying on the signature alone let whichever declaration Slither yielded last
    win, and it yields the base last."""
    contract = _contract(tmp_path, _SHADOWED_OVERRIDE, "C")
    verdicts = verified_guard_verdicts(contract)
    assert verdicts["payout()"] == _refusal(W2_REASON_GUARD_NOT_APPLIED, "Mid.payout()")
    # Internal functions shadow the same way, and the visibility never entered it.
    assert verdicts["helper()"] == _refusal(W2_REASON_GUARD_NOT_APPLIED, "Mid.helper()")
    # Non-vacuity: the shadowed guarded body is present and would have proven.
    shadowed = [f for f in contract.functions if f.canonical_name == "Base.payout()"]
    assert shadowed and shadowed[0].is_shadowed
    # ``Function.modifiers`` is a heterogeneous list (base-constructor calls ride
    # in it), so read the name off whatever is there.
    assert [getattr(m, "canonical_name", None) for m in shadowed[0].modifiers] == ["Base.nonReentrant()"]


def test_the_live_override_still_proves_when_it_keeps_the_guard(tmp_path):
    """The paired positive: one added modifier on ``Mid.payout`` and the same
    chain proves — so the refusal above is the shadowing rule, not a chain the
    analysis cannot walk."""
    source = _SHADOWED_OVERRIDE.replace(
        "function payout() external virtual override {",
        "function payout() external virtual override nonReentrant {",
    )
    verdicts = verified_guard_verdicts(_contract(tmp_path, source, "C"))
    assert verdicts["payout()"]["state"] == "proven"
    assert verdicts["payout()"]["declaration"] == "Mid.payout()"


_DIAMOND = """
pragma solidity ^0.8.19;
contract Base {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier nonReentrant() {
        require(_status != 2);
        _status = 2;
        _;
        _status = 1;
    }
    function payout() external virtual nonReentrant {
        bal[msg.sender] = 0;
    }
}
contract L is Base {
    function payout() external virtual override nonReentrant {
        bal[msg.sender] = 1;
    }
}
contract R is Base {
    function payout() external virtual override nonReentrant {
        bal[msg.sender] = 2;
    }
}
contract D is L, R {
    function payout() external override(L, R) {
        bal[msg.sender] = 0;
    }
}
"""


def test_diamond_join_reads_the_most_derived_body_not_the_three_guarded_ones(tmp_path):
    """Three guarded ancestor declarations against one unguarded override — the
    shape with the most room for an iteration-order answer."""
    contract = _contract(tmp_path, _DIAMOND, "D")
    verdicts = verified_guard_verdicts(contract)
    assert verdicts["payout()"] == _refusal(W2_REASON_GUARD_NOT_APPLIED, "D.payout()")
    guarded_ancestors = [
        f for f in contract.functions if f.full_name == "payout()" and f.canonical_name != "D.payout()"
    ]
    assert len(guarded_ancestors) == 3
    assert all(f.is_shadowed and f.modifiers for f in guarded_ancestors)


def test_live_declarations_keeps_one_body_per_signature(tmp_path):
    """The resolution the key rests on, asserted directly."""
    contract = _contract(tmp_path, _DIAMOND, "D")
    live = live_declarations(contract)
    assert [f.canonical_name for f in live["payout()"]] == ["D.payout()"]


class _Fn:
    is_constructor = False

    def __init__(self, canonical_name: str, full_name: str, is_shadowed: bool, modifiers=()):
        self.canonical_name = canonical_name
        self.full_name = full_name
        self.is_shadowed = is_shadowed
        self.modifiers = list(modifiers)


class _Contract:
    def __init__(self, functions):
        self.functions = functions
        self.modifiers = []


def test_two_live_declarations_of_one_signature_refuse(tmp_path):
    """Solidity will not compile this, so the arm is exercised on a stub rather
    than left as an untested branch. It exists because ``is_shadowed`` going
    missing or unset must surface as a refusal, never as a silent pick between
    two bodies."""
    contract = _Contract(
        [
            _Fn("A.payout()", "payout()", is_shadowed=False),
            _Fn("B.payout()", "payout()", is_shadowed=False),
            _Fn("A.solo()", "solo()", is_shadowed=False),
        ]
    )
    verdicts = verified_guard_verdicts(contract)
    assert verdicts["payout()"] == _refusal(W2_REASON_AMBIGUOUS_DECLARATION)
    # Non-vacuity: an unambiguous sibling in the same stub still resolves.
    assert verdicts["solo()"] == _refusal(W2_REASON_NO_VERIFIED_GUARD, "A.solo()")


# ---------------------------------------------------------------------------
# Surface contract for the consumer
# ---------------------------------------------------------------------------


def test_verdicts_are_total_over_live_declarations(tmp_path):
    """One verdict per live body — so a consumer never reads absence as a fact,
    and a shadowed body never contributes a key of its own. Asserted on the
    inheritance fixture, where a signature-keyed comparison would collapse the
    two declarations it is supposed to tell apart."""
    contract = _contract(tmp_path, _SHADOWED_OVERRIDE, "C")
    live = [f for f in contract.functions if not f.is_constructor and not f.is_shadowed]
    shadowed = [f for f in contract.functions if not f.is_constructor and f.is_shadowed]
    assert shadowed, "guard: the fixture must actually contain shadowed declarations"
    assert len(verdicts_of := verified_guard_verdicts(contract)) == len(live)
    assert set(verdicts_of) == {f.full_name for f in live}
    assert {v["declaration"] for v in verdicts_of.values()} == {f.canonical_name for f in live}
    assert all(v["state"] in ("proven", "not_determined") for v in verdicts_of.values())


def test_refusal_reasons_separate_the_two_ways_a_guard_can_be_missing(tmp_path):
    """``guard_modifier_not_applied`` (a proven guard exists elsewhere on the
    contract) and ``no_verified_guard_modifier`` (none does) are different
    findings for the consumer, and only the first is the fail-open shape."""
    guarded = verified_guard_verdicts(_contract(tmp_path, _A12_GUARD_VAR_BUT_NO_MODIFIER, "C"))
    unguarded = verified_guard_verdicts(_contract(tmp_path, _A13_FAKE_GUARD_NO_REVERT, "C"))
    assert guarded["payout()"]["reason"] == W2_REASON_GUARD_NOT_APPLIED
    assert unguarded["payout()"]["reason"] == W2_REASON_NO_VERIFIED_GUARD


def test_proven_dict_names_which_modifier_holds_which_var(tmp_path):
    """The modifier-retaining computation is the whole difference from the
    contract-scoped var set — without it there is nothing to join against."""
    contract = _contract(tmp_path, _A12_GUARD_VAR_BUT_NO_MODIFIER, "C")
    proven = reentrancy_guard_modifiers(contract)
    by_name = {m.canonical_name: proven[id(m)] for m in contract.modifiers if id(m) in proven}
    assert by_name == {"C.nonReentrant()": frozenset({"_status"})}


def test_proven_dict_is_empty_when_no_modifier_earns_it(tmp_path):
    contract = _contract(tmp_path, _A13_FAKE_GUARD_NO_REVERT, "C")
    assert reentrancy_guard_modifiers(contract) == {}
    # Non-vacuity: the modifier exists and does write the var on both sides.
    assert [m.canonical_name for m in contract.modifiers] == ["C.notAGuard()"]


_TWO_GUARD_VARS = """
pragma solidity ^0.8.19;
contract C {
    uint256 private a = 1;
    uint256 private b = 1;
    mapping(address => uint256) public bal;
    modifier m() {
        require(a != 2);
        require(b != 2);
        a = 2;
        b = 2;
        _;
        a = 1;
        b = 1;
    }
    function payout() external m {
        bal[msg.sender] = 0;
    }
}
"""


def test_a_modifier_holding_two_guard_vars_publishes_both(tmp_path):
    """``run`` unions the proven set. Picking one — which is what iterating a
    ``set`` and returning the first amounted to — made the published var depend
    on the hash seed."""
    contract = _contract(tmp_path, _TWO_GUARD_VARS, "C")
    assert reentrancy_guard_modifiers(contract) == {id(contract.modifiers[0]): frozenset({"a", "b"})}
    assert ReentrancyAnalyzer(contract).run() == {"a", "b"}
    assert verified_guard_verdicts(contract)["payout()"]["guard_vars"] == ["a", "b"]
