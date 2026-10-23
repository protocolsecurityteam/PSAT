"""Every probe of the scope rule's reviews, as Solidity under ``scope_probes/``: what each function's writes come to.
The rule is conservative: whatever can't be shown to stay in the caller's position is shared."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic.test_scope import AT, _Deployed

PROBES = Path(__file__).parent / "scope_probes"

EXPECTED = {
    ("scope1.sol", "Probe"): {
        **dict.fromkeys(
            [
                "selfMint",
                "selfGrant",
                "doubleCredit",
                "blockedDrain",
                "selfOperator",
                "sendEth",
                "tokenOut",
                "makeVault",
                "kill",
                "killOnly",
                "libBump",
                "loopZero",
                "pauseIfNot",
                "hashOperator",
                "killOpen",
                "ownRaise",
                "enqueue",
            ],
            "shared",
        ),
    },
    ("scope2.sol", "Probe"): {
        # A second asset credited for the first's debit; ``amount <= allowance`` with amount 0; a "grant" the caller
        # sets itself; a sanction an early return enforces; a freeze checked only on an argument; a flag another
        # contract may read through its getter; unchecked and signed debits; a holder looked up at a key the caller
        # picks.
        **dict.fromkeys(
            [
                "allow",
                "crossAsset",
                "prefsLe",
                "report",
                "punish",
                "leaveBlk",
                "xferFrom",
                "unfreeze",
                "unfreezeX",
                "approveMax",
                "approveZero",
                "setDelegate",
                "clearDelegate",
                "loopDebit",
                "deletePos",
                "uncheckedDebit",
                "signedDebit",
                "withdrawAll",
                "nominate",
                "setData",
            ],
            "shared",
        ),
        # Shown to stay in the caller's position: a checked debit moved to another holder of the same asset, its
        # own credits cleared, a field no check reads, what a delegate or manager the holder named may clear.
        **dict.fromkeys(["transfer2", "crossUser", "modClear", "zeroStake", "asDelegate", "asMgr"], "self"),
    },
    ("split.sol", "Probe"): {
        **dict.fromkeys(["allow", "deactivate", "reactivate", "freeze", "unfreezeToken", "move"], "shared"),
        "changeReward": "self",
    },
    ("gate.sol", "G"): dict.fromkeys(["ownerSpend", "gated", "ownerPaused"], "self"),
    ("asm.sol", "A"): dict.fromkeys(["approveA", "clearFlag", "transferFromA", "useFlag"], "shared"),
    ("asm2.sol", "A"): dict.fromkeys(["approveA", "clearFlag", "transferFromA", "useFlag"], "shared"),
    ("loop.sol", "Probe"): dict.fromkeys(["addDelegate", "setApproved", "moveLoop", "moveApproved"], "shared"),
    # An approval no check here reads, handed out by a view: another contract's check may read it. A balance a
    # view hands out may still be moved, debit for credit.
    ("approvals.sol", "Approvals"): {"approve": "shared", "move": "self"},
}

CASES = [(file, name, fn, scope) for (file, name), fns in EXPECTED.items() for fn, scope in fns.items()]


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    out = {}
    for file, name in EXPECTED:
        path = tmp_path_factory.mktemp("review") / file
        path.write_text((PROBES / file).read_text())
        out[(file, name)] = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == name)
    return out


@pytest.mark.parametrize(("file", "name", "fn", "scope"), CASES, ids=[f"{c[0]}:{c[2]}" for c in CASES])
def test_each_probe_comes_out_as_expected(compiled, file, name, fn, scope):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = compiled[(file, name)]
    function = next(f for f in contract.functions_entry_points if f.name == fn)
    verdict, _ = function_verdict(contract, function, AT, _Deployed(), {AT: contract})
    assert verdict.scope == scope
    if scope == "shared":
        assert "self_scoped" not in verdict.gaps
