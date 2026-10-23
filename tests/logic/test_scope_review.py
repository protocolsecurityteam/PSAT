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
        # ``changeReward``: the manager is appointed by the owner, so holding ``ops[id]`` is not the caller's own.
        **dict.fromkeys(
            ["allow", "deactivate", "reactivate", "freeze", "unfreezeToken", "move", "changeReward"], "shared"
        ),
    },
    ("gate.sol", "G"): dict.fromkeys(["ownerSpend", "gated", "ownerPaused"], "self"),
    ("asm.sol", "A"): dict.fromkeys(["approveA", "clearFlag", "transferFromA", "useFlag"], "shared"),
    ("asm2.sol", "A"): dict.fromkeys(["approveA", "clearFlag", "transferFromA", "useFlag"], "shared"),
    ("loop.sol", "Probe"): dict.fromkeys(["addDelegate", "setApproved", "moveLoop", "moveApproved"], "shared"),
    # An approval no check here reads, handed out by a view: another contract's check may read it. A balance a
    # view hands out may still be moved, debit for credit.
    ("approvals.sol", "Approvals"): {"approve": "shared", "move": "self"},
    # Third review. A fixed key is one protocol-wide position; a keeper an admin appoints holds nothing of the
    # vault's; a reporter's entry everyone's settlement reads is value flow; value moved to this contract or a
    # treasury is conserved; a self-move that also stamps is not shown conserved.
    ("review3_p1.sol", "ConstKey"): dict.fromkeys(["setFee", "clearFee", "pay"], "shared"),
    ("review3_p1.sol", "Keeper"): dict.fromkeys(["setKeeper", "sweep", "retarget"], "shared"),
    ("review3_p1.sol", "Oracle"): dict.fromkeys(["addReporter", "retract", "settle"], "shared"),
    ("review3_p1.sol", "Treasury"): dict.fromkeys(["toThis", "toTreasury"], "self"),
    ("review3_p1.sol", "Stamp"): dict.fromkeys(["selfMove", "selfMoveOnly"], "shared"),
    ("review3_p3.sol", "TwoExit"): {"f": "shared"},
    ("review3_p3.sol", "Origin"): {"clearOrigin": "shared"},
    ("review3_p3.sol", "EventOnly"): {"ping": "none"},
    ("review3_p3.sol", "Sstore"): {"clear": "self", "raw": "shared"},
    ("review3_p3.sol", "Sstore2"): dict.fromkeys(["clearAndTake", "clearAndTake2"], "shared"),
    ("review3_p3.sol", "Proxy"): {"fwd": "shared", "fallback": "shared"},
    ("review3_p3.sol", "Unchk"): dict.fromkeys(["bounded", "boundedOther"], "shared"),
    ("bounded.sol", "Bounded"): {"bounded": "self"},
    # What a non-view function, a loop, a helper or a hash hands out; a holder entry anyone can claim; an operator
    # an admin can forge.
    ("review3_p4.sol", "NonView"): {"approve": "shared", "peek": "none"},
    ("review3_p4.sol", "LoopView"): {"approve": "shared"},
    ("review3_p4.sol", "HelperView"): {"approve": "shared"},
    ("review3_p4.sol", "DerivedView"): {"approve": "shared"},
    ("review3_p4.sol", "Claim"): dict.fromkeys(["claim", "approve"], "shared"),
    ("review3_p4.sol", "Forge"): dict.fromkeys(["setOp", "adminOp", "drain"], "shared"),
    ("review3_p4.sol", "Hash"): {"clearPacked": "self", "setVictim": "shared"},
    # Assembly calls, delegatecalls, selfdestruct and sload, seen by the lowering.
    ("review3_p5.sol", "AsmAct"): dict.fromkeys(["fwdAsm", "sendAsm", "killAsm"], "shared"),
    ("review3_p5.sol", "AsmRead"): dict.fromkeys(["setFrozen", "guarded", "clearCredits"], "shared"),
    ("review3_p6.sol", "ConstKeyPub"): {"setFee": "shared"},
    ("review3_p6.sol", "SolSend"): {"sendSol": "shared"},
    ("review3_p6.sol", "Oracle2"): dict.fromkeys(["retract", "lower", "settle"], "shared"),
    ("review3_p7.sol", "AsmAct2"): dict.fromkeys(["allow", "sendAsm", "sendSol"], "shared"),
    # A check hidden behind recursion or depth: lowered in part, so everything counts as checked.
    ("review3_p8.sol", "Deep"): dict.fromkeys(["act", "unban"], "shared"),
    ("review3_p8.sol", "Deep2"): dict.fromkeys(["act", "unban"], "shared"),
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
    function = next(f for f in contract.functions_entry_points if f.name == fn and not f.is_constructor)
    verdict, _ = function_verdict(contract, function, AT, _Deployed(), {AT: contract})
    assert verdict.scope == scope
    if scope == "shared":
        assert "self_scoped" not in verdict.gaps


def test_facts_cut_off_by_the_budget_are_cached_as_everything_checked(tmp_path, monkeypatch):
    # Whatever the next function asks, the contract isn't lowered again: its facts are "unknown, all checked".
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic import lower, scope

    path = tmp_path / "B.sol"
    path.write_text((PROBES / "bounded.sol").read_text())
    contract = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Bounded")
    calls = []

    def timeout(self, fn):
        calls.append(fn)
        raise TimeoutError("function budget")

    monkeypatch.setattr(lower.Lowerer, "success", timeout)
    with pytest.raises(TimeoutError):
        scope.contract_facts(contract)
    assert scope.contract_facts(contract).everything and len(calls) == 1
