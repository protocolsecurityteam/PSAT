"""Generated authorization contracts, the static verdict on them, and the EVM's.

A case is a boolean guard over caller/state/argument atoms, placed by one of several semantics-preserving wrappers
behind unrelated branch noise. Execution on anvil is the oracle: which callers actually get through decides what the
static verdict may say, so no expected values are written by hand.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_abi.abi import encode
from eth_utils.address import to_checksum_address

from tests.support.anvil import ACCOUNT0, calldata, rpc, send

OWNER = "0x" + "a1" * 20
ADMIN = "0x" + "b2" * 20
STRANGER = "0x" + "c3" * 20
ARGS = (0, 11, 12)  # ``x > 10`` false/true, both parities

# Rendered against ``who`` (the caller, or a helper's parameter) and ``x``.
ATOMS = {
    "owner": "{who} == owner",
    "owner_rev": "owner == {who}",
    "owner_getter": "getOwner() == {who}",
    "admin": "{who} == admin",
    "constant": "{who} == " + to_checksum_address(OWNER),
    "constant_var": "{who} == HARDCODED",
    "immutable": "{who} == boss",
    "origin": "tx.origin == owner",
    "member": "isAdmin[{who}]",
    "flag": "flag",
    "arg": "{x} > 10",
    "time": "block.timestamp > 1",
}
WRAPPERS = (
    "require",
    "if_revert",
    "modifier",
    "helper",
    "nested_helper",
    "early_return_helper",
    "guard_fn",  # void internal check, OZ 5 ``_checkOwner`` shape
    "modifier_guard_fn",
    "gated_returning",  # the check lives in an internal function whose result ``f`` returns
)
# ``branch`` runs the check only for odd ``x``; ``loop`` inside a one-iteration loop.
PLACEMENTS = ("before", "after_write", "branch", "loop")
SENDERS = ("msg.sender", "_sender()")
SOLCS = ("0.8.27", "0.8.25", "0.7.0")
# What the controller-tracking stage reads for this contract, code-resident constants and immutables included.
STATE_VALUES = {"owner": OWNER, "admin": ADMIN, "HARDCODED": OWNER, "boss": ADMIN}


@dataclass(frozen=True)
class Case:
    guard: Any  # ("atom", name) | ("not", g) | ("and" | "or", g, g)
    wrapper: str = "require"
    placement: str = "before"
    noise: int = 0
    sender: str = "msg.sender"
    solc: str = "0.8.27"

    def render_guard(self, who: str) -> str:
        def go(g: Any) -> str:
            if g[0] == "atom":
                return ATOMS[g[1]].format(who=who, x="x")
            if g[0] == "not":
                return f"!({go(g[1])})"
            return f"({go(g[1])} {'&&' if g[0] == 'and' else '||'} {go(g[2])})"

        return go(self.guard)

    def source(self) -> str:
        direct, helper = self.render_guard(self.sender), self.render_guard("who")
        helpers = modifier = mod = ""
        if self.wrapper == "require":
            check = f"require({direct});"
        elif self.wrapper == "if_revert":
            check = f"if (!({direct})) revert();"
        elif self.wrapper == "modifier":
            modifier, mod, check = f"modifier gated(uint256 x) {{ require({direct}); _; }}", " gated(x)", ""
        elif self.wrapper in ("guard_fn", "modifier_guard_fn"):
            # Custom errors need >=0.8.4.
            revert = "revert Unauthorized(who);" if self.solc.startswith("0.8") else "revert();"
            helpers = f"function _guard(address who, uint256 x) internal view {{ if (!({helper})) {revert} }}"
            if self.solc.startswith("0.8"):
                helpers = "error Unauthorized(address account);" + helpers
            check = f"_guard({self.sender}, x);"
            if self.wrapper == "modifier_guard_fn":
                modifier, mod, check = f"modifier gated(uint256 x) {{ {check} _; }}", " gated(x)", ""
        elif self.wrapper == "gated_returning":
            helpers = (
                "function _gated(address who, uint256 x) internal returns (uint256) "
                f"{{ require({helper}); y = x; return x; }}"
            )
            check = f"value = _gated({self.sender}, x);"
        else:
            body = (
                f"if ({helper}) return true; return false;"
                if self.wrapper == "early_return_helper"
                else f"return {helper};"
            )
            helpers = f"function check(address who, uint256 x) internal view returns (bool) {{ {body} }}"
            entry = "check"
            if self.wrapper == "nested_helper":
                helpers += (
                    "function outer(address who, uint256 x) internal view returns (bool) { return check(who, x); }"
                )
                entry = "outer"
            check = f"require({entry}({self.sender}, x));"
        body = {
            "before": f"{check} value = x;",
            "after_write": f"value = x; {check}",
            "branch": f"if (x % 2 == 1) {{ {check} }} value = x;",
            "loop": f"for (uint256 i = 0; i < 1; i++) {{ {check} }} value = x;",
        }[self.placement]
        noise = "".join(f"if (x & {1 << i} != 0) {{ y ^= {i}; }} else {{ y ^= {i + 1}; }}" for i in range(self.noise))
        return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^{self.solc};
contract C {{
    address public owner; address public admin; bool public flag; uint256 public value; uint256 y;
    mapping(address => bool) public isAdmin;
    address constant HARDCODED = {to_checksum_address(OWNER)};
    address immutable boss;
    constructor(address o, address a, bool f) {{ owner = o; admin = a; flag = f; isAdmin[a] = true; boss = a; }}
    function _sender() internal view returns (address) {{ return msg.sender; }}
    function getOwner() public view returns (address) {{ return owner; }}
    {modifier}
    {helpers}
    function f(uint256 x) external{mod} {{ {noise}{body} }}
}}
"""


def solc_path(version: str) -> Path | None:
    for root in (Path(".venv/.solc-select/artifacts"), Path.home() / ".solc-select/artifacts"):
        if (candidate := root / f"solc-{version}" / f"solc-{version}").exists():
            return candidate.resolve()
    return None


@dataclass(frozen=True)
class Verdict:
    openness: str  # open | restricted | not_determined
    principals: frozenset[str]
    complete: bool  # every row claims ``exact`` membership
    seconds: float


def static_verdict(path: Path, case: Case) -> Verdict:
    from slither import Slither

    from services.policy.capability_surface import capability_surface_openness, project_capability_surface
    from services.resolution.capability_resolver import capability_to_dict
    from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
    from services.static.contract_analysis_pipeline.predicates import build_predicate_tree

    started = time.monotonic()
    function = next(
        f for c in Slither(str(path), solc=str(solc_path(case.solc))).contracts for f in c.functions if f.name == "f"
    )
    cap = capability_to_dict(
        evaluate_tree(build_predicate_tree(function), EvaluationContext(state_var_values=STATE_VALUES))
    )
    surface = project_capability_surface(cap)
    rows = surface.principal_rows
    principals = frozenset(str(row.get("address", "")).lower() for row in rows)
    complete = all((row.get("details") or {}).get("membership_quality") == "exact" for row in rows)
    return Verdict(capability_surface_openness(cap, surface), principals, complete, time.monotonic() - started)


@dataclass(frozen=True)
class Truth:
    open: bool  # a stranger gets through for some argument and business state
    admitted: frozenset[str]  # known principals that get through for some argument and business state


def evm_truth(url: str, path: Path, case: Case) -> Truth:
    out = subprocess.run(
        [str(solc_path(case.solc)), "--combined-json", "bin", str(path)], check=True, capture_output=True, text=True
    )
    bytecode = "0x" + next(iter(json.loads(out.stdout)["contracts"].values()))["bin"]
    calls = [calldata("f(uint256)", [arg]) for arg in ARGS]
    passed: set[str] = set()
    # Business state is a condition, not authority: whoever passes under any ``flag`` is admitted.
    for flag in (False, True):
        receipt = send(url, ACCOUNT0, bytecode + encode(["address", "address", "bool"], [OWNER, ADMIN, flag]).hex())
        assert receipt["status"] == "0x1", receipt
        for caller in (OWNER, ADMIN, STRANGER):
            for data in calls:
                try:
                    rpc(url, "eth_call", [{"from": caller, "to": receipt["contractAddress"], "data": data}, "latest"])
                except RuntimeError:
                    continue
                passed.add(caller)
                break
    return Truth(open=STRANGER in passed, admitted=frozenset(passed - {STRANGER}))


def unsound(verdict: Verdict, truth: Truth) -> list[str]:
    """Verdicts execution contradicts in the dangerous direction. ``not_determined`` is incomplete, never wrong."""
    out = []
    if verdict.openness == "restricted" and truth.open:
        out.append("fail-open: reported restricted, a stranger gets through")
    if verdict.openness == "restricted" and verdict.complete and (missing := truth.admitted - verdict.principals):
        out.append(f"hidden principal: {sorted(missing)} get through but are not reported")
    return out
