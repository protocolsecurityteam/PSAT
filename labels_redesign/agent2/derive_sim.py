#!/usr/bin/env python
"""Consumer-fit simulation: recompute lane + chip text for every
state-changing function under (a) CURRENT labels (frontend laneForFunction
logic), (b) H2+H3 (standards first, then fact-derived), and diff.

Lane logic (a) mirrors site/src/surface/lane.js + meta.js exactly.
Lane logic (b):
  control  <- H3 control_plane match, OR writes a non-constant gate var
              (gate_for_n_fns>0 | caller_eq_in_predicate_tree |
               modifier_calls_it | fallback_delegatecall_reads_it),
              OR contract_creation/selfdestruct sink, OR assembly
              delegatecall in own body (proxy-admin ops).
  right    <- H3 user-out semantic, or asset_send/burn fact
  left     <- H3 user-in semantic, or asset_pull/mint fact
  ops      <- everything else (facts chip)
Chips (b): H3 semantic string, else generated from facts.
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from h3sim import match_contract  # noqa: E402

CONTROL_EFFECTS = {
    "implementation_update", "delegatecall_execution", "ownership_transfer",
    "role_management", "authority_update", "hook_update", "pause_toggle",
    "timelock_operation", "contract_deployment", "selfdestruct_capability",
}
INPUT_EFFECTS = {"asset_pull", "mint"}
OUTPUT_EFFECTS = {"asset_send", "burn"}
INPUT_HINTS = ["deposit", "mint", "stake", "supply", "repay", "transferin", "bridgein", "join", "wrap"]
OUTPUT_HINTS = ["withdraw", "redeem", "transfer", "send", "sweep", "claim", "borrow", "unstake", "burn"]
CONTROL_HINTS = ["upgrade", "owner", "admin", "pause", "role", "authority", "hook", "timelock", "config"]

H3_OUT = {"unwraps ETH (user withdrawal)"}
H3_IN = {"wraps ETH (user deposit)"}


def hint(name, hints):
    return any(h in name for h in hints)


def lane_current(fn_name, labels):
    e = set(labels)
    n = fn_name.lower()
    if e & CONTROL_EFFECTS:
        return "control"
    if e & INPUT_EFFECTS and not e & OUTPUT_EFFECTS:
        return "in"
    if e & OUTPUT_EFFECTS:
        return "out"
    if hint(n, CONTROL_HINTS):
        return "control"
    if hint(n, INPUT_HINTS) and not hint(n, OUTPUT_HINTS):
        return "in"
    if hint(n, OUTPUT_HINTS):
        return "out"
    return "ops"


def lane_facts(d, sig, info, m):
    """H2+H3 lane + chip."""
    var_roles = d.get("var_roles") or {}
    if sig in m:
        std, sem, control = m[sig]
        if control:
            return "control", f"[{std}] {sem}"
        if sem in H3_OUT:
            return "out", f"[{std}] {sem}"
        if sem in H3_IN:
            return "in", f"[{std}] {sem}"
        # user-plane standard op (erc20 transfer/approve, safe exec, comp votes)
        lane = "ops"
        if std == "erc20":
            lane = "ops"  # allowance/balance user op; value routing needs flow facts
        return lane, f"[{std}] {sem}"

    labels = set(info.get("labels") or [])  # value labels reused as flow facts
    gate_vars = []
    ghost_vars = []
    for w in info.get("writes") or []:
        r = var_roles.get(w)
        if not r:
            continue
        if r.get("type") == "bytes32" and r.get("caller_eq_in_predicate_tree") and w.endswith(("StorageLocation", "_SLOT", "_STORAGE")):
            ghost_vars.append(w)  # namespaced-storage pseudo var: excluded from claims
            continue
        if (r.get("gate_for_n_fns") or 0) > 0 or r.get("caller_eq_in_predicate_tree") \
           or r.get("modifier_calls_it") or r.get("fallback_delegatecall_reads_it"):
            gate_vars.append((w, r))

    sinks = set(info.get("sink_kinds") or [])
    if gate_vars:
        w, r = gate_vars[0]
        kind = "gate bool" if r.get("is_bool") else ("authority address" if r.get("caller_eq_in_predicate_tree") else ("gate mapping" if r.get("is_mapping") else "gate var"))
        n = r.get("gate_for_n_fns") or 0
        return "control", f"writes {kind} `{w}`" + (f" (gates {n} fns)" if n else "")
    if "contract_creation" in sinks:
        return "control", "deploys a contract"
    if "selfdestruct" in sinks:
        return "control", "can self-destruct"
    if info.get("assembly") and "delegatecall" in sinks:
        return "control", "assembly delegatecall/storage op"
    if "asset_send" in labels or "burn" in labels:
        return "out", "moves value out (low-level value call / burn)"
    if "asset_pull" in labels or "mint" in labels:
        return "in", "moves value in / mints"
    writes = [w for w in (info.get("writes") or []) if w not in ghost_vars]
    if writes:
        return "ops", f"writes: {', '.join(writes[:3])}"
    if "external_call" in sinks:
        return "ops", "calls external contract"
    return "ops", ""


def main():
    diffs = []
    counts = {"current": {"control": 0, "in": 0, "out": 0, "ops": 0},
              "h2h3": {"control": 0, "in": 0, "out": 0, "ops": 0}}
    for path in sorted(glob.glob(os.path.join(HERE, "runs", "*.json"))):
        d = json.load(open(path))
        m = match_contract(d)
        for sig, info in sorted(d["functions"].items()):
            if not info.get("state_changing"):
                continue
            name = sig.split("(")[0]
            lc = lane_current(name, info.get("labels") or [])
            lf, chip = lane_facts(d, sig, info, m)
            counts["current"][lc] += 1
            counts["h2h3"][lf] += 1
            if lc != lf:
                diffs.append((d["contract"], name, lc, lf, chip))
    print("lane totals current:", counts["current"])
    print("lane totals h2+h3  :", counts["h2h3"])
    print(f"\nlane changes: {len(diffs)}")
    for c, n, lc, lf, chip in diffs:
        print(f"  {c+'.'+n:58s} {lc:8s}-> {lf:8s} | {chip[:70]}")


if __name__ == "__main__":
    main()
