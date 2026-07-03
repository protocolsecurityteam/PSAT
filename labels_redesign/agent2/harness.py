#!/usr/bin/env python
"""READ-ONLY investigation harness: run the CURRENT static label pipeline
in-process on an Etherscan-fetched verified contract.

Usage: harness.py <address> <ContractName> [chain_prefix]
Writes runs/<ContractName>_<addr8>.json with per-function:
  effect_labels (post authority pass), action_summary, sinks, state_changing,
plus artifact-level: owner_vars from predicate trees, pause_info, standards.
"""
import json
import os
import sys
import traceback

sys.path.insert(0, "/home/riley/PSAT")

SCRATCH = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRATCH)  # crytic-export lands here, never in the repo

from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    apply_authority_effect_labels,
    build_effects,
)
from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    _owner_vars_from_predicate_trees,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)


def main() -> int:
    addr = sys.argv[1]
    want_name = sys.argv[2] if len(sys.argv) > 2 else None
    prefix = sys.argv[3] if len(sys.argv) > 3 else "mainnet"
    key = os.environ["ETHERSCAN_API_KEY"]

    target = f"{prefix}:{addr}"
    sl = Slither(target, etherscan_api_key=key, disable_solc_warnings=True)

    contracts = [c for c in sl.contracts if not c.is_interface]
    subject = None
    if want_name:
        for c in contracts:
            if c.name == want_name:
                subject = c
                break
    if subject is None:
        # largest deployable contract as fallback
        cands = [c for c in contracts if not c.is_abstract and not c.is_library]
        subject = max(cands, key=lambda c: len(list(c.functions))) if cands else contracts[-1]

    predicate_trees, pause_info = build_predicate_artifacts_with_pause_info(subject)
    effects = build_effects(subject)
    apply_authority_effect_labels(subject, effects, predicate_trees)

    owner_vars = sorted(_owner_vars_from_predicate_trees(predicate_trees))

    ercs = []
    try:
        ercs = list(subject.ercs()) if callable(getattr(subject, "ercs", None)) else []
    except Exception:
        pass

    # ---- facts prototype (H2): role-of-written-state, computed structurally ----
    # For every state var written by an externally-observable fn, record
    # checkable structural facts about how the var is USED.
    entry_fns = [f for f in subject.functions if getattr(f, "visibility", "") in ("external", "public")]
    written_vars = {}
    for f in subject.functions:
        try:
            for v in f.all_state_variables_written():
                written_vars.setdefault(getattr(v, "name", ""), v)
        except Exception:
            pass

    var_roles = {}
    fallback_dc_reads = set()
    for fn in subject.functions:
        if not (getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False)):
            continue
        has_dc = any("delegatecall" in str(ir).lower() for node in fn.nodes for ir in node.irs)
        if has_dc:
            for v in fn.all_state_variables_read():
                fallback_dc_reads.add(getattr(v, "name", ""))

    tree_eq_vars = set(owner_vars)

    for name, v in written_vars.items():
        if not name:
            continue
        t = str(getattr(v, "type", ""))
        gate_for = []
        modifier_called = False
        for modifier in subject.modifiers:
            try:
                reads = {getattr(x, "name", "") for x in modifier.all_state_variables_read()}
            except Exception:
                reads = set()
            if name in reads:
                gated = [
                    getattr(f2, "full_name", f2.name)
                    for f2 in entry_fns
                    if modifier in getattr(f2, "modifiers", [])
                ]
                gate_for.extend(gated)
            try:
                for _cc, call_ir in modifier.all_high_level_calls():
                    if f"dest:{name}" in str(call_ir):
                        modifier_called = True
            except Exception:
                pass
        var_roles[name] = {
            "type": t,
            "is_mapping": t.startswith("mapping"),
            "is_bool": t == "bool",
            "is_address": t == "address",
            "gate_for_n_fns": len(set(gate_for)),
            "modifier_calls_it": modifier_called,
            "fallback_delegatecall_reads_it": name in fallback_dc_reads,
            "caller_eq_in_predicate_tree": name in tree_eq_vars,
        }

    out = {
        "address": addr,
        "contract": subject.name,
        "owner_vars_from_trees": owner_vars,
        "pause_info": {
            "pause_state_vars": list(pause_info.get("pause_state_vars") or []),
            "pause_toggle_functions": list(pause_info.get("pause_toggle_functions") or []),
        },
        "slither_ercs": [str(e) for e in ercs],
        "var_roles": var_roles,
        "functions": {},
    }
    for sig, info in sorted(effects.get("functions", {}).items()):
        out["functions"][sig] = {
            "labels": info.get("effect_labels"),
            "summary": info.get("action_summary"),
            "state_changing": info.get("state_changing"),
            "assembly": info.get("assembly_state_access"),
            "sink_kinds": sorted({s["kind"] for s in info.get("sinks") or []}),
            "writes": sorted({s["target"] for s in (info.get("sinks") or []) if s["kind"] == "state_write"}),
        }

    os.makedirs(os.path.join(SCRATCH, "runs"), exist_ok=True)
    path = os.path.join(SCRATCH, "runs", f"{subject.name}_{addr[2:10]}.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"WROTE {path} fns={len(out['functions'])} owner_vars={owner_vars}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
