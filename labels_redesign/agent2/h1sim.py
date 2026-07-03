#!/usr/bin/env python
"""H1 simulator: keep the vocabulary, delete the guess/string tiers, derive
authority-adjacent labels from predicate trees + pause pass, canonical
selectors unchanged. Two variants:

  H1  = exactly the incumbent proposal mechanics:
        - ownership_transfer: post-pass (predicate equality leaves) ONLY
        - pause_toggle: pause_info.pause_toggle_functions (structural pass)
        - authority_update: canonical selector ONLY
        - hook_update: _writes_hook_reference (structural) ONLY (guess tier deleted)
        - implementation_update: unchanged detectors (still same-contract only)
        - everything else unchanged
  H1G = H1 + is_constant guard on the ownership post-pass write set
        (kills OZ v5 storage-location ghost writes + Solady _OWNER_SLOT).

Runs in-process on the cached/etherscan sources for the same 27 contracts,
prints per-(contract,fn) label diffs vs the baseline runs/*.json.
"""
import glob
import json
import os
import sys

sys.path.insert(0, "/home/riley/PSAT")
HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

from slither import Slither  # noqa: E402

import services.static.contract_analysis_pipeline.summaries as summaries  # noqa: E402
from services.static.contract_analysis_pipeline import effects as effects_mod  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)

# ---- H1 monkeypatches (in-memory only) ----
summaries._writes_unclassified_address_pointer = lambda f: False  # delete guess tier
summaries._writes_owner_like_address = lambda f: False  # ownership via post-pass only
summaries._writes_authority_reference = lambda f: False  # authority via canonical selector only
summaries._writes_pause_like_bool = lambda f: False  # pause via pause pass (added below)

GUARDED = os.environ.get("H1_CONST_GUARD") == "1"
if GUARDED:
    _orig_apply = effects_mod.apply_authority_effect_labels

    def guarded_apply(contract, effects_artifact, predicate_trees_artifact):
        functions = effects_artifact.get("functions") if isinstance(effects_artifact, dict) else None
        if not isinstance(functions, dict):
            return
        owner_vars = effects_mod._owner_vars_from_predicate_trees(predicate_trees_artifact)
        if not owner_vars:
            return
        for fn in getattr(contract, "functions", []) or []:
            info = functions.get(effects_mod._function_full_name(fn))
            if not isinstance(info, dict):
                continue
            written = {
                getattr(var, "name", None)
                for var in fn.all_state_variables_written()
                if not getattr(var, "is_constant", False)  # <-- the guard
            }
            if "ownership_transfer" in (info.get("effect_labels") or []) or not (written & owner_vars):
                continue
            labels = [l for l in (info.get("effect_labels") or []) if l not in effects_mod._COARSE_AUTHORITY_LABELS]
            labels.append("ownership_transfer")
            info["effect_labels"] = labels
            info["action_summary"] = effects_mod._action_summary(labels, list(info.get("effect_targets") or []))

    apply_pass = guarded_apply
else:
    apply_pass = effects_mod.apply_authority_effect_labels

TARGETS = json.load(open(os.path.join(HERE, "targets.json")))


def main():
    out_name = "h1g" if GUARDED else "h1"
    os.makedirs(os.path.join(HERE, out_name), exist_ok=True)
    key = os.environ["ETHERSCAN_API_KEY"]
    for addr, name, prefix in TARGETS:
        outp = os.path.join(HERE, out_name, f"{name}_{addr[2:10]}.json")
        if os.path.exists(outp):
            continue
        try:
            sl = Slither(f"{prefix}:{addr}", etherscan_api_key=key, disable_solc_warnings=True)
            subject = None
            for c in sl.contracts:
                if c.name == name:
                    subject = c
                    break
            if subject is None:
                cands = [c for c in sl.contracts if not c.is_interface and not c.is_abstract and not c.is_library]
                subject = max(cands, key=lambda c: len(list(c.functions)))
            trees, pause_info = build_predicate_artifacts_with_pause_info(subject)
            art = effects_mod.build_effects(subject)
            apply_pass(subject, art, trees)
            # pause via the structural pause pass
            toggles = set(pause_info.get("pause_toggle_functions") or [])
            for sig, info in art.get("functions", {}).items():
                if sig in toggles and "pause_toggle" not in (info.get("effect_labels") or []):
                    info["effect_labels"] = list(info.get("effect_labels") or []) + ["pause_toggle"]
            slim = {
                "contract": subject.name,
                "pause_toggle_functions": sorted(toggles),
                "pause_state_vars": sorted(pause_info.get("pause_state_vars") or []),
                "functions": {
                    sig: sorted(i.get("effect_labels") or []) for sig, i in art.get("functions", {}).items()
                },
            }
            json.dump(slim, open(outp, "w"), indent=1)
            print("OK", name)
        except Exception as exc:  # noqa: BLE001
            print("FAIL", name, type(exc).__name__, str(exc)[:120])


if __name__ == "__main__":
    main()
