#!/usr/bin/env python
"""Local in-process static-pipeline runner for the labels investigation.

READ-ONLY wrt the repo: fetches verified source from Etherscan, scaffolds a
Foundry project in the scratchpad, compiles with Slither, and runs the exact
sequence core.py:186-248 runs:
    Slither -> build_predicate_artifacts_with_pause_info -> build_effects
            -> apply_authority_effect_labels
Dumps per-function labels plus the internals (pause_info, owner_vars, leaf
roles) needed to prototype H1/H4 derivations offline.
"""
import json
import os
import sys
import time
import traceback
from pathlib import Path

SCRATCH = Path(__file__).resolve().parent
PROJECTS = SCRATCH / "projects"
RUNS = SCRATCH / "runs"
PROJECTS.mkdir(parents=True, exist_ok=True)
RUNS.mkdir(parents=True, exist_ok=True)

# Dead local DB URL so the etherscan pg-cache no-ops (no DB writes anywhere).
os.environ["DATABASE_URL"] = "postgresql://nouser:nopass@127.0.0.1:1/nonexistent"

sys.path.insert(0, "/home/riley/PSAT")

from slither.slither import Slither  # noqa: E402

from services.discovery.fetch import fetch, scaffold  # noqa: E402
from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    apply_authority_effect_labels,
    build_effects,
    _owner_vars_from_predicate_trees,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)
from services.static.contract_analysis_pipeline.shared import _select_subject_contract  # noqa: E402


def leaf_summaries(tree):
    """Flatten a predicate tree into (role, kind, operator, refs, references_msg_sender) leaf tuples."""
    out = []

    def visit(node):
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            refs = []
            for op_ in leaf.get("operands") or []:
                if isinstance(op_, dict):
                    if op_.get("state_variable_name"):
                        refs.append("sv:" + op_["state_variable_name"])
                    elif op_.get("source") not in (None, "msg_sender", "constant"):
                        refs.append(op_.get("source") or "?")
            sd = leaf.get("set_descriptor") or {}
            if isinstance(sd, dict) and sd.get("storage_var"):
                refs.append("set:" + str(sd.get("storage_var")))
            out.append(
                {
                    "role": leaf.get("authority_role"),
                    "kind": leaf.get("kind"),
                    "op": leaf.get("operator"),
                    "msg_sender": bool(leaf.get("references_msg_sender")),
                    "refs": refs,
                }
            )
            return
        for ch in node.get("children") or []:
            visit(ch)

    visit(tree)
    return out


def run(address: str, label: str, force: bool = False) -> dict:
    address = address.lower()
    pdir = PROJECTS / address
    if force or not (pdir / "contract_meta.json").exists():
        result = fetch(address)
        scaffold(address, result, pdir)
        time.sleep(1.2)  # shared-key pacing
    meta = json.loads((pdir / "contract_meta.json").read_text())

    sl = Slither(str(pdir))
    subject = _select_subject_contract(sl, meta.get("contract_name"))
    if subject is None:
        raise RuntimeError("no subject contract")

    trees_artifact, pause_info = build_predicate_artifacts_with_pause_info(subject)
    effects = build_effects(subject)
    apply_authority_effect_labels(subject, effects, trees_artifact)

    owner_vars = sorted(_owner_vars_from_predicate_trees(trees_artifact))
    trees = trees_artifact.get("trees") or {}

    fns = {}
    for sig, info in (effects.get("functions") or {}).items():
        fns[sig] = {
            "labels": sorted(info.get("effect_labels") or []),
            "summary": info.get("action_summary"),
            "state_changing": info.get("state_changing"),
            "sink_kinds": sorted({s.get("kind") for s in info.get("sinks") or []}),
            "state_writes": sorted(
                {s.get("target") for s in info.get("sinks") or [] if s.get("kind") == "state_write"}
            ),
            "leaves": leaf_summaries(trees.get(sig)),
        }

    # Written-vars per function straight from Slither (post-passes need this)
    written_by_fn = {}
    for fn in subject.functions:
        try:
            written_by_fn[fn.full_name] = sorted(
                {getattr(v, "name", "") for v in fn.all_state_variables_written() if getattr(v, "name", "")}
            )
        except Exception:
            pass

    out = {
        "address": address,
        "label": label,
        "contract_name": subject.name,
        "compiler": meta.get("compiler_version"),
        "owner_vars_from_trees": owner_vars,
        "pause_info": pause_info,
        "functions": fns,
        "written_by_fn": {k: v for k, v in written_by_fn.items() if k in fns},
        "guard_extraction_uncertain": sorted(trees_artifact.get("guard_extraction_uncertain") or []),
    }
    (RUNS / f"{label}.json").write_text(json.dumps(out, indent=1))
    # also persist raw trees for derivation prototyping
    (RUNS / f"{label}.trees.json").write_text(json.dumps(trees_artifact, indent=1, default=str))
    return out


if __name__ == "__main__":
    targets = json.loads(Path(sys.argv[1]).read_text()) if len(sys.argv) > 1 else []
    results = {}
    for t in targets:
        label = t["label"]
        try:
            out = run(t["address"], label, force=t.get("force", False))
            results[label] = {
                "ok": True,
                "n_fns": len(out["functions"]),
                "owner_vars": out["owner_vars_from_trees"],
                "pause_vars": out["pause_info"]["pause_state_vars"],
            }
            print(f"OK   {label} fns={len(out['functions'])} owner_vars={out['owner_vars_from_trees']} pause={out['pause_info']['pause_state_vars']}")
        except Exception as exc:
            results[label] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            print(f"FAIL {label}: {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=3)
        sys.stdout.flush()
    (RUNS / "_batch_summary.json").write_text(json.dumps(results, indent=1))
