#!/usr/bin/env python
"""Prototype the H1 evidence-standard derivations against cached local projects.

Variants measured per contract (current code vs H1):
  A. fallback-deleted: `_writes_unclassified_address_pointer` disabled.
  B. pause-from-trees: pause_toggle sourced from PauseInfo.pause_toggle_functions
     (+ struct-member extension: member-level pause writes where the member is
     read by another function's revert leaf and the writer is auth-gated).
  C. implementation_update selector-canonical: upgradeTo(address)/
     upgradeToAndCall(address,bytes) + structural corroboration (contract
     declares proxiableUUID()/inherits UUPS or emits Upgraded).
  D. ownership harvest tightened: only scalar address-typed state vars
     (excludes mappings harvested through param-keyed equality leaves).
Prints per-contract label diffs current -> H1.
"""
import json
import sys
from pathlib import Path

SCRATCH = Path(__file__).resolve().parent
PROJECTS = SCRATCH / "projects"
OUT = SCRATCH / "h1_results"
OUT.mkdir(exist_ok=True)

import os
os.environ["DATABASE_URL"] = "postgresql://nouser:nopass@127.0.0.1:1/nonexistent"
sys.path.insert(0, "/home/riley/PSAT")

from slither.slither import Slither  # noqa: E402
from slither.slithir.operations import Assignment, Member  # noqa: E402

import services.static.contract_analysis_pipeline.summaries as summaries  # noqa: E402
from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    apply_authority_effect_labels,
    build_effects,
    _iter_predicate_leaves,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)
from services.static.contract_analysis_pipeline.shared import _select_subject_contract  # noqa: E402

UPGRADE_SELECTORS = {"upgradeTo(address)": "0x3659cfe6", "upgradeToAndCall(address,bytes)": "0x4f1ef286"}


def member_writes_by_fn(contract):
    """{fn_full_name: set[(var, member)]} member-level state writes via IR."""
    out = {}
    for fn in contract.functions:
        pairs = set()
        ref_to_pair = {}
        for node in fn.nodes:
            for ir in node.irs:
                if isinstance(ir, Member):
                    base = getattr(ir, "variable_left", None)
                    base_name = getattr(base, "name", None)
                    member = getattr(ir, "variable_right", None)
                    member_name = getattr(member, "name", None) or str(member)
                    lv = getattr(ir, "lvalue", None)
                    if base_name and lv is not None:
                        ref_to_pair[id(lv)] = (base_name, str(member_name))
                elif isinstance(ir, Assignment):
                    lv = getattr(ir, "lvalue", None)
                    if lv is not None and id(lv) in ref_to_pair:
                        pairs.add(ref_to_pair[id(lv)])
        if pairs:
            out[fn.full_name] = pairs
    return out


def tree_member_reads(trees):
    """{(var, member)} pairs read in any leaf, per function -> set."""
    per_fn = {}
    for sig, tree in (trees.get("trees") or {}).items():
        pairs = set()
        for leaf in _iter_predicate_leaves(tree):
            for op in leaf.get("operands") or []:
                if not isinstance(op, dict):
                    continue
                sv = op.get("state_variable_name")
                mp = op.get("member_path") or []
                if sv and mp:
                    pairs.add((sv, mp[0]))
        if pairs:
            per_fn[sig] = pairs
    return per_fn


def fn_has_caller_authority(trees, sig):
    tree = (trees.get("trees") or {}).get(sig)
    if not tree:
        return False
    for leaf in _iter_predicate_leaves(tree):
        if leaf.get("authority_role") in ("caller_authority", "delegated_authority"):
            return True
    return False


def struct_pause_toggles(contract, trees):
    """Member-level pause extension: (var,member) written by an auth-gated fn
    and read in another fn's revert leaf -> writers labeled."""
    mwrites = member_writes_by_fn(contract)
    mreads = tree_member_reads(trees)
    # candidate pairs: read in >=1 non-writer fn leaf
    toggles = set()
    for wsig, pairs in mwrites.items():
        for pair in pairs:
            readers = {rsig for rsig, rpairs in mreads.items() if pair in rpairs and rsig != wsig}
            if not readers:
                continue
            if fn_has_caller_authority(trees, wsig):
                # pause-ish member name not required: evidence is structural
                # (auth-gated writer + revert-read elsewhere). Record pair for audit.
                toggles.add((wsig, pair))
    return toggles


def contract_has_uups_marker(contract):
    names = {f.full_name for f in contract.functions}
    if "proxiableUUID()" in names:
        return True
    for c in getattr(contract, "inheritance", []) or []:
        if "UUPS" in getattr(c, "name", "") or "ERC1967" in getattr(c, "name", ""):
            return True
    return False


def scalar_address_owner_vars(contract, trees):
    """Variant D: the post-pass harvest, restricted to scalar address-typed vars."""
    by_name = {getattr(v, "name", ""): v for v in contract.state_variables}
    out = set()
    for tree in (trees.get("trees") or {}).values():
        for leaf in _iter_predicate_leaves(tree):
            if leaf.get("authority_role") != "caller_authority":
                continue
            if leaf.get("kind") == "equality" and leaf.get("references_msg_sender"):
                for op in leaf.get("operands") or []:
                    if not isinstance(op, dict):
                        continue
                    name = op.get("state_variable_name")
                    if not name:
                        continue
                    var = by_name.get(name)
                    tstr = str(getattr(var, "type", "")) if var is not None else ""
                    if op.get("mapping_name"):
                        continue  # param-keyed mapping equality: not an owner scalar
                    if tstr.startswith("mapping") or "[]" in tstr:
                        continue
                    out.add(name)
    return out


def run_one(pdir: Path):
    meta = json.loads((pdir / "contract_meta.json").read_text())
    sl = Slither(str(pdir))
    subject = _select_subject_contract(sl, meta.get("contract_name"))
    trees, pause_info = build_predicate_artifacts_with_pause_info(subject)

    # current labels
    cur = build_effects(subject)
    apply_authority_effect_labels(subject, cur, trees)
    cur_labels = {s: sorted(i.get("effect_labels") or []) for s, i in cur["functions"].items()}

    # Variant A: fallback deleted
    orig = summaries._writes_unclassified_address_pointer
    summaries._writes_unclassified_address_pointer = lambda fn: False
    try:
        nofb = build_effects(subject)
        apply_authority_effect_labels(subject, nofb, trees)
    finally:
        summaries._writes_unclassified_address_pointer = orig
    nofb_labels = {s: sorted(i.get("effect_labels") or []) for s, i in nofb["functions"].items()}

    # Variant B: pause from PauseInfo (+ struct extension)
    pause_fns = set(pause_info.get("pause_toggle_functions") or [])
    struct_toggles = struct_pause_toggles(subject, trees)
    struct_pause_fns = {w for (w, _p) in struct_toggles}

    # Variant C: impl selector-canonical
    uups = contract_has_uups_marker(subject)
    impl_fns = {s for s in cur_labels if s in UPGRADE_SELECTORS} if uups else set()

    # Variant D: tightened owner harvest
    tight_owner = scalar_address_owner_vars(subject, trees)

    h1_labels = {}
    for sig, labels in nofb_labels.items():
        ls = set(labels)
        ls.discard("pause_toggle")
        if sig in pause_fns or sig in struct_pause_fns:
            ls.add("pause_toggle")
        if sig in impl_fns:
            ls.add("implementation_update")
            ls.discard("delegatecall_execution")  # the dc sink is the upgrade call path itself
        h1_labels[sig] = sorted(ls)

    diffs = []
    for sig in sorted(cur_labels):
        if cur_labels[sig] != h1_labels.get(sig, []):
            diffs.append((sig, cur_labels[sig], h1_labels.get(sig, [])))
    return {
        "contract": subject.name,
        "pause_info_fns": sorted(pause_fns),
        "struct_pause": sorted(str(t) for t in struct_toggles),
        "uups_marker": uups,
        "owner_vars_tight": sorted(tight_owner),
        "diffs": diffs,
        "current": cur_labels,
        "h1": h1_labels,
    }


if __name__ == "__main__":
    which = sys.argv[1:] if len(sys.argv) > 1 else [p.name for p in PROJECTS.iterdir() if (p / "contract_meta.json").exists()]
    for addr in which:
        pdir = PROJECTS / addr.lower()
        if not (pdir / "contract_meta.json").exists():
            print(f"SKIP {addr}: not fetched")
            continue
        try:
            res = run_one(pdir)
            (OUT / f"{addr.lower()}.json").write_text(json.dumps(res, indent=1))
            print(f"== {res['contract']} ({addr[:10]}) uups={res['uups_marker']} pauseinfo={res['pause_info_fns']} structpause={res['struct_pause']} owner_tight={res['owner_vars_tight']}")
            for sig, c, h in res["diffs"]:
                print(f"   {sig:55s} {','.join(c) or '-':45s} -> {','.join(h) or '-'}")
        except Exception as exc:
            print(f"FAIL {addr}: {type(exc).__name__}: {exc}")
        sys.stdout.flush()
