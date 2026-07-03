# Patch prototype_h1 in-place logic via import-and-override: v2 gates.
import json, sys, os
from pathlib import Path
os.environ["DATABASE_URL"] = "postgresql://nouser:nopass@127.0.0.1:1/nonexistent"
sys.path.insert(0, "/home/riley/PSAT")
sys.path.insert(0, str(Path(__file__).parent))
import prototype_h1 as p1
from slither.slithir.operations import Assignment, Member
from services.static.contract_analysis_pipeline.effects import _iter_predicate_leaves

def struct_pause_toggles_v2(contract, trees):
    """v2: member must be bool-typed per the struct decl; writer auth-gated;
    member read in another fn's leaf. Slither struct member types via
    contract.structures / var.type.type.elems."""
    mwrites = p1.member_writes_by_fn(contract)
    mreads = p1.tree_member_reads(trees)
    # map (var -> {member: type_str})
    var_member_types = {}
    from services.static.contract_analysis_pipeline.shared import _all_state_variables as _asv2
    for sv in _asv2(contract):
        t = getattr(sv, "type", None)
        st = getattr(t, "type", None)  # UserDefinedType -> Structure
        elems = getattr(st, "elems", None)
        if isinstance(elems, dict):
            var_member_types[sv.name] = {mn: str(getattr(mv, "type", "")) for mn, mv in elems.items()}
    toggles = set()
    for wsig, pairs in mwrites.items():
        if wsig.startswith("slitherConstructor"):
            continue
        for (var, member) in pairs:
            mtype = var_member_types.get(var, {}).get(member, "")
            if mtype != "bool":
                continue
            readers = {r for r, rp in mreads.items() if (var, member) in rp and r != wsig}
            if readers and p1.fn_has_caller_authority(trees, wsig):
                toggles.add((wsig, (var, member)))
    return toggles

def one_shot_gated(trees, sig):
    tree = (trees.get("trees") or {}).get(sig)
    if not tree: return False
    for leaf in _iter_predicate_leaves(tree):
        if leaf.get("authority_role") == "one_shot":
            return True
    return False

def pause_fns_v2(contract, trees, pause_info):
    """v2 gate on PauseInfo toggles: drop synthetic fns, one_shot-gated fns
    (initializers), and fns whose ONLY flagged var is non-bool with
    indeterminate polarity."""
    from services.static.contract_analysis_pipeline.summaries import _classify_pause_toggle_polarity
    pause_vars = set(pause_info.get("pause_state_vars") or [])
    from services.static.contract_analysis_pipeline.shared import _all_state_variables as _asv
    bool_vars = {sv.name for sv in _asv(contract) if str(getattr(sv, "type", "")) == "bool"}
    fns_by_full = {f.full_name: f for f in contract.functions}
    out = set()
    for sig in pause_info.get("pause_toggle_functions") or []:
        if sig.startswith("slitherConstructor"):
            continue
        if one_shot_gated(trees, sig):
            continue
        fn = fns_by_full.get(sig)
        if fn is None:
            continue
        written = {v.name for v in fn.all_state_variables_written()} & pause_vars
        ok = False
        for var in written:
            if var in bool_vars:
                ok = True; break
            if _classify_pause_toggle_polarity(fn, {var}) in ("pause", "unpause"):
                ok = True; break
        if ok:
            out.add(sig)
    return out

def scalar_owner_vars_v2(contract, trees):
    from services.static.contract_analysis_pipeline.shared import _all_state_variables
    by_name = {getattr(v, "name", ""): v for v in _all_state_variables(contract)}
    out = set()
    for tree in (trees.get("trees") or {}).values():
        for leaf in _iter_predicate_leaves(tree):
            if leaf.get("authority_role") != "caller_authority": continue
            if leaf.get("kind") == "equality" and leaf.get("references_msg_sender"):
                for op in leaf.get("operands") or []:
                    if not isinstance(op, dict): continue
                    name = op.get("state_variable_name")
                    if not name or op.get("mapping_name"): continue
                    var = by_name.get(name)
                    if var is None: continue
                    if getattr(var, "is_constant", False) or getattr(var, "is_immutable", False) and False: pass
                    if getattr(var, "is_constant", False): continue
                    t = str(getattr(var, "type", ""))
                    if t.startswith("mapping") or "[]" in t or t == "bytes32": continue
                    out.add(name)
    return out

CANONICAL_OWNERSHIP = {"transferOwnership(address)": "0xf2fde38b", "renounceOwnership()": "0x715018a6"}

def run_one_v2(pdir):
    meta = json.loads((pdir / "contract_meta.json").read_text())
    from slither.slither import Slither
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract
    from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts_with_pause_info
    from services.static.contract_analysis_pipeline.effects import build_effects, apply_authority_effect_labels
    import services.static.contract_analysis_pipeline.summaries as summaries
    sl = Slither(str(pdir))
    subject = _select_subject_contract(sl, meta.get("contract_name"))
    trees, pause_info = build_predicate_artifacts_with_pause_info(subject)
    cur = build_effects(subject); apply_authority_effect_labels(subject, cur, trees)
    cur_labels = {s: sorted(i.get("effect_labels") or []) for s, i in cur["functions"].items()}
    state_changing = {s: bool(i.get("state_changing")) for s, i in cur["functions"].items()}

    orig = summaries._writes_unclassified_address_pointer
    summaries._writes_unclassified_address_pointer = lambda fn: False
    try:
        nofb = build_effects(subject)
    finally:
        summaries._writes_unclassified_address_pointer = orig
    nofb_labels = {s: set(i.get("effect_labels") or []) for s, i in nofb["functions"].items()}

    # ownership v2: tightened harvest + view-exclusion + canonical selector tier
    owner_vars = scalar_owner_vars_v2(subject, trees)
    fns_by_full = {f.full_name: f for f in subject.functions}
    ownership_fns = set()
    for sig, fn in fns_by_full.items():
        if sig not in nofb_labels or not state_changing.get(sig): continue
        written = {v.name for v in fn.all_state_variables_written()}
        if written & owner_vars:
            ownership_fns.add(sig)
    for sig in CANONICAL_OWNERSHIP:
        if sig in nofb_labels and state_changing.get(sig):
            ownership_fns.add(sig)

    pause_fns = pause_fns_v2(subject, trees, pause_info)
    struct_fns = {w for (w, _p) in struct_pause_toggles_v2(subject, trees)}
    uups = p1.contract_has_uups_marker(subject)
    impl_fns = {s for s in nofb_labels if s in p1.UPGRADE_SELECTORS} if uups else set()

    h1 = {}
    for sig, ls in nofb_labels.items():
        s = set(ls); s.discard("pause_toggle"); s.discard("ownership_transfer")
        if sig in pause_fns or sig in struct_fns: s.add("pause_toggle")
        if sig in ownership_fns: s.add("ownership_transfer"); s -= {"hook_update", "external_contract_call"}
        if sig in impl_fns: s.add("implementation_update"); s.discard("delegatecall_execution")
        h1[sig] = sorted(s)
    diffs = [(sig, cur_labels[sig], h1.get(sig, [])) for sig in sorted(cur_labels) if cur_labels[sig] != h1.get(sig, [])]
    return {"contract": subject.name, "owner_vars_v2": sorted(owner_vars), "pause_v2": sorted(pause_fns | struct_fns), "impl_fns": sorted(impl_fns), "diffs": diffs, "current": cur_labels, "h1": h1, "state_changing": state_changing}

if __name__ == "__main__":
    OUT = Path(__file__).parent / "h1v2_results"; OUT.mkdir(exist_ok=True)
    for pdir in sorted((Path(__file__).parent / "projects").iterdir()):
        if not (pdir / "contract_meta.json").exists(): continue
        try:
            r = run_one_v2(pdir)
            (OUT / f"{pdir.name}.json").write_text(json.dumps(r, indent=1))
            print(f"== {r['contract']:32s} pause_v2={r['pause_v2']} impl={len(r['impl_fns'])} owner_vars={r['owner_vars_v2']}")
            for sig, c, h in r["diffs"]:
                print(f"   {sig:52s} {','.join(c) or '-':42s} -> {','.join(h) or '-'}")
        except Exception as e:
            print(f"FAIL {pdir.name}: {type(e).__name__}: {e}")
        sys.stdout.flush()
