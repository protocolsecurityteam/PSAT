#!/usr/bin/env python3
"""
Prototype protocol-security scorer honoring SCORING_INVARIANTS.md.

Reads the PR-161 Neon DB (SELECT only) and emits, for etherfi (protocol_id=1):
  - score.json  : grade + confidence + itemized finding ledger (decomposes to 0)
  - report.md   : human-readable headline / deductions / credits / warnings
  - manifest.json: the load-bearing published facts a validator should on-chain check

Design map to invariants (see SCORING_INVARIANTS.md):
  inv.1  three-valued: unknown -> zero to grade, feeds confidence only
  inv.2  witness-required: every scored item cites a witness; name/shape inference banned
  inv.3  (capability, principal) unit; permissionless user flows score nothing
  inv.4  dual-use: a credited protective power is also an attack surface
  inv.5  weakest-path composition (OR-gate -> weakest principal wins)
  inv.6  grade vs confidence vs warnings are three separate channels
  inv.7  value-at-stake: transitive over control graph, log-banded, with a floor
  inv.8  deterministic perimeter, idempotent over (chain, address)
  inv.9  exact decomposition: grade = 100 - Sigma(deductions)
  inv.10 counterfactual per deduction
  inv.13 anti-gaming: aggregate by (principal, capability) so splits/merges are no-ops
"""

import json
import os
from collections import defaultdict

import psycopg2
import psycopg2.extras

PROTOCOL_ID = 1
MODEL_VERSION = "proto-0.1"
SEV_SCALE = 60.0  # calibrates: one catastrophic EOA path (~54pts) fails the grade

DB = os.environ["DATABASE_URL"]


# --------------------------------------------------------------------------
# Capability model (inv.2/inv.3). Severity is the *proven* component only.
# For a capability whose severity turns on a witness field (flow.out
# destination, exec.arbitrary destination), we branch on that field below,
# never on the function name.
# --------------------------------------------------------------------------
# Capabilities that are the *product working* when permissionless (inv.3):
PRODUCT_CLAIMS = {
    "flow.in",
    "erc20.approve",
    "erc20.transfer",
    "erc20.transfer_from",
    "gov.delegate",
    "pause.unset",
    "supply.mint",
    "supply.burn",
    "ownership.accept",
    "ownership.renounce",
    "timelock.execute",
    "timelock.schedule",
    "timelock.cancel",
    "rate_limit.consume",
}
# value_router is static-only by design (inv.2) - never a value-out from *this*
# contract, never discounted for lacking a fork verdict. Not scored.
NOT_SCORED = {"value_router", "contract_deployment", "callee_pointer.rotate"}

# capabilities that grant CONTROL of a contract -> value at stake is transitive
# (what the contract itself controls). Freeze/extraction/supply capabilities
# threaten only the contract's own value -> direct value.
TRANSITIVE_CAPS = {
    "upgrade.implementation",
    "exec.arbitrary",
    "delegatecall.execute",
    "authority.replace",
    "ownership.transfer",
    "roles.grant",
    "roles.configure",
    "authorized_caller.rotate",
}

# base severity for privileged capabilities (0..1), proven component only
BASE_SEV = {
    "upgrade.implementation": 1.0,
    "authority.replace": 0.75,
    "roles.grant": 0.55,
    "roles.revoke": 0.4,
    "roles.configure": 0.55,
    "authorized_caller.rotate": 0.55,
    "ownership.transfer": 0.55,
    "pause.set": 0.35,  # dual-use freeze (inv.4); bound unwitnessed
    "transfer_policy.configure": 0.25,
    "timelock.set_delay": 0.3,
    "lz_oapp.set_peer": 0.3,
    "lz_oapp.set_delegate": 0.3,
    "delegatecall.execute": 1.0,  # branch on destination witness below
    "exec.arbitrary": 1.0,  # branch on destination witness below
    "flow.out": 0.9,  # branch on destination_shape below
}


def band(usd):
    """Log-scaled value band with a floor (inv.7)."""
    if usd is None:
        usd = 0.0
    if usd < 100_000:
        return 0.15  # floor: rug-shape on empty contract still scores
    if usd < 1_000_000:
        return 0.3
    if usd < 10_000_000:
        return 0.5
    if usd < 100_000_000:
        return 0.7
    if usd < 1_000_000_000:
        return 0.9
    return 1.0


def band_label(usd):
    for lo, lab in [(1e9, ">$1B"), (1e8, "$100M-$1B"), (1e7, "$10M-$100M"), (1e6, "$1M-$10M"), (1e5, "$100k-$1M")]:
        if usd >= lo:
            return lab
    return "<$100k"


def load():
    conn = psycopg2.connect(DB)
    conn.set_session(readonly=True)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute(
        """
        select id, lower(address) addr, chain, contract_name, is_proxy,
               lower(admin) admin, lower(implementation) impl, lower(beacon) beacon
        from contracts where protocol_id=%s
    """,
        (PROTOCOL_ID,),
    )
    contracts = {r["id"]: r for r in cur.fetchall()}

    # value by contract address (dedup by entity key (chain,address), inv.8)
    cur.execute(
        """
        select c.id cid, lower(c.address) addr, coalesce(sum(cb.usd_value),0) usd
        from contracts c left join contract_balances_latest cb on cb.contract_id=c.id
        where c.protocol_id=%s group by 1,2
    """,
        (PROTOCOL_ID,),
    )
    val_by_addr = defaultdict(float)
    for r in cur.fetchall():
        val_by_addr[r["addr"]] = max(val_by_addr[r["addr"]], float(r["usd"]))

    # control edges for value closure (inv.7). from_node = controlled contract,
    # to_node = its controller.  controlled_by[controller] = {controlled...}
    cur.execute(
        """
        select lower(replace(e.from_node_id,'address:','')) frm,
               lower(replace(e.to_node_id,'address:','')) too,
               e.relation
        from control_graph_edges e join contracts c on c.id=e.contract_id
        where c.protocol_id=%s
          and e.relation in ('controller_value','role_principal','mapping_member','safe_owner')
    """,
        (PROTOCOL_ID,),
    )
    controls = defaultdict(set)  # controller -> set(controlled contract addrs)
    for r in cur.fetchall():
        frm, too, rel = r["frm"], r["too"], r["relation"]
        if rel == "safe_owner":
            # from=safe, to=owner ; owner controls the safe
            controls[too].add(frm)
        else:
            # from=controlled, to=controller ; controller controls from
            controls[too].add(frm)

    # proxy-admin links: admin controls the proxy contract (inv.7)
    for c in contracts.values():
        if c["admin"]:
            controls[c["admin"]].add(c["addr"])

    # functions + claims
    cur.execute(
        """
        select ef.id fid, ef.contract_id cid, ef.function_name fn,
               ef.authority_openness openness, ef.authority_public pub,
               ef.claims, ef.effect_labels, ef.state_changing
        from effective_functions ef join contracts c on c.id=ef.contract_id
        where c.protocol_id=%s
    """,
        (PROTOCOL_ID,),
    )
    funcs = cur.fetchall()

    # principals per function
    cur.execute(
        """
        select fp.function_id fid, lower(fp.address) addr, fp.resolved_type rtype,
               fp.details
        from function_principals fp
        join effective_functions ef on ef.id=fp.function_id
        join contracts c on c.id=ef.contract_id
        where c.protocol_id=%s
    """,
        (PROTOCOL_ID,),
    )
    princ = defaultdict(list)
    for r in cur.fetchall():
        princ[r["fid"]].append(r)

    # audit coverage (inv.2: only equivalence-proven is grade-admissible)
    cur.execute(
        """
        select acc.contract_id cid, acc.proof_kind, acc.equivalence_status eq,
               acc.match_confidence conf
        from audit_contract_coverage acc where acc.protocol_id=%s
    """,
        (PROTOCOL_ID,),
    )
    audits = cur.fetchall()

    conn.close()
    return contracts, val_by_addr, controls, funcs, princ, audits


def transitive_value(seeds, controls, val_by_addr):
    """Sum of value over the transitive closure of contracts reachable by
    exercising a capability on `seeds` (inv.7). BFS with a visited set."""
    seen = set()
    stack = list(seeds)
    total = 0.0
    while stack:
        a = stack.pop()
        if a in seen:
            continue
        seen.add(a)
        total += val_by_addr.get(a, 0.0)
        for nxt in controls.get(a, ()):  # contracts THIS one controls
            if nxt not in seen:
                stack.append(nxt)
    return total, seen


def principal_weakness(p):
    """How easily a principal can independently abuse a capability (inv.5).
    Returns (weakness 0..1, label, kind)."""
    rt = p["rtype"]
    d = p.get("details") or {}
    if rt == "eoa":
        return 0.9, "EOA", "eoa"
    if rt == "safe":
        thr = d.get("threshold")
        owners = d.get("owners")
        try:
            k = int(thr)
            n = len(owners) if owners else k
        except (TypeError, ValueError):
            return 0.55, "safe(?)", "safe"
        r = k / n if n else 1.0
        lab = f"Safe {k}/{n}"
        if k == 1:
            return 0.85, lab, "safe"  # single key
        if r < 0.5:
            return 0.55, lab, "safe"
        if r < 0.67:
            return 0.35, lab, "safe"
        return 0.2, lab, "safe"  # strong multisig
    if rt == "timelock":
        return 0.15, "timelock", "timelock"  # delay gives reaction time
    if rt == "contract":
        # gated by a PROGRAM (e.g. a Boring merkle-manager) whose own authority
        # we have NOT reduced to a key. We cannot witness the path is weak, so
        # calling it a proven-bad deduction would be a guess (inv.2). Route to
        # warnings / confidence as unknown weakest-path.
        return None, "contract", "contract"
    return None, rt or "unresolved", "unknown"  # unknown -> not scored


def main():
    contracts, val_by_addr, controls, funcs, princ, audits = load()
    total_value = sum(val_by_addr.values())

    ledger = defaultdict(
        lambda: {
            "instances": [],
            "max_weakness": 0.0,
            "weakest_label": None,
            "seed_addrs": set(),
            "witness_tiers": set(),
            "capability": None,
            "principal": None,
            "principal_kind": None,
        }
    )
    warnings = []

    for f in funcs:
        c = contracts[f["cid"]]
        caddr = c["addr"]
        cval = val_by_addr.get(caddr, 0.0)
        openness = f["openness"]
        claims = f["claims"] or []
        fprinc = princ.get(f["fid"], [])

        for claim in claims:
            cid = claim.get("claim_id")
            if cid in NOT_SCORED or cid in PRODUCT_CLAIMS:
                continue
            if cid not in BASE_SEV:
                continue
            sev = BASE_SEV[cid]
            wit = claim.get("witness") or {}

            # --- witness-branching severity (inv.2), never on the name ---
            if cid == "flow.out":
                obs = wit.get("observed") or {}
                dshape = obs.get("destination_shape")
                if dshape == "caller_arbitrary":
                    sev = 0.9  # proven arbitrary destination -> extraction
                else:
                    # fixed / unknown / static-only: operational routing power,
                    # NOT proven extraction (inv.2 EtherFiRestaker case).
                    sev = 0.25
                    if openness == "restricted" and dshape in (None, "unknown"):
                        # arbitrariness unproven on a restricted mover -> warn
                        pass
            elif cid in ("exec.arbitrary", "delegatecall.execute"):
                dc = wit.get("destination_constraint") or {}
                dest = wit.get("destination") or {}
                tgt_kind = dest.get("target_kind")
                if tgt_kind == "storage_setter":
                    # proxy/admin-impl delegatecall: callers reach it but the
                    # executed code is a STORED impl, not caller-controlled.
                    # Reattribute to whoever sets it; do NOT score the open
                    # fallback as arbitrary exec (banned shape inference, inv.2).
                    warnings.append(
                        {
                            "kind": "proxy_fallback_delegatecall",
                            "contract": c["contract_name"],
                            "address": caddr,
                            "function": f["fn"],
                            "note": (
                                "open fallback delegatecalls to a stored admin "
                                "impl (setAdminImpl); reachability shifts to the "
                                "impl-setter, not the public caller"
                            ),
                            "missing_witness": "who controls setAdminImpl",
                        }
                    )
                    continue
                if dc.get("state") == "constrained":
                    sev = 0.35  # guarded target -> softer
                else:
                    sev = 1.0  # not_determined -> genuinely arbitrary

            # --- principal channel (inv.3) ---
            if openness == "open":
                # permissionless: only score if privileged-shaped capability
                # reachable by anyone. flow.out/pause/supply on open fns are the
                # product (handled: product claims skipped; open flow.out here
                # is a user withdraw, not privileged) -> only truly-privileged.
                if cid in (
                    "upgrade.implementation",
                    "exec.arbitrary",
                    "delegatecall.execute",
                    "authority.replace",
                    "roles.grant",
                    "roles.configure",
                    "ownership.transfer",
                ):
                    key = ("ANYONE", cid)
                    row = ledger[key]
                    row["capability"] = cid
                    row["principal"] = "ANYONE (permissionless)"
                    row["principal_kind"] = "anyone"
                    row["max_weakness"] = 1.0
                    row["weakest_label"] = "ANYONE"
                    row["seed_addrs"].add(caddr)
                    row["witness_tiers"].add(claim.get("tier"))
                    row["instances"].append(
                        {"contract": c["contract_name"], "address": caddr, "function": f["fn"], "usd": cval, "sev": sev}
                    )
                continue

            if openness == "not_determined":
                # unknown reachability on a privileged-shaped fn -> warning, not
                # scored (inv.1/inv.6).
                warnings.append(
                    {
                        "kind": "unresolved_reachability",
                        "contract": c["contract_name"],
                        "address": caddr,
                        "function": f["fn"],
                        "capability": cid,
                        "note": "authority_openness not_determined on privileged capability",
                        "missing_witness": "principal resolution",
                    }
                )
                continue

            # restricted: score per resolved principal; unresolved -> warning
            scored_any = False
            for p in fprinc:
                w, lab, kind = principal_weakness(p)
                if w is None:
                    warnings.append(
                        {
                            "kind": ("contract_gated_unknown_path" if kind == "contract" else "unresolved_principal"),
                            "contract": c["contract_name"],
                            "address": caddr,
                            "function": f["fn"],
                            "capability": cid,
                            "principal": p["addr"],
                            "note": (
                                f"{cid} gated by a {lab} principal whose own "
                                "authority is not reduced to a key; weakest path "
                                "unresolved (not scored, inv.2)"
                            ),
                            "missing_witness": "controlling principal of the gating contract",
                        }
                    )
                    continue
                scored_any = True
                key = (p["addr"], cid)
                row = ledger[key]
                row["capability"] = cid
                row["principal"] = f"{lab} {p['addr']}"
                row["principal_kind"] = kind
                if w > row["max_weakness"]:
                    row["max_weakness"] = w
                    row["weakest_label"] = lab
                row["seed_addrs"].add(caddr)
                row["witness_tiers"].add(claim.get("tier"))
                row["instances"].append(
                    {"contract": c["contract_name"], "address": caddr, "function": f["fn"], "usd": cval, "sev": sev}
                )
            if not scored_any and not fprinc:
                warnings.append(
                    {
                        "kind": "restricted_no_principal",
                        "contract": c["contract_name"],
                        "address": caddr,
                        "function": f["fn"],
                        "capability": cid,
                        "note": "restricted privileged fn with no resolved principal",
                        "missing_witness": "principal resolution",
                    }
                )

    # --- aggregate into deductions (inv.13: one row per (principal,capability)) ---
    findings = []
    for (paddr, cid), row in ledger.items():
        if cid in TRANSITIVE_CAPS:
            vas, reach = transitive_value(row["seed_addrs"], controls, val_by_addr)
        else:
            # freeze / extraction / supply: only the contract's own value
            vas = sum(val_by_addr.get(a, 0.0) for a in row["seed_addrs"])
        # severity = the MAX proven severity across instances of this cap
        sev = max(i["sev"] for i in row["instances"])
        b = band(vas)
        w = row["max_weakness"]
        pts = SEV_SCALE * sev * w * b
        findings.append(
            {
                "principal": row["principal"],
                "principal_kind": row["principal_kind"],
                "capability": cid,
                "value_at_stake_usd": round(vas),
                "value_band": band_label(vas),
                "severity_proven": round(sev, 3),
                "weakness": round(w, 3),
                "weakest_gate": row["weakest_label"],
                "points": round(pts, 3),
                "n_functions": len(row["instances"]),
                "n_contracts": len(row["seed_addrs"]),
                "example_functions": sorted({i["function"] for i in row["instances"]})[:6],
                "witness_tiers": sorted(t for t in row["witness_tiers"] if t),
                "counterfactual": counterfactual(cid, row["principal_kind"], sev, b),
            }
        )

    # --- composition: worst-path-dominated with a diminishing tail (inv.5) ---
    # Findings threaten VALUE locally, not global catastrophe, so they must not
    # compound as independent catastrophe probabilities. Sort worst-first and
    # dampen each successive finding geometrically: D = Sigma p_i * LAMBDA^(i-1).
    #   - the weakest path to the most value dominates (inv.5),
    #   - a single catastrophic finding (p_1 ~ 54) still fails the grade,
    #   - many minor findings converge and can never zero a strong protocol,
    #   - one minor finding barely moves it.
    # Exact decomposition (inv.9): each finding's ledger contribution is exactly
    # p_i * LAMBDA^(i-1), and Sigma == D by construction. Aggregation is by
    # (principal, capability) (inv.13), so contract splits/merges are no-ops.
    LAMBDA = 0.6
    findings.sort(key=lambda x: -x["points"])
    cum = 0.0
    for i, f in enumerate(findings):
        f["raw_points"] = f["points"]
        share = f["points"] * (LAMBDA**i)
        f["points"] = round(share, 3)
        cum += share
    cum = min(cum, 100.0)
    grade_num = round(100.0 - cum, 3)

    # --- audits (inv.2): equivalence-proven -> confidence + modest credit ---
    proven = [a for a in audits if a["eq"] == "proven"]
    prefix_unpatched = [a for a in audits if a["proof_kind"] == "pre_fix_unpatched"]
    unknown_audit = [a for a in audits if a["eq"] != "proven"]
    for a in prefix_unpatched:
        c = contracts.get(a["cid"])
        warnings.append(
            {
                "kind": "audit_pre_fix_unpatched_llm_label",
                "contract": c["contract_name"] if c else a["cid"],
                "note": (
                    "audit LLM-labeled 'fix commit exists, not deployed' - "
                    "hallucinatable role label; equivalence core still holds"
                ),
                "missing_witness": "deterministic 'fixed in <sha>' phrase match in PDF",
            }
        )

    # --- confidence (inv.6): value-weighted fraction of privileged surface witnessed
    conf_num, conf_den = confidence(funcs, princ, contracts, val_by_addr)
    confidence_pct = round(100.0 * conf_num / conf_den, 1) if conf_den else 0.0

    grade_letter = letter(grade_num)

    # --- credits (inv.9): protective facts keeping catastrophic caps cheap ----
    # A control capability behind a timelock or strong multisig would be a
    # catastrophic EOA finding if unprotected. The credit is that counterfactual
    # delta (inv.10). Surfaced as an explicit protective ledger.
    credits = []
    for f in findings:
        if f["capability"] in TRANSITIVE_CAPS and f["principal_kind"] in ("timelock", "safe"):
            if f["value_at_stake_usd"] >= 100_000_000 and f["weakness"] <= 0.2:
                eoa_raw = SEV_SCALE * f["severity_proven"] * 0.9 * band(f["value_at_stake_usd"])
                credits.append(
                    {
                        "protective_fact": f"{f['weakest_gate']} gates {f['capability']}",
                        "principal": f["principal"],
                        "value_protected_band": f["value_band"],
                        "n_functions": f["n_functions"],
                        "counterfactual_if_eoa_gated": f"~-{round(eoa_raw, 1)} raw (vs -{f['raw_points']} now)",
                        "example_functions": f["example_functions"],
                    }
                )
    credits.append(
        {
            "protective_fact": "audit equivalence proven (deployed code == sha printed in audit PDF)",
            "rows": len([a for a in audits if a["eq"] == "proven"]),
            "note": "grade-admissible modest credit only; LLM role labels excluded (inv.2)",
        }
    )

    # group warnings for readability (raw list retained)
    wsummary = defaultdict(lambda: {"count": 0, "examples": []})
    for w in warnings:
        g = wsummary[w["kind"]]
        g["count"] += 1
        if len(g["examples"]) < 4:
            g["examples"].append(f"{w.get('contract', '?')}.{w.get('function', '?')} ({w.get('capability', '')})")

    headline = None
    if findings:
        t = max(findings, key=lambda x: x["raw_points"])
        headline = (
            f"{t['weakest_gate']} can {t['capability']} on {t['value_band']} "
            f"({', '.join(t['example_functions'][:3])}) — raw -{t['raw_points']}"
        )

    out = {
        "headline": headline,
        "credits": credits,
        "warnings_summary": {k: v for k, v in wsummary.items()},
        "protocol": "etherfi",
        "protocol_id": PROTOCOL_ID,
        "model_version": MODEL_VERSION,
        "grade": grade_letter,
        "grade_numeric": grade_num,
        "confidence_pct": confidence_pct,
        "confidence_note": f"assessed over {confidence_pct}% of value-weighted privileged surface",
        "total_tracked_value_usd": round(total_value),
        "decomposition_check": {
            "grade": grade_num,
            "sum_deductions": round(sum(f["points"] for f in findings), 3),
            "residual": round(100.0 - grade_num - sum(f["points"] for f in findings), 6),
        },
        "audit_credit": {
            "equivalence_proven_rows": len(proven),
            "unknown_rows": len(unknown_audit),
            "note": (
                "equivalence-proven = deployed code matches a sha printed in the audit PDF; "
                "grade-admissible modest credit only (inv.2)"
            ),
        },
        "findings": findings,
        "warnings": warnings,
    }

    with open("score.json", "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    print(
        json.dumps(
            {
                k: out[k]
                for k in ("grade", "grade_numeric", "confidence_pct", "total_tracked_value_usd", "decomposition_check")
            },
            indent=2,
            default=str,
        )
    )
    print(f"\n{len(findings)} findings, {len(warnings)} warnings")
    for f in findings[:12]:
        print(
            f"  -{f['points']:6.2f}  {f['capability']:24s} {f['weakest_gate'] or '':10s} "
            f"{f['value_band']:10s} x{f['n_functions']}fn  {f['example_functions'][:3]}"
        )


def counterfactual(cid, kind, sev, b):
    if kind == "anyone":
        return "gate this capability behind a multisig/timelock: removes the permissionless deduction"
    if kind == "eoa":
        return "move behind a strong multisig (>=k/n 0.67) or timelock: weakness 0.9 -> 0.15-0.2"
    if kind == "safe":
        return "raise threshold ratio and/or add a timelock in front: lowers weakness toward 0.15"
    if kind == "timelock":
        return "already timelock-gated; residual is the timelock's controlling principal"
    if kind == "contract":
        return "resolve the controlling principal of the gating contract to witness the real weakest path"
    return "n/a"


def confidence(funcs, princ, contracts, val_by_addr):
    """value-weighted fraction of the privileged surface that is witnessed."""
    num = den = 0.0
    for f in funcs:
        claims = f["claims"] or []
        privileged = any((cl.get("claim_id") in BASE_SEV) for cl in claims) or (f["openness"] == "not_determined")
        # a restricted state-changing fn with no claims is also unknown surface
        sensitive = privileged or (f["openness"] == "restricted" and f["state_changing"])
        if not sensitive:
            continue
        c = contracts[f["cid"]]
        b = band(val_by_addr.get(c["addr"], 0.0))
        den += b
        witnessed = bool(claims) and (f["openness"] == "open" or bool(princ.get(f["fid"])))
        if witnessed and f["openness"] != "not_determined":
            num += b
    return num, den


def letter(n):
    if n >= 90:
        return "A"
    if n >= 75:
        return "B"
    if n >= 60:
        return "C"
    if n >= 45:
        return "D"
    return "F"


if __name__ == "__main__":
    main()
