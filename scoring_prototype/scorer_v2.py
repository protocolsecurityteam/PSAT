#!/usr/bin/env python3
"""
Prototype protocol-security scorer, model_version proto-0.2.

Recalibration of proto-0.1 (scorer.py) per SCORING_CALIBRATION_REVIEW.md. The
detection logic is unchanged; what changed is how much each proven fact is worth.

Fixes, each grounded in a witness already present in the corpus:

 F1 reach-witnessed value-at-stake (inv.7)
      claim->'witness'->'observed'->>'observed_reach_value_usd' with
      reach_determined=true is a PROVEN upper bound on what the capability can
      move. It beats the contract balance sheet. sweepETH: $90.97, not $471,980.
 F2 freeze severity from proven components only (inv.1)
      flat 0.35 asserted "indefinite freeze"; duration_bound_source is
      'not_determined'. Unknown duration may not inflate magnitude.
 F3 blast-radius-scoped freeze value (inv.2)
      observed_blast_radius is 1-4 functions; VaS was the whole balance sheet.
 F4 capability-aware weakness (inv.4)
      k==1 -> 0.85 is right for upgrade, wrong for a reversible pause where a
      low threshold IS the emergency-response design.
 F5 dual-use credit for the brake (inv.4)
      a witnessed pause with a witnessed recovery path is a protective fact and
      must appear on the credit side, not only as attack surface.
 F6 unproven-destination flow.out -> warning (inv.1/inv.2)
      absence of a caller_arbitrary witness is not proof of a fixed destination.
 F7 per-principal subsumption (inv.13)
      severity now means "expected fraction of VaS lost", so the worst thing a
      key can do bounds the loss from that key; its lesser capabilities are
      subsumed rather than additive. Kills the 32% same-key restatement.
 F8 two compositions reported
      'lambda' reproduces proto-0.1's geometric rank damping for an
      apples-to-apples grade; 'exposure' is parameter-free (per-contract loss
      fraction capped at 1.0 x value), so no free knob sets the letter grade.
"""

import json
import os
from collections import defaultdict

import psycopg2
import psycopg2.extras

PROTOCOL_ID = 1
MODEL_VERSION = "proto-0.2"
SEV_SCALE = 60.0
LAMBDA = 0.6

DB = os.environ["DATABASE_URL"]

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
NOT_SCORED = {"value_router", "contract_deployment", "callee_pointer.rotate"}

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

# F4: capabilities whose harm is an availability incident that a legitimate
# quorum can reverse. A low pause threshold is intended design, so the
# single-key Safe cliff must not apply to them.
REVERSIBLE_CAPS = {"pause.set"}

# Claims that make a function value-bearing, for F3 blast-radius scoping.
VALUE_CLAIMS = {
    "flow.out",
    "flow.in",
    "erc20.transfer",
    "erc20.transfer_from",
    "supply.mint",
    "supply.burn",
}

# severity = expected fraction of value-at-stake lost if the principal acts
# maliciously (proven component only). See SCORING_CALIBRATION_REVIEW.md §5.
BASE_SEV = {
    "upgrade.implementation": 1.0,
    "authority.replace": 0.75,
    "roles.grant": 0.55,
    "roles.revoke": 0.4,
    "roles.configure": 0.55,
    "authorized_caller.rotate": 0.55,
    "ownership.transfer": 0.55,
    "pause.set": 0.05,  # F2: replaced by freeze_severity()
    "transfer_policy.configure": 0.25,
    "timelock.set_delay": 0.3,
    "lz_oapp.set_peer": 0.3,
    "lz_oapp.set_delegate": 0.3,
    "delegatecall.execute": 1.0,
    "exec.arbitrary": 1.0,
    "flow.out": 0.9,
}

# F2 freeze severity ladder (proven component only)
FREEZE_REVERSIBLE = 0.05  # availability incident, principal intact, liftable
FREEZE_IRREVERSIBLE = 0.20  # provable negative: nothing on the contract lifts it
FREEZE_AUTO_EXPIRY = 0.02  # duration bound witnessed and short
FREEZE_SCOPE_FLOOR = 0.10  # blast-radius scope never fully vanishes


def band(usd):
    if usd is None:
        usd = 0.0
    if usd < 100_000:
        return 0.15
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
    controls = defaultdict(set)
    for r in cur.fetchall():
        controls[r["too"]].add(r["frm"])
    for c in contracts.values():
        if c["admin"]:
            controls[c["admin"]].add(c["addr"])

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
    seen, stack, total = set(), list(seeds), 0.0
    while stack:
        a = stack.pop()
        if a in seen:
            continue
        seen.add(a)
        total += val_by_addr.get(a, 0.0)
        for nxt in controls.get(a, ()):
            if nxt not in seen:
                stack.append(nxt)
    return total, seen


def principal_weakness(p, cap):
    """F4: weakness is read against what the capability does. For a reversible
    capability a low multisig threshold is the emergency-response design, so the
    k==1 near-EOA cliff does not apply; the ratio curve still does."""
    rt = p["rtype"]
    d = p.get("details") or {}
    if rt == "eoa":
        return 0.9, "EOA", "eoa"
    if rt == "safe":
        thr, owners = d.get("threshold"), d.get("owners")
        try:
            k = int(thr)
            n = len(owners) if owners else k
        except (TypeError, ValueError):
            return 0.55, "safe(?)", "safe"
        r = k / n if n else 1.0
        lab = f"Safe {k}/{n}"
        if k == 1 and cap not in REVERSIBLE_CAPS:
            return 0.85, lab, "safe"
        if r < 0.5:
            return 0.55, lab, "safe"
        if r < 0.67:
            return 0.35, lab, "safe"
        return 0.2, lab, "safe"
    if rt == "timelock":
        return 0.15, "timelock", "timelock"
    if rt == "contract":
        return None, "contract", "contract"
    return None, rt or "unresolved", "unknown"


def reach_usd(claim):
    """F1: proven upper bound on what this capability can move, if witnessed."""
    obs = (claim.get("witness") or {}).get("observed") or {}
    if str(obs.get("reach_determined")).lower() != "true":
        return None
    v = obs.get("observed_reach_value_usd")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def blast_names(claim):
    obs = (claim.get("witness") or {}).get("observed") or {}
    br = obs.get("observed_blast_radius")
    if not br:
        return None
    return {str(s).split("(")[0] for s in br}


def freeze_severity(claim, unset_exists, unset_princs, pauser_addr, warn, ctx):
    """F2: pause severity from the proven component only.

    Independence is evaluated against the SPECIFIC key being scored: a freeze is
    recoverable if some resolved unpauser is not this pauser, because then this
    pauser cannot sustain the freeze. Testing unpausers against the whole pauser
    set is wrong -- on WeETH the 4/7 Safe is both a pauser and the unpauser, but
    a malicious 1/5 Safe still cannot stop it from lifting the pause.
    """
    obs = (claim.get("witness") or {}).get("observed") or {}

    bound = obs.get("duration_bound_seconds")
    bound_src = obs.get("duration_bound_source")
    if bound is not None and str(bound_src) not in ("not_determined", "None", ""):
        try:
            if float(bound) <= 30 * 86400:
                return FREEZE_AUTO_EXPIRY, "auto_expiry_witnessed"
        except (TypeError, ValueError):
            pass

    if not unset_exists:
        # provable negative: no capability on this contract lifts the pause
        return FREEZE_IRREVERSIBLE, "irreversibility_proven_no_unset_claim"

    if not unset_princs:
        warn.append(
            {
                "kind": "freeze_recovery_principal_unresolved",
                **ctx,
                "note": (
                    "pause.unset exists but no unpause principal resolved; "
                    "recoverability shape proven, responsible key unknown"
                ),
                "missing_witness": "principal resolution on the pause.unset function",
            }
        )
        return FREEZE_REVERSIBLE, "recovery_exists_principal_unresolved"

    if unset_princs - {pauser_addr}:
        return FREEZE_REVERSIBLE, "recovery_path_witnessed_independent"

    warn.append(
        {
            "kind": "freeze_recovery_not_independent",
            **ctx,
            "note": ("the only resolved unpauser is the pauser itself; this key can sustain its own freeze"),
            "missing_witness": "an unpause principal disjoint from this pauser",
        }
    )
    return FREEZE_IRREVERSIBLE, "attacker_sustained_freeze_same_key"


def main():
    contracts, val_by_addr, controls, funcs, princ, audits = load()
    total_value = sum(val_by_addr.values())

    # ---- pre-pass: per-contract pause recovery + value-bearing entrypoints ----
    unset_by_c = defaultdict(set)  # contract_id -> unpause principal addrs
    unset_exists = set()  # contract_ids with a pause.unset claim
    pausers_by_c = defaultdict(set)  # contract_id -> pause principal addrs
    value_fns = defaultdict(set)  # contract_id -> value-bearing fn names
    for f in funcs:
        for cl in f["claims"] or []:
            cid = cl.get("claim_id")
            if cid in VALUE_CLAIMS:
                value_fns[f["cid"]].add(f["fn"])
            if cid == "pause.unset":
                unset_exists.add(f["cid"])
                for p in princ.get(f["fid"], []):
                    unset_by_c[f["cid"]].add(p["addr"])
            if cid == "pause.set":
                for p in princ.get(f["fid"], []):
                    pausers_by_c[f["cid"]].add(p["addr"])

    ledger = defaultdict(
        lambda: {
            "instances": [],
            "max_weakness": 0.0,
            "weakest_label": None,
            "seed_addrs": set(),
            "witness_tiers": set(),
            "sev_reasons": set(),
            "capability": None,
            "principal": None,
            "principal_kind": None,
        }
    )
    warnings = []
    freeze_facts = []  # F5: dual-use credit material
    scored_fn_keys = set()  # (contract addr, fn) actually scored, non-pause

    for f in funcs:
        c = contracts[f["cid"]]
        caddr = c["addr"]
        cval = val_by_addr.get(caddr, 0.0)
        openness = f["openness"]
        claims = f["claims"] or []
        fprinc = princ.get(f["fid"], [])
        ctx = {"contract": c["contract_name"], "address": caddr, "function": f["fn"]}

        for claim in claims:
            cid = claim.get("claim_id")
            if cid in NOT_SCORED or cid in PRODUCT_CLAIMS or cid not in BASE_SEV:
                continue
            sev = BASE_SEV[cid]
            sev_reason = "base"
            wit = claim.get("witness") or {}

            # instance value: F1 reach witness beats the balance sheet
            inst_val = cval
            rv = reach_usd(claim)
            if rv is not None and cid not in TRANSITIVE_CAPS:
                inst_val = rv
                sev_reason = "reach_witnessed"

            if cid == "flow.out":
                obs = wit.get("observed") or {}
                dshape = obs.get("destination_shape")
                if dshape == "caller_arbitrary":
                    sev = 0.9
                    if rv is not None:
                        sev_reason = "caller_arbitrary_proven+reach"
                    else:
                        # F1b: extraction is proven, magnitude is not. Publishing
                        # the balance sheet as the amount that can leave would be
                        # an unproven positive (inv.2) -- e.g. recoverETH on WeETH
                        # charged $3.5B for stray-ETH recovery. Floor the weight
                        # and surface the missing witness.
                        sev_reason = "caller_arbitrary_proven+reach_unwitnessed"
                        inst_val = 0.0
                        warnings.append(
                            {
                                "kind": "extraction_magnitude_unwitnessed",
                                **ctx,
                                "capability": cid,
                                "note": (
                                    "destination proven caller_arbitrary but "
                                    "reach_determined is not true; amount that "
                                    "can leave is unproven, weight floored"
                                ),
                                "missing_witness": "observed_reach_value_usd (fork verdict)",
                            }
                        )
                elif dshape == "immutable_fixed":
                    sev = 0.10  # F6: operational routing, principal intact
                    sev_reason = "immutable_fixed_proven"
                else:
                    # F6: neither arbitrariness nor fixedness is proven -> unknown
                    warnings.append(
                        {
                            "kind": "flow_out_destination_unproven",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "flow.out with destination_shape "
                                f"{dshape!r}: arbitrariness unproven and "
                                "fixedness unproven; not scored (inv.1)"
                            ),
                            "missing_witness": "destination_shape (fork verdict or immutability proof)",
                        }
                    )
                    continue
            elif cid in ("exec.arbitrary", "delegatecall.execute"):
                dc = wit.get("destination_constraint") or {}
                dest = wit.get("destination") or {}
                if dest.get("target_kind") == "storage_setter":
                    warnings.append(
                        {
                            "kind": "proxy_fallback_delegatecall",
                            **ctx,
                            "note": (
                                "open fallback delegatecalls to a stored admin "
                                "impl; reachability shifts to the impl-setter"
                            ),
                            "missing_witness": "who controls setAdminImpl",
                        }
                    )
                    continue
                if dc.get("state") == "constrained":
                    sev, sev_reason = 0.35, "destination_constrained"
                else:
                    sev, sev_reason = 1.0, "destination_unconstrained"
            elif cid == "pause.set":
                # claim-level default; re-evaluated per pauser in the principal
                # loop below, since independence is a property of the key.
                sev, sev_reason = freeze_severity(
                    claim, f["cid"] in unset_exists, unset_by_c.get(f["cid"], set()), None, [], ctx
                )
                # F3: scope the frozen value by the witnessed blast radius
                bn = blast_names(claim)
                vfns = value_fns.get(f["cid"], set())
                if bn and vfns:
                    frac = len(bn & vfns) / len(vfns)
                    inst_val = cval * max(frac, FREEZE_SCOPE_FLOOR)
                    sev_reason += "+blast_scoped"
                elif not bn:
                    warnings.append(
                        {
                            "kind": "freeze_blast_radius_unwitnessed",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "pause capability with no observed_blast_radius; "
                                "frozen scope unproven, value not scoped down"
                            ),
                            "missing_witness": "observed_blast_radius (fork verdict)",
                        }
                    )
                # F5: record the brake as a protective fact
                freeze_facts.append(
                    {
                        **ctx,
                        "severity": sev,
                        "reason": sev_reason,
                        "blast_radius": sorted(bn) if bn else None,
                        "recovery_principals": sorted(unset_by_c.get(f["cid"], set()))[:3],
                    }
                )

            if openness == "open":
                if cid in (
                    "upgrade.implementation",
                    "exec.arbitrary",
                    "delegatecall.execute",
                    "authority.replace",
                    "roles.grant",
                    "roles.configure",
                    "ownership.transfer",
                ):
                    row = ledger[("ANYONE", cid)]
                    row.update(
                        capability=cid,
                        principal="ANYONE (permissionless)",
                        principal_kind="anyone",
                        max_weakness=1.0,
                        weakest_label="ANYONE",
                    )
                    row["seed_addrs"].add(caddr)
                    row["witness_tiers"].add(claim.get("tier"))
                    row["sev_reasons"].add(sev_reason)
                    row["instances"].append({**ctx, "usd": inst_val, "sev": sev})
                continue

            if openness == "not_determined":
                warnings.append(
                    {
                        "kind": "unresolved_reachability",
                        **ctx,
                        "capability": cid,
                        "note": "authority_openness not_determined on privileged capability",
                        "missing_witness": "principal resolution",
                    }
                )
                continue

            scored_any = False
            for p in fprinc:
                w, lab, kind = principal_weakness(p, cid)
                if w is None:
                    warnings.append(
                        {
                            "kind": ("contract_gated_unknown_path" if kind == "contract" else "unresolved_principal"),
                            **ctx,
                            "capability": cid,
                            "principal": p["addr"],
                            "note": (f"{cid} gated by a {lab} principal whose own authority is not reduced to a key"),
                            "missing_witness": "controlling principal of the gating contract",
                        }
                    )
                    continue
                scored_any = True
                p_sev, p_reason = sev, sev_reason
                if cid == "pause.set":
                    # F2: independence is a property of THIS key
                    p_sev, p_reason = freeze_severity(
                        claim, f["cid"] in unset_exists, unset_by_c.get(f["cid"], set()), p["addr"], warnings, ctx
                    )
                    if "blast_scoped" in sev_reason:
                        p_reason += "+blast_scoped"
                row = ledger[(p["addr"], cid)]
                row["capability"] = cid
                row["principal"] = f"{lab} {p['addr']}"
                row["principal_kind"] = kind
                if w > row["max_weakness"]:
                    row["max_weakness"] = w
                    row["weakest_label"] = lab
                row["seed_addrs"].add(caddr)
                row["witness_tiers"].add(claim.get("tier"))
                row["sev_reasons"].add(p_reason)
                row["instances"].append({**ctx, "usd": inst_val, "sev": p_sev})
                if cid != "pause.set":
                    scored_fn_keys.add((caddr, f["fn"]))
            if not scored_any and not fprinc:
                warnings.append(
                    {
                        "kind": "restricted_no_principal",
                        **ctx,
                        "capability": cid,
                        "note": "restricted privileged fn with no resolved principal",
                        "missing_witness": "principal resolution",
                    }
                )

    # ---- aggregate into candidate rows ----
    rows = []
    for (paddr, cid), row in ledger.items():
        if cid in TRANSITIVE_CAPS:
            vas, reach = transitive_value(row["seed_addrs"], controls, val_by_addr)
        else:
            # F1/F3: sum the per-instance witnessed values, deduped per contract
            per_c = defaultdict(float)
            for i in row["instances"]:
                per_c[i["address"]] = max(per_c[i["address"]], i["usd"])
            vas = sum(per_c.values())
            reach = set(per_c)
        sev = max(i["sev"] for i in row["instances"])
        w = row["max_weakness"]
        b = band(vas)
        rows.append(
            {
                "principal_address": paddr,
                "principal": row["principal"],
                "principal_kind": row["principal_kind"],
                "capability": cid,
                "value_at_stake_usd": round(vas, 2),
                "value_band": band_label(vas),
                "severity_proven": round(sev, 4),
                "severity_basis": sorted(row["sev_reasons"]),
                "weakness": round(w, 3),
                "weakest_gate": row["weakest_label"],
                "raw_points": round(SEV_SCALE * sev * w * b, 3),
                "n_functions": len(row["instances"]),
                "n_contracts": len(row["seed_addrs"]),
                "reach_addrs": sorted(reach)[:40],
                "example_functions": sorted({i["function"] for i in row["instances"]})[:6],
                "witness_tiers": sorted(t for t in row["witness_tiers"] if t),
                "counterfactual": counterfactual(cid, row["principal_kind"]),
            }
        )

    # ---- F7: per-principal subsumption (inv.13) ----
    by_p = defaultdict(list)
    for r in rows:
        by_p[r["principal_address"]].append(r)
    findings, subsumed = [], []
    for paddr, rs in by_p.items():
        rs.sort(key=lambda x: -x["raw_points"])
        top = dict(rs[0])
        top["subsumed_capabilities"] = [
            {"capability": x["capability"], "raw_points": x["raw_points"], "n_contracts": x["n_contracts"]}
            for x in rs[1:]
        ]
        top["subsumed_raw_points"] = round(sum(x["raw_points"] for x in rs[1:]), 3)
        findings.append(top)
        subsumed.extend(rs[1:])

    # ---- F8a: lambda composition (apples-to-apples with proto-0.1) ----
    findings.sort(key=lambda x: -x["raw_points"])
    cum = 0.0
    for i, f in enumerate(findings):
        f["net_points_lambda"] = round(f["raw_points"] * (LAMBDA**i), 3)
        cum += f["raw_points"] * (LAMBDA**i)
    grade_lambda = round(100.0 - min(cum, 100.0), 3)

    # ---- F8b: exposure composition (parameter-free) ----
    # Each finding claims sev*weakness of the value it reaches. Per contract the
    # total claim is capped at 1.0 (you cannot lose more than 100% of it), and
    # claims are attributed marginally in rank order -> exact decomposition.
    claimed = defaultdict(float)
    exposure = 0.0
    for f in findings:
        frac = f["severity_proven"] * f["weakness"]
        mine = 0.0
        if f["capability"] in TRANSITIVE_CAPS:
            addrs = {a: val_by_addr.get(a, 0.0) for a in f["reach_addrs"]}
        else:
            addrs = {}
            for a in f["reach_addrs"]:
                addrs[a] = (
                    min(val_by_addr.get(a, 0.0), f["value_at_stake_usd"])
                    if f["value_at_stake_usd"]
                    else val_by_addr.get(a, 0.0)
                )
        for a, v in addrs.items():
            room = max(0.0, 1.0 - claimed[a])
            take = min(frac, room)
            if take > 0:
                claimed[a] += take
                mine += take * v
        f["exposure_usd"] = round(mine, 2)
        exposure += mine
    grade_exposure = round(100.0 * (1.0 - exposure / total_value), 3) if total_value else 0.0

    conf_num, conf_den = confidence(funcs, princ, contracts, val_by_addr)
    confidence_pct = round(100.0 * conf_num / conf_den, 1) if conf_den else 0.0

    # ---- credits, incl. F5 dual-use brake credit ----
    credits = []
    for f in findings:
        if (
            f["capability"] in TRANSITIVE_CAPS
            and f["principal_kind"] in ("timelock", "safe")
            and f["value_at_stake_usd"] >= 100_000_000
            and f["weakness"] <= 0.2
        ):
            eoa_raw = SEV_SCALE * f["severity_proven"] * 0.9 * band(f["value_at_stake_usd"])
            credits.append(
                {
                    "protective_fact": f"{f['weakest_gate']} gates {f['capability']}",
                    "principal": f["principal"],
                    "value_protected_band": f["value_band"],
                    "n_functions": f["n_functions"],
                    "counterfactual_if_eoa_gated": f"~-{round(eoa_raw, 1)} raw (vs -{f['raw_points']} now)",
                }
            )
    rec_ok = [x for x in freeze_facts if "recovery_path_witnessed" in x["reason"]]
    if rec_ok:
        scored_fns = scored_fn_keys
        overlap = [
            x for x in rec_ok if x["blast_radius"] and any((x["address"], fn) in scored_fns for fn in x["blast_radius"])
        ]
        credits.append(
            {
                "protective_fact": (
                    "emergency brake: pause capability with a witnessed, "
                    "independent recovery path (inv.4 dual-use, credit side)"
                ),
                "n_pause_capabilities": len(rec_ok),
                "n_contracts": len({x["address"] for x in rec_ok}),
                "counterfactual_if_removed": (
                    "deleting the brake removes these rows "
                    "entirely; proto-0.1 paid +7.77 grade points "
                    "for having no pause at all"
                ),
                "mitigation_overlap": [
                    {
                        "contract": x["contract"],
                        "pause_function": x["function"],
                        "mitigates_scored_functions": sorted(
                            fn for fn in x["blast_radius"] if (x["address"], fn) in scored_fns
                        ),
                    }
                    for x in overlap
                ][:6],
            }
        )
    credits.append(
        {
            "protective_fact": "audit equivalence proven (deployed code == sha printed in audit PDF)",
            "rows": len([a for a in audits if a["eq"] == "proven"]),
            "note": "modest credit only; LLM role labels excluded (inv.2)",
        }
    )

    for a in [x for x in audits if x["proof_kind"] == "pre_fix_unpatched"]:
        c = contracts.get(a["cid"])
        warnings.append(
            {
                "kind": "audit_pre_fix_unpatched_llm_label",
                "contract": c["contract_name"] if c else a["cid"],
                "note": "LLM-labeled 'fix commit exists, not deployed' - hallucinatable",
                "missing_witness": "deterministic 'fixed in <sha>' phrase match in PDF",
            }
        )

    wsummary = defaultdict(lambda: {"count": 0, "examples": []})
    for w in warnings:
        g = wsummary[w["kind"]]
        g["count"] += 1
        if len(g["examples"]) < 4:
            g["examples"].append(f"{w.get('contract', '?')}.{w.get('function', '?')}")

    top = findings[0] if findings else None
    headline = None
    if top:
        headline = (
            f"{top['weakest_gate']} can {top['capability']} on "
            f"{top['value_band']} ({', '.join(top['example_functions'][:3])}) "
            f"— raw -{top['raw_points']}"
        )

    out = {
        "protocol": "etherfi",
        "protocol_id": PROTOCOL_ID,
        "model_version": MODEL_VERSION,
        "headline": headline,
        "grade_lambda": grade_lambda,
        "grade_lambda_letter": letter(grade_lambda),
        "grade_exposure": grade_exposure,
        "grade_exposure_letter": letter(grade_exposure),
        "confidence_pct": confidence_pct,
        "total_tracked_value_usd": round(total_value),
        "total_exposure_usd": round(exposure),
        "decomposition_check": {
            "lambda": {
                "grade": grade_lambda,
                "sum_net": round(sum(f["net_points_lambda"] for f in findings), 3),
                "residual": round(100.0 - grade_lambda - sum(f["net_points_lambda"] for f in findings), 6),
            },
            "exposure": {
                "grade": grade_exposure,
                "sum_exposure_usd": round(sum(f["exposure_usd"] for f in findings), 2),
                "residual_usd": round(exposure - sum(f["exposure_usd"] for f in findings), 4),
            },
        },
        "credits": credits,
        "warnings_summary": dict(wsummary),
        "findings": findings,
        "subsumed_rows": subsumed,
        "freeze_facts": freeze_facts,
        "warnings": warnings,
    }
    with open(os.path.join(os.path.dirname(__file__), "score_v2.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)

    print(f"model_version      {MODEL_VERSION}")
    print(f"grade (lambda 0.6) {grade_lambda:7.2f}  {letter(grade_lambda)}")
    print(f"grade (exposure)   {grade_exposure:7.2f}  {letter(grade_exposure)}")
    print(f"confidence         {confidence_pct}%")
    print(f"tracked value      ${round(total_value):,}")
    print(f"exposure           ${round(exposure):,}")
    print(f"findings {len(findings)}  (subsumed {len(subsumed)})  warnings {len(warnings)}")
    print(
        f"\n{'raw':>7} {'net_l':>7} {'exposure$':>14}  {'capability':24s} {'gate':10s} "
        f"{'band':10s} {'sev':>6} {'w':>5}  basis"
    )
    for f in findings[:14]:
        print(
            f"{f['raw_points']:7.2f} {f['net_points_lambda']:7.2f} "
            f"{f['exposure_usd']:14,.0f}  {f['capability'][:24]:24s} "
            f"{str(f['weakest_gate'])[:10]:10s} {f['value_band']:10s} "
            f"{f['severity_proven']:6.3f} {f['weakness']:5.2f}  "
            f"{','.join(f['severity_basis'])[:38]}"
        )
    return out


def counterfactual(cid, kind):
    return {
        "anyone": "gate this capability behind a multisig/timelock",
        "eoa": "move behind a strong multisig (>=k/n 0.67) or timelock: weakness 0.9 -> 0.15-0.2",
        "safe": "raise threshold ratio and/or add a timelock in front",
        "timelock": "already timelock-gated; residual is the timelock's controlling principal",
        "contract": "resolve the controlling principal of the gating contract",
    }.get(kind, "n/a")


def confidence(funcs, princ, contracts, val_by_addr):
    num = den = 0.0
    for f in funcs:
        claims = f["claims"] or []
        privileged = any(cl.get("claim_id") in BASE_SEV for cl in claims) or (f["openness"] == "not_determined")
        if not (privileged or (f["openness"] == "restricted" and f["state_changing"])):
            continue
        b = band(val_by_addr.get(contracts[f["cid"]]["addr"], 0.0))
        den += b
        if claims and (f["openness"] == "open" or princ.get(f["fid"])) and f["openness"] != "not_determined":
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
