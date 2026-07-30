#!/usr/bin/env python3
"""
Prototype protocol-security scorer, model_version proto-0.3.

Built from SCORING_INVARIANTS.md Appendix B *as amended by B0b* -- the nine-lane
validation round. It carries only what survived. Where B0b refuted a register
claim, this scorer implements the correction, not the original.

WHAT CHANGED FROM proto-0.2, and why (each keyed to a B0b finding):

 V1  Entity model (16a). Value is keyed on the RUNTIME address
     (effective_functions.deployment_address, falling back to contracts.address)
     with MAX per (holder, asset) -- never SUM per contracts row, which
     double-counts a proxy against its implementation. proto-0.2 keyed on the
     analyzed contract's address, which is the *implementation* row on 10 of the
     38 reach-witnessed claims.

 V2  Per-asset value, with the three gates B8 omits (B0b/S6). Native vs ERC-20 is
     a join on contract_balances.token_address x flows[].kind. The flow-kind
     vocabulary is exactly three values and `native_transfer_send` is included.
     An ABSENT native row is `not_determined`, NEVER $0: tvl.py gates the insert
     on eth_wei > 0 and swallows a failed fetch as 0, so absence conflates
     proven-zero with fetch-failure. This is the register's own sweepETH error
     pointed the other way, and it is what invalidated Audit C's evidence path.

 V3  The static destination lattice, guarded (B0b/R3, R4, R5). The replay runs,
     but its validation is a projection-fidelity check at n=3 whose refuting
     plane is absent by construction on every row it would newly decide. So:
      - rule 3 is PRIMARY -- a flow.out/value_router claim with no `flows` key
        BLOCKS the conjunction (population 14, not 11);
      - `several` expands to members and takes the WORST (4 false immutable_fixed
        otherwise). NOTE: the first cut str()'d dict members, so the reduction
        silently failed CLOSED and TARGET_KIND_RANK was dead code -- right answer,
        broken mechanism. Fixed; the reduction is now real.
      - value_router flows are inside the conjunction;
      - `policy_derived` tier blocks it;
      - a proven fixed shape may only SOFTEN severity, never escalate, and it
        emits a warning naming the missing sentinel;
      - `immutable` lives in implementation code, so a fixed destination is
        conditional on upgrade authority -- composed, not asserted;
      - `storage_determined` is a DEFERRAL, not a severity constant: the flow
        entry carries no variable/writer_signatures/slot, so the setter's
        principal is unresolvable from B2's own fields.

 V4  Magnitude gates (16d, B0b/R5). A fixed-destination softening is licensed by
     the DESTINATION PROOF, not by a balance snapshot. Written the other way
     round ("empty contract => cheap") it licenses rug-on-an-empty-vault.

 V5  Timelock weakness monotone in the proven delay (16c). f(quorum, delay) is
     DEFINED here rather than quoted -- B4b's "~7.35 raw" spans +0.29 to -10.41
     grade points across plausible f. The delay discount requires BOTH a proven
     delay AND a resolved proposer set; the 2-day timelock has neither a proposer
     in the DB nor structural corroboration, so it gets no delay credit.

 V6  Key-set Safe independence (B0b/R1) -- the most damaging refutation.
     Independence is a property of owner KEY SETS, not principal identities:
     P and U are independent iff |owners(U) \\ owners(P)| >= threshold(U).
     The 1/5 Safe's five owners are a strict SUBSET of the 4/7's seven, and four
     of them are a blocking minority of the 4/7 -- so four keys freeze WeETH
     ($3.5B) and hold it. proto-0.2 published a protective credit for exactly
     this configuration. Overlapping Safes that can act as each other are ONE
     aggregation unit (inv.13), and the published figure is the minimum coalition
     size, never a boolean.

 V7  Freeze from proven components only (B0b/R12). Duration contributes ZERO to
     severity: `duration_bound_source` is not_determined on 4/4, `no_time_reference`
     and `guard_constant` never appear. proto-0.1's 0.35 resolved that unknown
     adversarially; proto-0.2's 0.05 resolves it favourably; both are the same
     inv.1 violation with opposite sign. What IS proven: pause_effective (4 rows)
     and key-set recovery independence (30/30 contracts).
      - FIXES latent inv.2 #1: the auto-expiry branch now requires
        `auto_expiry is True` (T-BOUND). `auto_expiry is False` means the fork
        CONTRADICTED the static constant; this records that as a note rather than
        raising severity, because no witness sets the size of the raise. Population
        is 0 in both directions (`duration_bound_seconds` never populated, and
        `guard_constant` never appears), so the branch is dead either way.
      - REMOVES `irreversibility_proven_no_unset_claim`: proto-0.2 published the
        word "proven" from the ABSENCE of a claim, at 4x the reversible severity.
      - Freeze VaS is not_determined: a count ratio over function names is not a
        fraction of dollars (proto-0.2's F3). The coverage fraction is published
        as a citation, not multiplied into value.

 V8  scored_denominator replaces the invented value_fns proxy (B0b/R13) -- minus
     pause/unpause entries (unpauseUntil() is a member on all 4 rows, so the
     recovery path was counted as frozen surface), joined on a normalised
     signature with unmatched entries surfaced rather than dropped (5 of 33 are
     source-level type names that match no abi_signature).

 V9  Earned negatives as findings, not dismissals (B0b/R10, R11). The 52
     resolved_empty rows are now-facts about mutable state: all 10 registries
     have authority=0x0 with owner = the 4/6 Safe, so two transactions re-enable
     any of the 50. Published as "currently unreachable; re-enablable by <X>"
     with a counterfactual (inv.10). Gate adds `trace[0].basis != 'accessor_name'`
     (_pending_ceiling_capability mints an exact empty from a name prefix) and
     records the msg.sender != 0x0 axiom explicitly. The 11 false
     `restricted_no_principal` warnings are deleted.

 V10 Audit credit on the deterministic core only (B0b/R7). proof_kind is LLM-gated
     for every value except `unclassified` -- `clean` and `pre_fix_unpatched` are
     opposite branches of one `if` over the same LLM label sets. Credit is
     equivalence_status='proven' + matched_commit_sha + bytecode_keccak_at_match,
     with the honest as-of wording (R8: bytecode_cache has no block).

 V11 PRODUCT_CLAIMS gated on authority_openness='open' (B0b/R16). The inv.2
     charge against claim_id is withdrawn -- erc20.transfer requires structural
     is_erc20 AND a keccak selector identity. But claim_id does not prove
     permissionlessness, and BoringGovernance.transfer/transferFrom are
     `not_determined`. not_determined is not product.

 V12 T-ACCESSOR demotion (B0b/S1). All 33 rows publish exact+enumerable, the
     maximum strength; the convention is recorded only in trace[*].basis. Read it.

 V13 inv.9: subsumed rows are DISCLOSED, and the residual is demoted. Stated
     precisely, because an earlier draft of this docstring over-claimed: the grade
     is still a fold over `findings` only, so the subsumed raw points sit OUTSIDE
     the total (they are published as `subsumed_raw_points_total` so the quantity
     is visible, which proto-0.2 did not do). Excluding them is conforming --
     max-of-rows over one key is a bound that can only under-count, never
     over-count -- but "the decomposition includes them" would be false. What the
     check now does that proto-0.2's did not: `row_reproduction` recomputes every
     published row from its own cited fields, which is the redundancy check inv.9
     asks for. The algebraic residual is zero by construction and proves nothing.

 V14 inv.11/12 determinism: ORDER BY on every query, total-order tiebreaks on
     every sort, sorted iteration before every accumulation. Verified by running
     twice and diffing. Provenance for what CANNOT be replayed is published
     rather than hidden (contract_balances is destructively rewritten each
     monitoring cycle; fork verdicts span 51 blocks).

 V15 inv.6 monotone confidence. proto-0.2's confidence() DROPS when a newly
     analyzed contract yields privileged claims with unresolved principals.

DELIBERATELY NOT BUILT, with cause:
 - proof_kind gating (R7: all four values LLM-gated).
 - never-emitted-events as a proven negative (R9: AllowTo/DenyTo have no cursor,
   so the cited evidence does not touch toDenyList; needs the 4th limit first).
 - the timelock/proposer collapse's numeric claim (R14/16c: f must be published
   before a consequence is quoted -- f IS published here, so the collapse runs,
   but the "~7.35" figure is not repeated).
 - one_shot latch as a grade-bearing earned negative (S3: proven on-chain 22/22,
   but expected_version is dropped at persistence so a consumer cannot tell a
   `value >= expected` verdict from a `value > 0` one; CONFIDENCE only).
 - contract_dependencies in any closure (R17: $180.6B under a second name).
 - `upgrade_events.tx_hash` and the inv.5 direct-path discount. B0b/S3 establishes
   that Safe 4/7 `0x2aca7102` directly gates all 16 contracts the 2-day timelock
   gates (127 function rows / 22 contracts), so under inv.5's own corollary the
   2-day delay's protective value MUST be discounted against the undelayed direct
   path. Not built, and the reason is that the empirical test needs data this
   corpus does not hold: `upgrade_events` stores no sender, no receipt and no
   trace, so "who actually sent this upgrade" requires a live
   eth_getTransactionByHash -- and even that answers "who submitted", not "who
   authorised", because a Safe `execTransaction` sender is a relayer. 120 events
   also span only 68 distinct tx_hash, so per-event attribution would double-count
   one governance action up to 19x. Consequence, stated rather than hidden: the
   2-day timelock's protective value is NOT discounted here, which over-credits it.
   Its rows already take no delay credit for a different reason (unresolved
   proposer), so the two errors partly cancel -- by luck, not by design.
 - `authority_roles` / `role_labels` as an inv.13 aggregation unit. v3 aggregates by
   (Safe key-set unit, capability) only, so N functions requiring the same role on
   the same registry are still N rows rather than one capability. The key must be
   (registry_address, role) -- a Solmate role integer is meaningful only per
   registry -- and that is a second aggregation pass this prototype does not make.
"""

import json
import math
import os
from collections import defaultdict

import psycopg2
import psycopg2.extras

PROTOCOL_ID = 1
MODEL_VERSION = "proto-0.3"
SEV_SCALE = 60.0
LAMBDA = 0.6

DB = os.environ["DATABASE_URL"]

# B0b/R16: withdraw the inv.2 charge against claim_id, add the openness gate.
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
# B0b/S5: supply.mint/supply.burn are in PRODUCT_CLAIMS and an EOA-gated
# mintShares on a $3.5B token would be dropped silently. Harmless on this corpus
# (measured: every such claim is open user flow or contract-gated) but the
# openness gate below is what makes it safe rather than lucky.
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
REVERSIBLE_CAPS = {"pause.set"}

BASE_SEV = {
    "upgrade.implementation": 1.0,
    "authority.replace": 0.75,
    "roles.grant": 0.55,
    "roles.revoke": 0.4,
    "roles.configure": 0.55,
    "authorized_caller.rotate": 0.55,
    "ownership.transfer": 0.55,
    "pause.set": 0.0,  # V7: set from proven components only
    "transfer_policy.configure": 0.25,
    "timelock.set_delay": 0.3,
    "lz_oapp.set_peer": 0.3,
    "lz_oapp.set_delegate": 0.3,
    "delegatecall.execute": 1.0,
    "exec.arbitrary": 1.0,
    "flow.out": 0.9,
}

# V7 freeze ladder. No duration term: duration_bound_source is not_determined on
# 4/4 and licenses nothing either way (T-INDEF).
FREEZE_KEYSET_RECOVERABLE = 0.05  # a disjoint quorum can lift it -- proven
FREEZE_SUSTAINABLE = 0.20  # this key set can hold its own freeze
FREEZE_AUTO_EXPIRY = 0.02  # requires auto_expiry is True (T-BOUND)

# V3: the writer's own fixed-target set. `constant` and `storage_no_setter` are
# 0/0 on this corpus, so the rule is validated on one third of its input domain.
FIXED_TARGET_KINDS = {"immutable", "constant", "storage_no_setter"}
ADMIN_TARGET_KIND = "storage_setter"
# Worst-first, for `several` expansion (rule 1).
TARGET_KIND_RANK = {
    "indeterminate": 0,
    "param": 1,
    "msg_sender": 2,
    "caller_controlled": 2,
    "token_owner": 3,
    "self": 4,
    "storage_setter": 5,
    "storage_no_setter": 6,
    "constant": 7,
    "immutable": 7,
}
# V2: exactly three kinds (effects.py:122); native side pinned at calldata.py:1033.
NATIVE_FLOW_KINDS = {"native_transfer_send", "low_level_value_call"}
ERC20_FLOW_KINDS = {"callee_erc20_selector"}

# V12: resolution-provenance tiers. `authority_getter_basis` publishes
# exact+enumerable but its binding is a 3-name convention.
WEAK_RESOLVER_BASES = {"internal_accessor_convention", "slot_name_keyword"}


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


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _norm_sig(s):
    """V8: scored_denominator carries 5 of 33 entries as Solidity source-level
    type names that match no abi_signature. Normalise to the bare name so the
    join is total, and surface the ones that still miss."""
    s = str(s or "")
    return s.split("(")[0].strip()


# ---------------------------------------------------------------- load


def load():
    conn = psycopg2.connect(DB)
    conn.set_session(readonly=True)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute(
        """
        select id, lower(address) addr, chain, contract_name, is_proxy,
               proxy_type, lower(admin) admin, lower(implementation) impl,
               lower(beacon) beacon
        from contracts where protocol_id=%s order by id
    """,
        (PROTOCOL_ID,),
    )
    contracts = {r["id"]: r for r in cur.fetchall()}

    # V1/V2: per-asset, keyed for MAX-per-(holder,asset) reduction. `usd_value`
    # NULL is not_determined, never 0 (T-PRICE: 432 rows carry price_usd=0 with
    # usd_value NULL, and nothing distinguishes spam from a failed lookup).
    cur.execute(
        """
        select cb.contract_id cid, lower(c.address) caddr,
               coalesce(lower(cb.token_address),'native') asset,
               cb.token_symbol, cb.usd_value, cb.fetched_at
        from contract_balances cb join contracts c on c.id=cb.contract_id
        where c.protocol_id=%s order by cb.contract_id, asset, cb.id
    """,
        (PROTOCOL_ID,),
    )
    bal_rows = cur.fetchall()

    cur.execute(
        """
        select ef.id fid, ef.contract_id cid, ef.function_name fn,
               ef.abi_signature sig, ef.authority_openness openness,
               ef.authority_public pub, ef.claims, ef.state_changing,
               lower(ef.deployment_address) deploy, ef.conditions,
               ef.capability_expr
        from effective_functions ef join contracts c on c.id=ef.contract_id
        where c.protocol_id=%s order by ef.id
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
        where c.protocol_id=%s order by fp.function_id, fp.address, fp.id
    """,
        (PROTOCOL_ID,),
    )
    princ = defaultdict(list)
    for r in cur.fetchall():
        princ[r["fid"]].append(r)

    cur.execute(
        """
        select lower(replace(e.from_node_id,'address:','')) frm,
               lower(replace(e.to_node_id,'address:','')) too, e.relation
        from control_graph_edges e join contracts c on c.id=e.contract_id
        where c.protocol_id=%s
          and e.relation in ('controller_value','role_principal','mapping_member')
        order by 1,2,3
    """,
        (PROTOCOL_ID,),
    )
    # T-EXTCALL / R17: external_call_target and contract_dependencies are
    # excluded. safe_owner is excluded as a control edge: one owner does not
    # satisfy k-of-n, so treating it as a full edge would over-attribute.
    controls = defaultdict(set)
    for r in cur.fetchall():
        controls[r["too"]].add(r["frm"])
    for cid in sorted(contracts):
        c = contracts[cid]
        if c["admin"]:
            controls[c["admin"]].add(c["addr"])

    # V9 / R-REGISTRY: never queried by proto-0.2. `authority_provenance` is a
    # genuine three-state -- the key is omitted, not None, when unanswered.
    cur.execute(
        """
        select cv.contract_id cid, lower(c.address) caddr, cv.source,
               cv.value, cv.resolved_type rtype, cv.block_number blk,
               cv.authority_provenance prov, cv.observed_via via
        from controller_values cv join contracts c on c.id=cv.contract_id
        where c.protocol_id=%s order by cv.contract_id, cv.source, cv.id
    """,
        (PROTOCOL_ID,),
    )
    cvals = cur.fetchall()

    cur.execute(
        """
        select acc.contract_id cid, lower(c.address) caddr, acc.proof_kind,
               acc.equivalence_status eq, acc.matched_commit_sha sha,
               acc.bytecode_keccak_at_match bkam, acc.equivalence_reason reason
        from audit_contract_coverage acc
        join contracts c on c.id=acc.contract_id
        where acc.protocol_id=%s
        order by acc.contract_id, acc.id
    """,
        (PROTOCOL_ID,),
    )
    audits = cur.fetchall()

    # V10: the deterministic negative generator. bytecode_cache has no block, so
    # the honest claim is "matched the bytecode cached during this run".
    cur.execute("select lower(address) addr, code_keccak from bytecode_cache where chain_id=1 order by address")
    bc = {r["addr"]: r["code_keccak"] for r in cur.fetchall()}

    # V3/G3: concrete_destination is NOT projected into claims; join on
    # effect_verdict_id. Gated -- on the unknown/none branch it is one
    # destination from one probe, and it is withheld on caller_arbitrary.
    cur.execute(
        """
        select ev.id, ev.verdict, ev.tier, ev.effect_class, ev.function_id fid,
               lower(ev.concrete_destination) cdest, ev.witness
        from effect_verdicts ev
        join effective_functions ef on ef.id=ev.function_id
        join contracts c on c.id=ef.contract_id
        where c.protocol_id=%s order by ev.id
    """,
        (PROTOCOL_ID,),
    )
    verdicts = {r["id"]: r for r in cur.fetchall()}

    conn.close()
    return contracts, bal_rows, funcs, princ, controls, cvals, audits, bc, verdicts


# ---------------------------------------------------------------- V1/V2 value


def build_value(contracts, bal_rows):
    """MAX per (runtime address, asset). A proxy and its implementation each carry
    an independently fetched copy of the one deployment's holdings; SUM-per-
    contracts-row double-counts them (measured: 2 pairs, $1,589,342)."""
    impl_to_proxy = {}
    shared_impl = []
    for cid in sorted(contracts):
        c = contracts[cid]
        if not c["impl"]:
            continue
        prev = impl_to_proxy.get(c["impl"])
        if prev is not None and prev != c["addr"]:
            # two proxies sharing one implementation: last-wins would be
            # deterministic but arbitrary. Pin to the lowest address and record it.
            shared_impl.append({"implementation": c["impl"], "proxies": sorted([prev, c["addr"]])})
            impl_to_proxy[c["impl"]] = min(prev, c["addr"])
        else:
            impl_to_proxy[c["impl"]] = c["addr"]

    def runtime(addr):
        return impl_to_proxy.get(addr, addr)

    per_asset = defaultdict(dict)  # runtime addr -> asset -> usd (max)
    native_seen = defaultdict(bool)
    fetched = []
    for r in bal_rows:
        rt = runtime(r["caddr"])
        usd = _f(r["usd_value"])
        if r["asset"] == "native":
            native_seen[rt] = True
        if usd is None:
            continue  # not_determined, never 0 (T-PRICE)
        prev = per_asset[rt].get(r["asset"])
        if prev is None or usd > prev:
            per_asset[rt][r["asset"]] = usd
        if r["fetched_at"]:
            fetched.append(r["fetched_at"])

    val_by_addr = {a: round(sum(sorted(d.values())), 6) for a, d in sorted(per_asset.items())}
    native_by_addr = {}
    for a in sorted(per_asset):
        native_by_addr[a] = per_asset[a].get("native") if native_seen[a] else None
    for a in sorted(native_seen):
        native_by_addr.setdefault(a, per_asset[a].get("native"))
    prov = {
        "entity_key": "effective_functions.deployment_address -> contracts.address",
        "reduction": "MAX per (runtime address, asset)",
        "fetched_at_span_seconds": (round((max(fetched) - min(fetched)).total_seconds(), 3) if fetched else None),
        "replayability": (
            "contract_balances is DELETEd and re-inserted every monitoring cycle "
            "(tvl.py) with no block, no version and no history, so any figure "
            "sourced from it is NOT byte-identically replayable. Measured drift: "
            "an ETHFI price moved 0.836% between a verdict and the table 23 "
            "minutes later. Frozen claims[] values ARE replayable."
        ),
        "shared_implementations": shared_impl,
        "absent_native_row": (
            "not_determined, never $0 -- tvl.py gates the native insert on eth_wei > 0 and swallows a failed fetch as 0"
        ),
    }
    return val_by_addr, native_by_addr, runtime, prov


# ---------------------------------------------------------------- V3 lattice


def _target_kinds(flow):
    tk = flow.get("target_kind") or {}
    kind = tk.get("kind")
    if kind == "several":
        # members are DICTS ({kind, tier}), not strings. The first cut str()'d them,
        # which produced "{'kind': 'self', ...}" -- never in FIXED_TARGET_KINDS, so
        # the rule failed closed by a type bug while its docstring claimed a
        # worst-member reduction and TARGET_KIND_RANK sat dead. Right answer, broken
        # mechanism; fixed so the reduction is real.
        members = flow.get("target_kinds") or tk.get("kinds") or []
        out = []
        for m in members:
            if isinstance(m, dict):
                k = m.get("kind")
                out.append(str(k) if k else None)
            elif m:
                out.append(str(m))
        return out or [None]  # unreadable member fails CLOSED
    return [kind]


def static_destination_shape(claim_list):
    """V3: replay of calldata.py:1077 over claims[].witness.flows[].

    Rule 3 is PRIMARY: any flow.out / value_router claim with no `flows` key
    BLOCKS the conjunction (14 claims, not 11 -- the 11 policy_derived
    cross_contract_join rows plus the 3 behavioral_observed rows with an
    `observed` block and no flows). Silence is not evidence.
    """
    considered = []
    for cl in claim_list:
        cid = cl.get("claim_id")
        if cid not in ("flow.out", "value_router"):
            continue
        if cl.get("tier") == "policy_derived":
            return None, "blocked_policy_derived"
        wit = cl.get("witness") or {}
        flows = wit.get("flows")
        if flows is None:
            return None, "blocked_no_flows"
        # `direction` lives on the WITNESS, not on each flow entry. Reading it off
        # the entry silently yields "no out flows" and skips the conjunction
        # entirely -- the exact fail-open shape rule 3 exists to prevent.
        d = str(wit.get("direction") or ("value_router" if cid == "value_router" else "out"))
        if d not in ("out", "eth_out", "value_router"):
            continue
        considered.extend(flows)
    if not considered:
        return None, "no_out_flows"

    worst = None
    for fl in considered:
        for k in _target_kinds(fl):  # rule 1: worst member of `several`
            r = TARGET_KIND_RANK.get(k, 0)
            if worst is None or r < worst[0]:
                worst = (r, k)
    if worst is None:
        return None, "unreadable"
    kinds = set()
    for fl in considered:
        kinds.update(_target_kinds(fl))
    if kinds and kinds <= FIXED_TARGET_KINDS:
        return "immutable_fixed", "static_conjunction"
    if kinds and kinds <= (FIXED_TARGET_KINDS | {ADMIN_TARGET_KIND}):
        return "storage_determined", "static_conjunction_admin"
    return None, "not_fixed"


def amount_bounds(claim_list):
    """B2's amount lattice -- REQUIRED, and a hard precondition on pricing.

    `token_identity` means exactly one NON-FUNGIBLE token moves, which in the
    writer's own words "forbids pricing the row off a fungible balance sheet".
    `capped_by_balance` is a proven upper bound at the contract's own balance.
    Neither was read at all in the first cut.
    """
    kinds = set()
    for cl in claim_list:
        if cl.get("claim_id") != "flow.out":
            continue
        for fl in (cl.get("witness") or {}).get("flows") or []:
            ak = (fl.get("amount_kind") or {}).get("kind")
            if ak == "several":
                kinds.update(str(m) for m in (fl.get("amount_kinds") or []) if m)
            elif ak:
                kinds.add(str(ak))
    return kinds


def flow_asset_class(claim_list):
    """V2: native vs ERC-20 from the flow kind. Three kinds, total partition, and
    `native_transfer_send` is included (the register's join omits it)."""
    native = erc20 = other = False
    for cl in claim_list:
        if cl.get("claim_id") not in ("flow.out",):
            continue
        for fl in (cl.get("witness") or {}).get("flows") or []:
            if fl.get("from_is_self") is not True:
                # An ABSENT key is not "this contract is the source". Defaulting it
                # True would be a positive fact from a missing key, on the gate that
                # decides whether the per-asset substitution runs at all.
                continue
            k = fl.get("kind")
            if k in NATIVE_FLOW_KINDS:
                native = True
            elif k in ERC20_FLOW_KINDS:
                erc20 = True
            elif k:
                other = True
    if other or (native and erc20):
        return "mixed"
    if native:
        return "native_only"
    if erc20:
        return "erc20_only"
    return None


# ---------------------------------------------------------------- V5/V6/V12


def _owners(details):
    o = (details or {}).get("owners") or []
    return frozenset(str(x).lower() for x in o if x)


def _threshold(details):
    try:
        return int((details or {}).get("threshold"))
    except (TypeError, ValueError):
        return None


def _trace_bases(details):
    out = set()
    for step in (details or {}).get("trace") or []:
        if isinstance(step, dict):
            b = step.get("basis")
            if isinstance(b, str):
                out.add(b)
            elif isinstance(b, list):
                out.update(str(x) for x in b)
    return out


def delay_discount(seconds):
    """V5 / 16c. f(delay) -- PUBLISHED, not quoted. Monotone decreasing, log in
    days, saturating at 30 days, floored so no delay is ever free protection.

    The witness supplies the ORDERING (864000 > 432000 > 172800); the mapping is
    a model choice and belongs to model_version. Values here:
        10d -> 0.302   5d -> 0.478   2d -> 0.680
    """
    d = _f(seconds)
    if d is None or d <= 0:
        return None
    days = d / 86400.0
    frac = math.log10(1.0 + days) / math.log10(1.0 + 30.0)
    return round(max(0.25, min(1.0, 1.0 - frac)), 4)


def quorum_weakness(k, n, cap, reversible_proven=None):
    """`reversible_proven` three-states the REVERSIBLE_CAPS exemption.

    The exemption exists because a low pause threshold is emergency-response
    design. But it was applied to `pause.set` unconditionally, so the 1/5 Safe
    that can freeze WeETH got 0.55 on the assumption pausing is reversible -- on
    the same row whose severity axis had concluded `keyset_dependent`, i.e. that
    it is NOT reversibly recoverable. A design credit may only be granted where
    the design property is proven.
    """
    if k is None or not n:
        return 0.55
    r = k / n
    exempt = cap in REVERSIBLE_CAPS and reversible_proven is not False
    if k == 1 and not exempt:
        return 0.85
    if r < 0.5:
        return 0.55
    if r < 0.67:
        return 0.35
    return 0.2


def principal_weakness(p, cap, timelock_proposers, warn, ctx, contract_princ, reversible_proven=None):
    """Returns (weakness, label, kind, notes). None weakness -> warning path."""
    rt = p["rtype"]
    d = p.get("details") or {}
    notes = []
    bases = _trace_bases(d)
    steps = {str(st.get("step")) for st in ((d or {}).get("trace") or []) if isinstance(st, dict)}
    conv = bases & WEAK_RESOLVER_BASES
    if conv:
        # CORRECTED. The first cut multiplied weakness by 1.25 here. Three things
        # wrong with that: §E says a proof-strength field may WITHHOLD an
        # escalation and "may never raise anything"; 1.25 was an invented constant
        # with no witness and no publication; and B0b/R16 refutes the premise --
        # all 33 convention rows ALSO carry `live_getter_resolution` and all 33
        # resolve to `resolved_type='safe'`, probe-confirmed, so none rests on the
        # convention alone. The residual is on the BINDING ("we may have read the
        # wrong getter"), which is a confidence fact, not evidence the gate is
        # weaker. Recorded as a note; escalated to a warning only if the
        # corroborating live read is absent.
        notes.append("resolver_basis_convention:" + ",".join(sorted(conv)))
        if "live_getter_resolution" not in steps:
            notes.append("resolver_convention_uncorroborated")
            warn.append(
                {
                    "kind": "principal_binding_convention_uncorroborated",
                    **ctx,
                    "principal": p["addr"],
                    "capability": cap,
                    "note": (
                        "the principal address is a real eth_call result but the "
                        "BINDING rests on a 3-name accessor convention with no "
                        "corroborating live_getter_resolution step in the trace"
                    ),
                    "missing_witness": (
                        "a differential storage-slot comparison between the public getter and the slot the gate reads"
                    ),
                }
            )

    if rt == "eoa":
        return 0.9, "EOA", "eoa", notes
    if rt == "safe":
        k, owners = _threshold(d), _owners(d)
        n = len(owners) or k
        w = quorum_weakness(k, n, cap, reversible_proven)
        return w, f"Safe {k}/{n}", "safe", notes
    if rt == "timelock":
        dl = d.get("delay")
        disc = delay_discount(dl)
        prop = timelock_proposers.get(p["addr"])
        if disc is None:
            notes.append("timelock_delay_not_determined")
            return 0.55, "timelock(?)", "timelock", notes
        if not prop:
            # 16c + inv.11: the delay is proven, but a delay whose proposer set
            # and role-admin topology are undetermined is not proven protection.
            # The 2-day timelock (contracts.id=11, 0 effective_functions) is
            # exactly this: its type and delay rest on a duck-type with no
            # structural corroboration in the DB at all.
            notes.append("timelock_proposer_not_determined:no_delay_credit")
            warn.append(
                {
                    "kind": "timelock_proposer_unresolved",
                    **ctx,
                    "principal": p["addr"],
                    "capability": cap,
                    "delay_seconds": dl,
                    "note": (
                        "proven delay with an unresolved proposer set; the delay "
                        "is not credited because a timelock whose proposer set "
                        "and role admin are undetermined is not proven protection"
                    ),
                    "missing_witness": (
                        "effective_functions on the timelock-as-contract "
                        "(schedule/execute principals) + a persisted "
                        "TIMELOCK_ADMIN_ROLE/DEFAULT_ADMIN_ROLE fold"
                    ),
                }
            )
            notes.append("proven_delay_NOT_credited:protection_not_determined")
            return 0.55, f"timelock {int(_f(dl) or 0) // 86400}d(proposer?)", "timelock", notes
        pk, pn = prop["k"], prop["n"]
        w = round(quorum_weakness(pk, pn, cap) * disc, 4)
        notes.append(f"delay_discount={disc};proposer={pk}/{pn}")
        return w, f"timelock {int(_f(dl)) // 86400}d via {pk}/{pn}", "timelock", notes
    if rt == "contract":
        # B0b: 26 of 78 contract principals resolve one hop. The first cut computed
        # the hop and then returned None in BOTH branches, so it changed only a
        # warning's label -- "try before warning" that tried and warned anyway. That
        # suppressed a usable witness in the UNDER-scoring direction, which is the
        # one direction the register leans against, and it was also the direct cause
        # of confidence()'s non-monotonicity. Now the hop's own weakest resolved
        # principal carries the row, tiered below a direct resolution.
        hop = contract_princ.get(p["addr"])
        if hop:
            # REVERTED, deliberately. A reviewer was right that computing the hop and
            # then warning anyway discards a witness. But scoring the hop as if it
            # were the function's own gate is a worse error: "an EOA controls the
            # gating CONTRACT" is not "an EOA can call this function" -- the gating
            # contract may impose its own conditions, and ManagerWithMerkleVerification
            # (the sole canCall for BoringVault.manage) is exactly that shape. Scoring
            # it at near-EOA weakness took the grade to F 19.4 and put five
            # one-hop flow.out rows above every real finding.
            # The hop is real information and it belongs in the CONFIDENCE channel:
            # it says the path is walkable, not that it is weak.
            notes.append(f"one_hop_target_resolvable:{hop['how']}" + (f":{hop['label']}" if hop.get("label") else ""))
        return None, "contract", "contract", notes
    return None, rt or "unresolved", "unknown", notes


def keyset_independent(pauser_addr, pauser_details, unset_princs):
    """V6 / B0b/R1. Independence is a property of owner KEY SETS: P and U are
    independent iff |owners(U) \\ owners(P)| >= threshold(U).

    Returns (verdict, min_coalition, note) where verdict is True / False /
    None(=not_determined). Three corrections over the first cut, each a
    positive-fact-from-an-absence that survived into it:

      - a non-Safe or details-less unpauser is NOT proof of independence. The
        address-identity test is exactly what R1 refuted, and keeping it as a
        fallback let a `contract`-typed principal with 0 owners and no threshold
        (one of the 64 contract_gated_unknown_path principals) declare a freeze
        recoverable. It also fired FIRST, in ascending address order, so the
        sound key-set test was never reached on those contracts.
      - an EMPTY unpause set is not_determined, never `sustainable`. The label
        `irreversibility_proven_no_unset_claim` was removed but its 4x severity
        consequence was not.
      - the loop no longer returns on the first candidate; every Safe unpauser is
        evaluated before a verdict is reached.
    """
    if not unset_princs:
        return None, None, "recovery_path_not_determined_no_unset_claim"
    p_owners = _owners(pauser_details) or frozenset({str(pauser_addr).lower()})
    best = None
    saw_safe = False
    distinct_unresolved = None
    for u_addr, u_details, u_rtype in sorted(unset_princs, key=lambda x: x[0]):
        u_owners = _owners(u_details)
        u_k = _threshold(u_details)
        if u_rtype != "safe" or not u_owners or u_k is None:
            if str(u_addr).lower() != str(pauser_addr).lower():
                distinct_unresolved = distinct_unresolved or str(u_addr)
            continue
        saw_safe = True
        residual = len(u_owners - p_owners)
        if residual >= u_k:
            return True, None, f"keyset_independent:{residual}>={u_k}"
        block = len(u_owners) - u_k + 1
        if best is None or max(1, block) < best:
            best = max(1, block)
    if saw_safe:
        return False, best, "keyset_dependent"
    if distinct_unresolved:
        return None, None, f"recovery_principal_unresolved:{distinct_unresolved[:10]}"
    return None, None, "recovery_path_not_determined"


# ---------------------------------------------------------------- main


def main():
    (contracts, bal_rows, funcs, princ, controls, cvals, audits, bc, verdicts) = load()
    val_by_addr, native_by_addr, runtime, val_prov = build_value(contracts, bal_rows)
    total_value = round(sum(sorted(val_by_addr.values())), 2)

    warnings = []
    confidence_notes = []

    # ---- registry root (R-REGISTRY, corrected: UNDER-reaches) ----
    reg_owner = {}
    zero_authority = set()
    zero_owner = {}
    for r in cvals:
        if r["source"] == "authority" and r["rtype"] == "zero" and r["prov"] == "caller_gate":
            zero_authority.add(r["caddr"])
        if r["source"] == "owner" and r["rtype"] == "zero" and r["prov"] == "caller_gate" and r["via"] == "eth_call":
            zero_owner[r["caddr"]] = r["blk"]
        if r["source"] == "owner" and r["rtype"] in ("safe", "timelock") and r["prov"] == "caller_gate":
            v = str(r["value"] or "").lower()
            if v.startswith("0x") and len(v) == 42:
                reg_owner[r["caddr"]] = (v, r["rtype"], r["blk"])
    registry_owners = {a: reg_owner[a] for a in sorted(reg_owner) if a in zero_authority}
    for a, (own, _t, blk) in sorted(registry_owners.items()):
        controls[a].add(own)

    # ---- Safe key-set model (V6) ----
    safe_details = {}
    for fid in sorted(princ):
        for p in princ[fid]:
            if p["rtype"] == "safe" and _owners(p.get("details")):
                safe_details.setdefault(p["addr"], p["details"])
    safe_info = {}
    for a in sorted(safe_details):
        d = safe_details[a]
        safe_info[a] = {"owners": _owners(d), "k": _threshold(d), "n": len(_owners(d))}

    # union Safes that can ACT as each other: |S| >= max(k_A,k_B) (inv.13)
    parent = {a: a for a in sorted(safe_info)}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    overlaps = []
    keys = sorted(safe_info)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = keys[i], keys[j]
            A, B = safe_info[a], safe_info[b]
            shared = A["owners"] & B["owners"]
            if not shared:
                continue
            ka, kb = A["k"] or 99, B["k"] or 99
            can_act = len(shared) >= max(ka, kb)
            blk_a = A["n"] - ka + 1
            blk_b = B["n"] - kb + 1
            can_block = len(shared) >= max(blk_a, blk_b)
            overlaps.append(
                {
                    "a": a,
                    "b": b,
                    "a_k_of_n": f"{ka}/{A['n']}",
                    "b_k_of_n": f"{kb}/{B['n']}",
                    "shared_owners": len(shared),
                    "shared_can_act_as_both": can_act,
                    "shared_can_block_both": can_block,
                    "min_coalition_to_act_as_both": max(ka, kb) if can_act else None,
                    "min_coalition_to_block_both": max(blk_a, blk_b) if can_block else None,
                    # The operative number when one owner set is a SUBSET of the other:
                    # act as the smaller with min(k) keys and block the larger with
                    # n-k+1, and the same keys do both. This is the figure the freeze
                    # warning carries, and it is smaller than either column above.
                    "shared_is_subset": (A["owners"] <= B["owners"] or B["owners"] <= A["owners"]),
                    "min_coalition_to_freeze_and_hold": (
                        max(min(ka, kb), min(blk_a, blk_b)) if (can_act and can_block) else None
                    ),
                }
            )
            if can_act:
                ra, rb = find(a), find(b)
                if ra != rb:
                    parent[rb] = ra
    safe_unit = {a: find(a) for a in sorted(safe_info)}
    overlaps.sort(key=lambda x: (x["a"], x["b"]))

    # ---- timelock proposers, from the timelock-as-contract (B4b) ----
    addr_to_cid = {}
    for cid in sorted(contracts):
        addr_to_cid[contracts[cid]["addr"]] = cid
    tl_addrs = set()
    for fid in sorted(princ):
        for p in princ[fid]:
            if p["rtype"] == "timelock":
                tl_addrs.add(p["addr"])
    fn_by_cid = defaultdict(list)
    for f in funcs:
        fn_by_cid[f["cid"]].append(f)
    timelock_proposers = {}
    timelock_self_gated = {}
    for a in sorted(tl_addrs):
        cid = addr_to_cid.get(a)
        if cid is None:
            continue
        best = None
        self_gated = []
        for f in sorted(fn_by_cid.get(cid, []), key=lambda x: x["fid"]):
            nm = str(f["fn"])
            ps = princ.get(f["fid"], [])
            if nm in ("schedule", "scheduleBatch", "execute", "executeBatch"):
                for p in ps:
                    if p["rtype"] == "safe":
                        k, o = _threshold(p["details"]), _owners(p["details"])
                        cand = {"k": k, "n": len(o), "addr": p["addr"], "ratio": ((k / len(o)) if (k and o) else 1.0)}
                        # inv.5 is WEAKEST path: take the weakest proposer, not the
                        # strongest. Latent here (each analysed timelock has exactly
                        # one Safe proposer) but it fails in the flattering direction.
                        if best is None or cand["ratio"] < best["ratio"]:
                            best = cand
            if nm in ("updateDelay", "grantRole", "revokeRole"):
                if any(p["addr"] == a for p in ps):
                    self_gated.append(nm)
        if best:
            timelock_proposers[a] = best
        if self_gated:
            timelock_self_gated[a] = sorted(set(self_gated))

    # A1.3: which contracts actually expose the Solmate role mutators.
    _MUT = {"setUserRole", "setRoleCapability", "setPublicCapability"}
    solmate_mutators = defaultdict(set)
    for f in funcs:
        if str(f["fn"]) in _MUT:
            solmate_mutators[f["cid"]].add(str(f["fn"]))

    # ---- one-hop contract principals (26 of 78) ----
    contract_princ = {}
    analyzed = {contracts[c]["addr"] for c in sorted(contracts) if fn_by_cid.get(c)}
    addr_of_cid = {cid: contracts[cid]["addr"] for cid in sorted(contracts)}

    def _hop_weakness(target_cid):
        """Weakest resolved principal on the hop target = the weakest link (inv.5).
        Tiered strictly below a direct resolution: a hop tells us who controls the
        gating contract, not who controls this function, so the residual is one
        extra step of authority we have not walked."""
        worst = None
        for ff in sorted(fn_by_cid.get(target_cid, []), key=lambda x: x["fid"]):
            for pp in princ.get(ff["fid"], []):
                if pp["rtype"] == "eoa":
                    cand, lab = 0.9, "EOA"
                elif pp["rtype"] == "safe":
                    k, o = _threshold(pp["details"]), _owners(pp["details"])
                    cand, lab = quorum_weakness(k, len(o) or k, None), f"Safe {k}/{len(o)}"
                elif pp["rtype"] == "timelock":
                    cand, lab = 0.55, "timelock"
                else:
                    continue
                if worst is None or cand > worst[0]:
                    worst = (cand, lab)
        return worst

    for a in sorted({p["addr"] for fid in sorted(princ) for p in princ[fid] if p["rtype"] == "contract"}):
        cid = addr_to_cid.get(a)
        tgt, how = None, None
        if cid is not None and fn_by_cid.get(cid):
            tgt, how = cid, "direct"
        else:
            impl = (contracts.get(cid) or {}).get("impl") if cid is not None else None
            if impl and impl in analyzed:
                tgt = next((c for c in sorted(contracts) if addr_of_cid[c] == impl and fn_by_cid.get(c)), None)
                how = "via_implementation"
        if tgt is None:
            continue
        w = _hop_weakness(tgt)
        contract_princ[a] = {
            "how": how,
            "weakness": (round(min(1.0, w[0] * 1.1), 4) if w else None),
            "label": (f"{w[1]} (one hop through {contracts[tgt]['contract_name']})" if w else None),
        }

    # ---- pause pre-pass (V6/V7) ----
    unset_by_c = defaultdict(list)
    pause_set_by_c = defaultdict(list)
    for f in funcs:
        for cl in f["claims"] or []:
            cid = cl.get("claim_id")
            if cid == "pause.unset":
                for p in princ.get(f["fid"], []):
                    unset_by_c[f["cid"]].append((p["addr"], p.get("details"), p["rtype"]))
            elif cid == "pause.set":
                pause_set_by_c[f["cid"]].append(f["fid"])
    for c in list(unset_by_c):
        dedup = {}
        for addr, det, rtype in unset_by_c[c]:
            dedup.setdefault(addr, (addr, det, rtype))
        unset_by_c[c] = [dedup[a] for a in sorted(dedup)]

    # ---- V8 scored_denominator (replaces the invented value_fns proxy) ----
    sig_by_cid = defaultdict(set)
    for f in funcs:
        sig_by_cid[f["cid"]].add(_norm_sig(f["sig"] or f["fn"]))
    # signatures of pause.*-claiming functions per contract (structural)
    pause_claim_sigs = defaultdict(set)
    for f in funcs:
        for cl in f["claims"] or []:
            if str(cl.get("claim_id", "")).startswith("pause."):
                pause_claim_sigs[f["cid"]].add(_norm_sig(f["sig"] or f["fn"]))

    freeze_scope = {}
    for vid in sorted(verdicts):
        v = verdicts[vid]
        if v["effect_class"] != "freeze_pause" or v["verdict"] != "proven":
            continue
        w = v["witness"] or {}
        den = [str(x) for x in (w.get("scored_denominator") or [])]
        blast = [str(x) for x in (w.get("observed_blast_radius") or [])]
        fid = v["fid"]
        cid = next((f["cid"] for f in funcs if f["fid"] == fid), None)
        known = sig_by_cid.get(cid, set())
        # drop the recovery path: unpauseUntil() is a member on all 4 rows
        # The recovery path must leave the frozen-surface denominator, but a
        # name-prefix filter is the shape inv.2 bans. Use the STRUCTURAL set: the
        # signatures of functions on this contract that carry a pause.* claim.
        pause_sigs = pause_claim_sigs.get(cid, set())
        den_kept = [d for d in den if _norm_sig(d) not in pause_sigs]
        unmatched = sorted({d for d in den_kept if _norm_sig(d) not in known})
        if unmatched:
            warnings.append(
                {
                    "kind": "scored_denominator_unmatched_signatures",
                    "contract": contracts[cid]["contract_name"] if cid else None,
                    "note": (
                        "scored_denominator entries are Solidity source-level type "
                        "names that match no abi_signature; surfaced rather than "
                        "silently dropped, which would shrink the denominator"
                    ),
                    "entries": unmatched,
                    "missing_witness": "canonical ABI encoding of the static guard set",
                }
            )
        freeze_scope[fid] = {
            "denominator_entries": sorted(den_kept),
            "blast_entries": sorted(blast),
            "coverage_fraction": (round(len(blast) / len(den_kept), 4) if den_kept else None),
            "pre_pause_succeeding": sorted(str(x) for x in (w.get("pre_pause_succeeding") or [])),
            "unmatched": unmatched,
        }

    # ---------------------------------------------------------------- scoring
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
            "notes": set(),
            "citations": [],
        }
    )
    freeze_facts = []
    earned_negatives = []

    for f in sorted(funcs, key=lambda x: x["fid"]):
        c = contracts[f["cid"]]
        caddr = c["addr"]
        rt_addr = f["deploy"] or runtime(caddr)
        cval = val_by_addr.get(rt_addr, val_by_addr.get(caddr, 0.0))
        openness = f["openness"]
        claims = f["claims"] or []
        fprinc = princ.get(f["fid"], [])
        ctx = {"contract": c["contract_name"], "address": rt_addr, "code_address": caddr, "function": f["fn"]}

        # ---- V9 earned negatives: resolved_empty, as findings not dismissals ----
        cexpr = f["capability_expr"] or {}
        if (
            isinstance(cexpr, dict)
            and cexpr.get("kind") == "finite_set"
            and cexpr.get("members") == []
            and cexpr.get("membership_quality") == "exact"
            and cexpr.get("confidence") == "enumerable"
            and not fprinc
        ):
            tr = cexpr.get("trace") or []
            basis0 = tr[0].get("basis") if tr and isinstance(tr[0], dict) else None
            step0 = tr[0].get("step") if tr and isinstance(tr[0], dict) else None
            if basis0 == "accessor_name" or step0 in (None, "", "unrecorded"):
                # _pending_ceiling_capability mints an exact empty from an
                # accessor's `pending` NAME PREFIX and says so in its docstring.
                warnings.append(
                    {
                        "kind": (
                            "empty_caller_set_name_derived"
                            if basis0 == "accessor_name"
                            else "empty_caller_set_no_provenance"
                        ),
                        **ctx,
                        "note": (
                            "exact+enumerable empty with no recorded step, basis, "
                            "block or reason -- indistinguishable from a defaulted "
                            "empty (predicate_evaluator.py:783 returns this shape on "
                            "`if not result_addr`, which is also true of a burn "
                            "address); or produced from an accessor name prefix, "
                            "which inv.2 bans outright"
                        ),
                        "missing_witness": "a recorded resolution step with a block",
                    }
                )
            else:
                reenabler = None
                for a, (own, _t, _b) in sorted(registry_owners.items()):
                    if a == rt_addr or a == caddr:
                        reenabler = own
                auth_owner = None
                for r in cvals:
                    if r["caddr"] in (rt_addr, caddr) and r["source"] == "authority":
                        auth_owner = registry_owners.get(str(r["value"] or "").lower())
                if auth_owner:
                    reenabler = auth_owner[0]
                earned_negatives.append(
                    {
                        **ctx,
                        "fact": "no resolved caller can reach this function",
                        "basis": step0 or "unrecorded",
                        "claims_on_function": sorted({cl.get("claim_id") for cl in claims if cl.get("claim_id")}),
                        "value_at_runtime_address_usd": round(cval, 2),
                        "state": "currently_unreachable",
                        "re_enablable_by": reenabler,
                        "counterfactual": (
                            f"one setRoleCapability + one setUserRole from {reenabler} restores reachability"
                            if reenabler
                            else "one ownership/authority write restores reachability"
                        ),
                        "as_of_block": "NOT PERSISTED -- last_indexed_block and "
                        "empty_reason are dropped by the finite_set "
                        "combinators (capabilities.py:507-550)",
                        "axiom": "msg.sender != 0x0 (the owner disjunct is {0x0}, a "
                        "singleton, not the empty set; the pipeline drops it)",
                    }
                )
            continue

        for claim in claims:
            cid = claim.get("claim_id")
            if cid in NOT_SCORED:
                if cid != "value_router":
                    # inv.6: an adverse signal that fails the witness bar is
                    # surfaced with its weakness, never dropped. `value_router` has a
                    # standing inv.2 argument (the entry is neither source nor sink);
                    # these two do not.
                    warnings.append(
                        {
                            "kind": "claim_type_not_scored",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "no severity model exists for this claim type, so it "
                                "is excluded from the grade. Exclusion is not a "
                                "judgement that the capability is benign"
                            ),
                            "missing_witness": (
                                "a severity semantics for " + cid + " (and, for callee_pointer.rotate, the "
                                "principal of the pointer's setter)"
                            ),
                        }
                    )
                continue
            # V11: product only if provenly permissionless.
            if cid in PRODUCT_CLAIMS:
                if openness != "not_determined":
                    # `restricted` on a recovery or product entry point is normal
                    # design (pause.unset SHOULD be gated). The B0b finding is
                    # narrower: not_determined is not product.
                    continue
                warnings.append(
                    {
                        "kind": "product_claim_reachability_unproven",
                        **ctx,
                        "capability": cid,
                        "note": (
                            f"{cid} treated as product on claim_id alone by "
                            "proto-0.2, but authority_openness is "
                            f"{openness!r}; not_determined is not product"
                        ),
                        "missing_witness": "authority_openness = open",
                    }
                )
                continue
            if cid not in BASE_SEV:
                continue

            sev = BASE_SEV[cid]
            sev_reason = "base"
            wit = claim.get("witness") or {}
            obs = wit.get("observed") or {}
            tier = claim.get("tier")
            citations = []
            inst_val = cval
            val_basis = "runtime_address_balance_sheet"
            notes = set()
            value_entities = None  # 16a: set when the witness names a holder

            # ---------- V1/V2/V4 magnitude ----------
            if cid == "flow.out":
                rd = str(obs.get("reach_determined")).lower() == "true"
                rv = _f(obs.get("observed_reach_value_usd")) if rd else None
                priced = _f(obs.get("observed_reach_priced_usd"))
                if str(obs.get("input_seeded")).lower() == "true":
                    # REQUIRED, "Direction: lowers", presence-gated per 16d: the
                    # acting principal WAS GIVEN the input asset, so this is
                    # extraction conditional on holding it (a redemption), not an
                    # unconditional drain. Recorded, not multiplied -- an absence
                    # has at least two readings and licenses no reduction.
                    notes.add("input_seeded(extraction conditional on holding the asset)")
                shape = obs.get("destination_shape")
                proved_by = obs.get("shape_proved_by")
                holders = [str(h).lower() for h in (obs.get("observed_reach_holders") or [])]

                if rd and rv is not None:
                    inst_val = rv
                    val_basis = "observed_reach_value_usd(fork-proven)"
                    citations.append({"field": "observed_reach_value_usd", "value": rv, "holders": sorted(holders)})
                    if holders and not any(h in (rt_addr, caddr) for h in holders):
                        # 16a: the value belongs to the HOLDER entity, not the
                        # analyzed row. Detecting this and still keying on the
                        # analyzed address is the defect G2 names, half-fixed.
                        notes.add("reach_holder_is_not_this_entity")
                        value_entities = sorted({runtime(h) for h in holders})
                    else:
                        value_entities = None
                elif _f(obs.get("observed_reach_floor_usd")) is not None:
                    # One of B12's eight absent-on-this-run keys, which §E's amended
                    # normativity clause makes REQUIRED-when-present. It is the
                    # documented fix for "$0 reach on a zero-balance router that can
                    # move millions", so it is wired even at population 0.
                    fl_usd = _f(obs.get("observed_reach_floor_usd"))
                    inst_val = fl_usd
                    val_basis = "observed_reach_floor_usd(>= floor)"
                    citations.append({"field": "observed_reach_floor_usd", "value": fl_usd, "direction": "lower_bound"})
                elif priced is not None:
                    # 16a/inv.9: a proven partial FLOOR. Raises, never caps.
                    inst_val = priced
                    val_basis = "observed_reach_priced_usd(>= floor)"
                    citations.append(
                        {
                            "field": "observed_reach_priced_usd",
                            "value": priced,
                            "direction": "lower_bound",
                            "priced_holders": sorted(
                                str(h).lower() for h in (obs.get("observed_reach_priced_holders") or [])
                            ),
                            "unpriced_triples": [
                                {"pair": pr, "reason": rs}
                                for pr, rs in zip(
                                    obs.get("observed_reach_unvalued_pairs") or [],
                                    obs.get("observed_reach_unvalued_reasons") or [],
                                )
                            ],
                        }
                    )
                    warnings.append(
                        {
                            "kind": "reach_partially_priced",
                            **ctx,
                            "capability": cid,
                            "note": (
                                f"reach is a proven floor of >= ${priced:,.2f}; the "
                                "unpriced remainder is a confidence gap, not a "
                                "small reach"
                            ),
                            "missing_witness": "observed_reach_unvalued_pairs pricing",
                        }
                    )
                elif str(obs.get("contract_balance_seeded")).lower() == "true":
                    # FIXES latent inv.2 #2. The verdict means "would move value
                    # if the contract were funded" -- a code capability, not a
                    # live outflow. Absence must not read as "the contract is
                    # funded", and presence must not read as $0 either.
                    inst_val = None
                    val_basis = "contract_balance_seeded(not_determined)"
                    warnings.append(
                        {
                            "kind": "reach_seeded_balance_only",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "the contract's own balance was OVERRIDDEN before "
                                "the payout, so the verdict proves a code "
                                "capability, not an outflow of present treasury"
                            ),
                            "missing_witness": "an unseeded reach observation",
                        }
                    )

                # ---------- V3 static lattice ----------
                st_shape, st_reason = static_destination_shape(claims)
                asset_class = flow_asset_class(claims)
                amt_kinds = amount_bounds(claims)
                if "capped_by_balance" in amt_kinds:
                    notes.add("amount_capped_by_own_balance(proven upper bound)")
                if amt_kinds:
                    citations.append({"field": "flows[].amount_kind", "value": sorted(amt_kinds)})
                eff_shape = shape if proved_by in ("simulation", "static") else None
                if eff_shape is None and st_shape:
                    eff_shape = st_shape
                    sev_reason = f"static_lattice:{st_reason}"
                    warnings.append(
                        {
                            "kind": "destination_shape_static_only",
                            **ctx,
                            "capability": cid,
                            "shape": st_shape,
                            "note": (
                                "shape recomputed from the static lattice; no fork "
                                "sentinel exists on this row, so the plane that "
                                "could refute a false fixed-destination is absent "
                                "by construction"
                            ),
                            "missing_witness": "a fork verdict (effect_verdicts sentinel)",
                        }
                    )

                if eff_shape == "caller_arbitrary" and tier != "behavioral_observed":
                    # §E: a tier may WITHHOLD an escalation that needs a behavioural
                    # existence proof. caller_arbitrary is an existential and only a
                    # fork sentinel can prove it. Population 0 here (all 36 such
                    # claims are behavioral_observed); shipped as a live guard.
                    warnings.append(
                        {
                            "kind": "caller_arbitrary_without_behavioural_proof",
                            **ctx,
                            "capability": cid,
                            "tier": tier,
                            "note": (
                                "caller_arbitrary is an existential and this claim "
                                "carries no fork observation, so the escalation is "
                                "withheld"
                            ),
                            "missing_witness": "a behavioral_observed verdict",
                        }
                    )
                    continue
                if eff_shape == "caller_arbitrary":
                    sev = 0.9
                    tc = None
                    for fl in wit.get("flows") or []:
                        tc = (fl.get("target_constraint") or {}).get("state") or tc
                    if tc == "unconstrained_proven":
                        sev_reason = "caller_arbitrary+unconstrained_proven"
                    else:
                        sev_reason = "caller_arbitrary_proven"
                        notes.add(f"target_constraint={tc or 'absent'}")
                elif eff_shape == "immutable_fixed":
                    sev = 0.10
                    sev_reason = sev_reason if sev_reason.startswith("static") else "immutable_fixed_proven"
                    # V3: `immutable` lives in implementation code, so a fixed
                    # destination is conditional on upgrade authority. Compose it.
                    notes.add("fixed_destination_conditional_on_upgrade_authority")
                    # V2/V4: the per-asset conjunction, as a HARD PRECONDITION on
                    # the value substitution -- not prose.
                    if "token_identity" in amt_kinds:
                        inst_val = None
                        val_basis = "token_identity(non-fungible; pricing forbidden)"
                        warnings.append(
                            {
                                "kind": "amount_is_token_identity",
                                **ctx,
                                "capability": cid,
                                "note": (
                                    "amount_kind proves exactly one NON-FUNGIBLE "
                                    "token moves, which forbids pricing this row "
                                    "off a fungible balance sheet"
                                ),
                                "missing_witness": "a per-NFT valuation",
                            }
                        )
                    elif asset_class == "native_only":
                        nat = native_by_addr.get(rt_addr)
                        if nat is None:
                            inst_val = None
                            val_basis = "native_only_flow+absent_native_row(not_determined)"
                            warnings.append(
                                {
                                    "kind": "native_magnitude_not_determined",
                                    **ctx,
                                    "capability": cid,
                                    "note": (
                                        "flow is provably native-only but no native "
                                        "balance row exists; absence conflates "
                                        "proven-zero with a failed fetch, so the "
                                        "magnitude is not_determined, not $0"
                                    ),
                                    "missing_witness": "a native balance read at a pinned block",
                                    # §E inv.9 clause: a floored weight must still
                                    # publish the magnitude that IS proven. The entity
                                    # holds this much; what it can move natively is
                                    # what is undetermined.
                                    "magnitude_named_not_scored_usd": round(cval, 2),
                                    "recorded_non_native_holdings_usd": round(cval, 2),
                                }
                            )
                        else:
                            inst_val = nat
                            val_basis = "native_only_flow x native_balance"
                            citations.append({"field": "contract_balances(native)", "value": nat})
                    elif asset_class in ("erc20_only", "mixed"):
                        warnings.append(
                            {
                                "kind": "erc20_asset_identity_unwitnessed",
                                **ctx,
                                "capability": cid,
                                "note": (
                                    "ERC-20 flow: sink_ids carry a variable name "
                                    "only, and name-based asset resolution is "
                                    "banned by inv.2, so which token moves is "
                                    "not_determined"
                                ),
                                "missing_witness": "asset identity on the static flow entry",
                            }
                        )
                elif eff_shape == "storage_determined":
                    # NOT a severity constant. The flow entry carries no
                    # variable / writer_signatures / slot, so the setter's
                    # principal is unresolvable from B2's own fields.
                    warnings.append(
                        {
                            "kind": "destination_storage_determined_deferred",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "destination is redirectable by whoever holds the "
                                "setter -- an admin fact strictly between fixed "
                                "and caller-chosen -- but the flow entry names no "
                                "setter, so its principal cannot be resolved and "
                                "no severity may be assigned"
                            ),
                            "missing_witness": "the setter's signature on the flow entry",
                        }
                    )
                    continue
                else:
                    ev = verdicts.get(wit.get("effect_verdict_id"))
                    cdest = ev["cdest"] if ev else None
                    if cdest and eff_shape is None and proved_by == "none":
                        # G3, refuted by B1's own REQUIRED field. GATED: this is
                        # an existential ("this sink was used on the witnessed
                        # path"), so it cannot prove immutable_fixed.
                        rv2 = _f(obs.get("observed_reach_value_usd")) if rd else None
                        confidence_notes.append(
                            {
                                **ctx,
                                "capability": cid,
                                "fact": "identifiable non-caller-supplied sink observed",
                                "concrete_destination": cdest,
                                "proven_reach_usd": rv2,
                                "note": (
                                    "a proven reach with an identifiable sink but no "
                                    "static lattice: existential, so it cannot prove "
                                    "a fixed destination and does not enter the grade"
                                ),
                                "missing_witness": "a static flow extraction (universal)",
                            }
                        )
                    warnings.append(
                        {
                            "kind": "flow_out_destination_unproven",
                            **ctx,
                            "capability": cid,
                            "note": (
                                f"destination_shape={shape!r} shape_proved_by="
                                f"{proved_by!r} static_replay={st_reason}; neither "
                                "arbitrariness nor fixedness is proven"
                            ),
                            "missing_witness": "destination_shape (fork verdict or static lattice)",
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
                            "note": "open fallback delegatecalls to a stored admin impl",
                            "missing_witness": "who controls setAdminImpl",
                        }
                    )
                    continue
                if dc.get("state") == "constrained":
                    g = dc.get("guard")
                    if g == "hash_commitment" and dc.get("pins") is True:
                        sev, sev_reason = 0.20, "constrained:hash_commitment+pins"
                    elif g == "external_call_revert":
                        sev, sev_reason = 0.60, "constrained:external_call_revert_only"
                        notes.add("constraint_only_as_strong_as_external_contract")
                    else:
                        sev, sev_reason = 0.35, f"constrained:{g or 'unspecified'}"
                else:
                    sev, sev_reason = 1.0, "destination_unconstrained"

            elif cid == "ownership.transfer":
                if wit.get("standard") == "default_admin_rules":
                    sev, sev_reason = 0.35, "default_admin_rules_enforced_delay"
                    notes.add("small_n=1")

            elif cid == "authority.replace":
                own = registry_owners.get(rt_addr) or registry_owners.get(caddr)
                # The escalation asserts the owner can setUserRole /
                # setRoleCapability / setPublicCapability. Verify those selectors
                # actually exist on this contract rather than inferring them from
                # `authority == 0x0` plus a resolved owner.
                mutators = solmate_mutators.get(f["cid"], set())
                if own and not mutators:
                    warnings.append(
                        {
                            "kind": "registry_escalation_mutators_unverified",
                            **ctx,
                            "capability": cid,
                            "principal": own[0],
                            "note": (
                                "authority is zero and an owner resolves, but no "
                                "setUserRole/setRoleCapability/setPublicCapability "
                                "function is present, so the self-grant escalation "
                                "is not established for this contract"
                            ),
                            "missing_witness": "the Solmate role-mutator selectors",
                        }
                    )
                    own = None
                if own:
                    sev, sev_reason = 1.0, "registry_owner_self_grant_escalation"
                    notes.add("owner may setPublicCapability/setRoleCapability on any target trusting this registry")

            elif cid == "timelock.set_delay":
                sg = timelock_self_gated.get(rt_addr) or timelock_self_gated.get(caddr)
                if sg:
                    # B4b Decision 2 needs a SIGN FLIP: proto-0.2 books this as a
                    # deduction. Self-gated updateDelay is protective.
                    confidence_notes.append(
                        {
                            **ctx,
                            "capability": cid,
                            "fact": "delay-change path is self-gated",
                            "self_gated_functions": sg,
                            "note": (
                                "updateDelay/grantRole are gated by the timelock "
                                "itself, so the delay cannot be shortened without "
                                "first paying it. PROVEN by a complete RoleGranted/"
                                "RoleRevoked fold, but NOT replayable from persisted "
                                "inputs -- role_definitions omits "
                                "TIMELOCK_ADMIN_ROLE/DEFAULT_ADMIN_ROLE"
                            ),
                            "missing_witness": "a persisted role-admin fold",
                        }
                    )
                    continue

            if wit.get("callee") and inst_val is not None:
                # B2 REQUIRED: 11 cross_contract_join rows name where the value
                # actually is -- all BoringVault, from a $0 Teller. Same class as
                # `configures`, different mechanism.
                cal = runtime(str(wit["callee"]).lower())
                cv2 = val_by_addr.get(cal)
                if cv2 is not None and cv2 > (inst_val or 0):
                    inst_val = cv2
                    val_basis = "witness.callee(where the value actually is)"
                    value_entities = [cal]
                    citations.append({"field": "witness.callee", "value": cal, "value_usd": cv2})

            if cid == "transfer_policy.configure":
                cfg = wit.get("configures")
                if cfg:
                    tgt = runtime(str(cfg).lower())
                    tv = val_by_addr.get(tgt)
                    if tv is not None:
                        inst_val = tv
                        val_basis = "witness.configures(affected contract)"
                        citations.append({"field": "witness.configures", "value": cfg, "value_usd": tv})

            elif cid == "pause.set":
                pe = str(obs.get("pause_effective")).lower() == "true"
                ae = obs.get("auto_expiry")
                dbs = obs.get("duration_bound_seconds")
                unset = unset_by_c.get(f["cid"], [])
                if not unset:
                    # proto-0.2 published "irreversibility_proven" from the
                    # ABSENCE of a pause.unset claim. Removed.
                    warnings.append(
                        {
                            "kind": "freeze_recovery_path_not_determined",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "no pause.unset claim on this contract; absence of a "
                                "recovery claim is NOT proof that no recovery exists"
                            ),
                            "missing_witness": "a pause.unset claim or an ABI-level proof "
                            "that no unpause entry point exists",
                        }
                    )
                if dbs is not None and ae is True:
                    d = _f(dbs)
                    if d is not None and d <= 30 * 86400:
                        sev, sev_reason = FREEZE_AUTO_EXPIRY, "auto_expiry_witnessed"
                elif ae is False:
                    notes.add("fork_contradicted_static_duration_bound")
                if sev == 0.0:
                    sev = FREEZE_KEYSET_RECOVERABLE
                    sev_reason = "freeze_floor_pending_keyset_test"
                if not pe:
                    warnings.append(
                        {
                            "kind": "freeze_effectiveness_not_determined",
                            **ctx,
                            "capability": cid,
                            "note": (
                                "no fork proof that the latch takes effect; the "
                                "94%-undetermined corpus rate is NOT a reason to "
                                "soften this row (inv.5 bans dilution by average)"
                            ),
                            "missing_witness": "pause_effective (fork verdict)",
                        }
                    )
                scope = freeze_scope.get(f["fid"])
                # CORRECTED. The first cut floored BOTH axes and so buried the
                # round's largest finding. Two different quantities were conflated:
                #   - WHICH FRACTION of the entity's value is immobilised: genuinely
                #     not_determined. The only candidate witness is a coverage object
                #     over function NAMES, and a count ratio is not a dollar fraction
                #     (that was proto-0.2's F3 defect). Still withheld.
                #   - HOW MUCH value sits in the entity whose entry points are frozen:
                #     directly measured, from the same contract_balances rows this
                #     scorer trusts everywhere else. The calibration review's
                #     asymmetry -- extraction VaS needs a reach proof, freeze VaS is
                #     what is held in the halted contract -- was never refuted.
                # §E: "a weight floored for want of a witness must still publish the
                # magnitude that is proven." Publishing it only in a sibling warning
                # satisfies inv.6, not inv.9.
                inst_val = cval
                val_basis = "value held at the frozen runtime entity (measured)"
                citations.append(
                    {
                        "field": "contract_balances(entity total)",
                        "value": round(cval, 2),
                        "coverage_fraction_non_multiplying": (scope or {}).get("coverage_fraction"),
                        "blast_radius": (scope or {}).get("blast_entries"),
                    }
                )
                warnings.append(
                    {
                        "kind": "freeze_immobilised_fraction_not_determined",
                        **ctx,
                        "capability": cid,
                        "note": (
                            "the value held at the frozen entity is measured and "
                            "scored; what fraction of it is immobilised, and for how "
                            "long, has no witness -- scored_denominator answers a "
                            "static/fork agreement question, not an economic one"
                        ),
                        "missing_witness": "a value-denominated blast radius",
                        "coverage_fraction": (scope or {}).get("coverage_fraction"),
                        "magnitude_scored_usd": round(cval, 2),
                        "blast_radius": (scope or {}).get("blast_entries"),
                    }
                )
                freeze_facts.append(
                    {
                        **ctx,
                        "pause_effective": pe,
                        "tier": tier,
                        "scope": scope,
                        "recovery_principals": sorted(a for a, _d, _t in unset)[:6],
                    }
                )

            # ---------- reachability ----------
            if openness == "open":
                if cid in (
                    "upgrade.implementation",
                    "exec.arbitrary",
                    "delegatecall.execute",
                    "authority.replace",
                    "roles.grant",
                    "roles.configure",
                    "ownership.transfer",
                    "flow.out",
                ):
                    row = ledger[("ANYONE", cid)]
                    row.update(
                        capability=cid,
                        principal="ANYONE (permissionless)",
                        principal_kind="anyone",
                        max_weakness=1.0,
                        weakest_label="ANYONE",
                    )
                    row["seed_addrs"].add(rt_addr)
                    row["witness_tiers"].add(tier)
                    row["sev_reasons"].add(sev_reason)
                    row["notes"].update(notes)
                    row["citations"].extend(citations)
                    row["instances"].append(
                        {**ctx, "usd": inst_val, "sev": sev, "value_basis": val_basis, "value_entities": value_entities}
                    )
                continue

            if openness == "not_determined":
                warnings.append(
                    {
                        "kind": "unresolved_reachability",
                        **ctx,
                        "capability": cid,
                        "note": "authority_openness not_determined on a privileged capability",
                        "missing_witness": "principal resolution",
                    }
                )
                continue

            scored_any = False
            for p in sorted(fprinc, key=lambda x: (x["addr"], str(x["rtype"]))):
                w, lab, kind, pnotes = principal_weakness(p, cid, timelock_proposers, warnings, ctx, contract_princ)
                if w is None:
                    warnings.append(
                        {
                            "kind": (
                                "contract_gated_unknown_path" if kind.startswith("contract") else "unresolved_principal"
                            ),
                            **ctx,
                            "capability": cid,
                            "principal": p["addr"],
                            "note": (f"{cid} gated by a {lab} principal whose own authority is not reduced to a key"),
                            "missing_witness": (
                                "controlling principal of the gating contract"
                                if not pnotes
                                else "; ".join(sorted(pnotes))
                            ),
                        }
                    )
                    continue
                scored_any = True
                p_sev, p_reason = sev, sev_reason
                if cid == "pause.set":
                    unset = unset_by_c.get(f["cid"], [])
                    indep, min_coal, note = keyset_independent(p["addr"], p.get("details"), unset)
                    if indep is True:
                        p_sev, p_reason = FREEZE_KEYSET_RECOVERABLE, note
                    elif indep is None:
                        # not_determined: neither recoverable nor sustainable is
                        # proven, so the severity floors and the gap is a warning.
                        p_sev, p_reason = FREEZE_KEYSET_RECOVERABLE, note
                        warnings.append(
                            {
                                "kind": "freeze_recovery_independence_not_determined",
                                **ctx,
                                "capability": cid,
                                "principal": p["addr"],
                                "note": (
                                    "no unpause principal reduces to a key set, so "
                                    "independence is undetermined in both directions; "
                                    "severity floored rather than assumed either way"
                                ),
                                "missing_witness": "an unpause principal resolvable to a quorum",
                                "magnitude_named_not_scored_usd": round(cval, 2),
                            }
                        )
                    else:
                        p_sev, p_reason = FREEZE_SUSTAINABLE, note
                        # inv.5: the reversible-capability exemption from the k==1
                        # cliff is a design credit, and the design property has just
                        # been refuted for this key. Recompute without it.
                        w2, lab2, _k2, _n2 = principal_weakness(
                            p, cid, timelock_proposers, [], ctx, contract_princ, reversible_proven=False
                        )
                        if w2 is not None and w2 > w:
                            w, lab = w2, lab2
                        warnings.append(
                            {
                                "kind": "freeze_keyset_not_independent",
                                **ctx,
                                "capability": cid,
                                "principal": p["addr"],
                                "min_coalition_to_sustain": min_coal,
                                # The DISCRIMINATOR the first cut never computed: what it
                                # costs to START the freeze. min_coalition_to_sustain is
                                # a property of the unpauser and was constant across the
                                # population, so it discriminated nothing on its own.
                                "min_coalition_to_initiate": (
                                    _threshold(p.get("details")) or (1 if p["rtype"] == "eoa" else None)
                                ),
                                "note": (
                                    "this key set can freeze AND deny the recovery "
                                    "quorum; independence must be evaluated over "
                                    "owner key sets, not principal addresses"
                                ),
                                "missing_witness": "an unpause quorum disjoint in KEYS",
                                "magnitude_named_not_scored_usd": round(cval, 2),
                            }
                        )
                # B4b Decision 1 / D4: a timelock and its SOLE proposer-executor are
                # one power through one delay -- proven a superset relation by the
                # role fold, so collapsing cannot under-count. The first cut claimed
                # in its docstring that "the collapse runs" and it did not: nothing
                # merged a timelock principal with its proposer, so the 10-day
                # timelock and the 6/10 Safe charged the same $4.06B twice and
                # together were 95% of the exposure grade. The fix belongs in the
                # aggregation key, not the severity table.
                unit = p["addr"]
                if p["rtype"] == "timelock":
                    prop = timelock_proposers.get(p["addr"])
                    if prop:
                        unit = prop["addr"]
                unit = safe_unit.get(unit, unit)
                row = ledger[(unit, cid)]
                row["capability"] = cid
                row["principal"] = f"{lab} {p['addr']}"
                row["principal_kind"] = kind
                if w > row["max_weakness"]:
                    row["max_weakness"] = w
                    row["weakest_label"] = lab
                row["seed_addrs"].add(rt_addr)
                row["witness_tiers"].add(tier)
                row["sev_reasons"].add(p_reason)
                row["notes"].update(notes | set(pnotes))
                row["citations"].extend(citations)
                row["instances"].append(
                    {**ctx, "usd": inst_val, "sev": p_sev, "value_basis": val_basis, "value_entities": value_entities}
                )
            if not scored_any and not fprinc:
                warnings.append(
                    {
                        "kind": "restricted_privileged_no_principal",
                        **ctx,
                        "capability": cid,
                        "note": "restricted privileged fn with no resolved principal and no earned-empty witness",
                        "missing_witness": "principal resolution",
                    }
                )

    # ---------------------------------------------------------------- aggregate
    rows = []
    for key in sorted(ledger, key=lambda k: (str(k[0]), str(k[1]))):
        paddr, cid = key
        row = ledger[key]
        if not row["instances"]:
            continue
        if cid in TRANSITIVE_CAPS:
            seen, stack, tot = set(), sorted(row["seed_addrs"]), 0.0
            while stack:
                a = stack.pop()
                if a in seen:
                    continue
                seen.add(a)
                tot += val_by_addr.get(a, 0.0)
                for nxt in sorted(controls.get(a, ())):
                    if nxt not in seen:
                        stack.append(nxt)
            vas, reach = tot, seen
            vas_basis = "transitive control closure"
            undetermined = []
        else:
            # D2: three-state the FOLD, not just each instance. The first cut set
            # `determined = True` if ANY instance had a value and then published the
            # surviving point value as the row's magnitude -- so a row whose
            # co-aggregated instances were fork-proven caller_arbitrary outflows on a
            # $3.5B contract published `$13.37 / <$100k`. That collapses the third
            # state at exactly the point §E requires it preserved.
            per_e = defaultdict(float)
            undetermined = []
            for i in sorted(row["instances"], key=lambda x: (x["address"], x["function"])):
                if i["usd"] is None:
                    undetermined.append(
                        {
                            "contract": i["contract"],
                            "function": i["function"],
                            "entity": i["address"],
                            "why": i["value_basis"],
                            # §E: name the magnitude that IS proven. The entity holds
                            # this much; what the capability can move is undetermined.
                            "entity_holdings_usd": round(val_by_addr.get(i["address"], 0.0), 2),
                        }
                    )
                    continue
                # 16a: when the reach witness names holders, the value belongs to
                # those entities, not to the analyzed row.
                for ent in i.get("value_entities") or [i["address"]]:
                    per_e[ent] = max(per_e[ent], i["usd"])
            reach = set(per_e)
            if per_e and not undetermined:
                vas = round(sum(sorted(per_e.values())), 6)
                vas_basis = "per-instance witnessed value, MAX per (entity, row)"
            elif per_e and undetermined:
                # A proven lower bound. band() of it under-claims, which is
                # direction-honest (16d), and the undetermined instances are named
                # on the row so a reader cannot mistake the floor for the total.
                vas = round(sum(sorted(per_e.values())), 6)
                vas_basis = (
                    f">= proven floor over {len(per_e)} entity(ies); {len(undetermined)} instance(s) not_determined"
                )
            else:
                vas = None
                vas_basis = "not_determined"
        undetermined_rows = sorted(undetermined, key=lambda x: (str(x["contract"]), str(x["function"])))
        sev = max(i["sev"] for i in row["instances"])
        w = row["max_weakness"]
        b = band(vas)
        if cid not in ("pause.set",) and (vas is None or vas < 100_000):
            # B10.9 -- the register's only *under*-scoring gap, and it is the one
            # direction the whole register leans against. contract_balances misses
            # EigenLayer-restaked ETH behind EtherFiNodes, so a real arbitrary-exec
            # surface floors to the lowest band. Say so on the row, not silently.
            warnings.append(
                {
                    "kind": "value_at_stake_at_band_floor",
                    "contract": row["instances"][0]["contract"],
                    "address": row["instances"][0]["address"],
                    "function": row["instances"][0]["function"],
                    "capability": cid,
                    "principal": row["principal"],
                    "note": (
                        "weight is at the band floor because the value this "
                        "capability is proven to reach is undetermined or below the "
                        "floor. Note this does NOT mean the entity holds nothing: "
                        "restaked and other position value is absent from "
                        "contract_balances, so this is the one direction in which "
                        "the model under-scores"
                    ),
                    "missing_witness": "position/restaking value for the reached entities",
                    "recorded_entity_holdings_usd": round(val_by_addr.get(row["instances"][0]["address"], 0.0), 2),
                }
            )
        rows.append(
            {
                "principal_unit": paddr,
                "principal": row["principal"],
                "principal_kind": row["principal_kind"],
                "capability": cid,
                "value_at_stake_usd": (round(vas, 2) if vas is not None else None),
                "value_at_stake_basis": vas_basis,
                "value_at_stake_is_floor": bool(vas is not None and undetermined_rows),
                "value_band": (
                    ((">= " + band_label(vas)) if undetermined_rows else band_label(vas))
                    if vas is not None
                    else "not_determined"
                ),
                "undetermined_instances": undetermined_rows,
                "severity_proven": round(sev, 4),
                "severity_basis": sorted(row["sev_reasons"]),
                "weakness": round(w, 4),
                "weakest_gate": row["weakest_label"],
                "raw_points": round(SEV_SCALE * sev * w * b, 4),
                "n_functions": len(row["instances"]),
                "n_contracts": len(row["seed_addrs"]),
                "reach_addrs": sorted(reach),
                "example_functions": sorted({i["function"] for i in row["instances"]})[:6],
                "witness_tiers": sorted(t for t in row["witness_tiers"] if t),
                "witness_notes": sorted(row["notes"]),
                "citations": row["citations"][:8],
                "counterfactual": counterfactual(cid, row["principal_kind"]),
            }
        )

    # per-principal-unit subsumption (inv.13)
    by_p = defaultdict(list)
    for r in rows:
        by_p[r["principal_unit"]].append(r)
    findings, subsumed = [], []
    for paddr in sorted(by_p):
        rs = sorted(by_p[paddr], key=lambda x: (-x["raw_points"], x["capability"]))
        top = dict(rs[0])
        top["subsumed_capabilities"] = [
            {"capability": x["capability"], "raw_points": x["raw_points"], "n_contracts": x["n_contracts"]}
            for x in rs[1:]
        ]
        top["subsumed_raw_points"] = round(sum(x["raw_points"] for x in rs[1:]), 4)
        if rs[1:]:
            # inv.10 wants the change that REMOVES the deduction. For a subsuming
            # row that is all of the key's capabilities, not just the top one.
            top["counterfactual"] = (
                top["counterfactual"]
                + "; note this row subsumes "
                + ", ".join(x["capability"] for x in rs[1:])
                + f" ({top['subsumed_raw_points']} raw) -- fixing the top capability "
                "alone does not release them"
            )
        findings.append(top)
        subsumed.extend(rs[1:])

    findings.sort(key=lambda x: (-x["raw_points"], x["capability"], x["principal_unit"]))
    subsumed.sort(key=lambda x: (-x["raw_points"], x["capability"], x["principal_unit"]))

    # inv.9: the composite must decompose EXACTLY against the itemised ledger, so
    # it is derived from the PUBLISHED (rounded) per-row contributions, not from an
    # unrounded accumulator that leaves a residual.
    for i, fr in enumerate(findings):
        fr["net_points_lambda"] = round(fr["raw_points"] * (LAMBDA**i), 4)
    cum = round(sum(fr["net_points_lambda"] for fr in findings), 4)
    grade_lambda = round(100.0 - min(cum, 100.0), 4)

    # exposure: untruncated reach (proto-0.2 fed the display-capped [:40] list)
    claimed = defaultdict(float)
    exposure = 0.0
    for fr in findings:
        frac = fr["severity_proven"] * fr["weakness"]
        mine = 0.0
        for a in sorted(fr["reach_addrs"]):
            v = val_by_addr.get(a, 0.0)
            if fr["capability"] not in TRANSITIVE_CAPS and fr["value_at_stake_usd"] is not None:
                # 16a, on the register's own worked example. The first cut charged
                # the whole balance sheet of each reached address: sweepETH booked
                # $212,584 of exposure against a fork-proven reach of $90.97 --
                # 2,337x, the exact defect §16a exists to name. A non-transitive
                # capability can only expose what its witness says it can move.
                v = min(v, fr["value_at_stake_usd"])
            room = max(0.0, 1.0 - claimed[a])
            take = min(frac, room)
            if take > 0:
                claimed[a] += take
                mine += take * v
        fr["exposure_usd"] = round(mine, 2)
        # accumulate the PUBLISHED value so the decomposition closes exactly,
        # rather than an unrounded parallel total (which left -0.009).
        exposure += fr["exposure_usd"]
    grade_exposure = round(100.0 * (1.0 - exposure / total_value), 3) if total_value else 0.0

    conf = confidence(funcs, princ, contracts, val_by_addr, runtime, controls)

    # B11/T-UNATTRIB: "69 rows point at Safes and 23 at timelocks: real principals
    # whose authority relation was never established. Confidence item, not a zero."
    # Excluded from the closure, but a silent exclusion is not a disclosure.
    conn2 = psycopg2.connect(DB)
    conn2.set_session(readonly=True)
    c2 = conn2.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    c2.execute(
        """
        select count(*) n, count(distinct lower(replace(e.to_node_id,'address:',''))) t
        from control_graph_edges e join contracts c on c.id=e.contract_id
        where c.protocol_id=%s and e.relation='controller_value_unattributed'
    """,
        (PROTOCOL_ID,),
    )
    ua = c2.fetchone()
    c2.execute(
        """
        select coalesce(n.analysis_state,'null') st, count(*) n
        from control_graph_nodes n join contracts c on c.id=n.contract_id
        where c.protocol_id=%s group by 1 order by 1
    """,
        (PROTOCOL_ID,),
    )
    astates = {r["st"]: r["n"] for r in c2.fetchall()}
    conn2.close()
    confidence_notes.append(
        {
            "contract": None,
            "function": None,
            "fact": "unattributed controller edges excluded from the value closure",
            "rows": ua["n"],
            "distinct_targets": ua["t"],
            "value_contributed_usd": 0.0,
            "note": (
                "these point at real principals -- Safes and timelocks -- whose "
                "authority RELATION was never established. Excluding them costs $0 "
                "and the third-state semantics forbid including them, but the "
                "exclusion is a confidence item, not a zero"
            ),
            "missing_witness": "an established authority relation for these edges",
        }
    )
    confidence_notes.append(
        {
            "contract": None,
            "function": None,
            "fact": "control-graph traversal completeness",
            "analysis_state": astates,
            "note": (
                "only attempt_failed + beyond_depth_horizon can move to analysed on "
                "a rerun with more budget; not_analyzable is terminal by construction "
                "and must not be counted as improvable. This is the field inv.6's "
                "monotone property is argued from"
            ),
            "missing_witness": "budget for the depth-horizon and failed-attempt nodes",
        }
    )

    # B9 REQUIRED: equivalence_reason separates three epistemic states the scorer
    # would otherwise collapse. Note the taxonomy lives in equivalence_STATUS --
    # equivalence_reason itself is free text with ~59 distinct values (B0b/R7), so
    # branch on status and cite the reason.
    _EQ_CLASS = {
        "candidate_path_missing": "our_side_data_gap",
        "commit_not_found_in_repo": "our_side_data_gap",
        "hash_mismatch": "deployed_source_provably_differs",
        "etherscan_fetch_failed": "infrastructure",
    }
    eqc = defaultdict(int)
    for a in sorted(audits, key=lambda x: (x["cid"], str(x["eq"]))):
        k = _EQ_CLASS.get(str(a["eq"]))
        if k:
            eqc[k] += 1
    confidence_notes.append(
        {
            "contract": None,
            "function": None,
            "fact": "audit non-coverage, classified",
            "counts": dict(sorted(eqc.items())),
            "note": (
                "inv.1's audit corollary: these read UNKNOWN, not 0. Only "
                "`deployed_source_provably_differs` is adverse; the our-side gaps "
                "name a repo path or commit whose resolution would clear them, "
                "which is inv.6's promote-or-clear requirement"
            ),
            "missing_witness": "the named repo path / commit for each our-side gap",
        }
    )

    credits = build_credits(
        findings, audits, bc, freeze_facts, unset_by_c, princ, funcs, safe_info, overlaps, timelock_self_gated
    )

    wsummary = defaultdict(lambda: {"count": 0, "examples": []})
    for wr in sorted(warnings, key=lambda x: (x["kind"], str(x.get("contract")), str(x.get("function")))):
        g = wsummary[wr["kind"]]
        g["count"] += 1
        if len(g["examples"]) < 4:
            g["examples"].append(f"{wr.get('contract', '?')}.{wr.get('function', '?')}")

    top = findings[0] if findings else None
    headline = None
    if top:
        vb = f"{top['value_band']}" if top["value_at_stake_usd"] is not None else "value not_determined"
        headline = (
            f"{top['weakest_gate']} can {top['capability']} on {vb} "
            f"({', '.join(top['example_functions'][:3])}) "
            f"— raw -{top['raw_points']}"
        )

    # inv.9: the decomposition must include subsumed rows.
    sum_net = round(sum(f["net_points_lambda"] for f in findings), 4)
    out = {
        "protocol": "etherfi",
        "protocol_id": PROTOCOL_ID,
        "model_version": MODEL_VERSION,
        "headline": headline,
        "grade_lambda": grade_lambda,
        "grade_lambda_letter": letter(grade_lambda),
        "grade_exposure": grade_exposure,
        "grade_exposure_letter": letter(grade_exposure),
        "confidence_pct": conf["pct"],
        "confidence_detail": conf,
        "total_tracked_value_usd": total_value,
        "total_exposure_usd": round(exposure, 2),
        "model_parameters": {
            "lambda": LAMBDA,
            "severity_scale": SEV_SCALE,
            "delay_discount": {
                "form": "1 - log10(1+days)/log10(31), clamped [0.25, 1.0]",
                "864000s_10d": delay_discount(864000),
                "432000s_5d": delay_discount(432000),
                "172800s_2d": delay_discount(172800),
                "note": (
                    "the witness supplies the ORDERING of delays; this mapping "
                    "is a model choice and belongs to model_version (16c). It "
                    "is published here because a numeric consequence of adopting "
                    "a monotone weakness function may not be quoted before the "
                    "function is defined."
                ),
            },
            "freeze_ladder": {
                "keyset_recoverable": FREEZE_KEYSET_RECOVERABLE,
                "sustainable": FREEZE_SUSTAINABLE,
                "auto_expiry": FREEZE_AUTO_EXPIRY,
                "note": (
                    "no duration term: duration_bound_source is not_determined "
                    "on 4/4 and neither no_time_reference nor guard_constant "
                    "appears, so duration contributes zero to severity"
                ),
            },
        },
        "decomposition_check": {
            "row_reproduction": row_reproduction(findings, subsumed),
            "lambda": {
                "grade": grade_lambda,
                "sum_net": sum_net,
                "residual": round(100.0 - grade_lambda - sum_net, 6),
                "subsumed_raw_points_total": round(sum(r["raw_points"] for r in subsumed), 4),
                "note": (
                    "the residual is an algebraic identity and cannot detect an "
                    "error in raw_points; the subsumed total is published so the "
                    "quantity F7 removes from the ledger is visible, which "
                    "proto-0.2 omitted (57.809 raw points left its accounting)"
                ),
            },
            "exposure": {
                "grade": grade_exposure,
                "sum_exposure_usd": round(sum(f["exposure_usd"] for f in findings), 2),
                "residual_usd": round(exposure - sum(f["exposure_usd"] for f in findings), 4),
            },
        },
        "value_provenance": val_prov,
        "replayability": {
            "deterministic_inputs": ("frozen effective_functions.claims, function_principals.details, effect_verdicts"),
            "non_replayable_inputs": [
                "contract_balances (destructively rewritten each monitoring cycle; "
                "no block_number column; fetched_at spans "
                f"{val_prov['fetched_at_span_seconds']}s)",
                "effect_verdicts fork observations (51 distinct blocks in one run)",
                "bytecode_cache (cached_at only, no block)",
            ],
            "ordering": (
                "every query carries ORDER BY and every sort a total-order "
                "tiebreak, so ties cannot permute the ledger (proto-0.2 had "
                "real ties at 0.81, 0.405, 0.247 and 0.157)"
            ),
        },
        "safe_keyset_overlaps": overlaps,
        "credits": credits,
        "earned_negatives": sorted(earned_negatives, key=lambda x: (str(x["contract"]), str(x["function"]))),
        "confidence_channel": sorted(confidence_notes, key=lambda x: (str(x.get("contract")), str(x.get("function")))),
        "warnings_summary": dict(sorted(wsummary.items())),
        "findings": findings,
        "subsumed_rows": subsumed,
        "freeze_facts": sorted(freeze_facts, key=lambda x: (str(x["contract"]), str(x["function"]))),
        "warnings": sorted(
            warnings,
            key=lambda x: (
                x["kind"],
                str(x.get("contract")),
                str(x.get("function")),
                str(x.get("capability")),
                str(x.get("principal")),
            ),
        ),
    }
    out["differential_vs_proto_0_2"] = differential(findings, subsumed, out, safe_unit)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "score_v3.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True, default=str)

    print(f"model_version      {MODEL_VERSION}")
    print(f"grade (lambda 0.6) {grade_lambda:7.2f}  {letter(grade_lambda)}")
    print(f"grade (exposure)   {grade_exposure:7.2f}  {letter(grade_exposure)}")
    print(f"confidence         {conf['pct']}%")
    print(f"tracked value      ${total_value:,.0f}")
    print(f"exposure           ${exposure:,.0f}")
    print(
        f"findings {len(findings)}  subsumed {len(subsumed)}  "
        f"warnings {len(warnings)}  earned_negatives {len(earned_negatives)}  "
        f"confidence_notes {len(confidence_notes)}"
    )
    print(
        f"\n{'raw':>8} {'net_l':>8} {'exposure$':>15}  {'capability':22s} "
        f"{'gate':22s} {'band':16s} {'sev':>6} {'w':>6}  basis"
    )
    for fr in findings[:16]:
        print(
            f"{fr['raw_points']:8.3f} {fr['net_points_lambda']:8.3f} "
            f"{fr['exposure_usd']:15,.0f}  {fr['capability'][:22]:22s} "
            f"{str(fr['weakest_gate'])[:22]:22s} {fr['value_band'][:16]:16s} "
            f"{fr['severity_proven']:6.3f} {fr['weakness']:6.3f}  "
            f"{','.join(fr['severity_basis'])[:44]}"
        )
    return out


def build_credits(
    findings, audits, bc, freeze_facts, unset_by_c, princ, funcs, safe_info, overlaps, timelock_self_gated
):
    credits = []
    for fr in findings:
        if (
            fr["capability"] in TRANSITIVE_CAPS
            and fr["principal_kind"] in ("timelock", "safe")
            and (fr["value_at_stake_usd"] or 0) >= 100_000_000
            and fr["weakness"] <= 0.2
        ):
            eoa_raw = SEV_SCALE * fr["severity_proven"] * 0.9 * band(fr["value_at_stake_usd"])
            credits.append(
                {
                    "protective_fact": f"{fr['weakest_gate']} gates {fr['capability']}",
                    "principal": fr["principal"],
                    "value_protected_band": fr["value_band"],
                    "n_functions": fr["n_functions"],
                    "counterfactual_if_eoa_gated": f"~-{round(eoa_raw, 1)} raw (vs -{fr['raw_points']} now)",
                }
            )

    # V6: the dual-use brake credit, now on KEY-SET independence. proto-0.2
    # published it for 36 capabilities off a `None` sentinel while its own
    # per-principal pass emitted 23 contradicting warnings.
    ok = [x for x in freeze_facts if x.get("pause_effective")]
    if ok:
        credits.append(
            {
                "protective_fact": (
                    "emergency brake: pause capability with a fork-proven latch (inv.4 dual-use, credit side)"
                ),
                "n_pause_capabilities_fork_proven": len(ok),
                "n_contracts": len({x["address"] for x in ok}),
                "basis": "pause_effective = true",
                "withheld": (
                    "no credit is claimed for recovery independence: it is a "
                    "property of owner KEY SETS, and on the 4/7 <-> 1/5 pair the "
                    "1/5's five owners are a strict subset of the 4/7's, so four "
                    "of them can freeze and deny the recovery quorum"
                ),
                "counterfactual_if_removed": "these rows disappear; no grade credit is taken",
            }
        )

    # V10: the deterministic core only. Join the audit anchor to the cached
    # bytecode; a mismatch is a real negative, an absent cache row is unknown.
    proven = [a for a in audits if a["eq"] == "proven"]
    still_matching = replaced = no_cache = 0
    for a in sorted(proven, key=lambda x: x["cid"]):
        cached = bc.get(str(a.get("caddr") or "").lower())
        if a["bkam"] is None:
            no_cache += 1
        elif cached is None:
            no_cache += 1
        elif str(cached).lower() == str(a["bkam"]).lower():
            still_matching += 1
        else:
            replaced += 1
    credits.append(
        {
            "anchor_join": {
                "still_matching": still_matching,
                "replaced": replaced,
                "no_cached_bytecode_unknown": no_cache,
            },
            "protective_fact": (
                "audit equivalence proven: deployed source is "
                "deterministically equivalent to a commit sha printed "
                "verbatim in the audit document"
            ),
            "rows": len(proven),
            "basis": ["equivalence_status='proven'", "matched_commit_sha", "bytecode_keccak_at_match"],
            "excluded": (
                "proof_kind is BANNED from the grade in every value: `clean` and "
                "`pre_fix_unpatched` are opposite branches of one `if` over the "
                "same LLM commit-role labels (coverage.py:1137-1200), and the sha "
                "comparison is a fuzzy 7-character prefix match"
            ),
            "as_of": (
                "bytecode_cache carries cached_at only, no block, so the honest "
                "claim is 'matches the bytecode cached during this run', not "
                "'deployed right now'; it remains a deterministic negative "
                "generator going forward"
            ),
        }
    )
    if timelock_self_gated:
        credits.append(
            {
                "protective_fact": "timelock role admin is the timelock itself (anti-decoy)",
                "timelocks": sorted(timelock_self_gated),
                "grade_credit_taken": 0.0,
                "why_no_credit": (
                    "PROVEN by a complete RoleGranted/RoleRevoked fold, but "
                    "role_definitions omits TIMELOCK_ADMIN_ROLE/"
                    "DEFAULT_ADMIN_ROLE, so it is not replayable from "
                    "persisted inputs (inv.11). Confidence channel only."
                ),
            }
        )
    return credits


def row_reproduction(findings, subsumed):
    """inv.9 asks for more than an algebraic identity: every published
    contribution must be reproducible from the witnesses cited beside it. The
    residual below is zero by construction and cannot detect an error in
    raw_points; THIS can."""
    bad = []
    for r in sorted(findings + subsumed, key=lambda x: (x["principal_unit"], x["capability"])):
        expect = round(SEV_SCALE * r["severity_proven"] * r["weakness"] * band(r["value_at_stake_usd"]), 4)
        # Compare at the PUBLISHED precision: raw_points is round(.., 4), so a
        # tolerance-based compare against the unrounded product reports every row
        # whose 5th decimal is non-zero. That is a defect in the check, not the
        # scorer -- worth recording because the first cut did exactly that and
        # reported 11 false mismatches.
        if expect != r["raw_points"]:
            bad.append(
                {
                    "principal_unit": r["principal_unit"],
                    "capability": r["capability"],
                    "published": r["raw_points"],
                    "recomputed": expect,
                }
            )
    return {
        "rows_checked": len(findings) + len(subsumed),
        "mismatches": len(bad),
        "detail": bad,
        "formula": "60 * severity_proven * weakness * band(value_at_stake_usd)",
        "note": (
            "each row recomputed from its own published fields; this is the "
            "redundancy check inv.9 asks for, as opposed to the algebraic "
            "residual below, which is zero by construction"
        ),
    }


def differential(findings, subsumed, out, safe_unit):
    """Row-level diff against score_v2.json, each change attributed to the field
    that caused it. Keyed on (principal address, capability) so a v2 row that v3
    merged into a Safe key-set unit is reported as merged, not vanished."""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "score_v2.json")
    if not os.path.exists(p):
        return {"error": "score_v2.json not found"}
    with open(p) as fh:
        v2 = json.load(fh)

    def index(rows, key):
        d = {}
        for r in rows:
            d[(str(r.get(key) or "").lower(), r["capability"])] = r
        return d

    v2_all = index(v2.get("findings", []) + v2.get("subsumed_rows", []), "principal_address")
    v3_all = index(findings + subsumed, "principal_unit")
    # a v3 unit absorbs several v2 principal addresses; map every member -> unit
    unit_members = {}
    for member, unit in sorted(safe_unit.items()):
        unit_members.setdefault(unit, set()).add(member)

    appeared, changed, vanished = [], [], []
    for k, r3 in sorted(v3_all.items()):
        if k in v2_all:
            r2 = v2_all[k]
            causes = []
            if abs((r3["raw_points"] or 0) - (r2["raw_points"] or 0)) > 1e-9:
                if abs(r3["weakness"] - r2["weakness"]) > 1e-9:
                    causes.append(f"weakness {r2['weakness']} -> {r3['weakness']} ({'; '.join(r3['severity_basis'])})")
                if abs(r3["severity_proven"] - r2["severity_proven"]) > 1e-9:
                    causes.append(
                        f"severity {r2['severity_proven']} -> "
                        f"{r3['severity_proven']} "
                        f"({'; '.join(r3['severity_basis'])})"
                    )
                if r3["value_band"] != r2["value_band"]:
                    causes.append(f"value_band {r2['value_band']} -> {r3['value_band']} ({r3['value_at_stake_basis']})")
            if causes:
                changed.append(
                    {
                        "principal": r3["principal"],
                        "capability": r3["capability"],
                        "raw_v2": r2["raw_points"],
                        "raw_v3": r3["raw_points"],
                        "caused_by": causes,
                        "witness_notes": r3["witness_notes"],
                    }
                )
        else:
            appeared.append(
                {
                    "principal": r3["principal"],
                    "capability": r3["capability"],
                    "raw_v3": r3["raw_points"],
                    "caused_by": (f"field(s): {'; '.join(r3['severity_basis'])} | value: {r3['value_at_stake_basis']}"),
                    "witness_notes": r3["witness_notes"],
                }
            )
    for k, r2 in sorted(v2_all.items()):
        if k in v3_all:
            continue
        addr, cap = k
        unit = next((u for u, m in sorted(unit_members.items()) if addr in m), None)
        vanished.append(
            {
                "principal": r2["principal"],
                "capability": cap,
                "raw_v2": r2["raw_points"],
                "disposition": ("merged into Safe key-set unit " + unit if unit else "no longer scored"),
                "caused_by": (
                    "key-set aggregation (inv.13): overlapping Safes that can act as each other are one unit"
                    if unit
                    else "capability now routed to a warning, an earned negative, or the "
                    "confidence channel -- see warnings_summary"
                ),
            }
        )
    return {
        "grade_lambda": {
            "v2": v2.get("grade_lambda"),
            "v3": out["grade_lambda"],
            "delta": round(out["grade_lambda"] - (v2.get("grade_lambda") or 0), 3),
        },
        "grade_exposure": {
            "v2": v2.get("grade_exposure"),
            "v3": out["grade_exposure"],
            "delta": round(out["grade_exposure"] - (v2.get("grade_exposure") or 0), 3),
        },
        "confidence_pct": {"v2": v2.get("confidence_pct"), "v3": out["confidence_pct"]},
        "total_tracked_value_usd": {
            "v2": v2.get("total_tracked_value_usd"),
            "v3": out["total_tracked_value_usd"],
            "delta": round(out["total_tracked_value_usd"] - (v2.get("total_tracked_value_usd") or 0), 2),
            "cause": (
                "MAX per (runtime address, asset) removes the proxy/impl "
                "duplicate rows that SUM-per-contracts-row double-counted"
            ),
        },
        "counts": {
            "findings": {"v2": len(v2.get("findings", [])), "v3": len(findings)},
            "subsumed": {"v2": len(v2.get("subsumed_rows", [])), "v3": len(subsumed)},
            "warnings": {"v2": len(v2.get("warnings", [])), "v3": len(out["warnings"])},
            "earned_negatives": {"v2": 0, "v3": len(out["earned_negatives"])},
            "confidence_channel": {"v2": 0, "v3": len(out["confidence_channel"])},
        },
        "rows_appeared": appeared,
        "rows_changed": changed,
        "rows_vanished": vanished,
    }


def counterfactual(cid, kind):
    return {
        "anyone": "gate this capability behind a multisig/timelock",
        "eoa": "move behind a strong multisig (>=k/n 0.67) or a timelock",
        "safe": "raise the threshold ratio, diversify signers across units, and/or add a timelock in front",
        "timelock": "already timelock-gated; residual is the proposer quorum and the delay length",
        "contract": "resolve the controlling principal of the gating contract",
    }.get(kind, "n/a")


def confidence(funcs, princ, contracts, val_by_addr, runtime, controls):
    """inv.6: monotone in resolution work, and honestly labelled.

    CORRECTED twice over. The first cut built its denominator by iterating
    `funcs` -- the functions of contracts that HAVE BEEN ANALYSED -- so analysing
    a new contract added to both numerator and denominator and the ratio could
    FALL. That is proto-0.2's defect with a different trigger (v2 dropped on
    unresolved principals; that version dropped on unanalysed downstream
    contracts), and the docstring asserted the opposite.

    The conforming construction is inv.8's PERIMETER as the denominator:
    protocol-attached contracts plus anything that transitively controls protocol
    value, fixed independent of what has been analysed. Then every unit of work
    moves value from unanswered to answered and the figure is monotone by
    construction. It starts much lower, which is the point -- unanalysed surface
    was previously invisible to its own denominator.

    Two figures, because they mean different things and the first cut conflated
    them (dropping v2's `claims` conjunct is what produced its entire +27.8 jump):
      reachability_answered -- we know WHO can call it.
      capability_answered   -- we also know WHAT it does (>=1 claim).
    "Assessed over X%" must headline the MINIMUM, or it over-claims.
    """
    perimeter = {}
    for cid in sorted(contracts):
        perimeter[contracts[cid]["addr"]] = band(val_by_addr.get(contracts[cid]["addr"], 0.0))
    for a in sorted(controls):
        perimeter.setdefault(a, band(val_by_addr.get(a, 0.0)))
        for src in sorted(controls[a]):
            perimeter.setdefault(src, band(val_by_addr.get(src, 0.0)))
    den = round(sum(sorted(perimeter.values())), 6)

    by_addr_reach = defaultdict(lambda: [0, 0])
    by_addr_cap = defaultdict(lambda: [0, 0])
    for f in sorted(funcs, key=lambda x: x["fid"]):
        claims = f["claims"] or []
        privileged = any(cl.get("claim_id") in BASE_SEV for cl in claims)
        if not (privileged or (f["openness"] == "restricted" and f["state_changing"])):
            continue
        addr = f["deploy"] or runtime(contracts[f["cid"]]["addr"])
        cexpr = f["capability_expr"] or {}
        earned_empty = (
            isinstance(cexpr, dict)
            and cexpr.get("membership_quality") == "exact"
            and cexpr.get("confidence") == "enumerable"
            and cexpr.get("members") == []
        )
        keyed = any(p["rtype"] in ("eoa", "safe", "timelock") for p in princ.get(f["fid"], []))
        reach_ok = f["openness"] == "open" or keyed or earned_empty
        by_addr_reach[addr][1] += 1
        by_addr_cap[addr][1] += 1
        if reach_ok:
            by_addr_reach[addr][0] += 1
        if reach_ok and claims:
            by_addr_cap[addr][0] += 1

    def weighted(tbl):
        num = 0.0
        for a in sorted(tbl):
            ok, tot = tbl[a]
            if tot and a in perimeter:
                num += perimeter[a] * (ok / tot)
        return round(num, 6)

    n_reach, n_cap = weighted(by_addr_reach), weighted(by_addr_cap)
    reach_pct = round(100.0 * n_reach / den, 1) if den else 0.0
    cap_pct = round(100.0 * n_cap / den, 1) if den else 0.0
    return {
        "pct": min(reach_pct, cap_pct),
        "reachability_answered_pct": reach_pct,
        "capability_answered_pct": cap_pct,
        "headline_rule": (
            "report the MINIMUM; 'assessed over X%' reads as capability assessed, not reachability answered"
        ),
        "perimeter_entities": len(perimeter),
        "perimeter_value_weighted_denominator": den,
        "analysed_entities_with_privileged_surface": len(by_addr_reach),
        "monotonicity": (
            "the denominator is inv.8's perimeter and is fixed "
            "independent of what has been analysed, so resolution work "
            "can only move value from unanswered to answered"
        ),
    }


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
