"""Unit tests for services.governance.primary_controller.

The primary-controller assignment is what determines (a) which
non-contract principals materialize MonitoredContract rows during
enrollment and (b) which group container each contract joins on the
Surface canvas. Both call sites share this module, so the tiebreakers
and the FP-based eligibility rule are tested here in isolation.
"""

from __future__ import annotations

from services.governance.primary_controller import (
    assign_co_controllers,
    assign_operand_render_groups,
    assign_primary_controllers,
)


def _p(addr: str, ptype: str) -> dict:
    return {"address": addr, "type": ptype}


def _fn(callers: set[str], labels: set[str] | None = None, *, claims: list[str] | None = None) -> dict:
    """One EffectiveFunction's caller set + effect labels (and optional Plane-1
    claim ids), the shape ``assign_co_controllers`` reads per contract."""
    fn: dict = {"callers": set(callers), "labels": set(labels or ())}
    if claims is not None:
        fn["claims"] = list(claims)
    return fn


def test_unknown_type_excluded():
    principals = [_p("0xa", "contract"), _p("0xb", "safe")]
    fp = {"0xc1": {"0xa", "0xb"}}
    result = assign_primary_controllers(principals, fp)
    assert "0xa" not in result
    assert result["0xb"] == ["0xc1"]


def test_principals_winning_zero_contracts_present_with_empty_list():
    """The dict shape must distinguish 'unknown principal' from 'known
    principal that won nothing' — Surface uses the latter to know an
    EOA principal should NOT render as a group, and enrollment uses it
    to deactivate the corresponding MonitoredContract row.
    """
    principals = [_p("0xfee", "safe"), _p("0xreal", "safe")]
    fp = {"0xc1": {"0xreal"}}
    result = assign_primary_controllers(principals, fp)
    assert result["0xreal"] == ["0xc1"]
    assert result["0xfee"] == []


def test_state_variable_destination_safe_excluded_by_fp():
    """Concrete repro of the etherfi bug.

    Two same-type Safes: ``0xcea`` is the real governance multisig
    (FP-tagged on every protocol contract); ``0xa99`` is the fee
    destination stored in ``accountantState.payoutAddress`` and has no
    FP rows. The label heuristic the spec drafted would have caught
    this, but FP membership catches it without depending on label
    naming.
    """
    cea = "0xcea8039076e35a825854c5c2f85659430b06ec96"
    a99 = "0xa9962a5bfbea6918e958dee0647e99fd7863b95a"
    contracts = [
        "0x3994741a5b29c60d0ab318de1024f9256fe959dc",
        "0x49f954c67ff235034b69b8a59fbe309a40256c8d",
        "0x86b5780b606940eb59a062aa85a07959518c0161",
        "0x05a1552c5e18f5a0bb9571b5f2d6a4765ebda32b",
        "0x5f46d540b6ed704c3c8789105f30e075aa900726",
    ]
    fp = {c: {cea} for c in contracts}
    result = assign_primary_controllers([_p(cea, "safe"), _p(a99, "safe")], fp)
    assert sorted(result[cea]) == sorted(contracts)
    assert result[a99] == []


def test_priority_tiebreaker():
    """Safe wins over Timelock when both are eligible for the same contract."""
    fp = {"0xc1": {"0xsafe", "0xtl"}}
    result = assign_primary_controllers(
        [_p("0xsafe", "safe"), _p("0xtl", "timelock")],
        fp,
    )
    assert result["0xsafe"] == ["0xc1"]
    assert result["0xtl"] == []


def test_portfolio_size_does_not_decide():
    """Same type, same authority tier → lex order decides, NOT how many other
    contracts each principal holds. The old "owns more overall" tiebreak was a
    count over whatever subset happened to be analyzed, so box identity flipped
    between runs as coverage grew (the etherfi 0x2aca-vs-timelock regression).
    Here the lex-smaller ``0xaaa`` wins the contested ``0xc1`` even though
    ``0xzzzbig`` holds three other contracts."""
    fp = {
        "0xc1": {"0xzzzbig", "0xaaa"},
        "0xc2": {"0xzzzbig"},
        "0xc3": {"0xzzzbig"},
        "0xc4": {"0xzzzbig"},
    }
    result = assign_primary_controllers(
        [_p("0xzzzbig", "safe"), _p("0xaaa", "safe")],
        fp,
    )
    assert result["0xaaa"] == ["0xc1"]
    assert sorted(result["0xzzzbig"]) == ["0xc2", "0xc3", "0xc4"]


def test_lex_address_tiebreaker():
    """All else equal, lex-smaller address wins (stable across re-runs)."""
    fp = {"0xc1": {"0xaaa", "0xbbb"}}
    result = assign_primary_controllers(
        [_p("0xaaa", "safe"), _p("0xbbb", "safe")],
        fp,
    )
    assert result["0xaaa"] == ["0xc1"]
    assert result["0xbbb"] == []


def test_address_lowercasing():
    """Mixed-case principal addresses should match against the
    lower-cased FP map keys/values, since callers normalize one side
    and not always the other.
    """
    fp = {"0xc1": {"0xabc"}}
    result = assign_primary_controllers([_p("0xABC", "safe")], fp)
    assert result["0xabc"] == ["0xc1"]


def test_self_address_in_fp_is_still_counted():
    """A principal whose own address appears in its own FP map (rare,
    e.g. a Safe calling itself via execTransaction) still counts as
    primary for that contract. The function doesn't second-guess
    self-reference; that's a Surface-layout concern handled separately.
    """
    fp = {"0xsafe": {"0xsafe"}}
    result = assign_primary_controllers([_p("0xsafe", "safe")], fp)
    assert result["0xsafe"] == ["0xsafe"]


def test_empty_inputs():
    assert assign_primary_controllers([], {}) == {}
    assert assign_primary_controllers([_p("0xa", "safe")], {}) == {"0xa": []}
    # Contracts in fp without any principal listed are silently ignored.
    assert assign_primary_controllers([], {"0xc1": {"0xa"}}) == {}


def test_output_is_sorted():
    """Sorted contract lists per principal — stable enrollment / UI ordering."""
    fp = {"0xc3": {"0xa"}, "0xc1": {"0xa"}, "0xc2": {"0xa"}}
    result = assign_primary_controllers([_p("0xa", "safe")], fp)
    assert result["0xa"] == ["0xc1", "0xc2", "0xc3"]


def test_governance_passthrough_resolves_safe_behind_timelock():
    """Safe → Timelock → governed contract.

    The ether.fi shape: the governed contract's only FP caller is an
    in-protocol Timelock, which is itself a contract (never a principal). With
    the Timelock marked as a pass-through, the Safe that controls the Timelock
    becomes the contract's primary controller.
    """
    vault, timelock, safe = "0xc1", "0xtl", "0xsafe"
    fp = {
        vault: {timelock},  # vault.onlyOwner caller resolves to the timelock
        timelock: {safe},  # timelock.execute caller resolves to the safe
    }
    result = assign_primary_controllers([_p(safe, "safe")], fp, governance_passthrough={timelock})
    # Safe owns both the vault (through the timelock) and the timelock itself.
    assert sorted(result[safe]) == sorted([vault, timelock])


def test_governance_passthrough_off_is_unchanged_one_hop():
    """Same graph, no pass-through set → the Safe is only a direct caller of
    the timelock, not the vault. Proves the traversal — not some unrelated
    change — is what restores the vault attribution, and that the default
    (``None``) preserves the original one-hop behavior.
    """
    vault, timelock, safe = "0xc1", "0xtl", "0xsafe"
    fp = {vault: {timelock}, timelock: {safe}}
    result = assign_primary_controllers([_p(safe, "safe")], fp)
    assert result[safe] == [timelock]  # vault is NOT attributed without pass-through


def test_governance_passthrough_excludes_fee_destination():
    """A fee-destination Safe with no FP row anywhere is not pulled in by the
    pass-through traversal — only FP (call-authority) edges are followed.

    This is the Monitoring-tab regression the parent PR fixed: a Safe stored in
    a state variable (``accountantState.payoutAddress``) must never be promoted
    to a governing controller. Even with governance pass-through enabled, it
    stays out because it holds no function-level authority.
    """
    vault, timelock, gov_safe, fee_safe = "0xc1", "0xtl", "0xgov", "0xfee"
    fp = {vault: {timelock}, timelock: {gov_safe}}  # fee_safe absent from every FP set
    result = assign_primary_controllers(
        [_p(gov_safe, "safe"), _p(fee_safe, "safe")],
        fp,
        governance_passthrough={timelock},
    )
    assert sorted(result[gov_safe]) == sorted([vault, timelock])
    assert result[fee_safe] == []


def test_governance_passthrough_is_cycle_and_depth_safe():
    """A cyclic FP graph through pass-through contracts terminates (visited-set
    breaks the cycle) and still resolves the reachable principal."""
    a, b, safe = "0xa", "0xb", "0xsafe"
    fp = {a: {b, safe}, b: {a}}  # a <-> b mutually reference; safe calls a
    result = assign_primary_controllers([_p(safe, "safe")], fp, governance_passthrough={a, b})
    assert sorted(result[safe]) == ["0xa", "0xb"]


def test_governance_passthrough_does_not_recurse_through_non_governance():
    """Only addresses in ``governance_passthrough`` are expanded. An in-protocol
    contract that is an FP caller but is NOT a timelock/proxy-admin stays a
    terminal — its own callers are not pulled up, so we don't over-attribute
    through ordinary operational contracts.
    """
    vault, manager, safe = "0xc1", "0xmgr", "0xsafe"
    fp = {vault: {manager}, manager: {safe}}
    # manager is NOT passed through → safe only owns manager, not vault.
    result = assign_primary_controllers([_p(safe, "safe")], fp, governance_passthrough=set())
    assert result[safe] == [manager]


# --- authority-tier ranking + veto gating ----------------------------------
#
# The contest key is (authority tier on THIS contract, principal type, lex
# address) — per-contract facts only, so assignments cannot flip as coverage
# grows. Tier evidence comes from the optional fp_function_detail map.


def test_owner_tier_beats_operational_tier_regardless_of_portfolio():
    """The Base etherfi shape: 0x183f holds transferOwnership/setAuthority on
    the shared contracts while 0x607d (lex-smaller AND holding many more
    contracts elsewhere) holds only operational rights. The owner must win the
    shared contracts; the operator keeps only what nobody governs."""
    owner, ops = "0xffff", "0x0001"  # ops is lex-smaller: tier must dominate
    shared = ["0xc1", "0xc2"]
    fp = {"0xc1": {owner, ops}, "0xc2": {owner, ops}, "0xc3": {ops}, "0xc4": {ops}, "0xc5": {ops}}
    detail = {
        "0xc1": [
            _fn({owner}, claims=["ownership.transfer", "authority.replace"]),
            _fn({ops}, claims=["pause.set"]),
        ],
        "0xc2": [
            _fn({owner}, claims=["ownership.transfer"]),
            _fn({ops}, claims=["flow.out"]),
        ],
        "0xc3": [_fn({ops}, claims=["pause.set"])],
        "0xc4": [_fn({ops}, claims=["pause.set"])],
        "0xc5": [_fn({ops}, claims=["pause.set"])],
    }
    result = assign_primary_controllers(
        [_p(owner, "safe"), _p(ops, "safe")],
        fp,
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[owner]) == shared
    assert sorted(result[ops]) == ["0xc3", "0xc4", "0xc5"]


def test_tier_beats_type_priority():
    """An EOA that provably owns the contract outranks a Safe that can only
    pause it — evidence over identity."""
    eoa, safe = "0xeoa", "0xsafe"
    fp = {"0xc1": {eoa, safe}}
    detail = {
        "0xc1": [
            _fn({eoa}, claims=["ownership.transfer"]),
            _fn({safe}, claims=["pause.set"]),
        ]
    }
    result = assign_primary_controllers(
        [_p(eoa, "eoa"), _p(safe, "safe")],
        fp,
        fp_function_detail_by_contract=detail,
    )
    assert result[eoa] == ["0xc1"]
    assert result[safe] == []


def test_mediated_governing_tier_beats_direct_operational_tier():
    """The Ethereum etherfi shape: the timelock holds upgradeTo on the vault
    (governing tier), the ops Safe holds direct pause (operational). The Safe
    driving the timelock inherits the timelock's tier on the vault and wins,
    even though the ops Safe's authority is more direct."""
    vault, tl, driver, ops = "0xc1", "0xtl", "0xdriver", "0xaops"  # ops lex-smaller
    fp = {vault: {tl, ops}, tl: {driver}}
    detail = {
        vault: [
            _fn({tl}, claims=["upgrade.implementation"]),
            _fn({ops}, claims=["pause.set"]),
        ],
        tl: [_fn({driver}, claims=["timelock.schedule", "timelock.execute"])],
    }
    result = assign_primary_controllers(
        [_p(driver, "safe"), _p(ops, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    # Driver wins the vault (inherited governing tier) AND the timelock itself
    # (timelock.schedule/execute are governing claims on the mediator), so the
    # whole governance unit lands in one group.
    assert sorted(result[driver]) == [vault, tl]
    assert result[ops] == []


def test_veto_only_caller_does_not_inherit_through_mediator():
    """The 0x055a8b-vs-0xcdd57d shape: both Safes appear as FP callers of the
    timelock, but one can only ``cancel`` (a veto) while the other holds
    schedule/execute. The veto holder must not inherit the timelock's authority
    over the contracts it governs — even when it is lex-smaller — and the
    driver becomes primary for the whole unit."""
    vault, tl = "0xc1", "0xtl"
    canceller, driver = "0xaaa", "0xbbb"  # canceller lex-smaller: gating must do the work
    fp = {vault: {tl}, tl: {canceller, driver}}
    detail = {
        vault: [_fn({tl}, claims=["upgrade.implementation"])],
        tl: [
            _fn({canceller, driver}, claims=["timelock.cancel"]),
            _fn({driver}, claims=["timelock.schedule", "timelock.execute"]),
        ],
    }
    result = assign_primary_controllers(
        [_p(canceller, "safe"), _p(driver, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[driver]) == [vault, tl]
    assert result[canceller] == []


def test_partial_claim_coverage_does_not_read_as_veto_only():
    """Review finding: the veto test must be per-function, not per-claim-union.
    A caller holding cancel PLUS a claim-less privileged function on the
    mediator is not proven veto-only — the unclaimed function's power is not
    determined, so it keeps the legacy expansion."""
    vault, tl = "0xc1", "0xtl"
    canceller, prop = "0xbbb", "0xaaa"  # prop lex-smaller irrelevant; gating is the test
    fp = {vault: {tl}, tl: {canceller, prop}}
    detail = {
        vault: [_fn({tl}, claims=["upgrade.implementation"])],
        tl: [
            _fn({canceller, prop}, claims=["timelock.cancel"]),
            _fn({prop}, {"role_management"}),  # claim-less privileged row
        ],
    }
    result = assign_primary_controllers(
        [_p(canceller, "safe"), _p(prop, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[prop]) == [vault, tl]
    assert result[canceller] == []


def test_proven_non_driver_does_not_inherit():
    """Review finding: inheritance needs a positive driving witness, not just
    'not cancel-only'. A caller whose complete claim coverage shows only
    timelock.set_delay can tune the mediator but never make it act — it must
    not inherit the mediator's governing tier."""
    vault, tl = "0xc1", "0xtl"
    delay_setter, driver = "0xaaa", "0xzzz"  # delay setter lex-smaller: gating must do the work
    fp = {vault: {tl}, tl: {delay_setter, driver}}
    detail = {
        vault: [_fn({tl}, claims=["upgrade.implementation"])],
        tl: [
            _fn({delay_setter}, claims=["timelock.set_delay"]),
            _fn({driver}, claims=["timelock.schedule", "timelock.execute"]),
        ],
    }
    result = assign_primary_controllers(
        [_p(delay_setter, "safe"), _p(driver, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[driver]) == [vault, tl]
    assert result[delay_setter] == []


def test_whitelist_callers_do_not_inherit_through_mediator():
    """Review finding: significance gating must hold one hop out. A mediator
    whose own functions are a broad unprivileged whitelist anchors no primary
    claim for its callers on the contracts it governs — otherwise the
    lex-smallest whitelist member wins the vault the mediator can upgrade."""
    vault, tl = "0xd1", "0xtl"
    bidders = {f"0xb{i}" for i in range(6)}
    fp = {vault: {tl}, tl: set(bidders)}
    detail = {
        vault: [_fn({tl}, claims=["upgrade.implementation"])],
        tl: [_fn(bidders, {"external_contract_call"})],
    }
    result = assign_primary_controllers(
        [_p(b, "safe") for b in bidders],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert all(result[b] == [] for b in bidders)


def test_delegatecall_is_governing_tier():
    """Review finding: delegatecall executes arbitrary code in the contract's
    own storage context — it must rank governs (tier 3), above a role
    granter."""
    dc, granter = "0xzzz", "0xaaa"  # delegatecall holder lex-larger: tier must decide
    fp = {"0xc1": {dc, granter}}
    detail = {
        "0xc1": [
            _fn({dc}, {"delegatecall_execution"}),
            _fn({granter}, claims=["roles.grant"]),
        ]
    }
    result = assign_primary_controllers(
        [_p(dc, "safe"), _p(granter, "safe")],
        fp,
        fp_function_detail_by_contract=detail,
    )
    assert result[dc] == ["0xc1"]
    assert result[granter] == []


def test_composite_detail_caller_tokens_still_gate():
    """Review finding: the evidence fold must accept composite
    ``<chain>::<address>`` caller tokens in the detail map — a keyspace
    mismatch silently disabling the gates would let a whitelist bidder win."""
    bidders = {f"eth::0xb{i}" for i in range(6)}
    auction = "eth::0xauction"
    fp = {auction: set(bidders)}
    detail = {auction: [_fn(bidders, {"external_contract_call"})]}
    result = assign_primary_controllers(
        [_p(b.split("::")[1], "safe") for b in bidders],
        fp,
        fp_function_detail_by_contract=detail,
    )
    assert all(v == [] for v in result.values())


def test_claimless_mediator_caller_still_inherits():
    """Veto gating needs a positive cancel-only witness. A mediator caller with
    no claim rows at all (stale data / degraded artifact) keeps the legacy
    passthrough expansion — absence of claims is not proof of veto-only."""
    vault, tl, safe = "0xc1", "0xtl", "0xsafe"
    fp = {vault: {tl}, tl: {safe}}
    detail = {vault: [_fn({tl}, claims=["upgrade.implementation"])]}  # no rows for tl's callers
    result = assign_primary_controllers(
        [_p(safe, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[safe]) == [vault, tl]


def test_broad_whitelist_callers_not_primary_eligible():
    """With the portfolio-count tiebreak gone, the lex-smallest of ~33 bidders
    sharing ``createBid`` must not win the AuctionManager's box: a caller whose
    only proven functions on a contract are insignificant (no privileged
    label/claim, wider than the gate threshold) is not primary-eligible there.
    Nobody governs the auction here, so it simply has no primary."""
    bidders = {f"0xbidder{i}" for i in range(6)}
    auction = "0xauction"
    fp = {auction: set(bidders)}
    detail = {auction: [_fn(bidders, {"external_contract_call"})]}
    result = assign_primary_controllers(
        [_p(b, "safe") for b in bidders],
        fp,
        fp_function_detail_by_contract=detail,
    )
    assert all(result[b] == [] for b in bidders)


def test_assignment_stable_as_coverage_grows():
    """Population-insensitivity, the property the old count tiebreak lacked:
    re-running with extra unrelated contracts analyzed must not change who wins
    the original contract."""
    a, b = "0xaaa", "0xbbb"
    fp_small = {"0xc1": {a, b}}
    detail = {"0xc1": [_fn({a}, claims=["ownership.transfer"]), _fn({b}, claims=["pause.set"])]}
    small = assign_primary_controllers([_p(a, "safe"), _p(b, "safe")], fp_small, fp_function_detail_by_contract=detail)
    fp_big = dict(fp_small)
    for i in range(10):  # b picks up ten more contracts as analysis progresses
        fp_big[f"0xd{i}"] = {b}
    big = assign_primary_controllers([_p(a, "safe"), _p(b, "safe")], fp_big, fp_function_detail_by_contract=detail)
    assert small[a] == ["0xc1"]
    assert big[a] == ["0xc1"], "coverage growth must never flip an existing assignment"


# --- assign_operand_render_groups ------------------------------------------
#
# Machinery contracts render with the unit they operate on: a passthrough
# timelock driven by the ops Safe but acting entirely on the core box, a
# Pauser fanning out pauseAll over one unit's contracts, an L1 bridge receiver
# feeding one sync pool. The render-group override places them with their
# operand unit; primary_for is untouched, so their controller reads as a
# co-controller row inside that box.


def _all_contracts(fp: dict) -> set:
    return set(fp.keys())


def test_mediator_render_group_follows_operand_unit():
    """Mediator driven by the ops Safe, operating contracts won by the gov
    Safe → rendered with the gov Safe's group. The gov timelock, whose driver
    won both it and its operands, needs no override."""
    tl_ops, tl_gov = "0xtlops", "0xtlgov"
    primary_for = {"0xgov": ["0xc1", "0xc2", "0xc3", tl_gov], "0xops": [tl_ops]}
    fp = {
        "0xc1": {tl_gov, tl_ops},
        "0xc2": {tl_gov, tl_ops},
        "0xc3": {tl_gov, tl_ops},
        tl_gov: {"0xgov"},
        tl_ops: {"0xops"},
    }
    result = assign_operand_render_groups(fp, _all_contracts(fp), {tl_ops, tl_gov}, primary_for)
    assert result == {tl_ops: "0xgov"}


def test_unowned_mediator_joins_operand_unit():
    """A mediator nobody primary-controls (its own callers unresolved) still
    joins the group of the unit it operates — machinery belongs with its unit
    even when its driver is unknown."""
    tl = "0xtl"
    primary_for = {"0xgov": ["0xc1", "0xc2"]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, tl: set()}
    assert assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for) == {tl: "0xgov"}


def test_render_group_noop_when_already_home():
    """A mediator whose driver also won its operand contracts (the 10d
    timelock shape) needs no override."""
    tl = "0xtl"
    primary_for = {"0xgov": ["0xc1", "0xc2", tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, tl: {"0xgov"}}
    assert assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for) == {}


def test_mediator_render_group_tie_is_split_evidence():
    """A mediator's operand contracts split evenly between two groups: no
    single home is witnessed, so it stays with its driver."""
    tl = "0xtl"
    primary_for = {"0xgov1": ["0xc1"], "0xgov2": ["0xc2"], "0xops": [tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, tl: {"0xops"}}
    assert assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for) == {}


def test_mediator_render_group_ignores_unowned_operands():
    """Operand contracts nobody won contribute no plurality evidence for a
    mediator (and with none owned at all, there is no home to move to)."""
    tl = "0xtl"
    primary_for = {"0xops": [tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, tl: {"0xops"}}
    assert assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for) == {}


def test_mediator_plurality_tolerates_stray_operands():
    """The mediator arm is plurality, not unanimity: a timelock acting mostly
    on one unit joins it even with one operand elsewhere."""
    tl = "0xtl"
    primary_for = {"0xgov": ["0xc1", "0xc2"], "0xother": ["0xc3"], "0xops": [tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, "0xc3": {tl}, tl: {"0xops"}}
    result = assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for)
    assert result == {tl: "0xgov"}


def test_ordinary_machinery_moves_only_on_unanimity():
    """The etherfi Pauser / L1-receiver shape: an ordinary contract (not a
    passthrough mediator) joins its operand group only when EVERY operand is
    owned by that one principal. One stray operand keeps it home."""
    pauser, receiver = "0xpauser", "0xreceiver"
    primary_for = {
        "0xliquid": ["0xv1", "0xv2", "0xv3"],
        "0xcore": ["0xsyncpool"],
        "0xother": ["0xstray", pauser, receiver],
    }
    fp = {
        "0xv1": {pauser},
        "0xv2": {pauser},
        "0xv3": {pauser},
        "0xsyncpool": {receiver},
        "0xstray": {receiver},  # receiver also acts outside 0xcore's unit
        pauser: {"0xother"},
        receiver: {"0xother"},
    }
    result = assign_operand_render_groups(fp, _all_contracts(fp), set(), primary_for)
    # Pauser: unanimous over 0xliquid's unit → moves. Receiver: split → stays.
    assert result == {pauser: "0xliquid"}


def test_ordinary_machinery_blocked_by_unowned_operand():
    """Unanimity requires every operand OWNED: an unowned operand is not
    evidence for any home, so the contract stays with its controller (unlike
    the mediator arm, which weighs only the proven homes)."""
    pauser = "0xpauser"
    primary_for = {"0xliquid": ["0xv1"], "0xother": [pauser]}
    fp = {"0xv1": {pauser}, "0xv2": {pauser}, pauser: {"0xother"}}  # 0xv2 unowned
    assert assign_operand_render_groups(fp, _all_contracts(fp), set(), primary_for) == {}


def test_principals_never_rehomed():
    """A Safe appearing as an FP caller is not a contract — it must never get
    a render-group entry, no matter how unanimous its 'operands' are."""
    safe = "0xsafe"
    primary_for = {safe: ["0xc1", "0xc2"]}
    fp = {"0xc1": {safe}, "0xc2": {safe}}
    # contract_keys excludes the safe: only c1/c2 are rendered contracts.
    assert assign_operand_render_groups(fp, {"0xc1", "0xc2"}, set(), primary_for) == {}


# --- assign_co_controllers -------------------------------------------------
#
# The pauser/guardian case: a Safe with real authority (pause, recover, …) on
# contracts that a bigger governance Safe wins the primary contest for. It must
# be recovered as a co-controller; a permissionless caller (createBid, shared by
# many) must not be.


def test_co_controller_privileged_label_kept_despite_losing_primary():
    """A guardian Safe that can ``pause`` a contract the big Safe primary-owns
    co-controls it: ``pause_toggle`` is a privileged label, so the wide
    caller set is irrelevant. Mirrors EtherFi 0x2aca losing 8 contracts to the
    timelock-passthrough Safe yet holding pause/recover on all of them."""
    big, guardian, contract = "0xbig", "0xguardian", "0xc1"
    primary_for = {big: [contract], guardian: []}
    detail = {contract: [_fn({big, guardian, "0xeoa"}, {"pause_toggle"})]}
    result = assign_co_controllers([_p(big, "safe"), _p(guardian, "safe")], detail, primary_for)
    assert result[guardian] == [contract]
    # The primary is never listed as co-controlling what it already owns.
    assert result[big] == []


def test_co_controller_tight_gate_kept_even_without_strong_label():
    """A sole-caller config/withdrawal gate (e.g. ``setCapacity`` / ``sweepFunds``
    the analyzer only labels ``external_contract_call``) still counts: the gate
    arm keeps it. Mirrors the ops timelock 0xcd425f44, kept with no strong
    label because every function it holds is tightly gated."""
    big, ops, contract = "0xbig", "0xops", "0xc1"
    primary_for = {big: [contract], ops: []}
    detail = {contract: [_fn({ops}, {"external_contract_call"})]}
    result = assign_co_controllers([_p(big, "safe"), _p(ops, "timelock")], detail, primary_for)
    assert result[ops] == [contract]


def test_co_controller_permissionless_caller_excluded():
    """A function shared by many callers with no privileged label is a broad
    whitelist, not governance — none of its callers co-control. Mirrors
    ``AuctionManager.createBid`` (33 bidders, ``external_contract_call``)."""
    bidders = {f"0xbidder{i}" for i in range(8)}
    contract = "0xauction"
    principals = [_p(b, "safe") for b in bidders]
    primary_for = {b: [] for b in bidders}
    detail = {contract: [_fn(bidders, {"external_contract_call"})]}
    result = assign_co_controllers(principals, detail, primary_for)
    assert all(result[b] == [] for b in bidders)


def test_co_controller_non_principal_types_ignored():
    """Only safe/timelock/eoa/proxy_admin participate; a ``contract``-typed
    caller on a significant function is not a co-controller."""
    contract = "0xc1"
    detail = {contract: [_fn({"0xinner", "0xsafe"}, {"pause_toggle"})]}
    result = assign_co_controllers([_p("0xinner", "contract"), _p("0xsafe", "safe")], detail, {"0xsafe": []})
    assert "0xinner" not in result
    assert result["0xsafe"] == [contract]


def test_co_controller_privileged_claim_upgrade_gain():
    """``upgrade.implementation`` now fires as a claim (its ``implementation_update``
    legacy label was corpus-dead), so a Safe holding an upgrade function on a
    contract it lost the primary contest for co-controls it — even with a wide
    caller set the gate arm would reject."""
    big, guardian, contract = "0xbig", "0xguardian", "0xc1"
    wide = {guardian, big} | {f"0xrando{i}" for i in range(8)}
    primary_for = {big: [contract], guardian: []}
    detail = {contract: [_fn(wide, claims=["upgrade.implementation"])]}
    result = assign_co_controllers([_p(big, "safe"), _p(guardian, "safe")], detail, primary_for)
    assert result[guardian] == [contract]
    assert result[big] == []


def test_co_controller_callee_pointer_claim_excluded():
    """``callee_pointer.rotate`` (the precise hook-pointer rotation) is excluded
    from the privileged claim set — like the legacy ``hook_update`` — so a wide
    caller set on it does not make any caller a co-controller."""
    contract = "0xc1"
    wide = {f"0xcaller{i}" for i in range(8)}
    principals = [_p(c, "safe") for c in wide]
    primary_for = {c: [] for c in wide}
    detail = {contract: [_fn(wide, claims=["callee_pointer.rotate"])]}
    result = assign_co_controllers(principals, detail, primary_for)
    assert all(result[c] == [] for c in wide)


def test_co_controller_claims_take_precedence_over_legacy_labels():
    """When a row carries claims, they are authoritative for significance and the
    legacy labels are not consulted. A ``callee_pointer.rotate`` claim on a
    function whose legacy label is the privileged ``pause_toggle`` is NOT
    significant — the excluded claim wins over the would-be-privileged label."""
    contract = "0xc1"
    wide = {f"0xcaller{i}" for i in range(8)}
    principals = [_p(c, "safe") for c in wide]
    primary_for = {c: [] for c in wide}
    detail = {contract: [_fn(wide, {"pause_toggle"}, claims=["callee_pointer.rotate"])]}
    result = assign_co_controllers(principals, detail, primary_for)
    assert all(result[c] == [] for c in wide), (
        "claims are authoritative: the excluded callee_pointer.rotate claim must "
        "not be overridden by a privileged legacy label on the same row"
    )


def test_co_controller_new_claim_families_are_privileged():
    """The claim families with no legacy label — ``safe.*``, ``timelock.*`` — now
    make their callers co-controllers (a wide-caller Safe/timelock guardian)."""
    guardian, big, c_safe, c_tl = "0xguardian", "0xbig", "0xsafecontract", "0xtlcontract"
    wide = {guardian, big} | {f"0xr{i}" for i in range(8)}
    primary_for = {big: [c_safe, c_tl], guardian: []}
    detail = {
        c_safe: [_fn(wide, claims=["safe.signer_mgmt"])],
        c_tl: [_fn(wide, claims=["timelock.schedule"])],
    }
    result = assign_co_controllers([_p(big, "safe"), _p(guardian, "safe")], detail, primary_for)
    assert sorted(result[guardian]) == [c_safe, c_tl]


def test_co_controller_empty_and_shape():
    """Empty inputs are safe, and every participating principal appears with at
    least an empty list (so a consumer can tell 'co-controls nothing' from
    'unknown principal')."""
    assert assign_co_controllers([], {}, {}) == {}
    assert assign_co_controllers([_p("0xa", "safe")], {}, {}) == {"0xa": []}
    # Address casing is normalized on both sides.
    detail = {"0xC1": [_fn({"0xAbC"}, {"role_management"})]}
    result = assign_co_controllers([_p("0xABC", "safe")], detail, {})
    assert result == {"0xabc": ["0xc1"]}
