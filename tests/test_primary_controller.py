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
    assign_primary_controllers,
)


def _p(addr: str, ptype: str) -> dict:
    return {"address": addr, "type": ptype}


def _fn(callers: set[str], labels: set[str] | None = None) -> dict:
    """One EffectiveFunction's caller set + effect labels, the shape
    ``assign_co_controllers`` reads per contract."""
    return {"callers": set(callers), "labels": set(labels or ())}


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


def test_size_tiebreaker():
    """Same type → bigger owner wins."""
    fp = {
        "0xc1": {"0xbig", "0xsmall"},
        "0xc2": {"0xbig"},
        "0xc3": {"0xbig"},
    }
    result = assign_primary_controllers(
        [_p("0xbig", "safe"), _p("0xsmall", "safe")],
        fp,
    )
    assert sorted(result["0xbig"]) == ["0xc1", "0xc2", "0xc3"]
    assert result["0xsmall"] == []


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
