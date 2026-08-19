"""Regression tests for the two lattice kinds added by SDG §3 A1-recall:
``token_owner`` destinations and ``balance_delta`` amounts.

Same harness as ``tests/static/test_flow_lattice.py`` — a real solc compile driving the
production ``build_effects``. Every fixture here is SYNTHETIC and minimal so the
rules are exercised on their shape alone, never on a corpus-specific pattern.

Two of these guard a pre-existing FALSE POSITIVE rather than a missing kind: a
destination read back from ``ownerOf(id)`` used to classify as ``param`` (the
caller-supplied, theft-shaped kind) because the provenance of an internal call's
return value unions the call tag with the callee's own body sources — the
mapping KEY is a forwarded parameter, and the drop-the-rest shortcut in
``_forwarded_param_sources`` picked it out of that union.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import build_claims  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402


def _compile(tmp_path: Path, source: str, name: str):
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == name)


def _out_flow(info) -> Any:
    flows = [vf for vf in info["value_flows"] if vf["direction"] == "out"]
    assert flows, f"no out-flow in {info['value_flows']}"
    return flows[0]


# ---------------------------------------------------------------------------
# ``token_owner``: the destination is the CURRENT owner of a caller-named token.
# ---------------------------------------------------------------------------

TOKEN_OWNER_SRC = """
pragma solidity ^0.8.20;

interface IERC721Like { function ownerOf(uint256 tokenId) external view returns (address); }

contract Queue {
    mapping(uint256 => address) private _owners;
    address public sink;
    uint256 public locked;

    function setSink(address s) external { sink = s; }

    // An in-contract ERC-721 owner getter: Slither models the call as an
    // InternalCall, so the destination's provenance carries the mapping and its
    // caller-supplied KEY alongside the call tag.
    function ownerOf(uint256 tokenId) public view returns (address) { return _owners[tokenId]; }

    // Entry -> internal helper -> pay the token owner.
    function claim(uint256 id) external { _pay(id); }
    function _pay(uint256 id) internal {
        address recipient = ownerOf(id);
        (bool ok,) = payable(recipient).call{value: 1 ether}("");
        require(ok);
    }

    // The byte-identical shape written INLINE at the entry. Must classify the
    // same as the helper version (nested must never be more specific).
    function claimInline(uint256 id) external {
        address recipient = ownerOf(id);
        (bool ok,) = payable(recipient).call{value: 1 ether}("");
        require(ok);
    }

    // The same lookup against a FOREIGN ERC-721 (a HighLevelCall, no callee body
    // to union in) — one rule must cover both call shapes.
    function claimExternal(address nft, uint256 id) external {
        address recipient = IERC721Like(nft).ownerOf(id);
        (bool ok,) = payable(recipient).call{value: 1 ether}("");
        require(ok);
    }

    // Batch: the helper is reached once per array element, same binding.
    function batchClaim(uint256[] calldata ids) external {
        for (uint256 i = 0; i < ids.length; ++i) { _pay(ids[i]); }
    }

    // NOT a token-owner destination: the owner is only TAINTED into a computed
    // address, so the operand is not the call's return value.
    function claimMangled(uint256 id, uint160 salt) external {
        address recipient = address(uint160(ownerOf(id)) ^ salt);
        (bool ok,) = payable(recipient).call{value: 1 ether}("");
        require(ok);
    }

    // A two-branch union: token owner on one path, a settable storage sink on
    // the other. The merge must NOT collapse onto either member.
    function claimUnion(uint256 id, bool flag) external {
        address d = flag ? ownerOf(id) : sink;
        (bool ok,) = payable(d).call{value: 1 ether}("");
        require(ok);
    }

    // A NON-standard getter over the same mapping. Its return value has the
    // identical provenance shape as ownerOf's, so it is the general case of the
    // same trap: nothing here is caller-chosen, but the mapping key is a
    // forwarded parameter. Unrecognized callee -> no kind, never ``param``.
    function beneficiaryOf(uint256 tokenId) public view returns (address) { return _owners[tokenId]; }
    function claimUnknownGetter(uint256 id) external { _payUnknown(id); }
    function _payUnknown(uint256 id) internal {
        address recipient = beneficiaryOf(id);
        (bool ok,) = payable(recipient).call{value: 1 ether}("");
        require(ok);
    }

    receive() external payable {}
}
"""


def test_token_owner_destination_is_not_a_caller_supplied_param(tmp_path):
    """The load-bearing one. ``ownerOf(id)`` unions {view_call, state_variable,
    parameter} — the parameter being the mapping KEY. Picking ``param`` out of
    that union is the canonical forbidden failure and reports a token-owner
    payout as a caller-chosen destination."""
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    effects = build_effects(contract)
    target = _out_flow(effects["functions"]["claim(uint256)"])["target_kind"]
    assert target["kind"] != "param", target
    assert target == {"kind": "token_owner", "tier": "static_trace"}, target


def test_token_owner_external_erc721_lookup(tmp_path):
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    effects = build_effects(contract)
    target = _out_flow(effects["functions"]["claimExternal(address,uint256)"])["target_kind"]
    assert target == {"kind": "token_owner", "tier": "static_trace"}, target


def test_token_owner_nested_matches_inline_entry(tmp_path):
    """Entry-vs-nested parity: the helper hop must not make the classification
    MORE specific than the identical operand shape written at the entry."""
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    fns = build_effects(contract)["functions"]
    assert _out_flow(fns["claim(uint256)"])["target_kind"] == _out_flow(fns["claimInline(uint256)"])["target_kind"]


def test_token_owner_batch_matches_single(tmp_path):
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    fns = build_effects(contract)["functions"]
    assert _out_flow(fns["batchClaim(uint256[])"])["target_kind"] == {"kind": "token_owner", "tier": "static_trace"}


def test_token_owner_taint_is_not_a_token_owner_destination(tmp_path):
    """``ownerOf(id) ^ salt`` is caller-influenced arithmetic, not the owner. The
    classification is a POSITIVE def-chain test precisely so a merely-tainted
    value cannot borrow the kind."""
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    effects = build_effects(contract)
    target = _out_flow(effects["functions"]["claimMangled(uint256,uint160)"])["target_kind"]
    assert target["kind"] == "indeterminate", target


def test_unrecognized_getter_result_is_not_a_caller_supplied_param(tmp_path):
    """The general case of the same trap: ANY call return value unions the call
    tag with the callee's body sources, so a mapping read keyed by a forwarded
    parameter looks like ``param``. Only the ERC-721 selector earns a name; every
    other callee must fall to indeterminate rather than to the key's kind."""
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    effects = build_effects(contract)
    target = _out_flow(effects["functions"]["claimUnknownGetter(uint256)"])["target_kind"]
    assert target["kind"] != "param", target
    assert target["kind"] == "indeterminate", target


def test_token_owner_union_with_storage_stays_indeterminate(tmp_path):
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    effects = build_effects(contract)
    target = _out_flow(effects["functions"]["claimUnion(uint256,bool)"])["target_kind"]
    assert target["kind"] == "indeterminate", target


def test_token_owner_reaches_the_claims_witness(tmp_path):
    """The kind must survive the fact -> matcher -> claim projection, since the
    frontend renders it from the witness."""
    contract = _compile(tmp_path, TOKEN_OWNER_SRC, "Queue")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]
    out = [c for c in claims["claim(uint256)"] if c["claim_id"] == "flow.out"]
    assert out, claims["claim(uint256)"]
    kinds = [f.get("target_kind") for f in out[0]["witness"]["flows"]]
    assert {"kind": "token_owner", "tier": "static_trace"} in kinds, kinds


# ---------------------------------------------------------------------------
# Struct-member destinations: caller-supplied struct vs. stored request row.
# ---------------------------------------------------------------------------

STRUCT_DEST_SRC = """
pragma solidity ^0.8.20;

contract Requests {
    struct Request { address user; uint128 amount; }

    mapping(uint256 => Request) private _rows;

    // The caller hands the whole struct in calldata: the destination IS the
    // caller's to choose.
    function claim(Request calldata r) external { _pay(r); }
    function _pay(Request calldata r) internal {
        (bool ok,) = payable(r.user).call{value: r.amount}("");
        require(ok);
    }

    function batchClaim(Request[] calldata rs) external {
        for (uint256 i = 0; i < rs.length; ++i) { _pay(rs[i]); }
    }

    // The row is loaded from STORAGE keyed by a parameter. The caller picks the
    // id, but an earlier transaction wrote the payee — not caller-chosen.
    function claimStored(uint256 id) external { _payStored(id); }
    function _payStored(uint256 id) internal {
        Request storage r = _rows[id];
        (bool ok,) = payable(r.user).call{value: r.amount}("");
        require(ok);
    }

    receive() external payable {}
}
"""


def test_calldata_struct_array_element_destination_is_param(tmp_path):
    """The array-of-struct element shape. The single-struct twin lives in
    ``test_flow_interproc.py::test_calldata_struct_member_destination_is_param``,
    which also pins the tier and entry-vs-nested parity."""
    contract = _compile(tmp_path, STRUCT_DEST_SRC, "Requests")
    fns = build_effects(contract)["functions"]
    assert _out_flow(fns["batchClaim(Requests.Request[])"])["target_kind"]["kind"] == "param"


def test_stored_request_row_destination_is_not_param(tmp_path):
    """A stored row's payee was fixed by an earlier transaction. Classifying it
    ``param`` because the caller picked the KEY would read as caller-chosen
    extraction."""
    contract = _compile(tmp_path, STRUCT_DEST_SRC, "Requests")
    target = _out_flow(build_effects(contract)["functions"]["claimStored(uint256)"])["target_kind"]
    assert target["kind"] != "param", target
    assert target["kind"] in ("storage_no_setter", "storage_setter", "indeterminate"), target


# ---------------------------------------------------------------------------
# ``balance_delta`` amounts.
# ---------------------------------------------------------------------------

BALANCE_DELTA_SRC = """
pragma solidity ^0.8.20;

interface ILP { function withdraw(uint256 amt) external; }

contract Sweeper {
    ILP public immutable lp;
    address public sink;
    uint256 public locked;

    constructor(ILP l) { lp = l; }
    function setSink(address s) external { sink = s; }

    // balance_after - balance_before across an external call.
    function sweepDelta(address to, uint256 amt) external {
        uint256 before = address(this).balance;
        lp.withdraw(amt);
        uint256 got = address(this).balance - before;
        (bool ok,) = payable(to).call{value: got}("");
        require(ok);
    }

    // The stranded-ETH shape: balance minus a storage-tracked reservation. Used
    // to classify as ``bounded_by_storage`` — the storage operand won alone
    // because the balance read is only a ``computed`` tag.
    function sweepStranded() external {
        if (address(this).balance > locked) {
            uint256 stranded = address(this).balance - locked;
            (bool ok,) = payable(sink).call{value: stranded}("");
            require(ok);
        }
    }

    // A BARE balance read really can drain everything -> still whole_balance.
    function drain(address to) external {
        (bool ok,) = payable(to).call{value: address(this).balance}("");
        require(ok);
    }

    // Non-subtractive balance arithmetic is not a delta and must not borrow the
    // name.
    function half(address to) external {
        (bool ok,) = payable(to).call{value: address(this).balance / 2}("");
        require(ok);
    }

    // A plain storage-bounded amount keeps its own kind.
    function payLocked(address to) external {
        (bool ok,) = payable(to).call{value: locked}("");
        require(ok);
    }

    receive() external payable {}
}
"""


def test_balance_delta_across_external_call(tmp_path):
    contract = _compile(tmp_path, BALANCE_DELTA_SRC, "Sweeper")
    amount = _out_flow(build_effects(contract)["functions"]["sweepDelta(address,uint256)"])["amount_kind"]
    assert amount == {"kind": "balance_delta", "tier": "static_trace"}, amount


def test_balance_minus_storage_is_a_delta_not_storage_bounded(tmp_path):
    """``balance - locked`` tracks the BALANCE; crediting the storage value with
    bounding it understates how much can leave."""
    contract = _compile(tmp_path, BALANCE_DELTA_SRC, "Sweeper")
    amount = _out_flow(build_effects(contract)["functions"]["sweepStranded()"])["amount_kind"]
    assert amount["kind"] != "bounded_by_storage", amount
    assert amount == {"kind": "balance_delta", "tier": "static_trace"}, amount


def test_non_subtractive_balance_arithmetic_is_not_a_delta(tmp_path):
    """``balance / 2`` is balance-derived but not a delta. It also must not report
    the DIVISOR's kind: the constant is the only non-``computed`` source, so
    before the balance-derivation guard it won alone and the amount read as
    ``fixed_constant``."""
    contract = _compile(tmp_path, BALANCE_DELTA_SRC, "Sweeper")
    amount = _out_flow(build_effects(contract)["functions"]["half(address)"])["amount_kind"]
    assert amount["kind"] not in ("balance_delta", "fixed_constant"), amount
    assert amount["kind"] == "indeterminate", amount


def test_plain_storage_amount_unaffected(tmp_path):
    contract = _compile(tmp_path, BALANCE_DELTA_SRC, "Sweeper")
    amount = _out_flow(build_effects(contract)["functions"]["payLocked(address)"])["amount_kind"]
    assert amount["kind"] == "bounded_by_storage", amount


def test_balance_delta_reaches_the_claims_witness(tmp_path):
    contract = _compile(tmp_path, BALANCE_DELTA_SRC, "Sweeper")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]
    out = [c for c in claims["sweepStranded()"] if c["claim_id"] == "flow.out"]
    assert out, claims["sweepStranded()"]
    kinds = [f.get("amount_kind") for f in out[0]["witness"]["flows"]]
    assert {"kind": "balance_delta", "tier": "static_trace"} in kinds, kinds


def test_param_index_reaches_the_claims_witness(tmp_path):
    # A caller-supplied destination address resolves to calldata slot 0; that index
    # is now projected into the flow.out witness alongside its ``target_kind``.
    contract = _compile(tmp_path, BALANCE_DELTA_SRC, "Sweeper")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]
    out = [c for c in claims["half(address)"] if c["claim_id"] == "flow.out"]
    assert out, claims["half(address)"]
    indexes = [f.get("target_param_index") for f in out[0]["witness"]["flows"]]
    assert 0 in indexes, out[0]["witness"]["flows"]


# ---------------------------------------------------------------------------
# Helper RETURN values: the lattice threads arguments INTO a helper, so this is
# the way back out. A getter-read destination and a computed amount are facts the
# contract states plainly, and both used to publish "we traced nothing".
# ---------------------------------------------------------------------------

HELPER_RETURN_SRC = """
pragma solidity ^0.8.20;

contract Returns {
    mapping(uint256 => address) private _owners;
    address public immutable treasury;
    address public governor;
    uint256 public cap;
    bool public flag;

    constructor(address t) { treasury = t; governor = msg.sender; }
    function setGovernor(address g) external { governor = g; }

    function _governor() internal view returns (address) { return governor; }
    function _treasury() internal view returns (address) { return treasury; }
    function _claimable() internal view returns (uint256) { return cap; }
    function _indirect() internal view returns (address) { return _governor(); }
    function _echo(address a) internal pure returns (address) { return a; }
    function _either() internal view returns (address) {
        if (flag) return governor;
        return treasury;
    }
    // A keyed lookup: the BASE has no setter, but the caller picks the entry.
    function _beneficiary(uint256 id) internal view returns (address) { return _owners[id]; }

    function payGovernor(uint256 a) external { _send(_governor(), a); }
    function payTreasury(uint256 a) external { _send(_treasury(), a); }
    function payIndirect(uint256 a) external { _send(_indirect(), a); }
    function payEcho(address to, uint256 a) external { _send(_echo(to), a); }
    function payEither(uint256 a) external { _send(_either(), a); }
    function payBeneficiary(uint256 id, uint256 a) external { _send(_beneficiary(id), a); }
    function drainToCap(address to) external { _send(to, _claimable()); }

    function _send(address to, uint256 amount) internal {
        (bool ok,) = payable(to).call{value: amount}("");
        require(ok);
    }
    receive() external payable {}
}
"""


@pytest.fixture(scope="module")
def _returns(tmp_path_factory):
    contract = _compile(tmp_path_factory.mktemp("returns"), HELPER_RETURN_SRC, "Returns")
    return build_effects(contract)["functions"]


def test_a_getter_helper_return_resolves_to_the_variables_mutability(_returns):
    """``_send(_governor(), amount)``. The destination is an admin-settable state
    variable — the redirectable-vs-fixed distinction a scorer reads — and saying
    ``indeterminate`` claimed the contract had not told us."""
    assert _out_flow(_returns["payGovernor(uint256)"])["target_kind"]["kind"] == "storage_setter"


def test_an_immutable_helper_return_resolves_to_immutable(_returns):
    """The benign end of the same axis, through the same edge."""
    assert _out_flow(_returns["payTreasury(uint256)"])["target_kind"]["kind"] == "immutable"


def test_a_helper_returning_a_helper_resolves_through_both_hops(_returns):
    assert _out_flow(_returns["payIndirect(uint256)"])["target_kind"]["kind"] == "storage_setter"


def test_a_helper_returning_its_argument_resolves_to_the_caller_value(_returns):
    """Not a leak — a finding. The helper hands back what the caller passed, so
    the destination really is caller-named, and that is the theft-shaped case."""
    assert _out_flow(_returns["payEcho(address,uint256)"])["target_kind"]["kind"] == "param"


def test_a_calculating_helper_return_resolves_the_amount(_returns):
    assert _out_flow(_returns["drainToCap(address)"])["amount_kind"]["kind"] == "bounded_by_storage"


def test_a_helper_whose_returns_disagree_stays_indeterminate(_returns):
    """``if (flag) return governor; return treasury;`` — the answer genuinely
    depends on state, and picking either member asserts what the code does not."""
    assert _out_flow(_returns["payEither(uint256)"])["target_kind"]["kind"] == "indeterminate"


def test_a_keyed_lookup_return_is_never_published_as_fixed(_returns):
    """The safety case, and the reason element reads are refused outright.

    ``_owners`` has no setter function, so the element rule would classify the
    BASE as ``storage_no_setter`` — i.e. provably FIXED, the benign end of the
    axis, which §4.2 promotes to ``immutable_fixed`` on the verdict. The caller
    picks the key, and a different key is a different address. Resolving this at
    all is the worst over-claim available here."""
    target = _out_flow(_returns["payBeneficiary(uint256,uint256)"])["target_kind"]
    assert target["kind"] == "indeterminate", target


# ---------------------------------------------------------------------------
# `caller_supplied`: a merge is only caller-chosen if EVERY branch is, and a
# nested formal is only caller-chosen if the caller bound it to something that is.
# ---------------------------------------------------------------------------

MERGE_SRC = """
pragma solidity ^0.8.20;

contract Merge {
    uint256 public feeAmount;   // storage: NOT caller-chosen
    address public sink;
    bool public cond;

    // Genuine: the merge is between an ENTRY parameter and msg.value, both of
    // which the caller picks outright.
    function payEntry(uint256 amt) external payable {
        if (cond) { amt = msg.value; }
        _send(sink, amt);
    }

    // The trap: the entry forwards a STATE VARIABLE, and the merge happens one
    // frame down where the formal LOOKS like a parameter.
    function payForwardedStorage() external payable { _helper(feeAmount); }

    function _helper(uint256 amt) internal {
        if (cond) { amt = msg.value; }
        _send(sink, amt);
    }

    function _send(address to, uint256 a) internal {
        (bool ok,) = payable(to).call{value: a}("");
        require(ok);
    }
    receive() external payable {}
}
"""


@pytest.fixture(scope="module")
def _merge(tmp_path_factory):
    contract = _compile(tmp_path_factory.mktemp("merge"), MERGE_SRC, "Merge")
    return build_effects(contract)["functions"]


def test_a_merge_of_entry_param_and_msg_value_is_caller_supplied(_merge):
    """Both branches are the caller's number, so the disjunction says something
    an amount kind can assert — and it is stronger than ``indeterminate``."""
    assert _out_flow(_merge["payEntry(uint256)"])["amount_kind"]["kind"] == "caller_supplied"


def test_a_merge_reached_through_a_forwarded_state_variable_is_not(_merge):
    """The formal in ``_helper`` is a parameter of that UNIT, but the caller bound
    it to storage. Reading it as self-evidently caller-supplied asserts that the
    caller picks the magnitude on a branch where the magnitude is a state
    variable they cannot influence — an over-claim in the direction that matters,
    since a consumer reads ``caller_supplied`` as attacker-chosen."""
    flow = _out_flow(_merge["payForwardedStorage()"])
    assert flow["amount_kind"]["kind"] == "indeterminate", flow


# ---------------------------------------------------------------------------
# The token-first recognizer's limits. It reads `to`/`amount` off the CALL SITE
# without proving the callee forwards them, so where it may fire is the whole of
# its soundness argument.
# ---------------------------------------------------------------------------

RECOGNIZER_SRC = """
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address,uint256) external returns (bool); }

library SafeTransferLib {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        (bool ok, bytes memory d) = address(token).call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(ok && (d.length == 0 || abi.decode(d,(bool))), "FAIL");
    }
}

contract Recognizer {
    address public owner;
    address public immutable treasury;
    mapping(address => address) public payoutOverride;
    mapping(bytes32 => bytes) public queued;

    constructor(address t) { owner = msg.sender; treasury = t; }

    // Anyone may repoint their own payout.
    function setPayoutOverride(address dest) external { payoutOverride[msg.sender] = dest; }

    // The call site says `treasury`; the helper says otherwise.
    function sweep(IERC20 token, uint256 amount) external {
        _settle(token, treasury, amount);
    }
    function _settle(IERC20 token, address to, uint256 amount) internal {
        address dest = payoutOverride[to];
        if (dest == address(0)) dest = to;
        SafeTransferLib.safeTransfer(token, dest, amount);
    }

    // The dual-asset payout helper: ETH on one branch, ERC-20 on the other.
    function claim(IERC20 t, address to, uint256 amount) external { _payout(t, to, amount); }
    function _payout(IERC20 t, address to, uint256 amount) internal {
        if (address(t) == address(0)) { (bool ok,) = to.call{value: amount}(""); require(ok); }
        else { SafeTransferLib.safeTransfer(t, to, amount); }
    }

    // Mentions the selector to REFUSE it, and moves nothing.
    function enqueue(bytes4 sel, address to, uint256 amount) external { _check(sel, to, amount); }
    function _check(bytes4 sel, address to, uint256 amount) internal {
        require(sel != IERC20.transfer.selector, "blocked");
        queued[keccak256(abi.encode(to, amount))] = abi.encode(to, amount);
    }

    receive() external payable {}
}
"""


@pytest.fixture(scope="module")
def _recognizer(tmp_path_factory):
    contract = _compile(tmp_path_factory.mktemp("recog"), RECOGNIZER_SRC, "Recognizer")
    return build_effects(contract)["functions"]


def test_an_internal_helper_that_redirects_is_not_read_off_the_call_site(_recognizer):
    """`_settle(token, treasury, amount)` looks like a token-first transfer, but
    the helper repoints the destination through a permissionless mapping. Reading
    the call site published `immutable` at `dispositive_ast`, which §4.2 promotes
    to a PROVABLY-unredirectable destination — for a payout anyone can capture."""
    target = _out_flow(_recognizer["sweep(IERC20,uint256)"])["target_kind"]
    assert target["kind"] == "indeterminate", target


def test_descending_into_a_recognized_helper_keeps_its_other_moves(_recognizer):
    """The recognizer matching one move in a helper must not delete the rest of
    that helper's body. The ETH branch here is a real payout, and losing it also
    flipped `has_native_payout`, silently disabling the prober's
    contract-balance seeding for a function that provably sends ETH."""
    flows = _recognizer["claim(IERC20,address,uint256)"]["value_flows"]
    kinds = {f["kind"] for f in flows}
    assert "low_level_value_call" in kinds, flows
    assert "callee_erc20_selector" in kinds, flows


def test_mentioning_a_selector_is_not_issuing_it(_recognizer):
    """A deny-list checks the selector and moves nothing. Treating the constant's
    presence as evidence published a fabricated `flow.out` with resolved
    destination and amount slots."""
    assert not (_recognizer["enqueue(bytes4,address,uint256)"]["value_flows"]), _recognizer[
        "enqueue(bytes4,address,uint256)"
    ]["value_flows"]


ZERO_ID_SRC = """
pragma solidity ^0.8.20;

interface IERC721 {
    function transferFrom(address,address,uint256) external;
    function safeTransferFrom(address,address,uint256) external;
}
interface IERC20 { function transfer(address,uint256) external returns (bool); }

contract ZeroId {
    IERC721 public genesis;
    IERC20 public coin;
    function sendPlain(address to) external { genesis.transferFrom(address(this), to, 0); }
    function sendSafe(address to) external { genesis.safeTransferFrom(address(this), to, 0); }
    function sendNothing(address to) external { coin.transfer(to, 0); }
}
"""


@pytest.fixture(scope="module")
def _zero_id(tmp_path_factory):
    contract = _compile(tmp_path_factory.mktemp("zeroid"), ZERO_ID_SRC, "ZeroId")
    return build_effects(contract)["functions"]


def test_a_zero_trailing_arg_on_the_ambiguous_pull_selector_still_moves(_zero_id):
    """Both standards define ``transferFrom(address,address,uint256)``, so a
    literal 0 is a zero QUANTITY under ERC-20 and token id 0 — an ordinary NFT —
    under ERC-721. Suppressing the site deleted a real transfer, and shrank the
    member set a ``several`` fold asserts is the complete list of alternatives.
    The move stands; the amount stays unresolved, because naming it
    ``fixed_constant`` would assert the reading the selector cannot support."""
    flows = _zero_id["sendPlain(address)"]["value_flows"]
    assert len(flows) == 1, flows
    assert flows[0]["selector"] == "0x23b872dd"
    assert flows[0]["amount_kind"]["kind"] == "indeterminate", flows


def test_a_zero_token_id_on_the_erc721_only_selector_keeps_its_identity_kind(_zero_id):
    flows = _zero_id["sendSafe(address)"]["value_flows"]
    assert [f["amount_kind"]["kind"] for f in flows] == ["token_identity"], flows


def test_a_zero_amount_on_an_unambiguous_erc20_send_still_moves_nothing(_zero_id):
    """The exemption is scoped to the ambiguity. ``transfer(to, 0)`` is ERC-20's
    alone and provably moves nothing, so it must still be dropped."""
    assert not _zero_id["sendNothing(address)"]["value_flows"]


# ---------------------------------------------------------------------------
# A zero-value ``.call{value:}`` must not read as an ETH payout.
#
# Plane 0 mints ``asset_send`` from any ``.call{value: v}`` it can reach through
# an internal call, without looking at ``v``. OZ's ``Address`` helper chain — the
# bottom of every ``SafeERC20`` call — is such a site, and its ``value`` is a
# PARAMETER whose zero literal lives one frame up, so only an interprocedural
# read can settle it. Four real etherfi entry points ("record a withdrawal
# intent", which approve and then call) published "sends assets out of the
# contract" from nothing but this.
# ---------------------------------------------------------------------------

ZERO_VALUE_CALL_SRC = """
pragma solidity ^0.8.20;

interface IERC20 { function approve(address,uint256) external returns (bool); }

library Address {
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }
    function functionCallWithValue(address target, bytes memory data, uint256 value)
        internal returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "CALL_FAILED");
        return ret;
    }
}

contract Intent {
    address public immutable spender;

    constructor(address s) { spender = s; }

    // Approval only: the one ETH-bearing call it reaches carries a zero value.
    function recordIntent(IERC20 token, uint256 amount) external {
        Address.functionCall(address(token), abi.encodeWithSelector(IERC20.approve.selector, spender, amount));
    }

    // A real ETH payout, and it must keep saying so.
    function payOut(address to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "PAY_FAILED");
    }

    // Both in one function: the payment is what the label rests on.
    function approveAndPay(IERC20 token, address to, uint256 amount) external {
        Address.functionCall(address(token), abi.encodeWithSelector(IERC20.approve.selector, spender, amount));
        (bool ok,) = to.call{value: amount}("");
        require(ok, "PAY_FAILED");
    }
}
"""


@pytest.fixture(scope="module")
def _zero_value(tmp_path_factory):
    contract = _compile(tmp_path_factory.mktemp("zero_value"), ZERO_VALUE_CALL_SRC, "Intent")
    return build_effects(contract)["functions"]


def test_an_approval_is_not_an_eth_payout(_zero_value):
    info = _zero_value["recordIntent(IERC20,uint256)"]
    assert info["value_flows"] == []
    assert "asset_send" not in info["effect_labels"]


def test_a_real_value_call_still_reads_as_a_payout(_zero_value):
    info = _zero_value["payOut(address,uint256)"]
    assert [f["kind"] for f in info["value_flows"]] == ["low_level_value_call"]
    assert "asset_send" in info["effect_labels"]


def test_a_function_that_approves_AND_pays_keeps_the_payout_label(_zero_value):
    """The retraction is scoped to the absence of any real outflow: one zero-value
    site alongside a genuine payment must not take the payment's label with it."""
    info = _zero_value["approveAndPay(IERC20,address,uint256)"]
    assert "asset_send" in info["effect_labels"]
