// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Values that reach a value-flow sink as the RETURN of an internal helper.
//
// The lattice threads a caller's arguments INTO a helper, so a destination or
// amount forwarded as an argument resolves interprocedurally. It never traced
// the way back out: a helper's return value arrived at the sink with no origin,
// so a payout to a getter-read storage address, and an amount computed by a
// `_calculate*` helper, both published "we traced nothing" about facts the
// contract states plainly. The shape recurs on diamond-storage getters and on
// every `_calculate*`/`_convert*` helper.
//
// Each function below isolates one edge, and the last three are the negatives
// that must NOT resolve — a helper whose answer genuinely depends on the branch
// taken, one that returns a caller-chosen value, and one whose two returns
// disagree.
contract HelperReturns {
    address public immutable treasury;
    address public governor;
    uint256 public cap;
    bool public flag;

    constructor(address treasury_) {
        treasury = treasury_;
        governor = msg.sender;
    }

    function setGovernor(address g) external {
        governor = g;
    }

    function setCap(uint256 c) external {
        cap = c;
    }

    // --- destination through a getter -------------------------------------

    // `_governor()` reads an admin-settable state variable. The destination is
    // knowable and admin-redirectable, which is exactly the distinction a
    // scorer needs; it is not "unknown".
    function payGovernor(uint256 amount) external {
        _send(_governor(), amount);
    }

    // The same edge onto an IMMUTABLE, which is the benign end of the same axis.
    function payTreasury(uint256 amount) external {
        _send(_treasury(), amount);
    }

    function _governor() internal view returns (address) {
        return governor;
    }

    function _treasury() internal view returns (address) {
        return treasury;
    }

    // --- amount through a calculating helper ------------------------------

    // The amount is a helper's return value computed from a storage bound.
    function drainToCap(address to) external {
        _send(to, _claimable());
    }

    function _claimable() internal view returns (uint256) {
        return cap;
    }

    // Two hops: a helper returning another helper's return value.
    function payGovernorTwoHop(uint256 amount) external {
        _send(_governorIndirect(), amount);
    }

    function _governorIndirect() internal view returns (address) {
        return _governor();
    }

    // --- the negatives ----------------------------------------------------

    // The helper picks between two DIFFERENT destinations, so the answer really
    // does depend on state the caller cannot see. Must stay unresolved rather
    // than collapse onto either member.
    function payEither(uint256 amount) external {
        _send(_eitherDestination(), amount);
    }

    function _eitherDestination() internal view returns (address) {
        if (flag) return governor;
        return treasury;
    }

    // The helper hands back a caller-supplied argument. Resolving this to
    // storage would be worse than indeterminate: it would call a caller-chosen
    // destination fixed.
    function payEcho(address to, uint256 amount) external {
        _send(_echo(to), amount);
    }

    function _echo(address a) internal pure returns (address) {
        return a;
    }

    // Two return statements naming different origins, no branch merge to catch
    // it — the disagreement is the whole answer.
    function payDisagree(address to, uint256 amount) external {
        _send(_disagree(to), amount);
    }

    function _disagree(address a) internal view returns (address) {
        if (flag) {
            return a;
        }
        return governor;
    }

    function _send(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "send failed");
    }
}
