// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// The Safe/Zodiac transaction-guard idiom, held against its open control.
//
// `execGuarded` routes the caller-supplied (target, data) through a FIXED,
// nonview guard whose entire revert surface is the vetting: the guard leaf is a
// mandatory external_call_revert whose callee identity is a body call. A
// transparency set that admits every body call swallows that leaf and mints
// `unconstrained_proven` — byte-identical to `execOpen`, which really has no
// gate. The pair is the distinguishability requirement itself: the guarded and
// the open function must not publish the same destination-constraint state.

interface IGuard {
    // Deliberately NOT view: a real Safe guard may write (rate accounting,
    // nonces) and reverts when the target is not permitted.
    function checkTransaction(address to, bytes calldata data) external;
}

contract GuardedExec {
    IGuard public guard;

    // The fixed guard vets the destination before the arbitrary call.
    function execGuarded(address target, bytes calldata data) external {
        guard.checkTransaction(target, data);
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }

    // Control: same arbitrary call, no guard — genuinely unconstrained.
    function execOpen(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
