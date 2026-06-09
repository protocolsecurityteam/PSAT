// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// PSAT regression fixture — faithful to ether.fi MembershipNFT
//   (0x290d981b41b713437265cd7846806d7500307106, Etherscan-verified, mainnet;
//    on-chain pragma is 0.8.13, compiled here with an installed ^0.8.13 solc —
//    storage-layout rules are identical across 0.8.x).
// Why it's here: the `membershipManager` authority var is declared WITHOUT
//   `public`, so it has NO auto-generated getter. `onlyMembershipManagerContract`
//   lowers to `msg.sender == address(membershipManager)` — a bare INTERNAL
//   `state_variable` gate whose getter (`membershipManager()`) reverts on every
//   deployment (claim #3 group D). Resolution recovers the principal by reading
//   the var's *sequential* storage slot with `eth_getStorageAt`. See
//   tests/test_internal_authority_storage_read.py.
//
// The OZ upgradeable bases the real contract inherits (Ownable/UUPS/ERC1155) are
// replaced by `_InheritedStorage`, a stand-in for their preceding storage so the
// computed slot is realistic (non-zero) and the fixture stays self-contained; the
// modifier and the `membershipManager`-first declaration order are verbatim. The
// address packs at offset 0 of its slot (20-byte address followed by the uint32s),
// exactly as on-chain — the low-20-byte slot decode is therefore correct.

interface IMembershipManager {
    function tokenData(uint256 _tokenId) external view returns (uint96, uint40, uint40, uint32, uint32, uint8, uint8);
}

interface ILiquidityPool {
    function sharesForAmount(uint256 _amount) external view returns (uint256);
}

// Stand-in for the inherited OZ-upgradeable storage (Initializable / Ownable /
// UUPS / ERC1155), so `membershipManager` lands at a non-zero slot just as it
// does on-chain rather than degenerately at slot 0. `_legacyController` is a
// plain getter-less `address` (vs membershipManager's contract type) so the slot
// pass is exercised on both address-like shapes.
contract _InheritedStorage {
    uint256 private _initializableSlot; // slot 0
    address private _legacyController; // slot 1 — plain address, no getter
}

contract MembershipNFT is _InheritedStorage {
    IMembershipManager membershipManager; // ← NO `public` ⇒ no auto-generated getter
    uint32 public nextMintTokenId;
    uint32 public maxTokenId;
    bool public mintingPaused;
    uint24 __gap0;

    mapping(address => bool) public eapDepositProcessed;
    ILiquidityPool public liquidityPool; // PUBLIC ⇒ has getter; must NOT get a slot
    address private _owner; // PRIVATE but exposed via owner() below — read through the getter, NOT a slot

    error OnlyMembershipManagerContract();

    // OZ-Ownable shape: a private `_owner` with a manual public getter. The
    // onlyOwner gate lowers to `msg.sender == _owner`, but because `owner()`
    // exists the slot pass must NOT stamp `_owner` (a layout-sensitive slot read
    // is the wrong tool when a getter can read it).
    function owner() public view returns (address) {
        return _owner;
    }

    function adminAction() external {
        if (msg.sender != _owner) revert OnlyMembershipManagerContract();
    }

    modifier onlyMembershipManagerContract() {
        if (msg.sender != address(membershipManager)) revert OnlyMembershipManagerContract();
        _;
    }

    function mint(address _to, uint256 _amount) external onlyMembershipManagerContract returns (uint256) {
        uint32 tokenId = nextMintTokenId++;
        _to;
        _amount;
        return tokenId;
    }

    function burn(address _from, uint256 _tokenId, uint256 _amount) external onlyMembershipManagerContract {
        _from;
        _tokenId;
        _amount;
    }

    function incrementLock(uint256 _tokenId, uint32 _blocks) external onlyMembershipManagerContract {
        _tokenId;
        _blocks;
    }

    // Gated by a PUBLIC address var: this resolves through its auto-getter
    // (`liquidityPool()`), so the slot pass must NOT attach a slot to it.
    function rebase(uint256 _amount) external {
        if (msg.sender != address(liquidityPool)) revert OnlyMembershipManagerContract();
        _amount;
    }
}
