// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Gate conditions a predicate tree must state as the allowed condition: negation carried through a bool helper's
// return, and the path conditions a revert is reached under.

interface IPing {
    function ping(uint256 value) external returns (bool);
}

contract HelperPolarity {
    error EnforcedPause();
    error Blacklisted();

    address public owner;
    bool private _paused;
    mapping(address => bool) public blacklist;
    mapping(address => bool) public allowed;
    mapping(address => uint256) public bal;

    function paused() public view returns (bool) {
        return _paused;
    }

    function isBlacklisted(address a) public view returns (bool) {
        return blacklist[a];
    }

    function isAllowed(address a) public view returns (bool) {
        return allowed[a];
    }

    function pause() external {
        require(msg.sender == owner);
        _paused = true;
    }

    function unpause() external {
        require(msg.sender == owner);
        _paused = false;
    }

    function ifGetterRevert(uint256 x) external {
        if (paused()) revert EnforcedPause();
        bal[msg.sender] = x;
    }

    function requireGetter(uint256 x) external {
        require(paused(), "np");
        bal[msg.sender] = x;
    }

    function requireNotGetter(uint256 x) external {
        require(!paused(), "p");
        bal[msg.sender] = x;
    }

    function ifDirectRevert(uint256 x) external {
        if (_paused) revert EnforcedPause();
        bal[msg.sender] = x;
    }

    function ifBlacklistedRevert(uint256 x) external {
        if (isBlacklisted(msg.sender)) revert Blacklisted();
        bal[msg.sender] = x;
    }

    function requireNotBlacklisted(uint256 x) external {
        require(!isBlacklisted(msg.sender), "bl");
        bal[msg.sender] = x;
    }

    function requireAllowed(uint256 x) external {
        require(isAllowed(msg.sender), "na");
        bal[msg.sender] = x;
    }

    function ifNotAllowedRevert(uint256 x) external {
        if (!isAllowed(msg.sender)) revert Blacklisted();
        bal[msg.sender] = x;
    }

    function directBlacklist(uint256 x) external {
        if (blacklist[msg.sender]) revert Blacklisted();
        bal[msg.sender] = x;
    }
}

// OpenZeppelin >= 4.7 ``_requireNotPaused`` (``require(!paused())``) and v5 (``if (paused()) revert``).
contract OzPausable {
    error EnforcedPause();

    address public owner;
    bool private _paused;
    mapping(address => uint256) public bal;

    modifier whenNotPausedV4() {
        _requireNotPausedV4();
        _;
    }

    modifier whenNotPausedV5() {
        _requireNotPausedV5();
        _;
    }

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    function _requireNotPausedV4() internal view virtual {
        require(!paused(), "Pausable: paused");
    }

    function _requireNotPausedV5() internal view virtual {
        if (paused()) revert EnforcedPause();
    }

    function pause() external {
        require(msg.sender == owner);
        _paused = true;
    }

    function unpause() external {
        require(msg.sender == owner);
        _paused = false;
    }

    function depositV4(uint256 x) external whenNotPausedV4 {
        bal[msg.sender] = x;
    }

    function depositV5(uint256 x) external whenNotPausedV5 {
        bal[msg.sender] = x;
    }
}

// OpenZeppelin v5 upgradeable: the getter reads its flag through a namespaced storage pointer.
contract OzPausableUpgradeable {
    error EnforcedPause();

    struct PausableStorage {
        bool _paused;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Pausable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PausableStorageLocation = 0xcd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300;

    mapping(address => uint256) public bal;

    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    function _getPausableStorage() private pure returns (PausableStorage storage $) {
        assembly {
            $.slot := PausableStorageLocation
        }
    }

    function paused() public view virtual returns (bool) {
        PausableStorage storage $ = _getPausableStorage();
        return $._paused;
    }

    function _requireNotPaused() internal view virtual {
        if (paused()) revert EnforcedPause();
    }

    function deposit(uint256 x) external whenNotPaused {
        bal[msg.sender] = x;
    }
}

// Helpers whose return paths carry their own guards: a ``require`` keeps its polarity under a negated call, an early
// ``return true`` guards the tail return, and a missing return yields the default ``false``.
contract HelperPaths {
    address public owner;
    bool public halted;
    mapping(address => bool) public operators;
    mapping(address => bool) public flagged;
    mapping(address => uint256) public bal;

    function _isOperator(address a) internal view returns (bool) {
        require(!halted, "halted");
        if (a == owner) return true;
        return operators[a];
    }

    function _isFlagged(address a) internal view returns (bool) {
        if (flagged[a]) return true;
    }

    function _eitherCheck(address a, uint256 v) internal view returns (bool) {
        if (v > 100) return a == owner;
        return operators[a];
    }

    function nonOperatorOnly(uint256 x) external {
        require(!_isOperator(msg.sender), "op");
        bal[msg.sender] = x;
    }

    function operatorOnly(uint256 x) external {
        require(_isOperator(msg.sender), "not op");
        bal[msg.sender] = x;
    }

    function unflaggedOnly(uint256 x) external {
        require(!_isFlagged(msg.sender), "flagged");
        bal[msg.sender] = x;
    }

    function eitherCheck(uint256 x) external {
        require(_eitherCheck(msg.sender, x), "denied");
        bal[msg.sender] = x;
    }
}

// Reverts reached only under a path condition gate the function only under that condition.
contract ConditionalGates {
    error Unauthorized();

    event E(uint256 v);

    address public owner;
    bool public openMode;
    bool public live;
    uint256 public hook;
    mapping(address => bool) public allowed;

    modifier gatedUnlessOpen() {
        if (!openMode) {
            require(msg.sender == owner, "UNAUTHORIZED");
        }
        _;
    }

    modifier onlyWhenLive() {
        if (live) {
            _;
        }
    }

    function condNoEffect(uint256 v) external {
        if (!openMode) {
            require(msg.sender == owner, "UNAUTHORIZED");
        }
        emit E(v);
    }

    function condEffectInside(uint256 v) external {
        if (!openMode) {
            require(msg.sender == owner, "UNAUTHORIZED");
            hook = v;
        }
    }

    function condParam(uint256 v) external {
        if (v > 10) {
            require(msg.sender == owner, "UNAUTHORIZED");
        }
        hook = v;
    }

    function condModifier(uint256 v) external gatedUnlessOpen {
        hook = v;
    }

    function earlyReturn(uint256 v) external {
        if (v == 0) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function nestedIfRevert(uint256 v) external {
        if (openMode) {
            if (msg.sender != owner) revert("UNAUTHORIZED");
        }
        hook = v;
    }

    function conditionalHelper(uint256 v) external {
        _checkLarge(v);
        hook = v;
    }

    function placeholderUnderCondition(uint256 v) external onlyWhenLive {
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function loopGate(address[] calldata accounts) external {
        for (uint256 i = 0; i < accounts.length; i++) {
            require(allowed[accounts[i]], "not allowed");
        }
        emit E(accounts.length);
    }

    function tryGate(IPing target, uint256 v) external {
        try target.ping(v) returns (bool) {
            require(msg.sender == owner, "UNAUTHORIZED");
        } catch {}
        emit E(v);
    }

    function revertThenRequire(uint256 v) external {
        if (v > 3) revert("big");
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function joinThenRequire(uint256 v) external {
        uint256 x;
        if (v > 1) {
            x = 1;
        } else {
            x = 2;
        }
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = x;
    }

    function customErrorUnderBranch(uint256 v) external {
        if (v > 10) {
            require(msg.sender == owner, Unauthorized());
            hook = v;
        }
    }

    function constantBranch(uint256 v) external {
        if (_alwaysGuarded()) {
            require(msg.sender == owner, "UNAUTHORIZED");
        }
        hook = v;
    }

    function _alwaysGuarded() internal pure returns (bool) {
        return true;
    }

    function _checkLarge(uint256 v) internal view {
        if (v > 10) {
            require(msg.sender == owner, "UNAUTHORIZED");
        }
    }
}
