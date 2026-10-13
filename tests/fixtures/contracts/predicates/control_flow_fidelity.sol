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

// Helper return paths that join after branches, run in a loop, or pass a revert reached under a branch.
contract HelperJoins {
    enum Mode {
        Open,
        Whitelist,
        Blacklist
    }

    address public owner;
    Mode public mode;
    bool public globalPause;
    bool public localMode;
    bool public strict;
    bool public paused;
    bool public flag;
    mapping(address => bool) public whitelist;
    mapping(address => bool) public blacklist;
    mapping(address => bool) public localPaused;
    address[] public listed;
    mapping(address => uint256) public bal;

    function _isRestricted(address a) internal view returns (bool) {
        if (mode == Mode.Whitelist) {
            if (!whitelist[a]) return true;
        } else if (mode == Mode.Blacklist) {
            if (blacklist[a]) return true;
        }
        return false;
    }

    function _isPaused(address a) internal view returns (bool) {
        if (globalPause) return true;
        if (localMode) {
            if (localPaused[a]) return true;
        }
        return false;
    }

    function _requireUnderBranch() internal view returns (bool) {
        if (strict) {
            require(!paused, "paused");
        }
        return flag;
    }

    function _revertUnderBranch() internal view returns (bool) {
        if (strict) {
            if (paused) revert();
        }
        return flag;
    }

    function _ownerUnderBranch(address a) internal view returns (bool) {
        if (strict) {
            if (a != owner) revert();
        }
        return whitelist[a];
    }

    function _isListed(address a) internal view returns (bool) {
        for (uint256 i = 0; i < listed.length; i++) {
            if (listed[i] == a) return true;
        }
        return false;
    }

    function send(uint256 x) external {
        require(!_isRestricted(msg.sender), "restricted");
        bal[msg.sender] = x;
    }

    function act(uint256 x) external {
        require(!_isPaused(msg.sender), "paused");
        bal[msg.sender] = x;
    }

    function requireUnderBranch(uint256 x) external {
        require(_requireUnderBranch(), "no");
        bal[msg.sender] = x;
    }

    function revertUnderBranch(uint256 x) external {
        require(_revertUnderBranch(), "no");
        bal[msg.sender] = x;
    }

    function revertUnderBranchNegated(uint256 x) external {
        require(!_revertUnderBranch(), "no");
        bal[msg.sender] = x;
    }

    function ownerUnderBranch(uint256 x) external {
        require(_ownerUnderBranch(msg.sender), "no");
        bal[msg.sender] = x;
    }

    function notListed(uint256 x) external {
        require(!_isListed(msg.sender), "listed");
        bal[msg.sender] = x;
    }

    function listedOnly(uint256 x) external {
        require(_isListed(msg.sender), "not listed");
        bal[msg.sender] = x;
    }
}

library FlagLib {
    struct Flag {
        bool on;
    }

    function clear(Flag storage f) internal {
        f.on = false;
    }
}

// Branches on storage the call writes before they run: through a mapping or struct element, a library storage pointer,
// a modifier's code after ``_`` reading what the body or an inner modifier wrote, and a body run twice.
contract WriteBeforeBranch {
    struct Per {
        bool open;
    }

    struct Item {
        uint256 n;
    }

    address public owner;
    bool public open;
    uint256 public count;
    uint256 public hook;
    mapping(uint256 => uint256) public deadline;
    mapping(address => Per) public per;
    mapping(uint256 => Item) public items;
    FlagLib.Flag internal flag;

    modifier afterCheck() {
        _;
        if (open) return;
        require(msg.sender == owner, "UNAUTHORIZED");
    }

    modifier afterCount() {
        _;
        if (count > 1) return;
        require(msg.sender == owner, "UNAUTHORIZED");
    }

    modifier closeFirst() {
        open = false;
        _;
    }

    modifier twice() {
        _;
        _;
    }

    function elementWrite(uint256 id) external {
        deadline[id] = 0;
        if (deadline[id] > block.timestamp) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = id;
    }

    function structWrite(uint256 v) external {
        per[msg.sender].open = false;
        if (per[msg.sender].open) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function itemWrite(uint256 id) external {
        items[id].n = 0;
        if (items[id].n > 0) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = id;
    }

    function pointerWrite(uint256 v) external {
        FlagLib.clear(flag);
        if (flag.on) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function bodyWritesBeforeModifierBranch(uint256 v) external afterCheck {
        open = false;
        hook = v;
    }

    function bodyIncrements(uint256 v) external afterCount {
        count += 1;
        hook = v;
    }

    function innerModifierWrites(uint256 v) external afterCheck closeFirst {
        hook = v;
    }

    function bodyRunsTwice(uint256 v) external twice {
        if (open) {
            open = false;
            return;
        }
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }
}

// A helper whose own revert is reached under a branch on storage it writes, read from a body a modifier runs twice,
// called twice in one condition, or after a transient store.
contract HelperRunTwice {
    address public owner;
    bool public open;
    uint256 public hook;
    bytes32 private constant FLAG_SLOT = keccak256("flag");

    modifier twice() {
        _;
        _;
    }

    function _ok() internal returns (bool) {
        if (open) {
            open = false;
            return true;
        }
        require(msg.sender == owner, "UNAUTHORIZED");
        return true;
    }

    function _okView() internal view returns (bool) {
        if (open) return true;
        require(msg.sender == owner, "UNAUTHORIZED");
        return true;
    }

    function _transientFlag() internal view returns (bool r) {
        bytes32 slot = FLAG_SLOT;
        assembly {
            r := tload(slot)
        }
    }

    function viaOnce(uint256 v) external {
        require(_ok(), "x");
        hook = v;
    }

    function viaTwice(uint256 v) external twice {
        require(_ok(), "x");
        hook = v;
    }

    function viaTwiceIf(uint256 v) external twice {
        if (!_ok()) revert("x");
        hook = v;
    }

    function viewTwiceBody(uint256 v) external twice {
        require(_okView(), "x");
        open = false;
        hook = v;
    }

    function viaDouble(uint256 v) external {
        require(_ok() && _ok(), "x");
        hook = v;
    }

    function sameIf(uint256 v) external {
        if (!(_ok() && _ok())) revert("x");
        hook = v;
    }

    function transientWriteThenBranch(uint256 v) external {
        bytes32 slot = FLAG_SLOT;
        assembly {
            tstore(slot, 0)
        }
        if (_transientFlag()) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }
}

// Reverts reached only under a path condition gate the function only under that condition.
contract ConditionalGates {
    error Unauthorized();

    event E(uint256 v);

    address public owner;
    address public guardian;
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

    modifier twoPlaceholders() {
        if (openMode) {
            _;
            return;
        }
        require(msg.sender == guardian, "UNAUTHORIZED");
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

    function writeThenBranch(uint256 v) external {
        openMode = false;
        if (openMode) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function writeInCallThenBranch(uint256 v) external {
        _closeOpenMode();
        if (openMode) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function unrelatedWriteThenBranch(uint256 v) external {
        hook = v;
        if (openMode) return;
        require(msg.sender == owner, "UNAUTHORIZED");
    }

    function bothPlaceholders(uint256 v) external twoPlaceholders {
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function _closeOpenMode() internal {
        openMode = false;
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

// Helpers called where the order of evaluation is left open, from a loop, and ahead of later reads in the statement.
contract CallOrder {
    address public owner;
    bool public open;
    uint256 public hook;
    uint256 public count;
    IPing public target;

    function _gateU() internal returns (uint256) {
        if (open) {
            open = false;
            return 1;
        }
        require(msg.sender == owner, "UNAUTHORIZED");
        return 1;
    }

    function _closeU() internal returns (uint256) {
        open = false;
        return 1;
    }

    function _ok() internal returns (bool) {
        if (open) {
            open = false;
            return true;
        }
        require(msg.sender == owner, "UNAUTHORIZED");
        return true;
    }

    function _okView() internal view returns (bool) {
        if (open) return true;
        require(msg.sender == owner, "UNAUTHORIZED");
        return true;
    }

    function _gateOnly() internal {
        if (open) {
            open = false;
            return;
        }
        require(msg.sender == owner, "UNAUTHORIZED");
    }

    function _set(bool b) internal {
        open = !b;
    }

    function _gateThenPing() internal {
        if (open) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        target.ping(count);
    }

    function binRight(uint256 v) external {
        hook = _gateU() + _closeU() + v;
    }

    function modPair(uint256 v) external {
        hook = addmod(_gateU(), _closeU(), 7) + v;
    }

    function loopNested(uint256 v) external {
        for (uint256 i; i < 2; i++) {
            _set(_okView());
        }
        hook = v;
    }

    function whileNested(uint256 v) external {
        uint256 i;
        while (i < 2) {
            _set(_okView());
            i++;
        }
        hook = v;
    }

    function doNested(uint256 v) external {
        uint256 i;
        do {
            _set(_okView());
            i++;
        } while (i < 2);
        hook = v;
    }

    function straightNested(uint256 v) external {
        _set(_okView());
        hook = v;
    }

    function loopCall(uint256 v) external {
        for (uint256 i; i < 2; i++) {
            require(_ok(), "x");
        }
        hook = v;
    }

    function loopGate(uint256 v) external {
        for (uint256 i; i < 2; i++) {
            _gateOnly();
        }
        hook = v;
    }

    function readAfterCall(uint256 v) external {
        _gateThenPing();
        count += v;
    }
}
