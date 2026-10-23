pragma solidity 0.8.27;
interface IProbe { function frozenX(address) external view returns (bool); }
contract Probe {
    mapping(address => uint256) balances;      // 0
    mapping(address => bool) allowed;          // 1
    uint256 moved;                             // 2
    uint256 supply;                            // 3
    mapping(bytes32 => mapping(address => bool)) roles; // 4
    uint256 locked = 1;                        // 5
    address owner;
    event Allowed(address indexed who, bool ok);
    function allow(address who, bool ok) external { require(msg.sender == owner); allowed[who] = ok; emit Allowed(who, ok); }

    mapping(address => mapping(address => uint256)) bal2;
    mapping(address => mapping(address => uint256)) allowance;
    mapping(address => address) prefs;
    mapping(address => mapping(address => bool)) reported;
    mapping(address => uint256) bal3;
    mapping(address => bool) blk;
    mapping(address => bool) frozen;
    mapping(address => bool) public frozenX;
    mapping(address => address) delegates;
    mapping(address => uint256) dep;
    mapping(address => uint256) credits;
    struct P { uint256 stake; address mgr; }
    mapping(address => P) pos;
    mapping(address => uint256) bal4;
    mapping(address => int256) debt;
    mapping(uint256 => mapping(address => address)) nominee;
    mapping(uint256 => address) data;
    mapping(address => uint256) bal5;

    // N1 cross-asset: debit token ta, credit token tb
    function crossAsset(address ta, address tb, address to, uint256 d) external {
        require(allowed[msg.sender]); bal2[msg.sender][ta] -= d; bal2[to][tb] += d;
    }
    // N2 "grant" via amount <= allowance: amount = 0 passes for anyone
    function prefsLe(address from, uint256 amount, address v) external {
        require(allowed[msg.sender]); require(amount <= allowance[from][msg.sender]); prefs[from] = v;
    }
    // N3 [from][caller] set by the caller itself, not granted by from
    function report(address from) external { reported[from][msg.sender] = true; }
    function punish(address from) external {
        require(allowed[msg.sender]); require(reported[from][msg.sender]); bal3[from] = 0;
    }
    // N4 sanction enforced by early return, not revert
    function transfer2(address to, uint256 a) external {
        if (blk[msg.sender]) return; bal3[msg.sender] -= a; bal3[to] += a;
    }
    function leaveBlk() external { require(allowed[msg.sender]); blk[msg.sender] = false; }
    // N5 freeze checked only on an argument
    function xferFrom(address from, address to, uint256 a) external {
        require(msg.sender == owner); require(!frozen[from]); bal5[from] -= a; bal5[to] += a;
    }
    function unfreeze() external { require(allowed[msg.sender]); frozen[msg.sender] = false; }
    // N6 flag read by another contract's check (public getter)
    function unfreezeX() external { require(allowed[msg.sender]); frozenX[msg.sender] = false; }
    // N7 approval max
    function approveMax(address s) external { require(allowed[msg.sender]); allowance[msg.sender][s] = type(uint256).max; }
    function approveZero(address s) external { require(allowed[msg.sender]); allowance[msg.sender][s] = 0; }
    // N8 delegate as authority
    function setDelegate(address x) external { require(allowed[msg.sender]); delegates[msg.sender] = x; }
    function clearDelegate() external { require(allowed[msg.sender]); delegates[msg.sender] = address(0); }
    function asDelegate(address o) external { require(delegates[o] == msg.sender); bal3[o] = 0; }
    // N9 write under loop
    function loopDebit(uint256 n) external { require(allowed[msg.sender]); for (uint i; i < n; i++) { dep[msg.sender] -= 1; } }
    // N10 write in modifier
    modifier clears() { credits[msg.sender] = 0; _; }
    function modClear() external clears { require(allowed[msg.sender]); }
    // N11 struct: other field caller-checked
    function zeroStake() external { require(allowed[msg.sender]); pos[msg.sender].stake = 0; }
    function deletePos() external { require(allowed[msg.sender]); delete pos[msg.sender]; }
    function asMgr(address a) external { require(pos[a].mgr == msg.sender); bal3[a] = 0; }
    // N12 unchecked debit wraps
    function uncheckedDebit(uint256 a) external { require(allowed[msg.sender]); unchecked { bal4[msg.sender] -= a; } }
    // N13 signed debit
    function signedDebit(int256 x) external { require(allowed[msg.sender]); debt[msg.sender] -= x; }
    // N14 withdraw-all ETH
    function withdrawAll() external { require(allowed[msg.sender]); bal4[msg.sender] = 0; payable(msg.sender).transfer(address(this).balance); }
    // N15 holder via caller-chosen lookup
    function nominate(uint256 id, address a) external { nominee[id][msg.sender] = a; }
    function setData(uint256 id, address other, address v) external {
        require(allowed[msg.sender]); require(nominee[id][other] == msg.sender); data[id] = v;
    }
    // N16 debit then credit same key path with different keys depth: credit to [to][ta]
    function crossUser(address ta, address to, uint256 d) external {
        require(allowed[msg.sender]); bal2[msg.sender][ta] -= d; bal2[to][ta] += d;
    }
}
