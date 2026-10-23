pragma solidity 0.8.27;
contract G {
    mapping(address => uint256) balances;      // 0
    mapping(address => bool) allowed;          // 1  (two holders in _Deployed)
    uint256 moved; uint256 supply;
    mapping(bytes32 => mapping(address => bool)) roles; // 4
    uint256 locked = 1;                        // 5 (=1)
    address owner;                             // 6 (unset)
    bool paused;                               // 7
    uint256 deadline;                          // 8
    mapping(address => uint256) b2;
    event Allowed(address indexed who, bool ok);
    function allow(address who, bool ok) external { require(msg.sender == owner); allowed[who] = ok; emit Allowed(who, ok); }
    // self-scoped, gate caller == owner, owner unset -> nobody
    function ownerSpend(address to, uint256 a) external { require(msg.sender == owner); b2[msg.sender] -= a; b2[to] += a; }
    // self-scoped, gate allowed + not paused + deadline: gate should keep allowed and drop pure when atoms
    function gated(address to, uint256 a, uint256 dl) external {
        require(!paused); require(dl >= block.timestamp); require(allowed[msg.sender]); require(locked == 1);
        b2[msg.sender] -= a; b2[to] += a;
    }
    // gate caller == owner but paused forever-ish
    function ownerPaused(address to, uint256 a) external { require(paused); require(msg.sender == owner); b2[msg.sender] -= a; b2[to] += a; }
}
