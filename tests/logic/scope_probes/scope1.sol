pragma solidity 0.8.27;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
library PubLib { function bump(mapping(address=>uint256) storage m, address k) public { m[k] += 1; } }
contract Child { constructor() {} }
contract Probe {
    mapping(address => uint256) balances;      // 0
    mapping(address => bool) allowed;          // 1
    uint256 moved;                             // 2
    uint256 supply;                            // 3
    mapping(bytes32 => mapping(address => bool)) roles; // 4
    uint256 locked = 1;                        // 5
    mapping(address => mapping(address => bool)) operators;
    mapping(address => mapping(address => uint256)) allowance;
    mapping(address => mapping(address => bool)) blocked;
    mapping(address => address) vaults;
    mapping(address => uint256) counters;
    address[] queue;
    bool paused;
    IERC20 token;

    // value created in the caller's own entry, no total
    function selfMint(uint256 a) external { require(allowed[msg.sender]); balances[msg.sender] += a; }
    // privilege escalation into the caller's own entry
    function selfGrant(bytes32 role) external { require(allowed[msg.sender]); roles[role][msg.sender] = true; }
    // one debit, two credits of the same amount
    function doubleCredit(address a, address b, uint256 d) external {
        require(allowed[msg.sender]); balances[msg.sender] -= d; balances[a] += d; balances[b] += d;
    }
    // condition reads [from][caller] but requires the opposite of a grant
    function blockedDrain(address from, uint256 amt) external {
        require(allowed[msg.sender]); require(!blocked[from][msg.sender]); balances[from] = 0;
    }
    // caller makes itself operator of an arbitrary victim (caller-keyed at second position)
    function selfOperator(address victim) external { require(allowed[msg.sender]); operators[victim][msg.sender] = true; }
    // ETH out
    function sendEth(address payable to) external { require(allowed[msg.sender]); balances[msg.sender] = 0; to.transfer(1); }
    // token call out
    function tokenOut(address to) external { require(allowed[msg.sender]); balances[msg.sender] = 0; token.transfer(to, 1); }
    // contract creation
    function makeVault() external { require(allowed[msg.sender]); vaults[msg.sender] = address(new Child()); }
    // selfdestruct on one path
    function kill(bool f) external { require(allowed[msg.sender]); counters[msg.sender] += 1; if (f) selfdestruct(payable(msg.sender)); }
    // only selfdestruct
    function killOnly() external { require(allowed[msg.sender]); selfdestruct(payable(msg.sender)); }
    // public library (delegatecall) writing a shared key
    function libBump(address k) external { require(allowed[msg.sender]); PubLib.bump(counters, k); }
    // loop writing argument-keyed entries
    function loopZero(address[] calldata ts) external {
        require(allowed[msg.sender]); counters[msg.sender] += 1;
        for (uint i; i < ts.length; i++) { balances[ts[i]] = 0; }
    }
    // global flag write that equals the current value
    function pauseIfNot() external { require(allowed[msg.sender]); paused = false; counters[msg.sender] += 1; }
    // array push
    mapping(bytes32 => bool) hashed;
    function hashOperator(address victim) external { require(allowed[msg.sender]); hashed[keccak256(abi.encode(victim, msg.sender))] = true; }
    function killOpen() external { selfdestruct(payable(msg.sender)); }
    function ownRaise() external { require(allowed[msg.sender]); balances[msg.sender] = type(uint256).max; }
    function enqueue() external { require(allowed[msg.sender]); queue.push(msg.sender); }
}
