pragma solidity 0.8.27;

// The in-scope system is this vault: deposits create redeemable user credits.
contract ImpactVault {
    address public owner;
    bool public paused;
    uint16 public feeBps;
    mapping(address => uint256) public credits;
    string public caption;

    constructor() { owner = msg.sender; }

    function deposit() external payable { credits[msg.sender] += msg.value; }

    function withdrawOwn(uint256 amount) external {
        require(!paused && credits[msg.sender] >= amount);
        credits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount * (10000 - feeBps) / 10000);
    }

    function seize(address payable to) external {
        require(msg.sender == owner);
        to.transfer(address(this).balance);
    }

    function issue(address who, uint256 amount) external {
        require(msg.sender == owner);
        credits[who] += amount;
    }

    function nominate(address next) external {
        require(msg.sender == owner);
        owner = next;
    }

    function halt(bool value) external {
        require(msg.sender == owner);
        paused = value;
    }

    function boundedFee(uint16 value) external {
        require(msg.sender == owner && value <= 10);
        feeBps = value;
    }

    function changeCaption(string calldata value) external {
        require(msg.sender == owner);
        caption = value;
    }
}
