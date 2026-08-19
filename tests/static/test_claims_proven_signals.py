"""Claims must rest on what the chain publishes, not on what identifiers say.

Every fixture here is deliberately named OFF the conventional vocabulary — the
pause latch is not called ``paused``, the delegation ledger is not called
``delegates``, the supply variable does not exist — so a matcher that still keys
on identifier text cannot pass. Each positive is paired with a same-vocabulary
near-miss whose published ABI (selector set / event topic0) does not match the
standard, which must therefore earn no claim, or a strictly weaker tier.

Compiles the real static stack (Slither -> predicate artifacts -> effects ->
build_claims) on solc 0.8.27, the version the offline CI ``test`` job installs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")

from tests.support.label_corpus import (
    SolcNotInstalled,
    _foundry_env,
    _run_static_sequence,
    _solc_select_binary,
)

pytestmark = pytest.mark.compile

# --- fixtures ---------------------------------------------------------------

# OZ Pausable's published ABI (pause/unpause/paused) with a latch named nothing
# like "paused". Only the selector set can recognize this as the standard.
_OFF_VOCABULARY_PAUSABLE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract OffVocabularyPausable {
    address public steward;
    bool private _haltState;
    mapping(address => uint256) public ledger;

    modifier onlySteward() {
        require(msg.sender == steward, "not steward");
        _;
    }

    constructor() {
        steward = msg.sender;
    }

    function paused() public view returns (bool) {
        return _haltState;
    }

    function pause() external onlySteward {
        _haltState = true;
    }

    function unpause() external onlySteward {
        _haltState = false;
    }

    function move(address to, uint256 amount) external {
        require(!_haltState, "halted");
        ledger[msg.sender] -= amount;
        ledger[to] += amount;
    }
}
"""

# The mirror image: a latch literally named ``paused`` and togglers literally
# named pause/unpause, but no ``paused()`` in the ABI, so the OZ Pausable entry
# set is incomplete. The claim must still be minted — the toggle is real — at the
# idiom tier, never as a standard proof.
_NAME_ONLY_PAUSABLE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract NameOnlyPausable {
    address public steward;
    bool private paused;
    mapping(address => uint256) public ledger;

    modifier onlySteward() {
        require(msg.sender == steward, "not steward");
        _;
    }

    constructor() {
        steward = msg.sender;
    }

    function pause() external onlySteward {
        paused = true;
    }

    function unpause() external onlySteward {
        paused = false;
    }

    function move(address to, uint256 amount) external {
        require(!paused, "halted");
        ledger[msg.sender] -= amount;
        ledger[to] += amount;
    }
}
"""

# Comp/OZ-Votes delegation whose ledgers are named ``_agentOf`` / ``_voteLog``.
# Only the DelegateChanged topic0 can prove this is the voting-power move.
_OFF_VOCABULARY_VOTES = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract OffVocabularyVotes {
    mapping(address => address) private _agentOf;
    mapping(address => uint256) private _voteLog;
    mapping(address => uint256) public balanceOf;

    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);
    event DelegateVotesChanged(address indexed delegate, uint256 previousBalance, uint256 newBalance);

    function delegate(address to) external {
        address previous = _agentOf[msg.sender];
        _agentOf[msg.sender] = to;
        emit DelegateChanged(msg.sender, previous, to);
        _shiftVotes(previous, to, balanceOf[msg.sender]);
    }

    function _shiftVotes(address from, address to, uint256 amount) internal {
        uint256 next = _voteLog[to] + amount;
        _voteLog[to] = next;
        emit DelegateVotesChanged(to, next - amount, next);
        if (from != address(0)) {
            _voteLog[from] -= amount;
        }
    }

    /// Same shape of state write, no governance log — not a delegation.
    function assignAgent(address to) external {
        _agentOf[msg.sender] = to;
        _voteLog[to] += 1;
    }
}
"""

# WETH9's real shape: no supply variable at all, and no ``Transfer`` on wrap
# (WETH9 emits its own Deposit/Withdrawal). The only honest supply evidence is
# the observed one-directional balance write.
_WETH9_SHAPE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract Weth9Shape {
    string public name = "Wrapped Ether";
    string public symbol = "WETH";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "insufficient");
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient");
        if (src != msg.sender) {
            require(allowance[src][msg.sender] >= wad, "allowance");
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }
}
"""

# A UUPS-free proxy shape whose marker log is NAMED ``Upgraded`` but carries a
# different argument list, so its topic0 is not EIP-1967's. Nothing else on the
# contract is a proxy, so the upgrade/admin claims must not fire.
_WRONG_TOPIC_UPGRADED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract WrongTopicUpgraded {
    address public admin;
    address public strategy;

    // Same event NAME as EIP-1967, different arguments -> different topic0.
    event Upgraded(address indexed implementation, uint256 version);
    event AdminChanged(address newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function upgradeTo(address newStrategy) external onlyAdmin {
        strategy = newStrategy;
        emit Upgraded(newStrategy, 1);
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
        emit AdminChanged(newAdmin);
    }
}
"""

# The EIP-1967 logs with their published argument lists: same contract shape,
# real topic0s, so both claims land.
_RIGHT_TOPIC_UPGRADED = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract RightTopicUpgraded {
    address public admin;
    address public strategy;

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function upgradeTo(address newImplementation) external onlyAdmin {
        strategy = newImplementation;
        emit Upgraded(newImplementation);
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        emit AdminChanged(admin, newAdmin);
        admin = newAdmin;
    }
}
"""

# ``callee_pointer.rotate`` grants its principal the admin capability, so the
# pointer test must read the resolved type. ``Config`` is a STRUCT — capitalised,
# but not callable — while ``hook`` is a real interface reference.
_STRUCT_IS_NOT_A_POINTER = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

interface ITransferHook {
    function beforeTransfer(address from, address to) external view;
}

contract StructIsNotAPointer {
    struct Config {
        uint64 feeBps;
        uint64 window;
    }

    enum Mode {
        Open,
        Closed
    }

    address public owner;
    Config public config;
    Mode public mode;
    ITransferHook public hook;
    address payable public feeSink;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setConfig(uint64 feeBps, uint64 window) external onlyOwner {
        config = Config(feeBps, window);
    }

    function setMode(Mode newMode) external onlyOwner {
        mode = newMode;
    }

    function setHook(address newHook) external onlyOwner {
        hook = ITransferHook(newHook);
    }

    function setFeeSink(address payable newSink) external onlyOwner {
        feeSink = newSink;
    }

    function transfer(address to, uint256 amount) external {
        hook.beforeTransfer(msg.sender, to);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function settle(uint256 amount) external payable {
        balanceOf[msg.sender] -= amount;
        (bool ok,) = feeSink.call{value: amount}("");
        require(ok, "sink");
    }
}
"""

# The WETH gate with nothing minted: a full ERC-20 exposing deposit()/withdraw()
# that only forwards the native value on. The gate is satisfied and the wrap
# idiom would "explain" it, but no supply or share balance ever moves.
_WETH_GATE_NO_SUPPLY_MOVE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract ForwardingVault {
    string public name = "Forwarding Vault";
    string public symbol = "FWD";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address payable public treasury;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Forwarded(address indexed src, uint256 wad);

    constructor(address payable t) {
        treasury = t;
    }

    /// Wraps nothing: the native value goes straight out, no credit is issued.
    function deposit() public payable {
        (bool ok,) = treasury.call{value: msg.value}("");
        require(ok, "forward");
        emit Forwarded(msg.sender, msg.value);
    }

    /// Unwraps nothing: a pull from the treasury, with no balance debited.
    function withdraw(uint256 wad) public {
        require(msg.sender == treasury, "not treasury");
        emit Forwarded(msg.sender, wad);
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient");
        if (src != msg.sender) {
            require(allowance[src][msg.sender] >= wad, "allowance");
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }
}
"""


# --- harness ----------------------------------------------------------------


def _claims(source: str, contract_name: str) -> dict[str, list[Any]]:
    from slither import Slither

    binary = _solc_select_binary("0.8.27")
    if not binary.exists():
        raise SolcNotInstalled(f"solc 0.8.27 is not installed via solc-select (expected {binary})")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"{contract_name}.sol"
        path.write_text(source)
        with _foundry_env(binary):
            slither = Slither(str(path), solc=str(binary))
            _subject, _effects, _trees, artifact = _run_static_sequence(slither, {"name": contract_name})
    return artifact["functions"]


def _compiled(source: str, contract_name: str) -> dict[str, list[Any]]:
    try:
        return _claims(source, contract_name)
    except SolcNotInstalled as exc:  # pragma: no cover - only when a solc version is absent
        pytest.skip(str(exc))


def _ids(claims: list[Any]) -> set[str]:
    return {c["claim_id"] for c in claims}


def _tier(claims: list[Any], claim_id: str) -> str:
    matches = [c for c in claims if c["claim_id"] == claim_id]
    assert len(matches) == 1, f"expected exactly one {claim_id}, got {[c['claim_id'] for c in claims]}"
    return matches[0]["tier"]


# --- pause ------------------------------------------------------------------


def test_pause_standard_tier_survives_an_off_vocabulary_flag():
    """The latch is ``_haltState``; the contract publishes OZ Pausable's entry
    set. The standard tier must come from the ABI, so it survives the rename."""
    fns = _compiled(_OFF_VOCABULARY_PAUSABLE, "OffVocabularyPausable")
    assert _tier(fns["pause()"], "pause.set") == "standard_exact"
    assert _tier(fns["unpause()"], "pause.unset") == "standard_exact"
    assert "pause.unset" not in _ids(fns["pause()"])
    assert "pause.set" not in _ids(fns["unpause()"])


def test_pause_standard_tier_is_not_earned_by_the_flag_name_alone():
    """Flag named ``paused``, togglers named pause/unpause — but the flag is
    private, so ``paused()`` is not in the ABI and OZ Pausable's entry set is
    incomplete. The toggle is still real, so the claim degrades rather than
    disappearing."""
    fns = _compiled(_NAME_ONLY_PAUSABLE, "NameOnlyPausable")
    assert _tier(fns["pause()"], "pause.set") == "idiom_structural"
    assert _tier(fns["unpause()"], "pause.unset") == "idiom_structural"


# --- gov.delegate -----------------------------------------------------------


def test_gov_delegate_proven_by_the_delegate_changed_topic():
    """Ledgers named ``_agentOf`` / ``_voteLog``: only the published
    ``DelegateChanged`` topic0 can recognize the delegation."""
    fns = _compiled(_OFF_VOCABULARY_VOTES, "OffVocabularyVotes")
    assert _tier(fns["delegate(address)"], "gov.delegate") == "standard_exact"
    claim = next(c for c in fns["delegate(address)"] if c["claim_id"] == "gov.delegate")
    assert claim["witness"]["kind"] == "delegate_changed_log"


def test_gov_delegate_near_miss_same_writes_without_the_log():
    """``assignAgent`` writes the very same two maps but emits no governance log
    — no delegation claim."""
    fns = _compiled(_OFF_VOCABULARY_VOTES, "OffVocabularyVotes")
    assert "gov.delegate" not in _ids(fns["assignAgent(address)"])


# --- supply -----------------------------------------------------------------


def test_weth9_wrap_unwrap_supply_is_observed_not_assumed():
    """WETH9 publishes no supply variable and emits no zero-address ``Transfer``
    on wrap, so both name-independent supply paths are silent; the wrap arm may
    claim only because the balance write is observed to move one way."""
    fns = _compiled(_WETH9_SHAPE, "Weth9Shape")
    assert _tier(fns["deposit()"], "supply.mint") == "idiom_structural"
    assert _tier(fns["withdraw(uint256)"], "supply.burn") == "idiom_structural"
    for signature, kind in (("deposit()", "supply.mint"), ("withdraw(uint256)", "supply.burn")):
        claim = next(c for c in fns[signature] if c["claim_id"] == kind)
        assert claim["witness"]["kind"] in ("weth_wrap", "weth_unwrap"), claim["witness"]
    # A ledger move between two holders creates nothing.
    assert not _ids(fns["transferFrom(address,address,uint256)"]) & {"supply.mint", "supply.burn"}
    assert not _ids(fns["approve(address,uint256)"]) & {"supply.mint", "supply.burn"}


def test_weth_gate_alone_does_not_mint_a_supply_claim():
    """The near-miss the corroboration exists for: the wrap/unwrap ABI on a
    contract that forwards the native value instead of issuing or destroying any
    balance. The gate is signature-exact, so only observing the (absent) supply
    move keeps the inference honest."""
    fns = _compiled(_WETH_GATE_NO_SUPPLY_MOVE, "ForwardingVault")
    assert not _ids(fns["deposit()"]) & {"supply.mint", "supply.burn"}
    assert not _ids(fns["withdraw(uint256)"]) & {"supply.mint", "supply.burn"}
    # The user-plane wrap claims are a separate, honest statement about the ABI.
    assert "weth.deposit" in _ids(fns["deposit()"])


# --- upgrade / proxy admin --------------------------------------------------


def test_upgrade_gate_rejects_a_same_named_event_with_a_different_topic():
    """``event Upgraded(address,uint256)`` is not EIP-1967's ``Upgraded(address)``
    — different topic0, so the contract is not a recognizable proxy and the
    upgrade selector alone earns nothing."""
    fns = _compiled(_WRONG_TOPIC_UPGRADED, "WrongTopicUpgraded")
    assert "upgrade.implementation" not in _ids(fns["upgradeTo(address)"])
    assert "proxy.admin_change" not in _ids(fns["changeAdmin(address)"])


def test_upgrade_gate_accepts_the_published_1967_topics():
    """Same contract shape, the real EIP-1967 argument lists: both claims land,
    proving the negative above is the topic and not the shape."""
    fns = _compiled(_RIGHT_TOPIC_UPGRADED, "RightTopicUpgraded")
    assert _tier(fns["upgradeTo(address)"], "upgrade.implementation") == "standard_exact"
    assert _tier(fns["changeAdmin(address)"], "proxy.admin_change") == "standard_exact"


# --- callee_pointer.rotate --------------------------------------------------


def test_callee_pointer_reads_the_type_not_the_capitalisation():
    """``config`` renders as ``StructIsNotAPointer.Config`` and ``mode`` as
    ``StructIsNotAPointer.Mode`` — capitalised, so a rendered-text test admits
    both as candidate code pointers. Neither is callable, so neither setter may
    claim the rotate (whose consumer grants the admin capability), while ``hook``
    — a real interface reference — does."""
    fns = _compiled(_STRUCT_IS_NOT_A_POINTER, "StructIsNotAPointer")
    assert "callee_pointer.rotate" not in _ids(fns["setConfig(uint64,uint64)"])
    assert "callee_pointer.rotate" not in _ids(fns["setMode(StructIsNotAPointer.Mode)"])
    assert _tier(fns["setHook(address)"], "callee_pointer.rotate") == "idiom_structural"


def test_callee_pointer_still_recognizes_a_plain_address_pointer():
    """Recall pin for the type-object rewrite: ``feeSink`` is an
    ``address payable`` a sibling invokes as a call destination, and it must keep
    its rotate."""
    fns = _compiled(_STRUCT_IS_NOT_A_POINTER, "StructIsNotAPointer")
    claim = next(c for c in fns["setFeeSink(address)"] if c["claim_id"] == "callee_pointer.rotate")
    assert claim["tier"] == "idiom_structural"
    assert any(link["pointer"] == "feeSink" for link in claim["witness"]["links"])
