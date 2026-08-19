"""Regression tests for the Plane-0 facts hardening in ``effects.py``.

Each test compiles a real Solidity fixture with Slither and drives the
production ``build_effects`` -> ``build_claims`` -> ``project_effect_labels``
sequence — no fakes, only the solc compile is real. Precedent:
``tests/policy/test_selector_canonicalization.py``.

The six hardening fixes (spec §3 FACT records / §5 facts-plane prerequisites):
  (a) sink ``origin`` in {body, guard} — a modifier's own auth call is a guard
      fact, not an effect;
  (b) ``build_effects`` keying prefers a concrete body over a 0-node interface
      re-declaration;
  (c) member-level write facts ``(var, member_path)`` with declared types;
  (d) ``hygiene_class`` on writes, and the ownership harvest gated on
      hygiene-clean scalar address vars;
  (e) native ``transfer``/``send`` become value sinks;
  (f) ``transferFrom`` direction corrected when ``from == address(this)``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import (  # noqa: E402
    attach_claims_to_effects,
    build_claims,
    project_effect_labels,
)
from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    SCHEMA_VERSION,
    build_effects,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)


def _compile(tmp_path: Path, source: str, name: str):
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == name)


def _effects_with_labels(contract):
    """Facts + Plane-1 claims + the effect-label projection, exactly as core.py
    runs them (the claim projection is what now emits ``ownership_transfer``)."""
    predicate_trees, _pause = build_predicate_artifacts_with_pause_info(contract)
    effects = build_effects(contract)
    claims_artifact = build_claims(contract, effects, predicate_trees)
    attach_claims_to_effects(effects, claims_artifact)
    project_effect_labels(effects)
    return effects


def _info(effects, signature):
    info = effects["functions"].get(signature)
    assert info is not None, f"expected {signature} in {sorted(effects['functions'])}"
    return info


def _sink(info, kind, target_contains):
    matches = [s for s in info["sinks"] if s["kind"] == kind and target_contains in s["target"]]
    assert matches, (
        f"no {kind} sink containing {target_contains!r} in {[(s['kind'], s['target']) for s in info['sinks']]}"
    )
    return matches[0]


# --- (a) sink origin: body vs guard -------------------------------------

_GUARD_ORIGIN_SRC = """
pragma solidity ^0.8.20;
interface Authority { function canCall(address u, address t, bytes4 s) external view returns (bool); }
interface Pinger { function ping(uint256 v) external; }
abstract contract Auth {
    address public owner;
    Authority public authority;
    modifier requiresAuth() { require(isAuthorized(msg.sender, msg.sig), "no"); _; }
    function isAuthorized(address u, bytes4 s) internal view returns (bool) {
        Authority a = authority;
        return (address(a) != address(0) && a.canCall(u, address(this), s)) || u == owner;
    }
}
contract Svc is Auth {
    bool public isPaused;
    function pause() external requiresAuth { isPaused = true; }
    function poke(Pinger t, uint256 v) external requiresAuth { t.ping(v); }
}
"""


def test_modifier_auth_call_is_guard_origin_and_never_an_effect(tmp_path):
    """The ``requiresAuth`` modifier's ``authority.canCall`` is reached only
    through the modifier, so it's a guard-origin sink and does NOT make
    ``pause()`` an ``external_contract_call``. A real body call (``t.ping``)
    stays body-origin and does drive the label."""
    contract = _compile(tmp_path, _GUARD_ORIGIN_SRC, "Svc")
    effects = build_effects(contract)

    pause = _info(effects, "pause()")
    assert _sink(pause, "external_call", "canCall")["origin"] == "guard"
    assert _sink(pause, "state_write", "isPaused")["origin"] == "body"
    # The only external call is the guard's — the effect is not diluted.
    assert "external_contract_call" not in pause["effect_labels"]

    poke = _info(effects, "poke(Pinger,uint256)")
    assert _sink(poke, "external_call", "ping")["origin"] == "body"
    assert _sink(poke, "external_call", "canCall")["origin"] == "guard"
    # A genuine body call still surfaces as an external_contract_call.
    assert "external_contract_call" in poke["effect_labels"]


# --- (b) concrete body preferred over 0-node interface re-declaration ----

_CLOBBER_SRC = """
pragma solidity ^0.8.20;
interface IPausable {
    function pause(uint256 status) external;
}
abstract contract Pausable is IPausable {
    uint256 internal _paused;
    function pause(uint256 status) public virtual override { _paused = status; }
}
contract Manager is Pausable {
    uint256 public x;
    function setX(uint256 v) external { x = v; }
}
"""


def test_concrete_body_wins_over_zero_node_interface_declaration(tmp_path):
    """``Manager`` inherits both the concrete ``Pausable.pause`` and the
    0-node ``IPausable.pause`` interface declaration under one ``full_name``.
    Keying by ``full_name`` alone lets the interface clobber the real record
    and blank its sinks; the fix keeps the implemented body."""
    contract = _compile(tmp_path, _CLOBBER_SRC, "Manager")

    # Precondition: the clobber scenario really exists (two records, one blank).
    pause_fns = [fn for fn in contract.functions if fn.full_name == "pause(uint256)"]
    assert len(pause_fns) >= 2
    assert any(not getattr(fn, "nodes", None) for fn in pause_fns), "expected a 0-node interface re-declaration"

    effects = build_effects(contract)
    pause = _info(effects, "pause(uint256)")
    assert _sink(pause, "state_write", "_paused")["target"] == "_paused"
    # writer_selectors is only populated when the implemented body is chosen.
    assert pause["writer_selectors"] == [pause["selector"]]


# --- (c) member-level write facts ---------------------------------------

_MEMBER_SRC = """
pragma solidity ^0.8.20;
contract Accountant {
    struct State { bool isPaused; address payoutAddress; uint24 delay; }
    State internal s;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function pause() external onlyOwner { s.isPaused = true; }
    function setPayout(address p) external onlyOwner { s.payoutAddress = p; }
    function setDelay(uint24 d) external onlyOwner { s.delay = d; }
}
"""


def test_member_write_facts_carry_member_path_and_declared_type(tmp_path):
    """Writing ``s.isPaused`` vs. ``s.payoutAddress`` produces distinct member
    facts with the member's own declared type — the substrate a pause claim
    needs to tell the bool member from the address member of one struct."""
    contract = _compile(tmp_path, _MEMBER_SRC, "Accountant")
    effects = build_effects(contract)

    def member_fact(signature):
        writes = [sw for sw in _info(effects, signature)["state_writes"] if sw["granularity"] == "member"]
        assert len(writes) == 1, writes
        return writes[0]

    pause_fact = member_fact("pause()")
    assert pause_fact["var"] == "s"
    assert pause_fact["member_path"] == ["isPaused"]
    assert pause_fact["declared_type"] == "bool"

    payout_fact = member_fact("setPayout(address)")
    assert payout_fact["member_path"] == ["payoutAddress"]
    assert payout_fact["declared_type"] == "address"

    delay_fact = member_fact("setDelay(uint24)")
    assert delay_fact["member_path"] == ["delay"]
    assert delay_fact["declared_type"] == "uint24"


# --- (d) hygiene classes + ownership harvest gate -----------------------

# OZ v5 namespaced-storage Ownable: Slither attributes the bytes32 slot
# *constant* ``OwnableStorageLocation`` as "written" by every function that
# touches the namespaced storage — including the ``owner()`` view.
_OZ_V5_SRC = """
pragma solidity ^0.8.20;
abstract contract OwnableUpgradeable {
    bytes32 constant OwnableStorageLocation = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
    struct OwnableStorage { address _owner; }
    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly { $.slot := OwnableStorageLocation }
    }
    function owner() public view returns (address) { return _getOwnableStorage()._owner; }
    modifier onlyOwner() { require(owner() == msg.sender, "no"); _; }
    function transferOwnership(address n) public onlyOwner { _getOwnableStorage()._owner = n; }
}
contract Vault is OwnableUpgradeable {
    address public token;
    function setToken(address t) public onlyOwner { token = t; }
}
"""


def test_oz_v5_slot_constant_ghost_is_not_ownership_and_is_hygiene_tagged(tmp_path):
    """Ghost-immunity via standards, not write identity: the ``ownership.*``
    matcher keys on the canonical ``transferOwnership`` selector + the
    ``owner()`` getter sibling, so ``transferOwnership`` IS tagged even on OZ v5
    namespaced storage — while the ``owner()`` view and the unrelated
    ``setToken`` setter (which also "write" the ``OwnableStorageLocation`` slot
    constant per Slither) are NOT. The ghost writes stay recorded with a hygiene
    class (``view_writer`` / ``storage_location_pseudo``)."""
    contract = _compile(tmp_path, _OZ_V5_SRC, "Vault")
    effects = _effects_with_labels(contract)

    assert "ownership_transfer" in _info(effects, "transferOwnership(address)")["effect_labels"]
    for signature in ("owner()", "setToken(address)"):
        assert "ownership_transfer" not in _info(effects, signature)["effect_labels"], signature

    # A view "writing" the slot constant is a ghost.
    owner_write = _sink(_info(effects, "owner()"), "state_write", "OwnableStorageLocation")
    assert owner_write["origin"] == "body"
    owner_fact = next(sw for sw in _info(effects, "owner()")["state_writes"] if sw["var"] == "OwnableStorageLocation")
    assert owner_fact["hygiene_class"] == "view_writer"

    set_token_facts = {sw["var"]: sw for sw in _info(effects, "setToken(address)")["state_writes"]}
    assert set_token_facts["token"]["hygiene_class"] == "normal"
    assert set_token_facts["OwnableStorageLocation"]["hygiene_class"] == "storage_location_pseudo"


_OZ_V4_OWNABLE_SRC = """
pragma solidity ^0.8.20;
abstract contract Ownable {
    address private _owner;
    modifier onlyOwner() { require(owner() == msg.sender, "no"); _; }
    function owner() public view returns (address) { return _owner; }
    function transferOwnership(address n) public onlyOwner { _owner = n; }
}
contract Token is Ownable {
    uint256 public x;
    function setX(uint256 v) external onlyOwner { x = v; }
}
"""


def test_hygiene_gate_keeps_real_address_owner_ownership(tmp_path):
    """The gate drops slot constants, not real pointers: a plain
    ``address private _owner`` still yields ``ownership_transfer`` on its
    setter (control for the OZ v5 ghost test)."""
    contract = _compile(tmp_path, _OZ_V4_OWNABLE_SRC, "Token")
    effects = _effects_with_labels(contract)

    assert "ownership_transfer" in _info(effects, "transferOwnership(address)")["effect_labels"]
    owner_fact = next(
        sw for sw in _info(effects, "transferOwnership(address)")["state_writes"] if sw["var"] == "_owner"
    )
    assert owner_fact["hygiene_class"] == "normal"


_REENTRANCY_SRC = """
pragma solidity ^0.8.20;
abstract contract ReentrancyGuard {
    uint256 private _status;
    constructor() { _status = 1; }
    modifier nonReentrant() { require(_status != 2, "reentrant"); _status = 2; _; _status = 1; }
}
contract Pool is ReentrancyGuard {
    uint256 public x;
    function doWork(uint256 v) external nonReentrant { x = v; }
}
"""


def test_reentrancy_guard_write_is_guard_origin_and_hygiene_tagged(tmp_path):
    """The ``_status`` write lives in the ``nonReentrant`` modifier, so it is
    a guard-origin, ``reentrancy_guard``-hygiene fact, kept apart from the
    body write ``x``."""
    contract = _compile(tmp_path, _REENTRANCY_SRC, "Pool")
    effects = build_effects(contract)
    facts = {sw["var"]: sw for sw in _info(effects, "doWork(uint256)")["state_writes"]}
    assert facts["_status"]["hygiene_class"] == "reentrancy_guard"
    assert facts["_status"]["origin"] == "guard"
    assert facts["x"]["hygiene_class"] == "normal"
    assert facts["x"]["origin"] == "body"


# --- (e) native transfer/send are value sinks ---------------------------

_NATIVE_TRANSFER_SRC = """
pragma solidity ^0.8.20;
contract W {
    mapping(address => uint256) public balanceOf;
    function deposit() public payable { balanceOf[msg.sender] += msg.value; }
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
    }
    function withdrawViaSend(uint256 wad) public {
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).send(wad);
    }
}
"""


def test_native_transfer_and_send_become_asset_send(tmp_path):
    """``.transfer()``/``.send()`` lower to their own IR op (not a low-level
    call), so the old scan missed them and the balance-map setters fell to the
    ``hook_update`` fallback. They are now outbound value flows → ``asset_send``."""
    contract = _compile(tmp_path, _NATIVE_TRANSFER_SRC, "W")
    effects = build_effects(contract)

    withdraw = _info(effects, "withdraw(uint256)")
    flows = withdraw["value_flows"]
    assert any(vf["kind"] == "native_transfer_send" and vf["direction"] == "out" for vf in flows), flows
    assert "asset_send" in withdraw["effect_labels"]
    assert "hook_update" not in withdraw["effect_labels"]

    send = _info(effects, "withdrawViaSend(uint256)")
    assert any(vf["kind"] == "native_transfer_send" for vf in send["value_flows"])
    assert "asset_send" in send["effect_labels"]

    # deposit takes ETH in but sends nothing out: no native value flow.
    assert not _info(effects, "deposit()")["value_flows"]


# --- (f) transferFrom direction correction ------------------------------

_DIRECTION_SRC = """
pragma solidity ^0.8.20;
interface IERC721 {
    function transferFrom(address from, address to, uint256 id) external;
}
contract Rec {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function recover(address token, address to, uint256 id) external onlyOwner {
        IERC721(token).transferFrom(address(this), to, id);
    }
    function pull(address token, address from, uint256 id) external onlyOwner {
        IERC721(token).transferFrom(from, address(this), id);
    }
}
"""


def test_transferfrom_from_self_is_asset_send_not_pull(tmp_path):
    """``transferFrom(address(this), to, id)`` sends OUT — the selector alone
    reads as a pull, so the ``from == address(this)`` fact corrects it to
    ``asset_send``. A genuine ``transferFrom(from, address(this), id)`` stays
    ``asset_pull``."""
    contract = _compile(tmp_path, _DIRECTION_SRC, "Rec")
    effects = build_effects(contract)

    recover = _info(effects, "recover(address,address,uint256)")
    out_flow = next(vf for vf in recover["value_flows"] if vf["kind"] == "callee_erc20_selector")
    assert out_flow["from_is_self"] is True
    assert out_flow["direction"] == "out"
    assert "asset_send" in recover["effect_labels"]
    assert "asset_pull" not in recover["effect_labels"]

    pull = _info(effects, "pull(address,address,uint256)")
    in_flow = next(vf for vf in pull["value_flows"] if vf["kind"] == "callee_erc20_selector")
    assert in_flow["from_is_self"] is False
    assert in_flow["direction"] == "in"
    assert "asset_pull" in pull["effect_labels"]
    assert "asset_send" not in pull["effect_labels"]


_ASSEMBLY_SLOT_SRC = """
pragma solidity ^0.8.20;
contract A {
    function setSlot(uint256 v) external {
        assembly { sstore(0x42, v) }
    }
}
"""


def test_inline_assembly_write_is_assembly_slot_granularity(tmp_path):
    """An inline-assembly ``sstore`` write (no named state var) is recorded as
    an ``assembly_slot`` state-write fact."""
    contract = _compile(tmp_path, _ASSEMBLY_SLOT_SRC, "A")
    effects = build_effects(contract)
    facts = _info(effects, "setSlot(uint256)")["state_writes"]
    assembly_facts = [sw for sw in facts if sw["granularity"] == "assembly_slot"]
    assert len(assembly_facts) == 1, facts
    assert assembly_facts[0]["var"].startswith("assembly_storage:")
    assert assembly_facts[0]["hygiene_class"] == "normal"
    assert assembly_facts[0]["member_path"] == []


def test_schema_version_bumped_for_additive_fact_fields(tmp_path):
    """The additive facts (``origin``, ``state_writes``, ``value_flows``) bump
    the artifact schema version."""
    contract = _compile(tmp_path, _MEMBER_SRC, "Accountant")
    artifact = build_effects(contract)
    assert artifact["schema_version"] == SCHEMA_VERSION == "semantic-3"


# ---------------------------------------------------------------------------
# Probe-input facts: which argument is the quantity, and can the target take ETH
# ---------------------------------------------------------------------------

_PROBE_INPUT_SRC = """
    pragma solidity ^0.8.20;

    contract Redeemer {
        mapping(uint256 => address) public ownerOf;

        // A quantity and a clock value, plus an id-keyed redemption: the three
        // argument roles a prober must tell apart.
        function payOut(address to, uint256 amount, uint256 deadline) external {
            require(block.timestamp <= deadline);
            payable(to).transfer(amount);
        }

        function redeem(uint256 tokenId) external {
            require(ownerOf[tokenId] == msg.sender);
            delete ownerOf[tokenId];
        }

        function deposit() external payable {}
    }
"""


def test_parameter_names_and_payability_are_recorded(tmp_path):
    """A prober cannot tell a quantity from a token id without the declared
    names, and cannot know a ``msg.value`` attempt is doomed without payability.
    Both are ABI facts the compiler already has."""
    contract = _compile(tmp_path, _PROBE_INPUT_SRC, "Redeemer")
    effects = build_effects(contract)

    pay = _info(effects, "payOut(address,uint256,uint256)")
    assert pay["parameter_names"] == ["to", "amount", "deadline"]
    assert pay["payable"] is False
    assert _info(effects, "redeem(uint256)")["parameter_names"] == ["tokenId"]
    assert _info(effects, "deposit()")["payable"] is True


def test_value_flow_records_which_parameter_carries_the_amount(tmp_path):
    """``amount_param_index`` is the dispositive answer to "which argument is the
    quantity" — the mirror of ``target_param_index`` for the destination."""
    contract = _compile(tmp_path, _PROBE_INPUT_SRC, "Redeemer")
    effects = build_effects(contract)
    flows = [f for f in _info(effects, "payOut(address,uint256,uint256)")["value_flows"] if f["direction"] == "out"]
    assert flows, "expected a native transfer out"
    assert any(f.get("amount_kind", {}).get("kind") == "param" for f in flows)
    assert {f.get("amount_param_index") for f in flows} == {1}
    # ...and the destination slot is still resolved independently.
    assert {f.get("target_param_index") for f in flows} == {0}
