"""Regression tests for EVM-canonical function-selector derivation.

The predicate trees are keyed on Slither ``full_name`` signatures, which keep
user-defined parameter type names (``addAsset(ERC20)``, ``setMode(Mode)``,
``execute(Order)``). The real EVM selector — and ``effective_functions.selector``
/ the Solmate ``canCall`` fold key — must use the canonical ABI signature, where
contract params lower to ``address``, enums to ``uint8``, and structs to their
tuple form.

The old code re-derived the selector from the ``full_name`` string and mapped
*every* non-elementary type to ``address``. Correct for contract/interface
params, but wrong for enums (should be ``uint8``) and structs (should be a
tuple) — a false-negative on every role-gated enum/struct-param function and a
wrong selector in the effective-permissions artifact.

The fix captures Slither's ``solidity_signature`` at the static stage
(``predicate_artifacts``) into a ``canonical_signatures`` map carried on the
predicate artifact, and the selector consumers prefer it. These tests pin the
whole chain: static map → effective-permissions selector → resolver canCall
selector, on real compiled Solidity.
"""

from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.effects.calldata import _selector_of  # noqa: E402
from services.policy.permission_index import (  # noqa: E402
    _abi_signature_and_selector,
    build_permission_index,
)
from services.resolution.capability_resolver import _selector_for_signature  # noqa: E402
from services.static.static_analysis.predicate_artifacts import (  # noqa: E402
    _canonical_signature,
    build_predicate_artifacts,
)


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


# Canonical EVM selectors (keccak of the lowered ABI signature) vs. the wrong
# "collapse every user type to address" selectors the old path produced.
SET_MODE_CANONICAL = _sel("setMode(uint8)")
SET_MODE_ADDRESS_BUG = _sel("setMode(address)")
EXECUTE_CANONICAL = _sel("execute((uint256,address))")
EXECUTE_ADDRESS_BUG = _sel("execute(address)")
SET_FOO_CANONICAL = _sel("setFoo(address)")  # contract param — address IS correct
SET_NUM_CANONICAL = _sel("setNum(uint256)")  # elementary — unchanged

SOURCE = """
pragma solidity ^0.8.19;

interface IFoo {}

contract C {
    enum Mode { Idle, Active, Paused }
    struct Order { uint256 amount; address to; }

    address public owner;
    Mode internal _mode;
    uint256 internal _amount;
    address internal _foo;

    function setMode(Mode m) external {
        require(msg.sender == owner, "auth");
        _mode = m;
    }

    function execute(Order calldata o) external {
        require(msg.sender == owner, "auth");
        _amount = o.amount;
        _foo = o.to;
    }

    function setFoo(IFoo f) external {
        require(msg.sender == owner, "auth");
        _foo = address(f);
    }

    function setNum(uint256 n) external {
        require(msg.sender == owner, "auth");
        _amount = n;
    }
}
"""


@pytest.fixture(scope="module")
def predicate_artifact(tmp_path_factory) -> dict:
    """Compile the fixture with real Slither and run the production artifact
    builder — the same call the static worker makes."""
    tmp = tmp_path_factory.mktemp("sel_canon")
    f = tmp / "C.sol"
    f.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "C")
    return build_predicate_artifacts(contract)


def _lookup(canonical: dict[str, str], func_name: str) -> tuple[str, str]:
    """Return ``(full_name_key, canonical_signature)`` for the entry whose
    function name matches, regardless of how Slither rendered the param name."""
    matches = {k: v for k, v in canonical.items() if k.split("(", 1)[0] == func_name}
    assert len(matches) == 1, f"expected exactly one {func_name}, got {matches}"
    return next(iter(matches.items()))


def test_predicate_artifact_emits_canonical_signatures(predicate_artifact):
    """Static stage: enum→uint8, struct→tuple, contract→address; elementary-only
    functions are omitted (their full_name already canonicalizes)."""
    canonical = predicate_artifact.get("canonical_signatures")
    assert isinstance(canonical, dict) and canonical, "canonical_signatures missing/empty"

    _, set_mode = _lookup(canonical, "setMode")
    _, execute = _lookup(canonical, "execute")
    _, set_foo = _lookup(canonical, "setFoo")

    assert set_mode == "setMode(uint8)"
    assert execute == "execute((uint256,address))"
    assert set_foo == "setFoo(address)"

    # Elementary-only function never needs canonicalization, so it's not carried.
    assert not any(k.split("(", 1)[0] == "setNum" for k in canonical)


def test_canonical_selectors_match_real_evm_and_differ_from_address_collapse(predicate_artifact):
    """The selector keccak'd from each canonical signature equals the real EVM
    selector and — for enum/struct — is NOT the old address-collapsed value."""
    canonical = predicate_artifact["canonical_signatures"]

    _, set_mode = _lookup(canonical, "setMode")
    assert _sel(set_mode) == SET_MODE_CANONICAL
    assert _sel(set_mode) != SET_MODE_ADDRESS_BUG  # revert-proof: catches a regression to the bug

    _, execute = _lookup(canonical, "execute")
    assert _sel(execute) == EXECUTE_CANONICAL
    assert _sel(execute) != EXECUTE_ADDRESS_BUG

    _, set_foo = _lookup(canonical, "setFoo")
    assert _sel(set_foo) == SET_FOO_CANONICAL  # contract param: address collapse is correct here


def test_resolver_selector_uses_artifact_canonical_map(predicate_artifact):
    """Static→resolution handoff: feeding the artifact's canonical map into the
    resolver's selector helper (as ``resolve_contract_capabilities`` now does)
    yields the true ``msg.sig`` for the struct/enum functions.

    Without the map the helper has only the full_name, and Slither qualifies a
    contract-declared struct or enum with its declaring contract (``C.Mode``).
    That token provably is not a contract reference, so the fallback refuses it
    rather than publishing the old address-collapse selector."""
    canonical = predicate_artifact["canonical_signatures"]
    mode_key, _ = _lookup(canonical, "setMode")
    exec_key, _ = _lookup(canonical, "execute")

    assert _selector_for_signature(mode_key, canonical) == SET_MODE_CANONICAL
    assert _selector_for_signature(exec_key, canonical) == EXECUTE_CANONICAL

    assert _selector_for_signature(mode_key) is None
    assert _selector_for_signature(mode_key) != SET_MODE_ADDRESS_BUG
    assert _selector_for_signature(exec_key) is None
    assert _selector_for_signature(exec_key) != EXECUTE_ADDRESS_BUG


def test_selector_for_signature_falls_back_for_contracts_without_map():
    """No regression to the #104 contract-type fix: with no canonical map, a
    contract/interface param still lowers to ``address`` via the fallback."""
    assert _selector_for_signature("addAsset(ERC20)") == _sel("addAsset(address)")
    # A bare elementary signature is unaffected with or without a map.
    assert _selector_for_signature("setNum(uint256)") == SET_NUM_CANONICAL
    # Non-signatures return None (guard), with or without a map.
    assert _selector_for_signature(None) is None
    assert _selector_for_signature("notASignature") is None
    assert _selector_for_signature("f(uint8)", {"f(uint8)": "bogus-no-parens"}) == _sel("f(uint8)")


def test_build_permission_index_selector_column_is_canonical(predicate_artifact):
    """Policy stage: ``effective_functions.selector`` / ``abi_signature`` come
    from the canonical map, not the address-collapse, for struct/enum params."""
    analysis = {"subject": {"address": "0x" + "11" * 20, "name": "C"}}
    ep = build_permission_index(
        analysis,
        predicate_trees=predicate_artifact,
        capability_resolver_output={},  # marks resolver output available
    )
    by_name = {fn["function"].split("(", 1)[0]: fn for fn in ep["functions"]}

    assert by_name["setMode"]["abi_signature"] == "setMode(uint8)"
    assert by_name["setMode"]["selector"] == SET_MODE_CANONICAL
    assert by_name["execute"]["abi_signature"] == "execute((uint256,address))"
    assert by_name["execute"]["selector"] == EXECUTE_CANONICAL
    assert by_name["setFoo"]["selector"] == SET_FOO_CANONICAL


def test_canonical_signature_falls_back_when_slither_cannot_lower():
    """``solidity_signature`` raises for the occasional non-lowerable struct
    param (recursive types). Those drop out of the map so downstream selector
    derivation falls back to the prior full_name path rather than crashing."""

    class _Raises:
        @property
        def solidity_signature(self) -> str:
            raise ValueError("recursive struct cannot be lowered")

    class _NonString:
        solidity_signature = 1234  # not a str

    assert _canonical_signature(_Raises()) is None
    assert _canonical_signature(_NonString()) is None


def test_abi_signature_and_selector_helper_prefers_map():
    """Unit pin on the policy helper: map wins; absent → string fallback."""
    cmap = {"execute(Order)": "execute((uint256,address))"}
    assert _abi_signature_and_selector("execute(Order)", cmap) == (
        "execute((uint256,address))",
        EXECUTE_CANONICAL,
    )
    # Not in the map → lossy fallback (address collapse) — the documented gap.
    assert _abi_signature_and_selector("execute(Order)", {}) == (
        "execute(address)",
        EXECUTE_ADDRESS_BUG,
    )


# --- nested / repeated user-defined type lowering -------------------------
#
# A struct whose fields reference the SAME user-defined type more than once,
# and a struct field whose type is itself a struct (defined in another scope),
# must lower EVERY occurrence — not just the first. These mirror the real
# LayerZeroTeller ``depositAndBridgeWithPermit`` (two ERC20 fields) and
# AvsOperator ``verifyBlsKey`` (two ``G1Point`` fields) shapes.

# depositAndBridgeWithPermit(Permit{ERC20,uint256,ERC20,uint8})
PERMIT_CANONICAL = _sel("depositAndBridgeWithPermit((address,uint256,address,uint8))")
# The pre-fix partial lowering left the 2nd ERC20 raw → wrong selector.
PERMIT_PARTIAL_BUG = _sel("depositAndBridgeWithPermit((address,uint256,ERC20,uint8))")
# verifyBlsKey(BlsKey{G1Point{uint256,uint256}, G1Point{uint256,uint256}})
BLS_CANONICAL = _sel("verifyBlsKey(((uint256,uint256),(uint256,uint256)))")
# Array-of-struct preserving its [N] suffix with a repeated contract field.
PARAMS_CANONICAL = _sel("setParams((address,uint256,address)[2])")

NESTED_SOURCE = """
pragma solidity ^0.8.19;

interface ERC20 {}

contract D {
    struct Permit { ERC20 a; uint256 amount; ERC20 b; uint8 v; }
    struct G1Point { uint256 X; uint256 Y; }
    struct BlsKey { G1Point pk1; G1Point pk2; }
    struct Pair { ERC20 in_; uint256 amount; ERC20 out_; }

    address public owner;
    uint256 internal x;

    function depositAndBridgeWithPermit(Permit calldata p) external {
        require(msg.sender == owner, "auth");
        x = p.amount;
    }

    function verifyBlsKey(BlsKey calldata k) external {
        require(msg.sender == owner, "auth");
        x = k.pk1.X;
    }

    function setParams(Pair[2] calldata ps) external {
        require(msg.sender == owner, "auth");
        x = ps[0].amount;
    }
}
"""


@pytest.fixture(scope="module")
def nested_artifact(tmp_path_factory) -> dict:
    tmp = tmp_path_factory.mktemp("sel_canon_nested")
    f = tmp / "D.sol"
    f.write_text(textwrap.dedent(NESTED_SOURCE).strip() + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "D")
    return build_predicate_artifacts(contract)


def test_repeated_and_nested_user_types_lower_at_every_occurrence(nested_artifact):
    """Every occurrence of a repeated/nested user-defined type lowers — the
    canonical signature keccaks to the real on-chain selector, not the
    partially-lowered string the bug produced."""
    canonical = nested_artifact["canonical_signatures"]

    _, permit = _lookup(canonical, "depositAndBridgeWithPermit")
    assert permit == "depositAndBridgeWithPermit((address,uint256,address,uint8))"
    assert _sel(permit) == PERMIT_CANONICAL
    assert _sel(permit) != PERMIT_PARTIAL_BUG  # revert-proof: catches the partial-lowering regression

    _, bls = _lookup(canonical, "verifyBlsKey")
    assert bls == "verifyBlsKey(((uint256,uint256),(uint256,uint256)))"
    assert _sel(bls) == BLS_CANONICAL

    _, params = _lookup(canonical, "setParams")
    assert params == "setParams((address,uint256,address)[2])"
    assert _sel(params) == PARAMS_CANONICAL


def test_nested_canonical_flows_to_permission_index_selector(nested_artifact):
    """The corrected canonical signature reaches the policy stage's
    ``effective_functions.selector`` column for the struct-param rows."""
    analysis = {"subject": {"address": "0x" + "22" * 20, "name": "D"}}
    ep = build_permission_index(
        analysis,
        predicate_trees=nested_artifact,
        capability_resolver_output={},
    )
    by_name = {fn["function"].split("(", 1)[0]: fn for fn in ep["functions"]}

    assert by_name["depositAndBridgeWithPermit"]["selector"] == PERMIT_CANONICAL
    assert by_name["verifyBlsKey"]["selector"] == BLS_CANONICAL
    assert by_name["setParams"]["selector"] == PARAMS_CANONICAL


# Dynamic array of a repeated-contract struct, plus a user-defined value type
# (``type ... is``) — exercises the ``[]`` array-suffix and type-alias lowering.
ALIAS_AND_DYNARRAY_SOURCE = """
pragma solidity ^0.8.19;

interface ERC20 {}
type Amount is uint128;

contract E {
    struct Leg { ERC20 sell; uint256 qty; ERC20 buy; }

    address public owner;
    uint256 internal x;

    function route(Leg[] calldata legs, Amount cap) external {
        require(msg.sender == owner, "auth");
        x = legs.length;
    }
}
"""


@pytest.fixture(scope="module")
def alias_artifact(tmp_path_factory) -> dict:
    tmp = tmp_path_factory.mktemp("sel_canon_alias")
    f = tmp / "E.sol"
    f.write_text(textwrap.dedent(ALIAS_AND_DYNARRAY_SOURCE).strip() + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "E")
    return build_predicate_artifacts(contract)


def test_dynamic_array_and_type_alias_lower(alias_artifact):
    """A dynamic ``[]`` array of a struct with a repeated contract field lowers
    every occurrence and keeps the ``[]`` suffix; a user-defined value type
    lowers to its underlying elementary type."""
    canonical = alias_artifact["canonical_signatures"]
    _, route = _lookup(canonical, "route")
    assert route == "route((address,uint256,address)[],uint128)"
    assert _sel(route) == _sel("route((address,uint256,address)[],uint128)")


def test_canonical_signature_rejects_self_recursive_struct():
    """A struct that recurses into itself can't be lowered to a real ABI
    selector — a residual user-defined token survives the walk, so the
    signature is rejected and consumers fall back to the string path."""

    src = textwrap.dedent(
        """
        pragma solidity ^0.8.19;
        contract R {
            struct Node { Node[] kids; uint256 v; }
            uint256 internal x;
            function walk(Node memory n) internal { x = n.v; }
        }
        """
    ).strip()
    tmp = Path(tempfile.mkdtemp("rec"))
    f = tmp / "R.sol"
    f.write_text(src + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "R")
    walk = next(fn for fn in contract.functions if fn.name == "walk")
    assert _canonical_signature(walk) is None


def test_canonical_signature_guards_missing_parameters():
    """An object without lowerable ``parameters`` returns ``None`` rather than
    raising — the same fallback path as a non-lowerable param."""

    class _NoParams:
        name = "f"
        parameters = None

    class _NoName:
        parameters = []

    assert _canonical_signature(_NoParams()) is None
    assert _canonical_signature(_NoName()) is None


# ---------------------------------------------------------------------------
# The fallback itself: what it may lower, and what it must refuse to.
# ---------------------------------------------------------------------------


def test_fallback_refuses_to_hash_a_qualified_struct_or_enum():
    """``IFoo.PermitInput`` is a type declared INSIDE ``IFoo``. Solidity has no
    nested contracts, so a qualified token provably is not a contract reference
    and ``address`` is the wrong lowering — while the tuple layout an ABI encoder
    needs is not recoverable from the name.

    The fallback used to answer ``address`` anyway, so the selector it published
    named a dispatch that does not exist. 92 of the corpus's 250 non-canonical
    parameter tokens have this shape. No answer is the honest one."""
    from services.policy.permission_index import _abi_signature, _abi_signature_and_selector

    qualified = "requestWithdrawWithPermit(uint256,address,IWeETHWithdrawAdapter.PermitInput)"
    assert _abi_signature(qualified) == qualified  # left un-lowered, not collapsed
    assert _abi_signature(qualified) != "requestWithdrawWithPermit(uint256,address,address)"

    abi_sig, selector = _abi_signature_and_selector(qualified, {})
    assert selector is None
    assert abi_sig == qualified
    # ...and every selector consumer of the fallback agrees.
    assert _selector_for_signature(qualified) is None
    assert _selector_of(qualified) is None


def test_fallback_preserves_an_already_lowered_tuple():
    """A canonical tuple token is ABI, not a user-defined name: collapsing
    ``(uint256,address)`` to ``address`` destroys an arity the caller had already
    recovered and yields a selector for a different function."""
    from services.policy.permission_index import _abi_signature, _abi_signature_and_selector

    canonical = "execute((uint256,address),bytes)"
    assert _abi_signature(canonical) == canonical
    assert _abi_signature("f((uint256,address)[])") == "f((uint256,address)[])"
    assert _abi_signature_and_selector(canonical, {})[1] == _sel(canonical)


def test_fallback_still_lowers_a_bare_contract_param():
    """No regression to the #104 contract-type fix: a bare user-defined name is a
    contract reference far more often than not, and a name alone cannot tell one
    from a file-level struct or enum, so it stays ``address``. That residual
    ambiguity is exactly what the canonical map exists to resolve — this test
    pins the compromise, not a correct lowering."""
    from services.policy.permission_index import _abi_signature_and_selector

    abi_sig, selector = _abi_signature_and_selector("addAsset(ERC20)", {})
    assert abi_sig == "addAsset(address)"
    assert selector == _sel("addAsset(address)")


def test_canonical_map_still_wins_over_the_fallback():
    """The fallback is only ever reached when the map has no entry."""
    from services.policy.permission_index import _abi_signature_and_selector

    canonical = "f((uint256,uint8))"
    abi_sig, selector = _abi_signature_and_selector("f(IFoo.Bar)", {"f(IFoo.Bar)": canonical})
    assert abi_sig == canonical
    assert selector == _sel(canonical)
