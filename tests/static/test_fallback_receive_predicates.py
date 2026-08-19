"""``fallback`` / ``receive`` as first-class entry points.

Two defects, one shape: having no 4-byte selector was treated as having no
caller.

1. ``predicate_artifacts._is_externally_callable`` excluded them, so a
   predicate tree was never *built* for a fallback/receive. The policy stage
   reads a missing tree as "no gate found", so an owner-gated fallback
   published exactly the evidence an open one does. Measured on the local
   corpus: 27 fallback/receive records across 88 replayed contracts, 0 with a
   tree; two of the seven that reach ``effective_functions`` --
   PriorityWithdrawalQueue and WithdrawRequestNFT -- gate ``receive()`` on
   ``msg.sender != address(liquidityPool)`` and were published
   ``authority_public = True``.

2. Slither renders their signatures as ``fallback()`` / ``receive()``, which
   every string-level canonicality test accepted and hashed:
   ``keccak("fallback()")[:4] = 0x552079dc`` and
   ``keccak("receive()")[:4] = 0xa3e76c0f`` were persisted as selectors on 7
   ``effective_functions`` rows. Neither is a dispatch any caller can send.
   ``db/effect_cache.py`` already fixes ``""`` as the sentinel for this case.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import _abi_signature_and_selector  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
    has_no_selector,
    is_canonical_abi_signature,
)

SOURCE = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        uint256 public total;
        // Gated fallback: a tree MUST be built and MUST carry the owner gate.
        fallback() external payable {
            require(msg.sender == owner, "not owner");
            total += msg.value;
        }
        // Open receive: a tree is attempted and legitimately finds nothing.
        receive() external payable {
            total += msg.value;
        }
        // Control: an ordinary selector-bearing entry point.
        function contribute() external payable {
            total += msg.value;
        }
    }
"""


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    path = tmp_path_factory.mktemp("classr") / "C.sol"
    path.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    slither = Slither(str(path))
    return next(c for c in slither.contracts if c.name == "C")


# ---------------------------------------------------------------------------
# 1. The tree is attempted
# ---------------------------------------------------------------------------


def test_gated_fallback_gets_a_predicate_tree(contract):
    trees = (build_predicate_artifacts(contract) or {}).get("trees") or {}
    assert "fallback()" in trees, "no tree was built for a fallback carrying a require"


def test_gated_fallback_tree_carries_the_caller_authority_leaf(contract):
    """The positive case. A tree that exists but lost the gate would satisfy the
    test above and still publish the function as open."""
    tree = ((build_predicate_artifacts(contract) or {}).get("trees") or {})["fallback()"]
    leaves: list[dict] = []

    def walk(node):
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaves.append(node.get("leaf") or {})
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    roles = {leaf.get("authority_role") for leaf in leaves}
    assert "caller_authority" in roles, f"the fallback's owner gate was not lifted: {roles}"
    assert evaluate_tree(tree).kind == "finite_set"


def test_open_receive_is_absent_after_being_attempted_not_before(contract):
    """The negative control. ``receive()`` genuinely has no gate, so it still
    has no tree -- but now that is a measured absence rather than an untried
    one, and the two must not be conflated back together."""
    trees = (build_predicate_artifacts(contract) or {}).get("trees") or {}
    assert "receive()" not in trees


# ---------------------------------------------------------------------------
# 2. The selector sentinel
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("signature", ["fallback()", "receive()"])
def test_selectorless_signatures_are_not_canonical(signature):
    assert has_no_selector(signature) is True
    assert is_canonical_abi_signature(signature) is False


def test_effects_emits_the_empty_selector_for_fallback_and_receive(contract):
    functions = build_effects(contract)["functions"]
    assert functions["fallback()"]["selector"] == ""
    assert functions["receive()"]["selector"] == ""
    # Positive control: a real entry point still gets its real selector.
    assert functions["contribute()"]["selector"] == "0xd7bb99ba"


def test_fallback_state_write_publishes_no_writer_selector(contract):
    """``writer_selectors`` replays a write by selector. Emitting
    ``0x552079dc`` there named a dispatch that matches nothing on chain."""
    functions = build_effects(contract)["functions"]
    assert functions["fallback()"]["writer_selectors"] == []
    assert functions["fallback()"]["state_writes"], "the write itself is still recorded"


@pytest.mark.parametrize("signature", ["fallback()", "receive()"])
def test_persisted_selector_is_the_empty_sentinel_not_a_fabricated_hash(signature):
    """Three states at the persistence boundary: ``""`` proven-absent (here),
    ``None`` not-determined (an unlowered signature), a hash when it is real."""
    abi_sig, selector = _abi_signature_and_selector(signature, {})
    assert abi_sig == signature
    assert selector == "", f"{signature} must carry the no-selector sentinel, got {selector!r}"

    assert _abi_signature_and_selector("setAuthority(IFoo.Bar)", {})[1] is None
    assert _abi_signature_and_selector("contribute()", {})[1] == "0xd7bb99ba"


def test_no_named_function_can_receive_the_selectorless_sentinel():
    """The ``""`` sentinel is reserved for a PROVEN absence of a selector.

    Two named functions (``alertBatchMetadataUpdate``, ``alertMetadataUpdate``)
    were once reported as carrying ``selector = ''`` beside well-formed ABI
    signatures. That does not reproduce — no row in any local database carries
    an empty or NULL selector, and both functions hold their real keccak — but
    the invariant it asks for was only pinned by a single unlowered example. Pin
    it over the shapes instead, because ``''`` on a named function re-opens an
    identity collision: ``_selector_key`` deliberately folds ``None`` onto
    ``""``, so a named function landing there shares an identity with the
    contract's ``fallback``/``receive`` and inherits its observed claims.

    ``fallbackHandler()`` is the discriminating control: it is the reason this
    recognition must stay signature-EXACT and can never become a prefix or
    substring test on "fallback"/"receive".
    """
    named = [
        "alertMetadataUpdate(uint256)",
        "alertBatchMetadataUpdate(uint256,uint256)",
        # Named functions whose names embed the selectorless keywords.
        "fallbackHandler()",
        "receiveELRewards()",
        "receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)",
        # Unlowered: not-determined, which is ``None`` — a different answer.
        "setAuthority(IFoo.Bar)",
    ]
    for signature in named:
        selector = _abi_signature_and_selector(signature, {})[1]
        assert selector != "", f"{signature} was handed the proven-no-selector sentinel"
        assert selector is None or selector.startswith("0x")

    # Positive controls, so a helper that returned ``None`` for everything could
    # not satisfy the assertions above.
    assert _abi_signature_and_selector("alertMetadataUpdate(uint256)", {})[1] == "0x6800a4f4"
    assert _abi_signature_and_selector("fallbackHandler()", {})[1] == "0xeed2f252"
    assert _abi_signature_and_selector("setAuthority(IFoo.Bar)", {})[1] is None
    # Negative control: the two signatures that DO earn the sentinel still do.
    assert _abi_signature_and_selector("fallback()", {})[1] == ""
    assert _abi_signature_and_selector("receive()", {})[1] == ""
