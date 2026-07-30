"""The published one-shot latch witness — what a ``latch_state`` is evidence of.

Before this, a consumed one-shot published four keys (``latch_state``,
``latch_value``, ``latch_target``, ``description``) and nothing about WHICH
oracle produced the verdict, WHERE it was read, or WHEN. Three rows carrying
identical published triples were decided by three different guards, and one
carried an Aragon initialization-block number under the same ``latch_value``
key that elsewhere holds an OZ version. This module pins the witness that closes
that: what is published, and — the harder half — what is NOT published when the
producer had nothing.

The three replayed shapes are the realized ones, with descriptors read verbatim
from the persisted ``predicate_trees`` blobs and storage words re-read on chain
at block **25643300** (pinned; never ``latest``):

  * Lido ``0xae7ab965…`` — ``unstructured_slot_latch``, guard ``eq 0``, no byte
    range, slot ``keccak("aragonOS.initializable.initializationBlock")``,
    word ``0x…af1140`` (11473216);
  * FiatTokenV2_2 ``0xa0b86991…`` — ``structural_scalar_latch``, a packed byte,
    three sibling functions reading ONE slot behind guards ``eq 0`` / ``eq 1`` /
    ``eq 2``;
  * EtherfiL1SyncPoolETH ``0xd789870b…`` — ``oz_v5_namespaced`` version member,
    the ERC-7201 slot, word ``0x…01``.

Fail-closed arms carry zero realized rows today, so each is constructed: an
unevaluable guard, an unread latch, a 255 that is not a sentinel, an unpinned
read height, a legacy descriptor with no ``expected_version`` provenance, and
two decisive latches that must not blur into one witness.

Hermetic: the wire is the ``FakeRpc`` stub from ``test_one_shot_probe``; the AST
controls compile through the production Slither toolchain. No live marker.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution.one_shot_probe import (  # noqa: E402
    LatchReadResult,
    annotate_capability_one_shot,
    latch_descriptor_digest,
    resolve_one_shot_state,
)
from tests.test_one_shot_probe import FakeRpc, _word  # noqa: E402

# Pinned probe height. Every on-chain value below was re-read here; the
# resolver's own runtime height is head-12 and is not persisted, so this pins
# stability at 25643300, not that the observed run read there.
BLOCK = 25643300

LIDO = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
LIDO_SLOT = "0xebb05b386a8d34882b8711d156f463690983dc47815980fb82aeeff1aa43579e"
LIDO_WORD = "0x0000000000000000000000000000000000000000000000000000000000af1140"

USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDC_SLOT_INITIALIZED = "0x0000000000000000000000000000000000000000000000000000000000000008"
USDC_WORD_INITIALIZED = "0x000000000000000000000001e982615d461dd5cd06575bbea87624fda4e3de17"
USDC_SLOT_VERSION = "0x0000000000000000000000000000000000000000000000000000000000000012"
USDC_WORD_VERSION = "0x0000000000000000000000000000000000000000000000000000000000000003"

SYNC_POOL = "0xd789870bea40d056a4d26055d0befcc8755da146"
ERC7201_SLOT = "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"
SYNC_POOL_WORD = "0x0000000000000000000000000000000000000000000000000000000000000001"


# --- descriptors, verbatim from the persisted predicate_trees blobs ---------


def _lido_descriptor() -> dict[str, Any]:
    return {
        "kind": "storage",
        "variable": "onlyInit",
        "slot": LIDO_SLOT,
        "byte_offset": None,
        "size_bytes": None,
        "value_type": None,
        "standard": "unstructured_slot_latch",
        "guard": {"operator": "eq", "constant": "0"},
    }


def _usdc_bool_descriptor() -> dict[str, Any]:
    return {
        "kind": "storage",
        "variable": "initialized",
        "slot": USDC_SLOT_INITIALIZED,
        "byte_offset": 20,
        "size_bytes": 1,
        "value_type": "bool",
        "standard": "structural_scalar_latch",
        "guard": {"operator": "falsy", "constant": None},
    }


def _usdc_version_descriptor(constant: str) -> dict[str, Any]:
    return {
        "kind": "storage",
        "variable": "_initializedVersion",
        "slot": USDC_SLOT_VERSION,
        "byte_offset": 0,
        "size_bytes": 1,
        "value_type": "uint8",
        "standard": "structural_scalar_latch",
        "guard": {"operator": "eq", "constant": constant},
    }


def _sync_pool_descriptor(*, basis: str | None = "oz_initializer_modifier_standard_constant") -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "kind": "storage",
        "role": "version",
        "variable": "INITIALIZABLE_STORAGE",
        "slot": ERC7201_SLOT,
        "byte_offset": 0,
        "size_bytes": 8,
        "value_type": "uint64",
        "expected_version": 1,
        "standard": "oz_v5_namespaced",
    }
    if basis is not None:
        descriptor["expected_version_basis"] = basis
    return descriptor


def _probe(address: str, storage: dict, latches: list[dict[str, Any]], **kwargs) -> LatchReadResult:
    rpc = FakeRpc(storage=storage)
    return resolve_one_shot_state(
        rpc_url="x",
        address=address,
        latches=latches,
        block=kwargs.pop("block", BLOCK),
        db_proxy_linked=kwargs.pop("db_proxy_linked", True),
        rpc=rpc,
    )


# ---------------------------------------------------------------------------
# The three realized shapes — byte-exact published witness
# ---------------------------------------------------------------------------


def test_lido_unstructured_slot_guard_witness_is_byte_exact():
    """Lido's latch is an Aragon initialization BLOCK NUMBER decided by a guard,
    not an OZ version reached by a version compare. The witness must say so:
    ``guard`` basis, the guard's own operator/constant, and no
    ``expected_version`` at all."""
    result = _probe(LIDO, {(LIDO, LIDO_SLOT): LIDO_WORD}, [_lido_descriptor()])
    assert result.state == "consumed"
    assert result.value == 11473216
    assert result.witness == {
        "latch_basis": "guard",
        "probe_address": LIDO,
        "probe_block": BLOCK,
        "standard": "unstructured_slot_latch",
        "variable": "onlyInit",
        "slot": LIDO_SLOT,
        "guard": {"operator": "eq", "constant": "0"},
        "read_kind": "storage",
        "raw_word": hex(int(LIDO_WORD, 16)),
    }
    # No byte range existed, so no byte range is published — and the absence of
    # size_bytes is exactly why 0xff could never have been read as a sentinel.
    for absent in ("byte_offset", "size_bytes", "value_type", "expected_version", "role"):
        assert absent not in result.witness


def test_fiat_token_siblings_publish_their_own_deciding_guard():
    """FiatTokenV2_2's initializeV2 / V2_1 / V2_2 read ONE slot behind guards
    ``eq 0`` / ``eq 1`` / ``eq 2``. All three are consumed at the same value, so
    the published triple is identical on all three rows — the witness is the
    only thing that separates them, and it must carry each row's own constant."""
    storage = {(USDC, USDC_SLOT_VERSION): USDC_WORD_VERSION}
    seen = []
    for constant in ("0", "1", "2"):
        result = _probe(USDC, storage, [_usdc_version_descriptor(constant)])
        assert (result.state, result.value) == ("consumed", 3)
        assert result.witness["latch_basis"] == "guard"
        assert result.witness["guard"] == {"operator": "eq", "constant": constant}
        assert result.witness["value_type"] == "uint8"
        seen.append(result.witness["guard"]["constant"])
    assert seen == ["0", "1", "2"]


def test_fiat_token_packed_bool_byte_witness_is_byte_exact():
    """The packed byte: the descriptor's byte range is what turns a 32-byte word
    holding an address into the value 1, so both the raw word and the range are
    published — the decode is replayable, not asserted."""
    result = _probe(USDC, {(USDC, USDC_SLOT_INITIALIZED): USDC_WORD_INITIALIZED}, [_usdc_bool_descriptor()])
    assert result.state == "consumed"
    assert result.value == 1
    assert result.witness == {
        "latch_basis": "guard",
        "probe_address": USDC,
        "probe_block": BLOCK,
        "standard": "structural_scalar_latch",
        "variable": "initialized",
        "slot": USDC_SLOT_INITIALIZED,
        "byte_offset": 20,
        "size_bytes": 1,
        "value_type": "bool",
        "guard": {"operator": "falsy"},  # constant was None → key absent
        "read_kind": "storage",
        "raw_word": hex(int(USDC_WORD_INITIALIZED, 16)),
    }


def test_erc7201_version_ge_witness_is_byte_exact():
    """The OZ v5 namespaced version member: ``version_ge`` basis, and
    ``expected_version`` published only next to the basis that says the integer
    came from a modifier NAME match rather than from the compiler."""
    result = _probe(SYNC_POOL, {(SYNC_POOL, ERC7201_SLOT): SYNC_POOL_WORD}, [_sync_pool_descriptor()])
    assert result.state == "consumed"
    assert result.value == 1
    assert result.witness == {
        "latch_basis": "version_ge",
        "probe_address": SYNC_POOL,
        "probe_block": BLOCK,
        "standard": "oz_v5_namespaced",
        "role": "version",
        "variable": "INITIALIZABLE_STORAGE",
        "slot": ERC7201_SLOT,
        "byte_offset": 0,
        "size_bytes": 8,
        "value_type": "uint64",
        "expected_version": 1,
        "expected_version_basis": "oz_initializer_modifier_standard_constant",
        "read_kind": "storage",
        "raw_word": hex(int(SYNC_POOL_WORD, 16)),
    }


def test_version_ge_witness_key_set_is_locked():
    """Shape lock: a silent drop of any strength key must redden here."""
    result = _probe(SYNC_POOL, {(SYNC_POOL, ERC7201_SLOT): SYNC_POOL_WORD}, [_sync_pool_descriptor()])
    assert set(result.witness) == {
        "latch_basis",
        "probe_address",
        "probe_block",
        "standard",
        "role",
        "variable",
        "slot",
        "byte_offset",
        "size_bytes",
        "value_type",
        "expected_version",
        "expected_version_basis",
        "read_kind",
        "raw_word",
    }


# ---------------------------------------------------------------------------
# Fail-closed arms — every one of these is zero-population today
# ---------------------------------------------------------------------------


def test_unevaluable_guard_publishes_not_determined_never_a_branch():
    """An operator the evaluator cannot fold decides nothing. The row lands on
    ``latch_basis: not_determined`` and an indeterminate state — never on a
    branch label, and never on a verdict."""
    descriptor = dict(_lido_descriptor(), guard={"operator": "weird", "constant": "0"})
    result = _probe(LIDO, {(LIDO, LIDO_SLOT): LIDO_WORD}, [descriptor])
    assert result.state == "indeterminate"
    assert result.witness["latch_basis"] == "not_determined"
    # The read still happened and is still published — an honest
    # not_determined cites what it read.
    assert result.witness["raw_word"] == hex(int(LIDO_WORD, 16))
    assert result.witness["probe_block"] == BLOCK


def test_unread_latch_publishes_no_witness_at_all():
    """A latch whose slot cannot be read yields no witness object. Absence is
    the third state: there is nothing to replay, so nothing is claimed."""

    class _DeadRpc:
        def __call__(self, rpc_url, method, params, retries=1):
            raise RuntimeError("wire down")

    result = resolve_one_shot_state(
        rpc_url="x",
        address=LIDO,
        latches=[_lido_descriptor()],
        block=BLOCK,
        db_proxy_linked=True,
        rpc=_DeadRpc(),
    )
    assert result.state == "indeterminate"
    assert result.witness == {}


def test_no_decisive_latch_publishes_no_witness():
    result = _probe(LIDO, {}, [])
    assert result.state == "indeterminate"
    assert result.witness == {}
    assert result.transcript.get("reason") == "no_latch_location"


def test_255_without_a_byte_width_is_not_a_sentinel():
    """The sentinel test is ``_DISABLED_SENTINELS[size_bytes]``, so 255 is a
    sentinel only for a one-byte latch. A descriptor with no width must never
    reach the sentinel basis — that is the shape the register's
    'sentinel is recoverable from latch_value' claim got wrong."""
    descriptor = dict(_sync_pool_descriptor(), size_bytes=None, byte_offset=None)
    word = _word(0xFF)
    result = _probe(SYNC_POOL, {(SYNC_POOL, ERC7201_SLOT): word}, [descriptor])
    assert result.witness["latch_basis"] == "version_ge"
    assert result.witness["latch_basis"] != "sentinel"
    assert "size_bytes" not in result.witness


def test_unpinned_height_publishes_no_probe_block():
    """A ``latest`` read has no reproducible height. Publishing one would make an
    unreplayable observation look replayable, so the key is simply absent."""
    result = _probe(LIDO, {(LIDO, LIDO_SLOT): LIDO_WORD}, [_lido_descriptor()], block=None)
    assert result.state == "consumed"
    assert "probe_block" not in result.witness
    assert result.transcript["block"] == "latest"


def test_legacy_descriptor_publishes_no_bare_expected_version():
    """Descriptors persisted before basis stamping carry ``expected_version``
    with no record of where it came from. The integer is still what the verdict
    was computed from — but it is published only WITH its provenance, so a
    legacy row publishes neither key rather than an unattributed number."""
    result = _probe(
        SYNC_POOL,
        {(SYNC_POOL, ERC7201_SLOT): SYNC_POOL_WORD},
        [_sync_pool_descriptor(basis=None)],
    )
    assert result.state == "consumed"  # verdict unchanged — no row flips
    assert result.witness["latch_basis"] == "version_ge"
    assert "expected_version" not in result.witness
    assert "expected_version_basis" not in result.witness


def test_witness_names_which_of_two_decisive_latches_decided():
    """Two decisive latches with different guards: the witness must name the one
    that actually produced the value, not blur both into one payload."""
    first = _usdc_version_descriptor("0")
    second = dict(_usdc_bool_descriptor(), guard={"operator": "eq", "constant": "9"})
    storage = {
        (USDC, USDC_SLOT_VERSION): USDC_WORD_VERSION,
        (USDC, USDC_SLOT_INITIALIZED): USDC_WORD_INITIALIZED,
    }
    result = _probe(USDC, storage, [first, second])
    assert result.witness["slot"] == USDC_SLOT_VERSION
    assert result.witness["guard"] == {"operator": "eq", "constant": "0"}
    assert result.witness["raw_word"] == hex(int(USDC_WORD_VERSION, 16))


def test_getter_read_is_not_attributed_to_the_descriptor_slot():
    """When the value came back from an ``eth_call``, the witness says so. The
    descriptor's slot is still published as the descriptor's location, but
    ``read_kind``/``getter_selector`` keep ``raw_word`` from being read as the
    content of that slot."""
    selector = "0x0d8e6e2c"  # getContractVersion()
    descriptor = dict(_lido_descriptor(), getter_selector=selector)
    rpc = FakeRpc(
        storage={(LIDO, LIDO_SLOT): _word(0)},
        calls={(LIDO, selector): _word(2)},
    )
    result = resolve_one_shot_state(
        rpc_url="x", address=LIDO, latches=[descriptor], block=BLOCK, db_proxy_linked=True, rpc=rpc
    )
    assert result.value == 2
    assert result.witness["read_kind"] == "getter"
    assert result.witness["getter_selector"] == selector
    assert result.witness["raw_word"] == _word(2)
    assert result.witness["slot"] == LIDO_SLOT


# ---------------------------------------------------------------------------
# Publication onto the capability dict
# ---------------------------------------------------------------------------


def test_annotate_lands_witness_on_every_one_shot_condition_unaliased():
    """A function carrying two one_shot conditions is decided by ONE read, so
    both carry that witness — as independent objects, since a shared nested
    guard dict would let one row's edit rewrite another's."""
    result = _probe(LIDO, {(LIDO, LIDO_SLOT): LIDO_WORD}, [_lido_descriptor()])
    cap_dict = {
        "kind": "conditional_universal",
        "conditions": [
            {"kind": "one_shot", "description": "a"},
            {"kind": "one_shot", "description": "b"},
        ],
    }
    annotate_capability_one_shot(cap_dict, result, confirmed_candidate=False)
    first, second = cap_dict["conditions"]
    assert first["latch_witness"] == second["latch_witness"] == result.witness
    assert first["latch_witness"] is not second["latch_witness"]
    assert first["latch_witness"]["guard"] is not second["latch_witness"]["guard"]


def test_annotate_omits_witness_when_none_was_earned():
    """No witness ⇒ no key. Never null, never an empty object that a consumer
    could read as 'measured, and empty'."""
    cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "one_shot"}]}
    annotate_capability_one_shot(
        cap_dict,
        LatchReadResult("indeterminate", None, "unverified", {"reason": "no_decisive_latch"}),
        confirmed_candidate=False,
    )
    condition = cap_dict["conditions"][0]
    assert "latch_witness" not in condition
    assert "latch_value" not in condition
    assert condition["latch_state"] == "indeterminate"


def test_appended_candidate_condition_carries_the_witness():
    """The structural-candidate promotion path builds its condition from
    scratch; it must not be the one place the witness goes missing."""
    result = _probe(LIDO, {(LIDO, LIDO_SLOT): LIDO_WORD}, [_lido_descriptor()])
    cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "business", "description": "x"}]}
    annotate_capability_one_shot(cap_dict, result, confirmed_candidate=True)
    appended = next(c for c in cap_dict["conditions"] if c["kind"] == "one_shot")
    assert appended["latch_witness"] == result.witness
    assert appended["latch_value"] == 11473216


def test_appended_condition_omits_null_latch_value():
    cap_dict = {"kind": "conditional_universal", "conditions": []}
    annotate_capability_one_shot(
        cap_dict,
        LatchReadResult("consumed", None, "db_linked_proxy"),
        confirmed_candidate=True,
    )
    appended = cap_dict["conditions"][0]
    assert "latch_value" not in appended


# ---------------------------------------------------------------------------
# Cache identity — a shared read must not lend one row another's guard
# ---------------------------------------------------------------------------


def test_descriptor_digest_separates_same_slot_different_guards():
    """The realized FiatTokenV2_2 collision: three functions, one slot, three
    guards. A slot-keyed cache would serve one witness to all three."""
    digests = {latch_descriptor_digest([_usdc_version_descriptor(c)]) for c in ("0", "1", "2")}
    assert len(digests) == 3


def test_descriptor_digest_is_stable_for_identical_descriptors():
    assert latch_descriptor_digest([_sync_pool_descriptor()]) == latch_descriptor_digest([_sync_pool_descriptor()])


def test_resolver_cache_does_not_share_witnesses_across_guards(monkeypatch):
    """End-to-end through the resolver's cache: sibling rows on the same slot
    and block get their own read, so each publishes its own guard."""
    from services.resolution import capability_resolver as cr

    cr.clear_one_shot_cache()
    monkeypatch.setattr(cr, "_resolve_probe_block", lambda *a, **k: BLOCK)

    def _fake_resolve(**kwargs):
        latch = kwargs["latches"][0]
        return LatchReadResult(
            "consumed",
            3,
            "db_linked_proxy",
            {},
            {"latch_basis": "guard", "guard": dict(latch["guard"]), "probe_block": BLOCK},
        )

    monkeypatch.setattr(cr, "resolve_one_shot_state", _fake_resolve)

    pass_cache: dict = {}
    block_cell = [cr._UNRESOLVED_BLOCK]
    published = []
    for constant in ("0", "1", "2"):
        leaf = {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "one_shot",
            "operands": [{"source": "state_variable", "state_variable_name": "_initializedVersion"}],
            "references_msg_sender": False,
            "expression": "version latch",
            "basis": [],
            "one_shot_latch": _usdc_version_descriptor(constant),
        }
        cap_dict = {"kind": "conditional_universal", "conditions": [{"kind": "one_shot"}]}
        cr._maybe_one_shot_probe(
            cap_dict,
            tree={"op": "LEAF", "leaf": leaf},
            runtime_addr=USDC,
            rpc_url="x",
            chain_id=1,
            block=None,
            block_cell=block_cell,
            db_proxy_linked=True,
            pass_cache=pass_cache,
        )
        published.append(cap_dict["conditions"][0]["latch_witness"]["guard"]["constant"])
    assert published == ["0", "1", "2"]


# ---------------------------------------------------------------------------
# AST controls — expected_version and its provenance, through real Slither
# ---------------------------------------------------------------------------

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.one_shot_probe import collect_one_shot_latches  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)

AST_SOURCE = """
pragma solidity ^0.8.19;

abstract contract Initializable {
    uint8 private _initialized;
    bool private _initializing;
    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) || (address(this).code.length == 0 && _initialized == 1),
            "already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) { _initializing = true; }
        _;
        if (isTopLevelCall) { _initializing = false; }
    }
    modifier reinitializer(uint8 version) {
        require(!_initializing && _initialized < version, "already initialized");
        _initialized = version;
        _initializing = true;
        _;
        _initializing = false;
    }
    modifier onlyInitializing() {
        require(_initializing, "not initializing");
        _;
    }
}

contract LiteralReinit is Initializable {
    address public manager;
    function upgradeTo3(address m) external reinitializer(3) { manager = m; }
}

contract VariableReinit is Initializable {
    uint8 public nextVersion;
    address public manager;
    function upgradeToNext(address m) external reinitializer(nextVersion) { manager = m; }
}

contract PlainInitializer is Initializable {
    address public manager;
    function initialize(address m) external initializer { manager = m; }
}

contract OnlyInitializingHelper is Initializable {
    address public manager;
    function helper(address m) external onlyInitializing { manager = m; }
}
"""


def _solc_path_for(floor: tuple[int, int, int]) -> str | None:
    try:
        from solc_select import solc_select as ss
    except Exception:
        return None
    best: tuple[int, int, int] | None = None
    for version in ss.installed_versions():
        try:
            parsed = cast(tuple[int, int, int], tuple(int(x) for x in version.split(".")))
        except ValueError:
            continue
        if parsed[:2] == floor[:2] and parsed >= floor and (best is None or parsed > best):
            best = parsed
    if best is None:
        return None
    return str(ss.artifact_path(".".join(str(x) for x in best)))


@pytest.fixture(scope="module")
def ast_artifacts(tmp_path_factory) -> dict:
    solc = _solc_path_for((0, 8, 19))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.19")
    tmp = tmp_path_factory.mktemp("one_shot_witness")
    source = tmp / "Reinit.sol"
    source.write_text(textwrap.dedent(AST_SOURCE).strip() + "\n")
    sl = Slither(str(source), solc=solc)
    return {
        name: build_predicate_artifacts(next(c for c in sl.contracts if c.name == name))
        for name in ("LiteralReinit", "VariableReinit", "PlainInitializer", "OnlyInitializingHelper")
    }


def _standard_latch(artifact: dict, fn_name: str) -> dict | None:
    trees = artifact.get("trees") or {}
    tree = next(t for full, t in trees.items() if full.split("(", 1)[0] == fn_name)
    latches = collect_one_shot_latches(tree)["standard"]
    return latches[0] if latches else None


def test_reinitializer_literal_publishes_version_with_literal_basis(ast_artifacts):
    latch = _standard_latch(ast_artifacts["LiteralReinit"], "upgradeTo3")
    assert latch is not None
    assert latch["expected_version"] == 3
    assert latch["expected_version_basis"] == "oz_reinitializer_argument_literal"


def test_reinitializer_non_literal_publishes_no_version(ast_artifacts):
    """``reinitializer(someVar)`` has no statically known version. The producer
    records None — not 0, not a defaulted 1 — and the wire omits both keys."""
    latch = _standard_latch(ast_artifacts["VariableReinit"], "upgradeToNext")
    assert latch is not None
    assert latch["expected_version"] is None
    assert latch["expected_version_basis"] is None
    result = _probe(SYNC_POOL, {(SYNC_POOL, latch["slot"]): _word(1)}, [latch])
    assert "expected_version" not in result.witness
    assert "expected_version_basis" not in result.witness
    # Nothing said the version — so the compare that decided is the bare
    # non-zero one, and the witness names that, not version_ge.
    assert result.witness["latch_basis"] == "value_gt_zero"


def test_plain_initializer_version_is_the_standard_constant_not_a_literal(ast_artifacts):
    """``initializer`` implies version 1, but that 1 was never read from this
    source — its basis must not claim a literal."""
    latch = _standard_latch(ast_artifacts["PlainInitializer"], "initialize")
    assert latch is not None
    assert latch["expected_version"] == 1
    assert latch["expected_version_basis"] == "oz_initializer_modifier_standard_constant"


def test_only_initializing_helper_stamps_no_latch_location(ast_artifacts):
    """An ``onlyInitializing``-only helper reads the transient flag and nothing
    else, so it names no version AND earns no latch location — there is no
    descriptor to publish a witness from at all."""
    assert _standard_latch(ast_artifacts["OnlyInitializingHelper"], "helper") is None
