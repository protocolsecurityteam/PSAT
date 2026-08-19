"""Plane 2 — a flow sink's asset address, or nothing at all.

Every test here pins one of the ways a resolved address could become a fiction:

  * an accessor borrowed from a same-named hand-written getter (the corpus's
    ``getTokenOut()`` trap, where ``tokenOut()`` reverts);
  * a short, whitespace-padded or non-canonical return word decoded anyway;
  * a revert or transport failure resolving to the zero address, to ``null``, or
    to a key that is present-but-empty;
  * a real zero answer quietly dropped, or worse, priced;
  * an address published without the height it was read at;
  * ``immutable`` published as a runtime invariant behind a proxy;
  * a row keyed by the variable NAME rather than the minted selector.

The words asserted below were measured on chain at block 25643300 via eRPC and
are reproduced verbatim (`0x…8f08b704…` for ``token()`` at the CumulativeMerkleDrop
proxy, `0x…35fa1647…` for ``eETH()``/``eEth()``, `0x…ec53bf91…` for
``rewardTokenAddress()``); ``tokenOut()`` at the SyncPool proxy reverted with no
data at the same height while ``getTokenOut()`` answered.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from services.clients.rpc import EthCallResult
from services.resolution import flow_asset_plane as fap
from services.resolution.role_holder_plane import ProbeBlock
from workers.resolution_worker import ResolutionWorker

BLOCK = 25643300
BLOCK_HASH = bytes.fromhex("21d7f476ebacbed97ff15fbe213376984bada1928166b375ab1b1135bd21c188")
PROBE = ProbeBlock(number=BLOCK, block_hash=BLOCK_HASH)
PROBE_NO_HASH = ProbeBlock(number=BLOCK, block_hash=None)

# Runtime (proxy) addresses and the compiler-minted selectors measured on them.
MERKLE_DROP = "0x6db24ee656843e3fe03eb8762a54d86186ba6b64"
REDEMPTION_MGR = "0xdadef1ffbfeaab4f68a9fd181395f68b4e4e7ae0"
REWARDS_ROUTER = "0x89e45081437c959a827d2027135bc201ab33a2c8"
SYNC_POOL = "0xd789870bea40d056a4d26055d0befcc8755da146"

SEL_TOKEN = "0xfc0c546a"  # token()
SEL_EETH = "0x04fc532a"  # eEth()
SEL_REWARD_TOKEN = "0x125f9e33"  # rewardTokenAddress()

WORD_KING = "0x0000000000000000000000008f08b70456eb22f6109f57b8fafe862ed28e6040"
WORD_EETH = "0x00000000000000000000000035fa164735182de50811e8e2e824cfb9b6118ac2"
WORD_EIGEN = "0x000000000000000000000000ec53bf9167f50cdeb3ae105f56099aaab9061f83"
WORD_ZERO = "0x" + "0" * 64

ADDR_KING = "0x8f08b70456eb22f6109f57b8fafe862ed28e6040"
ADDR_EETH = "0x35fa164735182de50811e8e2e824cfb9b6118ac2"
ADDR_EIGEN = "0xec53bf9167f50cdeb3ae105f56099aaab9061f83"

# The exact tuple ``eth_call_batch`` produced for ``tokenOut()`` at 25643300:
# reverted, with no ``error.data`` at all.
MEASURED_REVERT = EthCallResult(False, "0x", None, "execution reverted")
OK = EthCallResult(True, WORD_KING, None, None)


# ---------------------------------------------------------------------------
# Descriptor fixtures — the shape the static effects artifact actually stores
# ---------------------------------------------------------------------------


def _state_var_receiver(selector: str, variable: str, *, mutability: str = "immutable_in_implementation") -> dict:
    return {
        "binding": "state_variable",
        "param_scope": None,
        "param_index": None,
        "mutability": mutability,
        "visibility": "public",
        "auto_getter_selector": selector,
        "variable": variable,
        "receiver_provenance": "contract_state_unresolved",
    }


def _effects(*sinks: dict, function: str = "recoverERC20()") -> dict:
    return {
        "schema_version": "semantic-3",
        "contract_name": "Fixture",
        "functions": {function: {"function": function, "sinks": list(sinks)}},
    }


def _sink(sink_id: str, receiver: dict | None, *, target: str = "asset.safeTransfer") -> dict:
    sink: dict[str, Any] = {
        "id": sink_id,
        "function": "recoverERC20()",
        "kind": "external_call",
        "target": target,
        "selector": "0xd0c407e1",
        "origin": "body",
    }
    if receiver is not None:
        sink["receiver"] = receiver
    return sink


def _run(
    monkeypatch: pytest.MonkeyPatch,
    effects: dict,
    results: list[EthCallResult],
    *,
    deployment_address: str = REWARDS_ROUTER,
    proven_proxied: bool = True,
    probe_block: ProbeBlock = PROBE,
) -> tuple[dict, list]:
    """Resolve with ``eth_call_batch`` stubbed; returns (payload, calls seen)."""
    seen: list = []

    def fake_batch(rpc_url, calls, block_tag, *, headers=None, chain_id=None):
        seen.append((rpc_url, [dict(c) for c in calls], block_tag, chain_id))
        return results

    monkeypatch.setattr(fap, "eth_call_batch", fake_batch)
    receivers = fap.collect_asset_receivers(effects)
    payload = fap.resolve_flow_asset_addresses(
        receivers,
        rpc_url="http://stub",
        chain_id=1,
        deployment_address=deployment_address,
        proven_proxied=proven_proxied,
        probe_block=probe_block,
    )
    return payload, seen


# ---------------------------------------------------------------------------
# 1. The resolved payload, byte for byte
# ---------------------------------------------------------------------------


def test_resolved_payload_is_byte_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    """A full-word answer publishes the address, its block, and the invariant —
    and nothing else. Asserted as whole-dict equality so a silently added key
    (a name, a confidence, a defaulted null) fails the test."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_REWARD_TOKEN, "rewardTokenAddress")))
    payload, seen = _run(monkeypatch, effects, [EthCallResult(True, WORD_EIGEN, None, None)])

    assert payload == {
        "schema_version": "flow-asset-1",
        "chain_id": 1,
        "deployment_address": REWARDS_ROUTER,
        "deployment_proven_proxied": True,
        "probe_block": BLOCK,
        "probe_block_hash": BLOCK_HASH.hex(),
        "receivers": [
            {
                "asset_getter_selector": SEL_REWARD_TOKEN,
                "sink_ids": ["s0"],
                "receiver_variables": ["rewardTokenAddress"],
                "declared_mutability": "immutable_in_implementation",
                "observed_at_block": BLOCK,
                "observed_block_hash": BLOCK_HASH.hex(),
                "asset_address_status": "resolved",
                "asset_address": ADDR_EIGEN,
                "asset_identity_invariant": "redirectable_by_upgrade_authority",
            }
        ],
    }
    # One pinned call, at the runtime address, at an explicit height.
    assert seen == [("http://stub", [{"to": REWARDS_ROUTER, "data": SEL_REWARD_TOKEN}], hex(BLOCK), 1)]


def test_the_three_pinned_corpus_reads_reproduce(monkeypatch: pytest.MonkeyPatch) -> None:
    """The measured words for ``token()``, ``eEth()`` and ``rewardTokenAddress()``
    decode to the addresses the investigation pinned at 25643300."""
    cases = [
        (MERKLE_DROP, SEL_TOKEN, "token", WORD_KING, ADDR_KING),
        (REDEMPTION_MGR, SEL_EETH, "eEth", WORD_EETH, ADDR_EETH),
        (REWARDS_ROUTER, SEL_REWARD_TOKEN, "rewardTokenAddress", WORD_EIGEN, ADDR_EIGEN),
    ]
    for host, selector, variable, word, expected in cases:
        effects = _effects(_sink("s0", _state_var_receiver(selector, variable)))
        payload, _ = _run(monkeypatch, effects, [EthCallResult(True, word, None, None)], deployment_address=host)
        row = payload["receivers"][0]
        assert row["asset_address"] == expected
        assert row["observed_at_block"] == BLOCK
        assert row["asset_getter_selector"] == selector


# ---------------------------------------------------------------------------
# 2. The invariant enum has exactly two members
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "proven_proxied,expected",
    [(True, "redirectable_by_upgrade_authority"), (False, "not_determined")],
)
def test_invariant_tracks_proven_proxiedness(
    monkeypatch: pytest.MonkeyPatch, proven_proxied: bool, expected: str
) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)], proven_proxied=proven_proxied)
    assert payload["receivers"][0]["asset_identity_invariant"] == expected


def test_immutable_declaration_never_becomes_a_runtime_invariant(monkeypatch: pytest.MonkeyPatch) -> None:
    """The declaration class is carried verbatim and is NOT promoted: an
    ``immutable`` behind a proxy still publishes ``redirectable_by_upgrade_authority``,
    and no value in the enum means closed."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token", mutability="immutable_in_implementation")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    row = payload["receivers"][0]
    assert row["declared_mutability"] == "immutable_in_implementation"
    assert row["asset_identity_invariant"] == "redirectable_by_upgrade_authority"
    assert "immutable" not in {
        fap.INVARIANT_REDIRECTABLE,
        fap.INVARIANT_NOT_DETERMINED,
    }


def test_constant_declaration_is_not_a_closed_invariant_either(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token", mutability="constant")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    assert payload["receivers"][0]["asset_identity_invariant"] == "redirectable_by_upgrade_authority"


# ---------------------------------------------------------------------------
# 3. Failure never resolves to a value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result,reason",
    [
        (MEASURED_REVERT, "call_did_not_answer"),
        (EthCallResult(False, "0x", "0x08c379a0", "execution reverted"), "call_did_not_answer"),
        (EthCallResult(False, "0x", None, "transport: connection reset"), "call_did_not_answer"),
        (EthCallResult(True, "0x", None, None), "malformed_return_word"),
        (EthCallResult(True, "0x" + "0" * 62, None, None), "malformed_return_word"),
        # Over-long: 33 bytes is not the ABI this plane decodes, and taking the
        # first or last word of it would be a guess about which.
        (EthCallResult(True, WORD_KING + "00", None, None), "malformed_return_word"),
        # Non-canonical: the high-order 12 bytes are set, so this word is not an
        # address. Truncating it would read it as one.
        (
            EthCallResult(True, "0x" + "ff" * 12 + "8f08b70456eb22f6109f57b8fafe862ed28e6040", None, None),
            "malformed_return_word",
        ),
        # ``bytes.fromhex`` ignores ASCII whitespace: 62 nibbles + two spaces is
        # 64 characters that decode to 31 bytes.
        (EthCallResult(True, "0x" + "0" * 62 + "  ", None, None), "malformed_return_word"),
    ],
)
def test_a_failed_read_publishes_no_address_and_no_block(
    monkeypatch: pytest.MonkeyPatch, result: EthCallResult, reason: str
) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [result])
    row = payload["receivers"][0]
    assert row["asset_address_status"] == "not_determined"
    assert row["not_determined_reason"] == reason
    # ABSENT — not null, not the zero address, not an empty string.
    assert "asset_address" not in row
    assert "observed_at_block" not in row
    assert "observed_block_hash" not in row
    assert "asset_identity_invariant" not in row


def test_short_word_is_rejected_at_63_nibbles(monkeypatch: pytest.MonkeyPatch) -> None:
    """One nibble short of a word still decodes under ``int(x, 16)``; the length
    check is what makes it a non-answer."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING[:-1], None, None)])
    assert payload["receivers"][0]["asset_address_status"] == "not_determined"
    assert "asset_address" not in payload["receivers"][0]


# ---------------------------------------------------------------------------
# 4. The zero address is a real answer and is not an asset
# ---------------------------------------------------------------------------


def test_zero_word_is_its_own_state(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_ZERO, None, None)])
    row = payload["receivers"][0]
    assert row["asset_address_status"] == "observed_zero_address"
    # The read completed at a known height, so the height IS published…
    assert row["observed_at_block"] == BLOCK
    # …but the zero address is never handed to a pricer, and never invented as
    # an identity invariant.
    assert "asset_address" not in row
    assert "asset_identity_invariant" not in row


def test_zero_answer_and_failed_read_are_distinguishable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapsing these two is the whole point of the third state."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    zero, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_ZERO, None, None)])
    failed, _ = _run(monkeypatch, effects, [MEASURED_REVERT])
    assert zero["receivers"][0] != failed["receivers"][0]
    assert zero["receivers"][0]["asset_address_status"] != failed["receivers"][0]["asset_address_status"]


def test_zero_row_is_not_counted_as_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    zero, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_ZERO, None, None)])
    assert fap.count_resolved(zero) == 0
    good, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    assert fap.count_resolved(good) == 1


# ---------------------------------------------------------------------------
# 5. The address and its block are inseparable by construction
# ---------------------------------------------------------------------------


def test_an_observation_cannot_exist_without_a_height() -> None:
    with pytest.raises(ValueError):
        fap.AssetObservation(address=ADDR_KING, block_number=0, block_hash=None)
    with pytest.raises(ValueError):
        fap.AssetObservation(address=ADDR_KING, block_number=cast(Any, None), block_hash=None)
    with pytest.raises(ValueError):
        fap.AssetObservation(address=cast(Any, None), block_number=BLOCK, block_hash=None)
    with pytest.raises(ValueError):
        fap.AssetObservation(address="0x8f08b704", block_number=BLOCK, block_hash=None)


def test_every_published_address_carries_its_block(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(
        _sink("s0", _state_var_receiver(SEL_TOKEN, "token")),
        _sink("s1", _state_var_receiver(SEL_EETH, "eEth")),
        _sink("s2", _state_var_receiver(SEL_REWARD_TOKEN, "rewardTokenAddress")),
    )
    payload, _ = _run(
        monkeypatch,
        effects,
        [
            EthCallResult(True, WORD_KING, None, None),
            EthCallResult(True, WORD_EETH, None, None),
            MEASURED_REVERT,
        ],
    )
    for row in payload["receivers"]:
        assert ("asset_address" in row) <= ("observed_at_block" in row)


def test_a_hashless_probe_block_still_publishes_the_height(monkeypatch: pytest.MonkeyPatch) -> None:
    """Losing the hash weakens replay-after-reorg only; the height still stands."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)], probe_block=PROBE_NO_HASH)
    row = payload["receivers"][0]
    assert row["observed_at_block"] == BLOCK
    assert "observed_block_hash" not in row
    assert payload["probe_block_hash"] is None


# ---------------------------------------------------------------------------
# 6. Only the compiler-minted accessor is licensed — the getTokenOut() trap
# ---------------------------------------------------------------------------


def test_the_view_getter_local_mints_no_row_and_no_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """``IERC20 tokenOut = IERC20(getTokenOut())`` binds a LOCAL. On chain at
    25643300 ``getTokenOut()`` answers ``0xcd5fe23c…`` while ``tokenOut()``
    REVERTS — so pairing the receiver with a same-named getter would publish an
    address for a function that does not exist. The row stays not_determined by
    never entering this plane at all."""
    local_receiver = {
        "binding": "local",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "tokenOut",
        "receiver_provenance": "not_determined",
    }
    effects = _effects(_sink("s0", local_receiver, target="tokenOut.safeTransfer"))
    assert fap.collect_asset_receivers(effects) == []
    payload, seen = _run(monkeypatch, effects, [], deployment_address=SYNC_POOL)
    assert payload["receivers"] == []
    assert seen == []  # no call was placed at all


def test_a_local_carrying_a_selector_is_still_refused() -> None:
    """Defence in depth: even if a descriptor arrived with a non-null selector on
    a non-state-variable binding, the binding gate refuses it. The selector's
    licence comes from the DECLARATION, not from the field being populated."""
    poisoned = {
        "binding": "local",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": "public",
        "auto_getter_selector": "0xd0202d3b",  # tokenOut()
        "variable": "tokenOut",
        "receiver_provenance": "not_determined",
    }
    assert fap.collect_asset_receivers(_effects(_sink("s0", poisoned))) == []


def test_a_parameter_receiver_mints_no_row() -> None:
    caller_named = {
        "binding": "parameter",
        "param_scope": "entry_point",
        "param_index": 0,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "token",
        "receiver_provenance": "caller_named",
    }
    assert fap.collect_asset_receivers(_effects(_sink("s0", caller_named))) == []


def test_a_non_public_declaration_with_a_selector_is_refused() -> None:
    incoherent = _state_var_receiver(SEL_TOKEN, "token")
    incoherent["visibility"] = "internal"
    assert fap.collect_asset_receivers(_effects(_sink("s0", incoherent))) == []


@pytest.mark.parametrize("bad", ["0xfc0c546", "0xfc0c546aa", "fc0c546a", "0xfc0c546g", "", "0x"])
def test_a_malformed_selector_is_never_called(bad: str) -> None:
    receiver = _state_var_receiver(SEL_TOKEN, "token")
    receiver["auto_getter_selector"] = bad
    assert fap.collect_asset_receivers(_effects(_sink("s0", receiver))) == []


# ---------------------------------------------------------------------------
# 7. Rows a descriptor never reached are left exactly as they were
# ---------------------------------------------------------------------------


def test_a_sink_with_no_receiver_key_is_untouched() -> None:
    assert fap.collect_asset_receivers(_effects(_sink("s0", None))) == []


def test_a_state_variable_without_a_minted_selector_is_untouched() -> None:
    receiver = _state_var_receiver(SEL_TOKEN, "token")
    receiver["auto_getter_selector"] = None
    assert fap.collect_asset_receivers(_effects(_sink("s0", receiver))) == []


@pytest.mark.parametrize("effects", [{}, {"functions": None}, {"functions": []}, {"functions": {}}])
def test_an_effects_artifact_with_nothing_to_read_yields_nothing(effects: dict) -> None:
    assert fap.collect_asset_receivers(effects) == []


@pytest.mark.parametrize(
    "effects",
    [
        {"functions": ["not a record"]},
        {"functions": {"f()": "not a record"}},
        {"functions": {"f()": {"sinks": None}}},
        {"functions": {"f()": {"sinks": "not a list"}}},
        {"functions": {"f()": {"sinks": ["not a sink"]}}},
        {"functions": {"f()": {"sinks": [{"id": "s0", "receiver": "not a descriptor"}]}}},
    ],
)
def test_a_malformed_artifact_yields_nothing_rather_than_raising(effects: dict) -> None:
    """The step is error-isolated, but a shape it cannot read must produce an
    empty plane, not an exception that costs the stage its degradation budget."""
    assert fap.collect_asset_receivers(effects) == []


def test_a_functions_list_is_read_the_same_as_a_functions_map(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = _sink("s0", _state_var_receiver(SEL_TOKEN, "token"))
    as_list = {"functions": [{"function": "f()", "sinks": [sink]}]}
    as_map = {"functions": {"f()": {"function": "f()", "sinks": [sink]}}}
    assert fap.collect_asset_receivers(as_list) == fap.collect_asset_receivers(as_map)


@pytest.mark.parametrize("value", [None, 4207540330, b"0xfc0c546a", ["0xfc0c546a"]])
def test_a_non_string_selector_is_never_called(value: Any) -> None:
    receiver = _state_var_receiver(SEL_TOKEN, "token")
    receiver["auto_getter_selector"] = value
    assert fap.collect_asset_receivers(_effects(_sink("s0", receiver))) == []


@pytest.mark.parametrize("payload", [{}, {"receivers": None}, {"receivers": "x"}, {"receivers": ["x"]}])
def test_count_resolved_reads_nothing_out_of_a_shape_it_cannot_read(payload: dict) -> None:
    assert fap.count_resolved(payload) == 0


# ---------------------------------------------------------------------------
# 8. Identity is the selector, never the name
# ---------------------------------------------------------------------------


def test_sinks_sharing_a_selector_fold_to_one_read(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(
        _sink("s0", _state_var_receiver(SEL_EETH, "eEth")),
        _sink("s1", _state_var_receiver(SEL_EETH, "eEth")),
    )
    payload, seen = _run(monkeypatch, effects, [EthCallResult(True, WORD_EETH, None, None)])
    assert len(payload["receivers"]) == 1
    assert payload["receivers"][0]["sink_ids"] == ["s0", "s1"]
    assert len(seen[0][1]) == 1


def test_same_name_different_selector_does_not_fold(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two declarations sharing an identifier but not a minted selector are two
    assets. Folding them on the name is the inv.2 shape this plane replaces."""
    a = _state_var_receiver(SEL_TOKEN, "token")
    b = _state_var_receiver(SEL_REWARD_TOKEN, "token")
    payload, seen = _run(
        monkeypatch,
        _effects(_sink("s0", a), _sink("s1", b)),
        [EthCallResult(True, WORD_KING, None, None), EthCallResult(True, WORD_EIGEN, None, None)],
    )
    assert [r["asset_getter_selector"] for r in payload["receivers"]] == [SEL_REWARD_TOKEN, SEL_TOKEN]
    assert {r["asset_address"] for r in payload["receivers"]} == {ADDR_KING, ADDR_EIGEN}
    assert len(seen[0][1]) == 2


def test_no_row_is_keyed_by_a_variable_name(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    row = payload["receivers"][0]
    # The name is carried for display; it is not the key and never stands alone.
    assert row["receiver_variables"] == ["token"]
    assert row["asset_getter_selector"] == SEL_TOKEN


def test_conflicting_declaration_classes_withhold_the_mutability(monkeypatch: pytest.MonkeyPatch) -> None:
    a = _state_var_receiver(SEL_TOKEN, "token", mutability="immutable_in_implementation")
    b = _state_var_receiver(SEL_TOKEN, "token", mutability="mutable")
    receivers = fap.collect_asset_receivers(_effects(_sink("s0", a), _sink("s1", b)))
    assert len(receivers) == 1
    assert receivers[0].declared_mutability is None


# ---------------------------------------------------------------------------
# 9. Idempotence and determinism
# ---------------------------------------------------------------------------


def test_two_identical_runs_produce_the_identical_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(
        _sink("s1", _state_var_receiver(SEL_REWARD_TOKEN, "rewardTokenAddress")),
        _sink("s0", _state_var_receiver(SEL_TOKEN, "token")),
    )
    results = [EthCallResult(True, WORD_KING, None, None), EthCallResult(True, WORD_EIGEN, None, None)]
    first, _ = _run(monkeypatch, effects, results)
    second, _ = _run(monkeypatch, effects, results)
    assert first == second
    # Sorted by selector, so sink declaration order cannot reorder the payload.
    assert [r["asset_getter_selector"] for r in first["receivers"]] == sorted([SEL_TOKEN, SEL_REWARD_TOKEN])


def test_a_rerun_replaces_the_payload_rather_than_appending(monkeypatch: pytest.MonkeyPatch) -> None:
    """The artifact is upserted on (job_id, name), so a second pass at a new
    height cannot leave a stale address sitting beside a fresh one."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    ctx = _stage_ctx(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    worker, session, job = ctx["worker"], ctx["session"], ctx["job"]
    worker._resolve_flow_asset_addresses(
        session, job, chain_id=1, rpc_url="http://stub", deployment_address=MERKLE_DROP, proven_proxied=True
    )
    worker._resolve_flow_asset_addresses(
        session, job, chain_id=1, rpc_url="http://stub", deployment_address=MERKLE_DROP, proven_proxied=True
    )
    stored = [(name, data) for name, data in ctx["store_calls"] if name == "flow_asset_addresses"]
    assert len(stored) == 2
    assert stored[0][1] == stored[1][1]
    assert len(ctx["artifact_store"]["flow_asset_addresses"]["receivers"]) == 1


# ---------------------------------------------------------------------------
# 10. Call-site wiring: pinned height, runtime address, stage isolation
# ---------------------------------------------------------------------------


def _stage_ctx(
    monkeypatch: pytest.MonkeyPatch,
    effects: Any,
    results: list[EthCallResult],
    *,
    probe_block: ProbeBlock | None = PROBE,
) -> dict[str, Any]:
    import workers.resolution_worker as rw

    store_calls: list[tuple[str, Any]] = []
    artifact_store: dict[str, Any] = {}

    def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
        return effects if name == "effects" else None

    def fake_store_artifact(_session: Any, _job_id: Any, name: str, data: Any = None, text_data: Any = None) -> None:
        store_calls.append((name, data))
        artifact_store[name] = data

    monkeypatch.setattr(rw, "get_artifact", fake_get_artifact)
    monkeypatch.setattr(rw, "store_artifact", fake_store_artifact)
    monkeypatch.setattr(rw, "pin_probe_block", lambda *a, **k: probe_block)
    monkeypatch.setattr(fap, "eth_call_batch", lambda *a, **k: results)

    return {
        "worker": ResolutionWorker(),
        "session": MagicMock(),
        "job": SimpleNamespace(id=uuid.uuid4(), address=MERKLE_DROP, name="Fixture", request={}, chain_id=1),
        "store_calls": store_calls,
        "artifact_store": artifact_store,
    }


def test_an_unpinnable_height_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """No pinned height means no read. There is no ``"latest"`` fallback: an
    address observed at an unrecorded height may not be published."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    ctx = _stage_ctx(monkeypatch, effects, [], probe_block=None)
    monkeypatch.setattr(fap, "eth_call_batch", lambda *a, **k: pytest.fail("must not read unpinned"))
    written = ctx["worker"]._resolve_flow_asset_addresses(
        ctx["session"],
        ctx["job"],
        chain_id=1,
        rpc_url="http://stub",
        deployment_address=MERKLE_DROP,
        proven_proxied=True,
    )
    assert written == 0
    assert ctx["store_calls"] == []


def test_no_effects_artifact_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _stage_ctx(monkeypatch, None, [])
    written = ctx["worker"]._resolve_flow_asset_addresses(
        ctx["session"],
        ctx["job"],
        chain_id=1,
        rpc_url="http://stub",
        deployment_address=MERKLE_DROP,
        proven_proxied=True,
    )
    assert written == 0
    assert ctx["store_calls"] == []


def test_an_effects_artifact_with_no_licensed_receiver_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A contract whose every sink receiver is caller-named leaves no trace here —
    an empty plane is not published as a proven-empty one."""
    caller_named = {
        "binding": "parameter",
        "param_scope": "entry_point",
        "param_index": 0,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "token",
        "receiver_provenance": "caller_named",
    }
    ctx = _stage_ctx(monkeypatch, _effects(_sink("s0", caller_named)), [])
    monkeypatch.setattr(fap, "eth_call_batch", lambda *a, **k: pytest.fail("must not read"))
    written = ctx["worker"]._resolve_flow_asset_addresses(
        ctx["session"],
        ctx["job"],
        chain_id=1,
        rpc_url="http://stub",
        deployment_address=MERKLE_DROP,
        proven_proxied=True,
    )
    assert written == 0
    assert ctx["store_calls"] == []


def test_no_deployment_address_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    ctx = _stage_ctx(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    written = ctx["worker"]._resolve_flow_asset_addresses(
        ctx["session"],
        ctx["job"],
        chain_id=1,
        rpc_url="http://stub",
        deployment_address=None,
        proven_proxied=False,
    )
    assert written == 0
    assert ctx["store_calls"] == []


def test_the_writer_reads_the_proxy_not_the_implementation(monkeypatch: pytest.MonkeyPatch) -> None:
    """An implementation job in proxy context resolves at the PROXY, and that is
    also the sole licence for ``redirectable_by_upgrade_authority``."""
    import workers.resolution_worker as rw

    effects = _effects(_sink("s0", _state_var_receiver(SEL_REWARD_TOKEN, "rewardTokenAddress")))
    ctx = _stage_ctx(monkeypatch, effects, [EthCallResult(True, WORD_EIGEN, None, None)])
    seen: list = []

    def fake_batch(rpc_url, calls, block_tag, *, headers=None, chain_id=None):
        seen.append((calls[0]["to"], block_tag))
        return [EthCallResult(True, WORD_EIGEN, None, None)]

    monkeypatch.setattr(fap, "eth_call_batch", fake_batch)
    ctx["job"].request = {"proxy_address": REWARDS_ROUTER}
    ctx["job"].address = "0x6bf6acd4b22795080c719d987baa8f4fcb1ab3f8"  # the implementation
    rw.ResolutionWorker()._resolve_flow_asset_addresses(
        ctx["session"],
        ctx["job"],
        chain_id=1,
        rpc_url="http://stub",
        deployment_address=REWARDS_ROUTER,
        proven_proxied=True,
    )
    assert seen == [(REWARDS_ROUTER, hex(BLOCK))]
    payload = ctx["artifact_store"]["flow_asset_addresses"]
    assert payload["deployment_address"] == REWARDS_ROUTER
    assert payload["receivers"][0]["asset_identity_invariant"] == "redirectable_by_upgrade_authority"


def test_a_failing_writer_degrades_the_step_not_the_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    """The step is isolated exactly as the dependency-edge and role-holder steps
    are: it records a degradation and the stage still completes."""
    import workers.resolution_worker as rw
    from tests.support.resolution_worker_stubs import _job, _patch_all

    ctx = _patch_all(monkeypatch)
    degraded: list[dict] = []
    monkeypatch.setattr(rw, "record_degraded", lambda **kw: degraded.append(kw))

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("plane exploded")

    monkeypatch.setattr(rw.ResolutionWorker, "_resolve_flow_asset_addresses", boom)

    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    rw.ResolutionWorker().process(session, cast(Any, _job()))

    assert [d["phase"] for d in degraded] == ["resolution_flow_asset_plane"]
    # The stage still stored what it did prove.
    stored = [name for name, _ in ctx["store_calls"]]
    assert "control_snapshot" in stored
    assert "resolved_control_graph" in stored
