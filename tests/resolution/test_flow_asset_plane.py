"""Plane 2: a flow sink's asset address, or nothing.

Each test pins one way an address could become fiction: a same-named hand-written getter (``tokenOut()`` reverts
where ``getTokenOut()`` answers), a malformed word decoded anyway, a failure resolving to a value, a zero
priced, an address without its height, or ``immutable`` treated as invariant behind a proxy. Words were measured
at block 25643300.
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

# The exact result ``tokenOut()`` gave at 25643300.
MEASURED_REVERT = EthCallResult(False, "0x", None, "execution reverted")
OK = EthCallResult(True, WORD_KING, None, None)


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


_CALLER_NAMED_RECEIVER = {
    "binding": "parameter",
    "param_scope": "entry_point",
    "param_index": 0,
    "mutability": None,
    "visibility": None,
    "auto_getter_selector": None,
    "variable": "token",
    "receiver_provenance": "caller_named",
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


@pytest.mark.parametrize(
    ("host", "selector", "variable", "word", "address"),
    [
        pytest.param(REWARDS_ROUTER, SEL_REWARD_TOKEN, "rewardTokenAddress", WORD_EIGEN, ADDR_EIGEN, id="reward_token"),
        pytest.param(MERKLE_DROP, SEL_TOKEN, "token", WORD_KING, ADDR_KING, id="pinned_token"),
        pytest.param(REDEMPTION_MGR, SEL_EETH, "eEth", WORD_EETH, ADDR_EETH, id="pinned_eeth"),
    ],
)
def test_resolved_payload_is_byte_exact(
    monkeypatch: pytest.MonkeyPatch, host: str, selector: str, variable: str, word: str, address: str
) -> None:
    """Whole-dict equality so a silently added key fails."""
    effects = _effects(_sink("s0", _state_var_receiver(selector, variable)))
    payload, seen = _run(monkeypatch, effects, [EthCallResult(True, word, None, None)], deployment_address=host)

    assert payload == {
        "schema_version": "flow-asset-1",
        "chain_id": 1,
        "deployment_address": host,
        "deployment_proven_proxied": True,
        "probe_block": BLOCK,
        "probe_block_hash": BLOCK_HASH.hex(),
        "receivers": [
            {
                "asset_getter_selector": selector,
                "sink_ids": ["s0"],
                "receiver_variables": [variable],
                "declared_mutability": "immutable_in_implementation",
                "observed_at_block": BLOCK,
                "observed_block_hash": BLOCK_HASH.hex(),
                "asset_address_status": "resolved",
                "asset_address": address,
                "asset_identity_invariant": "redirectable_by_upgrade_authority",
            }
        ],
    }
    assert seen == [("http://stub", [{"to": host, "data": selector}], hex(BLOCK), 1)]


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


@pytest.mark.parametrize("mutability", ["immutable_in_implementation", "constant"])
def test_declaration_class_never_becomes_a_runtime_invariant(monkeypatch: pytest.MonkeyPatch, mutability: str) -> None:
    """An ``immutable`` behind a proxy is still redirectable by the upgrade authority."""
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token", mutability=mutability)))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    row = payload["receivers"][0]
    assert row["declared_mutability"] == mutability
    assert row["asset_identity_invariant"] == "redirectable_by_upgrade_authority"
    assert "immutable" not in {
        fap.INVARIANT_REDIRECTABLE,
        fap.INVARIANT_NOT_DETERMINED,
    }


@pytest.mark.parametrize(
    "result,reason",
    [
        (MEASURED_REVERT, "call_did_not_answer"),
        (EthCallResult(False, "0x", "0x08c379a0", "execution reverted"), "call_did_not_answer"),
        (EthCallResult(False, "0x", None, "transport: connection reset"), "call_did_not_answer"),
        (EthCallResult(True, "0x", None, None), "malformed_return_word"),
        (EthCallResult(True, "0x" + "0" * 62, None, None), "malformed_return_word"),
        # Taking either word of 33 bytes would be a guess.
        (EthCallResult(True, WORD_KING + "00", None, None), "malformed_return_word"),
        # The high 12 bytes are set, so this isn't an address.
        (
            EthCallResult(True, "0x" + "ff" * 12 + "8f08b70456eb22f6109f57b8fafe862ed28e6040", None, None),
            "malformed_return_word",
        ),
        # ``bytes.fromhex`` ignores whitespace.
        (EthCallResult(True, "0x" + "0" * 62 + "  ", None, None), "malformed_return_word"),
        # The length check is what makes it a non-answer.
        (EthCallResult(True, WORD_KING[:-1], None, None), "malformed_return_word"),
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
    assert "asset_address" not in row
    assert "observed_at_block" not in row
    assert "observed_block_hash" not in row
    assert "asset_identity_invariant" not in row


def test_zero_word_is_its_own_state(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_ZERO, None, None)])
    row = payload["receivers"][0]
    assert row["asset_address_status"] == "observed_zero_address"
    assert row["observed_at_block"] == BLOCK
    # The zero address is never handed to a pricer.
    assert "asset_address" not in row
    assert "asset_identity_invariant" not in row


def test_zero_row_is_not_counted_as_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    zero, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_ZERO, None, None)])
    assert fap.count_resolved(zero) == 0
    good, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)])
    assert fap.count_resolved(good) == 1


def test_an_observation_cannot_exist_without_a_height() -> None:
    with pytest.raises(ValueError):
        fap.AssetObservation(address=ADDR_KING, block_number=0, block_hash=None)
    with pytest.raises(ValueError):
        fap.AssetObservation(address=ADDR_KING, block_number=cast(Any, None), block_hash=None)
    with pytest.raises(ValueError):
        fap.AssetObservation(address=cast(Any, None), block_number=BLOCK, block_hash=None)
    with pytest.raises(ValueError):
        fap.AssetObservation(address="0x8f08b704", block_number=BLOCK, block_hash=None)


def test_a_hashless_probe_block_still_publishes_the_height(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token")))
    payload, _ = _run(monkeypatch, effects, [EthCallResult(True, WORD_KING, None, None)], probe_block=PROBE_NO_HASH)
    row = payload["receivers"][0]
    assert row["observed_at_block"] == BLOCK
    assert "observed_block_hash" not in row
    assert payload["probe_block_hash"] is None


def test_the_view_getter_local_mints_no_row_and_no_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """The receiver binds a local; pairing it with a same-named getter would publish an address for a function that
    doesn't exist.
    """
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


def _token_receiver(**overrides: Any) -> dict:
    return {**_state_var_receiver(SEL_TOKEN, "token"), **overrides}


@pytest.mark.parametrize(
    "receiver",
    [
        # The selector's licence comes from the declaration, not the populated field.
        pytest.param(
            {
                "binding": "local",
                "param_scope": None,
                "param_index": None,
                "mutability": None,
                "visibility": "public",
                "auto_getter_selector": "0xd0202d3b",  # tokenOut()
                "variable": "tokenOut",
                "receiver_provenance": "not_determined",
            },
            id="local_carrying_a_selector",
        ),
        pytest.param(_CALLER_NAMED_RECEIVER, id="parameter_receiver"),
        pytest.param(_token_receiver(visibility="internal"), id="non_public_declaration_with_a_selector"),
        pytest.param(_token_receiver(auto_getter_selector=None), id="no_minted_selector"),
        pytest.param(None, id="sink_with_no_receiver_key"),
        *[
            pytest.param(_token_receiver(auto_getter_selector=bad), id=f"malformed_selector_{bad or 'empty'}")
            for bad in ["0xfc0c546", "0xfc0c546aa", "fc0c546a", "0xfc0c546g", "", "0x"]
        ],
        *[
            pytest.param(_token_receiver(auto_getter_selector=value), id=f"non_string_selector_{i}")
            for i, value in enumerate([None, 4207540330, b"0xfc0c546a", ["0xfc0c546a"]])
        ],
    ],
)
def test_an_unlicensed_receiver_mints_no_row_and_is_never_called(receiver: dict | None) -> None:
    assert fap.collect_asset_receivers(_effects(_sink("s0", receiver))) == []


def test_a_state_variable_without_a_minted_selector_is_untouched() -> None:
    receiver = _state_var_receiver(SEL_TOKEN, "token")
    receiver["auto_getter_selector"] = None
    assert fap.collect_asset_receivers(_effects(_sink("s0", receiver))) == []


@pytest.mark.parametrize(
    "effects",
    [
        {},
        {"functions": None},
        {"functions": []},
        {"functions": {}},
        {"functions": ["not a record"]},
        {"functions": {"f()": "not a record"}},
        {"functions": {"f()": {"sinks": None}}},
        {"functions": {"f()": {"sinks": "not a list"}}},
        {"functions": {"f()": {"sinks": ["not a sink"]}}},
        {"functions": {"f()": {"sinks": [{"id": "s0", "receiver": "not a descriptor"}]}}},
    ],
)
def test_an_artifact_with_nothing_readable_yields_nothing_rather_than_raising(effects: dict) -> None:
    assert fap.collect_asset_receivers(effects) == []


def test_a_functions_list_is_read_the_same_as_a_functions_map(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = _sink("s0", _state_var_receiver(SEL_TOKEN, "token"))
    as_list = {"functions": [{"function": "f()", "sinks": [sink]}]}
    as_map = {"functions": {"f()": {"function": "f()", "sinks": [sink]}}}
    assert fap.collect_asset_receivers(as_list) == fap.collect_asset_receivers(as_map)


@pytest.mark.parametrize("payload", [{}, {"receivers": None}, {"receivers": "x"}, {"receivers": ["x"]}])
def test_count_resolved_reads_nothing_out_of_a_shape_it_cannot_read(payload: dict) -> None:
    assert fap.count_resolved(payload) == 0


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
    assets. Folding them on the name is the name-derived inference this plane replaces."""
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


def test_conflicting_declaration_classes_withhold_the_mutability(monkeypatch: pytest.MonkeyPatch) -> None:
    a = _state_var_receiver(SEL_TOKEN, "token", mutability="immutable_in_implementation")
    b = _state_var_receiver(SEL_TOKEN, "token", mutability="mutable")
    receivers = fap.collect_asset_receivers(_effects(_sink("s0", a), _sink("s1", b)))
    assert len(receivers) == 1
    assert receivers[0].declared_mutability is None


def test_two_identical_runs_produce_the_identical_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    effects = _effects(
        _sink("s1", _state_var_receiver(SEL_REWARD_TOKEN, "rewardTokenAddress")),
        _sink("s0", _state_var_receiver(SEL_TOKEN, "token")),
    )
    results = [EthCallResult(True, WORD_KING, None, None), EthCallResult(True, WORD_EIGEN, None, None)]
    first, _ = _run(monkeypatch, effects, results)
    second, _ = _run(monkeypatch, effects, results)
    assert first == second
    assert [r["asset_getter_selector"] for r in first["receivers"]] == sorted([SEL_TOKEN, SEL_REWARD_TOKEN])


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
    """No ``"latest"`` fallback."""
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


@pytest.mark.parametrize(
    ("effects", "probe_block", "deployment_address"),
    [
        pytest.param(None, PROBE, MERKLE_DROP, id="no_effects_artifact"),
        # An empty plane is not published as a proven-empty one.
        pytest.param(_effects(_sink("s0", _CALLER_NAMED_RECEIVER)), PROBE, MERKLE_DROP, id="no_licensed_receiver"),
        pytest.param(
            _effects(_sink("s0", _state_var_receiver(SEL_TOKEN, "token"))), PROBE, None, id="no_deployment_address"
        ),
    ],
)
def test_a_stage_with_nothing_to_resolve_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, effects: Any, probe_block: ProbeBlock, deployment_address: str | None
) -> None:
    ctx = _stage_ctx(monkeypatch, effects, [], probe_block=probe_block)
    monkeypatch.setattr(fap, "eth_call_batch", lambda *a, **k: pytest.fail("must not read"))
    written = ctx["worker"]._resolve_flow_asset_addresses(
        ctx["session"],
        ctx["job"],
        chain_id=1,
        rpc_url="http://stub",
        deployment_address=deployment_address,
        proven_proxied=deployment_address is not None,
    )
    assert written == 0
    assert ctx["store_calls"] == []


def test_the_writer_reads_the_proxy_not_the_implementation(monkeypatch: pytest.MonkeyPatch) -> None:
    """The proxy context is also the sole licence for ``redirectable_by_upgrade_authority``."""
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
    stored = [name for name, _ in ctx["store_calls"]]
    assert "control_snapshot" in stored
    assert "resolved_control_graph" in stored
