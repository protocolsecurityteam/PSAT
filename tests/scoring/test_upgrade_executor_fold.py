"""Upgrade executor fold (C4): what a receipt can and cannot prove. It proves which contract executed an upgrade
and whether a stored ``Upgraded`` log was the proxy's own deployment (24 of 120 protocol-1 events), and
``(chain_id, tx_hash)`` collapses the 19x fanout. It proves nothing about who authorised it: ``receipt.from``
on a Safe ``execTransaction`` is a relayer (5 senders for 11 txs on one Safe), so ``authorising_eoa`` is
always ``not_determined``. Fixtures are real mainnet receipts trimmed to the three topics the fold reads.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from db.models import (
    UPGRADE_SOURCE_BACKFILL,
    Contract,
    ContractCreationWitness,
    ControlGraphNode,
    Protocol,
    UpgradeEvent,
    UpgradeTransaction,
)
from services.discovery import upgrade_history as uh
from services.monitoring.event_topics import CALL_EXECUTED_TOPIC0, EXECUTION_SUCCESS_TOPIC0

_FIXTURES = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "upgrade_receipts" / "protocol1_receipts.json").read_text()
)

TX_FANOUT = "0xc9c80e5bc8a3f2eedfca80030eba7a5531bcb23774ca9da3e29a591032570314"  # 19 protocol-1 events
TX_SAFE_DIRECT = "0x142d4eb9434ec544c10811b222701445f5ba4078540a1194dae4a004a0c8b851"
TX_DEPLOY_EOA = "0x91ead36d1f684c35f6e32ea70cff333a60b3e2985b4ad62f4670319a52ca2306"  # receipt.to is null
TX_ONE_HOP = "0x3440c1094672739d4cdd3a09e86bd267af6f97a374d9f5695ec5d262db25e560"  # receipt.to == proxy
TX_DEPLOY_FACTORY = "0x884ad34345c5df9c0035b3c1dc2ca38d693c3a8186e3acbf699341873afd7851"  # via factory
# A genuinely dual-class proxy: the one the fanout touched, upgraded directly by a Safe 7.8M blocks earlier.
TX_DIRECT_ON_DUAL_PROXY = "0x3e2550609c6fef5a01b0f8f29a0163f7eccd3ed4fd8260f980fe9228771ba68d"
TX_SWAP_AND_RESTORE = "0xa2e2ce95c31eb30357d4a6fc58a417b11e55f35bdcf0b4464a3622f364d4cec9"

TIMELOCK = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761"
SAFE_ROUTING_THE_TIMELOCK = "0xcdd57d11476c22d265722f68390b036f3da48c21"
SAFE_DIRECT_EMITTER = "0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5"
SAFE_UNMODELLED = "0xf155a2632ef263a6a382028b3b33feb29175b8a5"  # 0 rows on every plane
PROXY_ONE_HOP = "0xb49e4420ea6e35f98060cd133842dbea9c27e479"
PROXY_FACTORY_MADE = "0xfbfe6b9cee0e555bad7e2e7309effc75200cbe38"
FACTORY = "0x356d1b83970cef2018f2c9337cddb67dff5aef99"
PROXY_SAFE_DIRECT = "0x8f08b70456eb22f6109f57b8fafe862ed28e6040"
PROXY_ETHERFI_NODES_MANAGER = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"

BLOCK_FANOUT = 25533308
BLOCK_SAFE_DIRECT = 21266067
BLOCK_DEPLOY_EOA = 17664328
BLOCK_ONE_HOP = 17666565
BLOCK_DEPLOY_FACTORY = 23583226
BLOCK_DIRECT_ON_DUAL_PROXY = 17730747
BLOCK_SWAP_AND_RESTORE = 21045075

FANOUT_PROXIES_IN_SCOPE = [
    "0x0ef8fa4760db8f5cd4d993f3e3416f30f942d705",
    "0x1b7a4c3797236a1c37f8741c0be35c2c72736fff",
    "0x308861a430be4cce5502d0a12724771fc6daf216",
    "0x35e7d6fef6f72add3c3e39dec6d9ccc29e3345fa",
    "0x35fa164735182de50811e8e2e824cfb9b6118ac2",
    "0x3d320286e014c3e1ce99af6d6b00f0c1d63e3000",
    "0x57aaf0004c716388b21795431cd7d5f9d3bb6a41",
    "0x62247d29b4b9becf4bb73e0c722cf6445cfc7ce9",
    "0x6c7c54cfc2225fa985cd25f04d923b93c60a02f8",
    "0x7d5706f6ef3f89b3951e23e557cdfbc3239d4e2c",
    "0x89e45081437c959a827d2027135bc201ab33a2c8",
    PROXY_ETHERFI_NODES_MANAGER,
    "0x9ffdf407cde9a93c47611799da23924af3ef764f",
    PROXY_ONE_HOP,
    "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
    "0xd5edf7730abad812247f6f54d7bd31a52554e35e",
    "0xd789870bea40d056a4d26055d0befcc8755da146",
    "0xdadef1ffbfeaab4f68a9fd181395f68b4e4e7ae0",
    PROXY_FACTORY_MADE,
]
FANOUT_PROXIES_OUT_OF_SCOPE = [
    "0x00c452affee3a17d9cecc1bcd2b8d5c7635c4cb9",
    "0x25e821b7197b146f7713c3b89b6a4d83516b912d",
]
# Not targets of the timelock's CallExecuted calls; joining every log in the tx would over-attribute them.
FANOUT_UNTARGETED = ["0x3c55986cfee455e2533f4d29006634ecf9b7c03f", "0xd789870bea40d056a4d26055d0befcc8755da146"]


class _Wire:
    """Records every call so tests can assert what was not asked for."""

    def __init__(self, receipts=None, code=None, creation=None):
        self.receipts = dict(receipts or {})
        self.code = dict(code or {})
        self.creation = dict(creation or {})
        self.calls: list[tuple] = []

    def rpc_request(self, _url, method, params, **_kw):
        self.calls.append((method, tuple(params)))
        if method == "eth_getTransactionReceipt":
            if params[0] not in self.receipts:
                raise RuntimeError("receipt not available")
            return self.receipts[params[0]]
        if method == "eth_getCode":
            return self.code.get((params[0].lower(), params[1]), "0xdeadbeef")
        raise AssertionError(f"unexpected RPC method {method}")

    def etherscan_get(self, module, action, chain_id, **params):
        self.calls.append((f"{module}/{action}", params.get("contractaddresses", "")))
        assert (module, action) == ("contract", "getcontractcreation")
        addrs = [a.lower() for a in params["contractaddresses"].split(",")]
        return {
            "result": [
                {"contractAddress": a, "txHash": self.creation[a][0], "blockNumber": str(self.creation[a][1])}
                for a in addrs
                if a in self.creation
            ]
        }


@pytest.fixture()
def wire():
    return _Wire()


def _run_fold(session, wire_stub, contract_ids, chain_id=1):
    with (
        patch("services.clients.rpc.rpc_url_for_chain_id", return_value="https://stub.invalid"),
        patch("services.clients.rpc.rpc_request", side_effect=wire_stub.rpc_request),
        patch("services.clients.etherscan.get", side_effect=wire_stub.etherscan_get),
    ):
        stats = uh.fold_upgrade_transactions(session, chain_id=chain_id, contract_ids=contract_ids)
    session.commit()
    return stats


@pytest.fixture()
def world(db_session):
    protocol = Protocol(name=f"u8-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()

    made: dict[tuple[str, str | None], Contract] = {}

    def contract(address, *, protocol_id=None, chain="ethereum"):
        key = (address.lower(), chain)
        if key in made:
            return made[key]
        row = Contract(
            protocol_id=protocol.id if protocol_id is None else protocol_id,
            address=address.lower(),
            chain=chain,
            contract_name="Proxy",
        )
        db_session.add(row)
        db_session.commit()
        made[key] = row
        return row

    def event(proxy_contract, tx_hash, block, *, impl=None):
        row = UpgradeEvent(
            contract_id=proxy_contract.id,
            proxy_address=proxy_contract.address,
            old_impl=None,
            new_impl=impl or ("0x" + "11" * 20),
            block_number=block,
            tx_hash=tx_hash,
            source=UPGRADE_SOURCE_BACKFILL,
        )
        db_session.add(row)
        db_session.commit()
        return row

    def classify(address, resolved_type, *, details=None, chain="ethereum"):
        anchor = contract(address, chain=chain)
        db_session.add(
            ControlGraphNode(
                contract_id=anchor.id,
                address=address.lower(),
                node_type="principal",
                resolved_type=resolved_type,
                details=details,
            )
        )
        db_session.commit()

    yield {
        "session": db_session,
        "protocol": protocol,
        "contract": contract,
        "event": event,
        "classify": classify,
    }

    db_session.rollback()
    ids = [c.id for c in made.values()]
    if ids:
        db_session.query(UpgradeEvent).filter(UpgradeEvent.contract_id.in_(ids)).delete(synchronize_session=False)
        db_session.query(ControlGraphNode).filter(ControlGraphNode.contract_id.in_(ids)).delete(
            synchronize_session=False
        )
    db_session.query(UpgradeTransaction).delete()
    db_session.query(ContractCreationWitness).delete()
    db_session.commit()
    if ids:
        db_session.query(Contract).filter(Contract.id.in_(ids)).delete(synchronize_session=False)
    db_session.query(Protocol).filter(Protocol.id == protocol.id).delete(synchronize_session=False)
    db_session.commit()


def _receipt(tx_hash, **overrides):
    data = json.loads(json.dumps(_FIXTURES[tx_hash]))
    data.update(overrides)
    return data


def test_topic0_pins():
    from eth_utils.crypto import keccak

    assert uh.UPGRADED_TOPIC0 == "0x" + keccak(text="Upgraded(address)").hex()
    assert CALL_EXECUTED_TOPIC0 == "0x" + keccak(text="CallExecuted(bytes32,uint256,address,uint256,bytes)").hex()
    assert EXECUTION_SUCCESS_TOPIC0 == "0x" + keccak(text="ExecutionSuccess(bytes32,uint256)").hex()
    assert CALL_EXECUTED_TOPIC0 == "0xc2617efa69bab66782fa219543714338489c4e9e178271560a91b82c3f612b58"
    assert uh.UPGRADED_TOPIC0 == "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"


def test_bloom_membership_matches_the_real_receipts():
    """A bloom has no false negatives, which licenses ``safe_direct``; the log array's completeness is exactly what's
    in question.
    """
    direct = _FIXTURES[TX_SAFE_DIRECT]
    fanout = _FIXTURES[TX_FANOUT]
    assert uh._bloom_has_topic(direct["logsBloom"], CALL_EXECUTED_TOPIC0) is False
    assert uh._bloom_has_topic(fanout["logsBloom"], CALL_EXECUTED_TOPIC0) is True
    assert uh._bloom_has_topic(None, CALL_EXECUTED_TOPIC0) is None
    assert uh._bloom_has_topic("0x00", CALL_EXECUTED_TOPIC0) is None


def test_pruned_log_array_with_intact_bloom_is_not_determined(world, wire):
    """eRPC fans out across upstreams, so a pruned log array is a real risk."""
    session = world["session"]
    proxy = world["contract"](PROXY_ETHERFI_NODES_MANAGER)
    world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)
    world["classify"](TIMELOCK, "timelock")
    world["classify"](SAFE_ROUTING_THE_TIMELOCK, "safe")

    stripped = _receipt(TX_FANOUT)
    stripped["logs"] = [log for log in stripped["logs"] if log["topics"][0].lower() != CALL_EXECUTED_TOPIC0.lower()]
    wire.receipts = {TX_FANOUT: stripped}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_FANOUT))
    assert row.receipt_log_set_complete_for_tx is False
    assert row.executor_kind == "not_determined"
    assert row.executor_address is None
    assert row.executor_call_targets is None


def test_pruned_log_array_with_the_bloom_removed_is_not_determined(world, wire):
    """With no bloom, a consistent-unless-contradicted rule would mint ``safe_direct`` from a ``timelock_routed``
    receipt.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_ETHERFI_NODES_MANAGER)
    world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)
    world["classify"](TIMELOCK, "timelock")
    world["classify"](SAFE_ROUTING_THE_TIMELOCK, "safe")

    stripped = _receipt(TX_FANOUT)
    stripped["logs"] = [log for log in stripped["logs"] if log["topics"][0].lower() != CALL_EXECUTED_TOPIC0.lower()]
    stripped.pop("logsBloom")
    wire.receipts = {TX_FANOUT: stripped}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_FANOUT))
    assert row.receipt_log_set_complete_for_tx is False
    assert row.executor_kind == "not_determined"
    assert row.executor_kind != "safe_direct"
    assert row.executor_address is None


def test_all_zero_bloom_is_not_proof_of_absence(world, wire):
    """The log array carries an ``Upgraded`` log, so a working bloom must confirm it."""
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")

    zeroed = _receipt(TX_SAFE_DIRECT, logsBloom="0x" + "0" * 512)
    assert uh._bloom_has_topic(zeroed["logsBloom"], CALL_EXECUTED_TOPIC0) is False, (
        "the zeroed bloom is shape-valid and reports absence — that is the trap"
    )
    wire.receipts = {TX_SAFE_DIRECT: zeroed}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.receipt_log_set_complete_for_tx is False
    assert row.executor_kind == "not_determined"
    assert row.executor_kind != "safe_direct"

    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])
    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    session.refresh(row)
    assert row.receipt_log_set_complete_for_tx is True
    assert row.executor_kind == "safe_direct"


def test_receipt_missing_our_own_event_is_not_complete(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")

    filtered = _receipt(TX_SAFE_DIRECT)
    filtered["logs"] = [log for log in filtered["logs"] if log["topics"][0].lower() != uh.UPGRADED_TOPIC0.lower()]
    wire.receipts = {TX_SAFE_DIRECT: filtered}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.receipt_log_set_complete_for_tx is False
    assert row.executor_kind == "not_determined"


@pytest.fixture()
def fanout_world(world, wire):
    session = world["session"]
    in_scope = [world["contract"](a) for a in FANOUT_PROXIES_IN_SCOPE]
    out_of_scope = [world["contract"](a) for a in FANOUT_PROXIES_OUT_OF_SCOPE]
    for proxy in in_scope + out_of_scope:
        world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)
    world["classify"](TIMELOCK, "timelock")
    world["classify"](SAFE_ROUTING_THE_TIMELOCK, "safe")
    wire.receipts = {TX_FANOUT: _receipt(TX_FANOUT)}
    _run_fold(session, wire, [c.id for c in in_scope + out_of_scope])
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, **world}


def test_nineteen_events_are_one_governance_action(fanout_world):
    """Per event this publishes 19 exercises of upgrade authority; per action, one."""
    session = fanout_world["session"]
    ids = [c.id for c in fanout_world["in_scope"]]
    assert len(ids) == 19
    assert session.query(UpgradeEvent).filter(UpgradeEvent.tx_hash == TX_FANOUT).count() == 21

    # The same hash can name another chain's transaction (#158).
    actions = uh.governance_actions_for(session, ids)
    assert actions == {(1, TX_FANOUT)}
    assert len(actions) == 1

    # A7: widening the scope must not multiply the action.
    all_ids = ids + [c.id for c in fanout_world["out_of_scope"]]
    assert uh.governance_actions_for(session, all_ids) == {(1, TX_FANOUT)}
    assert session.query(UpgradeTransaction).count() == 1


def test_fanout_executor_is_the_classified_timelock(fanout_world):
    session = fanout_world["session"]
    row = session.get(UpgradeTransaction, (1, TX_FANOUT))
    assert row.executor_kind == "timelock_routed"
    assert row.executor_address == TIMELOCK
    assert row.executor_classified_type == "timelock"
    assert row.executor_classification_source == "control_graph_nodes"
    assert row.receipt_log_set_complete_for_tx is True
    assert row.tx_status == 1
    assert row.block_number == BLOCK_FANOUT
    assert row.is_contract_creation is False
    # The tx also carries a Safe's ExecutionSuccess; CallExecuted decides.
    assert row.executor_address != SAFE_ROUTING_THE_TIMELOCK


def test_call_targets_distinguish_the_proxies_the_timelock_actually_called(fanout_world):
    """A3: 26 ``Upgraded`` emitters, 24 of them ``CallExecuted`` targets."""
    session = fanout_world["session"]
    row = session.get(UpgradeTransaction, (1, TX_FANOUT))
    targets = {t.lower() for t in row.executor_call_targets}
    assert len(targets) == 26

    emitters = {
        log["address"].lower() for log in _FIXTURES[TX_FANOUT]["logs"] if log["topics"][0] == uh.UPGRADED_TOPIC0
    }
    assert len(emitters) == 26
    assert len(emitters & targets) == 24
    assert sorted(emitters - targets) == sorted(FANOUT_UNTARGETED)

    assert PROXY_ETHERFI_NODES_MANAGER.lower() in targets


def test_safe_direct_publishes_no_authoriser_though_receipt_from_is_populated(world, wire):
    """``receipt.from`` is the submitter, not the signer set: five senders relayed for one Safe."""
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "safe_direct"
    assert row.executor_address == SAFE_DIRECT_EMITTER
    assert row.executor_classified_type == "safe"
    assert row.executor_call_targets is None

    assert row.receipt_from == "0x544bdcbb88f2756000de227580aaad7376f3794e"
    assert not hasattr(row, "authorising_eoa")
    basis = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    assert basis["authorising_eoa"] == "not_determined"


def test_one_hop_publishes_no_authoriser(world, wire):
    """``receipt.to == proxy`` only proves the top-level frame; self-calls, multicall and ERC-2771 break it at the
    upgrade site.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_ONE_HOP, BLOCK_ONE_HOP)
    wire.receipts = {TX_ONE_HOP: _receipt(TX_ONE_HOP)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_ONE_HOP))
    assert row.executor_kind == "not_determined"
    assert row.executor_kind != "eoa_one_hop"
    assert "eoa_one_hop" not in set(__import__("db.models", fromlist=["EXECUTOR_KINDS"]).EXECUTOR_KINDS)
    assert row.executor_address is None
    assert row.receipt_to == PROXY_ONE_HOP
    assert row.receipt_from == "0xf8a86ea1ac39ec529814c377bd484387d395421e"
    basis = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    assert basis["authorising_eoa"] == "not_determined"


def test_eoa_creation_transaction_is_a_deployment_not_an_upgrade(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA)
    world["event"](proxy, TX_ONE_HOP, BLOCK_ONE_HOP)
    wire.receipts = {TX_DEPLOY_EOA: _receipt(TX_DEPLOY_EOA), TX_ONE_HOP: _receipt(TX_ONE_HOP)}
    wire.creation = {PROXY_ONE_HOP: (TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA)}
    wire.code = {(PROXY_ONE_HOP, hex(BLOCK_DEPLOY_EOA - 1)): "0x"}
    _run_fold(session, wire, [proxy.id])

    deploy = session.get(UpgradeTransaction, (1, TX_DEPLOY_EOA))
    assert deploy.is_contract_creation is True
    assert deploy.receipt_to is None
    assert deploy.created_contract_address == PROXY_ONE_HOP
    assert uh.event_is_deployment(
        deploy, None, proxy_address=PROXY_ONE_HOP, event_block=BLOCK_DEPLOY_EOA, pair_event_count=1
    )

    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["count"] == 1, "the creation event must not be published as an upgrade"
    assert entry["basis"]["deployments_excluded"] == 1
    assert entry["basis"]["events_total"] == 2


def test_factory_deployed_proxy_needs_both_witnesses(world, wire):
    """A factory deployment has a populated ``receipt.to``, so it needs the indexer naming the tx and no code at the
    preceding block, together.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_FACTORY_MADE)
    world["event"](proxy, TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)
    wire.receipts = {TX_DEPLOY_FACTORY: _receipt(TX_DEPLOY_FACTORY)}
    wire.creation = {PROXY_FACTORY_MADE: (TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)}
    wire.code = {(PROXY_FACTORY_MADE, hex(BLOCK_DEPLOY_FACTORY - 1)): "0x"}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_DEPLOY_FACTORY))
    assert row.is_contract_creation is False, "the receipt names the factory, not a creation"
    assert row.receipt_to == FACTORY
    witness = session.get(ContractCreationWitness, (1, PROXY_FACTORY_MADE))
    assert witness.creation_tx_hash == TX_DEPLOY_FACTORY
    assert witness.code_probe_block == BLOCK_DEPLOY_FACTORY - 1
    assert witness.code_absent_at_probe is True

    assert uh.event_is_deployment(
        row, witness, proxy_address=PROXY_FACTORY_MADE, event_block=BLOCK_DEPLOY_FACTORY, pair_event_count=1
    )
    # A5: with only a deployment there's no proven upgrade, and "0 upgrades" isn't what the rows support.
    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["count"] is None
    assert entry["basis"]["deployments_excluded"] == 1


def test_one_witness_alone_never_proves_a_deployment(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_FACTORY_MADE)
    world["event"](proxy, TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)
    wire.receipts = {TX_DEPLOY_FACTORY: _receipt(TX_DEPLOY_FACTORY)}
    wire.creation = {PROXY_FACTORY_MADE: (TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)}
    wire.code = {(PROXY_FACTORY_MADE, hex(BLOCK_DEPLOY_FACTORY - 1)): "0x60016000"}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_DEPLOY_FACTORY))
    witness = session.get(ContractCreationWitness, (1, PROXY_FACTORY_MADE))
    assert witness.code_absent_at_probe is False
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_FACTORY_MADE, event_block=BLOCK_DEPLOY_FACTORY, pair_event_count=1
    )
    assert uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["count"] == 1

    witness.creation_tx_hash = "0x" + "ee" * 32
    witness.code_absent_at_probe = True
    session.commit()
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_FACTORY_MADE, event_block=BLOCK_DEPLOY_FACTORY, pair_event_count=1
    )


def test_creation_probe_is_taken_only_where_it_could_decide(world, wire):
    """Elsewhere a probe would produce a height with no verdict attached."""
    session = world["session"]
    proxy = world["contract"](PROXY_FACTORY_MADE)
    world["event"](proxy, TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)
    wire.receipts = {TX_DEPLOY_FACTORY: _receipt(TX_DEPLOY_FACTORY)}
    wire.creation = {PROXY_FACTORY_MADE: ("0x" + "cc" * 32, BLOCK_DEPLOY_FACTORY - 500)}
    _run_fold(session, wire, [proxy.id])

    witness = session.get(ContractCreationWitness, (1, PROXY_FACTORY_MADE))
    assert witness.creation_tx_hash == "0x" + "cc" * 32
    assert witness.code_probe_block is None
    assert witness.code_absent_at_probe is None
    assert ("eth_getCode", (PROXY_FACTORY_MADE, hex(BLOCK_DEPLOY_FACTORY - 1))) not in wire.calls

    row = session.get(UpgradeTransaction, (1, TX_DEPLOY_FACTORY))
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_FACTORY_MADE, event_block=BLOCK_DEPLOY_FACTORY, pair_event_count=1
    )
    assert uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["count"] == 1


def test_within_tx_double_upgrade_is_never_excluded(world, wire):
    """A6: excluding a swap-and-restore would drop a real implementation change."""
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA, impl="0x" + "aa" * 20)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA, impl="0x" + "bb" * 20)
    wire.receipts = {TX_DEPLOY_EOA: _receipt(TX_DEPLOY_EOA)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_DEPLOY_EOA))
    assert uh.event_is_deployment(
        row, None, proxy_address=PROXY_ONE_HOP, event_block=BLOCK_DEPLOY_EOA, pair_event_count=1
    )
    assert not uh.event_is_deployment(
        row, None, proxy_address=PROXY_ONE_HOP, event_block=BLOCK_DEPLOY_EOA, pair_event_count=2
    )
    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["count"] == 1
    assert entry["basis"]["deployments_excluded"] == 0


def test_under_projected_pair_is_caught_by_the_receipts_own_count(world, wire):
    """If only one of a swap-and-restore's two logs was stored, the stored rows can't show it; the receipt's
    per-proxy count is the independent check. Latent (0 live instances) but silent when it fires.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SWAP_AND_RESTORE, BLOCK_SWAP_AND_RESTORE, impl="0x" + "aa" * 20)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")
    wire.receipts = {TX_SWAP_AND_RESTORE: _receipt(TX_SWAP_AND_RESTORE)}
    wire.creation = {PROXY_SAFE_DIRECT: (TX_SWAP_AND_RESTORE, BLOCK_SWAP_AND_RESTORE)}
    wire.code = {(PROXY_SAFE_DIRECT, hex(BLOCK_SWAP_AND_RESTORE - 1)): "0x"}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SWAP_AND_RESTORE))
    witness = session.get(ContractCreationWitness, (1, PROXY_SAFE_DIRECT))
    assert row.receipt_upgraded_counts[PROXY_SAFE_DIRECT] == 2
    assert witness.creation_tx_hash == TX_SWAP_AND_RESTORE
    assert witness.code_absent_at_probe is True
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_SAFE_DIRECT, event_block=BLOCK_SWAP_AND_RESTORE, pair_event_count=1
    )
    assert uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["count"] == 1


def test_real_swap_and_restore_is_one_action_not_two(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SWAP_AND_RESTORE, BLOCK_SWAP_AND_RESTORE, impl="0x" + "aa" * 20)
    world["event"](proxy, TX_SWAP_AND_RESTORE, BLOCK_SWAP_AND_RESTORE, impl="0x" + "bb" * 20)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")
    wire.receipts = {TX_SWAP_AND_RESTORE: _receipt(TX_SWAP_AND_RESTORE)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SWAP_AND_RESTORE))
    assert row.executor_kind == "safe_direct"
    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["basis"]["events_total"] == 2
    assert entry["count"] == 1


def test_unavailable_receipt_writes_no_row_and_drops_no_event(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    wire.receipts = {}
    stats = _run_fold(session, wire, [proxy.id])

    assert stats["tx_in_scope"] == 1
    assert stats["tx_folded"] == 0
    assert stats["tx_receipt_unusable"] == 1
    assert session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT)) is None
    assert session.query(UpgradeEvent).filter(UpgradeEvent.contract_id == proxy.id).count() == 1

    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["count"] == 1, "an unwitnessed event stays counted — the count is an upper bound"
    assert entry["basis"]["events_unlinked"] == 1
    assert entry["basis"]["tx_facts_present"] == 0


def test_unclassified_safe_emitter_is_not_determined(world, wire):
    """T7: the emitter really is a Safe, but nothing in the classification plane says so, and the fold may not decide
    that itself.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.receipt_log_set_complete_for_tx is True, "the receipt is fine; the emitter is what is unknown"
    assert row.executor_kind == "not_determined"
    assert row.executor_address is None
    assert row.executor_classification_source is None


def test_reverted_transaction_publishes_nothing_positive(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT, status="0x0")}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.tx_status == 0
    assert row.executor_kind == "not_determined"
    assert row.executor_address is None
    assert not uh.event_is_deployment(
        row, None, proxy_address=PROXY_SAFE_DIRECT, event_block=BLOCK_SAFE_DIRECT, pair_event_count=1
    )


def test_receipt_without_status_is_unusable(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    payload = _receipt(TX_SAFE_DIRECT)
    payload.pop("status")
    wire.receipts = {TX_SAFE_DIRECT: payload}
    stats = _run_fold(session, wire, [proxy.id])

    assert stats["tx_receipt_unusable"] == 1
    assert session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT)) is None


# ``probe_block`` is absent on every current row, so the kind never claims "was a Safe at the upgrade's block".
@pytest.mark.parametrize(
    ("details", "expected_block"),
    [
        pytest.param({"address": SAFE_DIRECT_EMITTER}, None, id="not-determined-when-the-plane-has-none"),
        pytest.param(
            {"safe_protection": {"probe_block": 25643300, "guard": "not_determined"}},
            25643300,
            id="published-when-the-probe-recorded-one",
        ),
        pytest.param(
            {"safe_protection": {"probe_block": "not_determined"}},
            None,
            id="not-determined-probe-block-string-is-not-a-height",
        ),
    ],
)
def test_classification_block(world, wire, details, expected_block):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", details=details)
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "safe_direct"
    assert row.executor_classification_block == expected_block
    assert expected_block is None or row.executor_classification_block > row.block_number


def test_direct_upgrade_witnessed_block_is_published_and_decoy_is_not(world, wire):
    """History shows a path was exercised, not that it's closed now, so ``timelock_is_decoy`` is ``not_determined``
    either way.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DIRECT_ON_DUAL_PROXY, BLOCK_DIRECT_ON_DUAL_PROXY)
    world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)
    # Classified deliberately; in the real corpus this Safe has no rows (see T7).
    world["classify"](SAFE_UNMODELLED, "safe")
    world["classify"](TIMELOCK, "timelock")
    world["classify"](SAFE_ROUTING_THE_TIMELOCK, "safe")
    wire.receipts = {
        TX_DIRECT_ON_DUAL_PROXY: _receipt(TX_DIRECT_ON_DUAL_PROXY),
        TX_FANOUT: _receipt(TX_FANOUT),
    }
    _run_fold(session, wire, [proxy.id])

    basis = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    assert basis["direct_upgrade_witnessed_at_block"] == BLOCK_DIRECT_ON_DUAL_PROXY
    assert BLOCK_DIRECT_ON_DUAL_PROXY < BLOCK_FANOUT
    assert basis["timelock_is_decoy"] == "not_determined"
    assert basis["executor_kinds"] == {"safe_direct": 1, "timelock_routed": 1}

    later = session.query(UpgradeEvent).filter(UpgradeEvent.tx_hash == TX_DIRECT_ON_DUAL_PROXY).one()
    later.block_number = BLOCK_FANOUT + 1
    session.commit()
    basis_after = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    assert basis_after["timelock_is_decoy"] == "not_determined"


def test_published_count_drops_the_deployment_and_keeps_the_unwitnessed(world, wire):
    """T11: the count is an upper bound either way."""
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA)
    world["event"](proxy, TX_ONE_HOP, BLOCK_ONE_HOP)
    world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)

    before = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert before["count"] == 3
    assert before["basis"]["events_unlinked"] == 3
    assert before["basis"]["deployments_excluded"] == 0

    world["classify"](TIMELOCK, "timelock")
    world["classify"](SAFE_ROUTING_THE_TIMELOCK, "safe")
    wire.receipts = {
        TX_DEPLOY_EOA: _receipt(TX_DEPLOY_EOA),
        TX_ONE_HOP: _receipt(TX_ONE_HOP),
        TX_FANOUT: _receipt(TX_FANOUT),
    }
    _run_fold(session, wire, [proxy.id])

    after = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert after["count"] == 2
    assert after["basis"]["deployments_excluded"] == 1
    assert after["basis"]["tx_facts_present"] == 3
    assert after["basis"]["events_unlinked"] == 0
    assert after["basis"]["recorded_event_coverage"] == "not_determined"


def test_post_exclusion_zero_is_not_determined_never_zero(world, wire):
    """A5: the recording surface is unwitnessed (only ERC-1967 topics; ``old_impl`` NULL on backfilled rows), so zero
    would read as an earned negative.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA)
    wire.receipts = {TX_DEPLOY_EOA: _receipt(TX_DEPLOY_EOA)}
    _run_fold(session, wire, [proxy.id])

    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["count"] is None
    assert entry["count"] != 0
    assert entry["basis"]["events_total"] == 1
    assert entry["basis"]["deployments_excluded"] == 1
    assert entry["basis"]["recorded_event_coverage"] == "not_determined"


def test_company_overview_publishes_the_count_with_its_basis(world, wire):
    from services.aggregations.company_overview import _prefetch_child_tables

    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA)
    world["event"](proxy, TX_ONE_HOP, BLOCK_ONE_HOP)
    wire.receipts = {TX_DEPLOY_EOA: _receipt(TX_DEPLOY_EOA), TX_ONE_HOP: _receipt(TX_ONE_HOP)}
    _run_fold(session, wire, [proxy.id])

    children = _prefetch_child_tables(session, {proxy.id})
    entry = children["upgrade_events_count"][proxy.id]
    assert entry["count"] == 1
    assert entry["basis"]["authorising_eoa"] == "not_determined"
    assert entry["basis"]["timelock_is_decoy"] == "not_determined"
    assert entry["basis"]["recorded_event_coverage"] == "not_determined"


# Addresses are identities only within a chain; an unscoped read is the cross-chain fail-open PR #158 closed elsewhere.


def test_off_chain_twin_does_not_classify_the_emitter(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](
        SAFE_DIRECT_EMITTER,
        "safe",
        chain="base",
        details={"safe_protection": {"probe_block": 24_000_000}},
    )
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == uh.NOT_DETERMINED
    assert row.executor_address is None
    assert row.executor_classification_source is None
    assert row.executor_classified_type is None
    assert row.executor_classification_block is None


def test_same_chain_twin_still_classifies_exactly_as_before(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](
        SAFE_DIRECT_EMITTER,
        "safe",
        chain="ethereum",
        details={"safe_protection": {"probe_block": 21_000_000}},
    )
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "safe_direct"
    assert row.executor_address == SAFE_DIRECT_EMITTER
    assert row.executor_classified_type == "safe"
    assert row.executor_classification_source == "control_graph_nodes"
    assert row.executor_classification_block == 21_000_000


def test_classification_block_is_never_taken_from_another_chains_probe(world, wire):
    """Publishing Base's probe height beside a mainnet row would cite a chain this tx was never on."""
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", chain="ethereum")
    world["classify"](
        SAFE_DIRECT_EMITTER,
        "safe",
        chain="base",
        details={"safe_protection": {"probe_block": 24_000_000}},
    )
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "safe_direct"
    assert row.executor_classification_block is None


def test_a_row_whose_contract_has_no_chain_classifies_nothing(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", chain=None)
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == uh.NOT_DETERMINED
    assert row.executor_address is None


def test_an_off_chain_disagreement_no_longer_blocks_a_same_chain_verdict(world, wire):
    """The unscoped read also failed closed wrongly: a Base twin typed ``timelock`` blanked the mainnet ``safe``
    verdict.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", chain="ethereum")
    world["classify"](SAFE_DIRECT_EMITTER, "timelock", chain="base")
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "safe_direct"
    assert row.executor_classified_type == "safe"


# ``mainnet`` is the registry alias for chain 1.
@pytest.mark.parametrize(
    "classifications",
    [
        pytest.param([("safe", {}), ("timelock", {})], id="planes-that-disagree"),
        pytest.param(
            [("safe", {"chain": "ethereum"}), ("timelock", {"chain": "mainnet"})],
            id="same-chain-disagreement",
        ),
    ],
)
def test_disagreeing_classifications_blank_the_verdict(world, wire, classifications):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    for classified_type, kwargs in classifications:
        world["classify"](SAFE_DIRECT_EMITTER, classified_type, **kwargs)
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == uh.NOT_DETERMINED
    assert row.executor_address is None
