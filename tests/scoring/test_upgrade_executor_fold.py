"""Upgrade executor fold (C4) — what a transaction receipt can and cannot prove.

``upgrade_events`` stores no sender, no receipt and no trace. The fold adds the
transaction's own receipt as a second instrument, and the whole point of this
file is to pin the LINE between what that instrument proves and what it does
not:

* it proves which contract EXECUTED an upgrade (a keccak-matched marker log
  whose emitter an independent classifier typed) — ``executor_kind``;
* it proves a stored ``Upgraded`` log was the proxy's own DEPLOYMENT, by either
  of two arms, and 24 of the 120 protocol-1 events turn out to be exactly that;
* it collapses the 19x fanout, because ``(chain_id, tx_hash)`` is the governance
  action id;
* it proves NOTHING about who authorised anything. ``receipt.from`` on a Safe
  ``execTransaction`` is a relayer — the 11 ``ExecutionSuccess``-bearing
  transactions on one Safe were submitted by five distinct senders — so
  ``authorising_eoa`` is ``not_determined`` on every row including the one-hop
  transactions where ``receipt.to == proxy``.

Every fixture is a real mainnet receipt, trimmed to the three topics the fold
reads (``tests/fixtures/upgrade_receipts/protocol1_receipts.json``); the wire is
stubbed, so nothing here touches the network. The expected values were
re-measured against those receipts, not copied from a report.
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

# --- the real measured transactions -----------------------------------------
TX_FANOUT = "0xc9c80e5bc8a3f2eedfca80030eba7a5531bcb23774ca9da3e29a591032570314"  # 19 protocol-1 events
TX_SAFE_DIRECT = "0x142d4eb9434ec544c10811b222701445f5ba4078540a1194dae4a004a0c8b851"
TX_DEPLOY_EOA = "0x91ead36d1f684c35f6e32ea70cff333a60b3e2985b4ad62f4670319a52ca2306"  # receipt.to is null
TX_ONE_HOP = "0x3440c1094672739d4cdd3a09e86bd267af6f97a374d9f5695ec5d262db25e560"  # receipt.to == proxy
TX_DEPLOY_FACTORY = "0x884ad34345c5df9c0035b3c1dc2ca38d693c3a8186e3acbf699341873afd7851"  # via factory
# The same proxy the fanout touched, upgraded directly by a Safe 7.8M blocks
# earlier — a genuinely dual-class proxy, which is the shape the decoy question
# is asked about.
TX_DIRECT_ON_DUAL_PROXY = "0x3e2550609c6fef5a01b0f8f29a0163f7eccd3ed4fd8260f980fe9228771ba68d"
# Two Upgraded logs for ONE proxy in ONE transaction — a real swap-and-restore.
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

# The 19 protocol-1 proxies the fanout transaction touched (measured against the
# persisted rows), plus the two it touched outside that scope.
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
# The same transaction also touched two proxies with no protocol of their own —
# the persisted table carries 21 rows for it, 19 of them in protocol 1.
FANOUT_PROXIES_OUT_OF_SCOPE = [
    "0x00c452affee3a17d9cecc1bcd2b8d5c7635c4cb9",
    "0x25e821b7197b146f7713c3b89b6a4d83516b912d",
]
# Two of the 26 Upgraded emitters in the fanout receipt are NOT targets of the
# timelock's own CallExecuted calls — the naive "join every log in the tx to the
# executor" would over-attribute both.
FANOUT_UNTARGETED = ["0x3c55986cfee455e2533f4d29006634ecf9b7c03f", "0xd789870bea40d056a4d26055d0befcc8755da146"]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _Wire:
    """Stubbed chain + indexer. Records every call so a test can assert what
    was NOT asked for as well as what was."""

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
        patch("utils.rpc.rpc_url_for_chain_id", return_value="https://stub.invalid"),
        patch("utils.rpc.rpc_request", side_effect=wire_stub.rpc_request),
        patch("utils.etherscan.get", side_effect=wire_stub.etherscan_get),
    ):
        stats = uh.fold_upgrade_transactions(session, chain_id=chain_id, contract_ids=contract_ids)
    session.commit()
    return stats


@pytest.fixture()
def world(db_session):
    """A protocol plus the address bookkeeping the fold reads."""
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
        # The plane row reaches its chain through the contract it is anchored
        # to, which is exactly the join the fold scopes on.
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


# ---------------------------------------------------------------------------
# T10 — topic pins. Everything below rests on these three hashes.
# ---------------------------------------------------------------------------


def test_topic0_pins():
    from eth_utils.crypto import keccak

    assert uh.UPGRADED_TOPIC0 == "0x" + keccak(text="Upgraded(address)").hex()
    assert CALL_EXECUTED_TOPIC0 == "0x" + keccak(text="CallExecuted(bytes32,uint256,address,uint256,bytes)").hex()
    assert EXECUTION_SUCCESS_TOPIC0 == "0x" + keccak(text="ExecutionSuccess(bytes32,uint256)").hex()
    assert CALL_EXECUTED_TOPIC0 == "0xc2617efa69bab66782fa219543714338489c4e9e178271560a91b82c3f612b58"
    assert uh.UPGRADED_TOPIC0 == "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"


# ---------------------------------------------------------------------------
# A2 — the completeness basis is COMPUTED
# ---------------------------------------------------------------------------


def test_bloom_membership_matches_the_real_receipts():
    """A bloom has no false negatives, so ``False`` is proof of absence.

    This is what licenses the ``safe_direct`` verdict, which rests on the
    absence of ``CallExecuted``: without it the absence would be observed only
    in the log array whose completeness is exactly what is in question.
    """
    direct = _FIXTURES[TX_SAFE_DIRECT]
    fanout = _FIXTURES[TX_FANOUT]
    assert uh._bloom_has_topic(direct["logsBloom"], CALL_EXECUTED_TOPIC0) is False
    assert uh._bloom_has_topic(fanout["logsBloom"], CALL_EXECUTED_TOPIC0) is True
    # An unusable bloom is not a "no".
    assert uh._bloom_has_topic(None, CALL_EXECUTED_TOPIC0) is None
    assert uh._bloom_has_topic("0x00", CALL_EXECUTED_TOPIC0) is None


def test_pruned_log_array_with_intact_bloom_is_not_determined(world, wire):
    """Bloom says ``CallExecuted`` is there, the log array does not have it.

    eRPC fans out across upstreams, so a pruned or filtered log array is a real
    risk rather than a theoretical one. The transaction must not be read as
    ``safe_direct`` just because the marker it would have to rule out went
    missing.
    """
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
    """The same pruning, with the ``logsBloom`` gone as well.

    This is the shape that made the bloom a *consistency check* rather than a
    witness: with no bloom there is nothing to disagree with, so a
    "consistent-unless-contradicted" rule reads silence as agreement and mints
    ``safe_direct`` from a receipt whose ground truth is ``timelock_routed``.
    The absence arm is only ever licensed by a bloom that is actually there and
    actually works.
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
    """An all-zero bloom is shape-valid and answers "absent" to every query.

    Read as a witness it proves every marker missing at once — the purest form
    of absence-as-evidence. The positive control catches it: the log array
    carries an ``Upgraded`` log, so a working bloom must confirm THAT, and a
    bloom which cannot answer a question whose answer we know may not be
    trusted on the question we do not.
    """
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

    # Control: the same receipt with its real bloom does reach safe_direct, so
    # the assertion above is the bloom's doing and not some other refusal.
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])
    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    session.refresh(row)
    assert row.receipt_log_set_complete_for_tx is True
    assert row.executor_kind == "safe_direct"


def test_receipt_missing_our_own_event_is_not_complete(world, wire):
    """Self-consistency: a receipt that does not carry the very ``Upgraded`` log
    we stored for it cannot be used to reason about what it does NOT carry."""
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


# ---------------------------------------------------------------------------
# T1 / A3 / A7 — the fanout, its executor, and what the executor targeted
# ---------------------------------------------------------------------------


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
    """The whole reason ``(chain_id, tx_hash)`` is the key.

    One transaction, 19 stored protocol-1 events across 19 distinct proxies.
    Counted per event it publishes 19 exercises of upgrade authority; counted
    per action it publishes one.
    """
    session = fanout_world["session"]
    ids = [c.id for c in fanout_world["in_scope"]]
    assert len(ids) == 19
    assert session.query(UpgradeEvent).filter(UpgradeEvent.tx_hash == TX_FANOUT).count() == 21

    # The action id is the PAIR, not the bare hash: the same 32 bytes can name
    # a different transaction on another chain, and a bare-hash union across
    # contracts would silently merge them (#158).
    actions = uh.governance_actions_for(session, ids)
    assert actions == {(1, TX_FANOUT)}
    assert len(actions) == 1

    # A7: the answer is always relative to the scope asked for. The same
    # transaction touches proxies outside it, and widening the scope must not
    # multiply the action.
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
    # The transaction also carries an ExecutionSuccess (a Safe routed the call
    # through the timelock). CallExecuted decides, and the Safe is not the
    # executor of record.
    assert row.executor_address != SAFE_ROUTING_THE_TIMELOCK


def test_call_targets_distinguish_the_proxies_the_timelock_actually_called(fanout_world):
    """A3 — 26 ``Upgraded`` emitters, 24 of them named as ``CallExecuted``
    targets. Joining every log in a timelock-routed transaction to the timelock
    over-attributes the other two."""
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


# ---------------------------------------------------------------------------
# T2 / T4 — the tx.from ban, on both shapes that tempt it
# ---------------------------------------------------------------------------


def test_safe_direct_publishes_no_authoriser_though_receipt_from_is_populated(world, wire):
    """The reject-list pin.

    ``receipt.from`` is right there, populated, on a transaction whose executor
    is a Safe we positively classified. It is still the submitter, not the
    signer set: five distinct senders were measured relaying for one Safe.
    """
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
    # ExecutionSuccess carries no target word.
    assert row.executor_call_targets is None

    assert row.receipt_from == "0x544bdcbb88f2756000de227580aaad7376f3794e"
    assert not hasattr(row, "authorising_eoa")
    basis = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    assert basis["authorising_eoa"] == "not_determined"


def test_one_hop_publishes_no_authoriser(world, wire):
    """``receipt.to == proxy`` is the strongest shape the corpus offers, and it
    is still not authorship.

    It proves ``tx.from`` was msg.sender in the TOP-LEVEL frame. It does not
    prove it was msg.sender at the upgrade site (a self-call, a multicall entry
    point or an ERC-2771 path all break that), and it says nothing about what
    the upgrade's guard reads. So: no ``eoa_one_hop`` executor kind, and the
    authoriser stays unknown.
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


# ---------------------------------------------------------------------------
# T3 / T5 / A1 — the two deployment arms
# ---------------------------------------------------------------------------


def test_eoa_creation_transaction_is_a_deployment_not_an_upgrade(world, wire):
    """Arm 1, airtight: ``receipt.to`` is null and ``contractAddress`` is the
    proxy, so this ``Upgraded`` log is the proxy's own birth."""
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
    """Arm 2 — the six the receipt rule alone could never catch.

    A factory-deployed proxy has a populated ``receipt.to`` (the factory), so
    its deployment is indistinguishable from an upgrade on the receipt alone.
    The indexer naming this exact transaction AND ``eth_getCode`` proving the
    address held no code in the preceding block prove it together. Neither
    alone is admitted.
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
    # A5: the only event was a deployment, so there is no proven upgrade — and
    # "0 upgrades" is not what the rows support.
    entry = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]
    assert entry["count"] is None
    assert entry["basis"]["deployments_excluded"] == 1


def test_one_witness_alone_never_proves_a_deployment(world, wire):
    """Disagreement between the two witnesses stays ``not_determined``, and a
    not-determined event stays COUNTED."""
    session = world["session"]
    proxy = world["contract"](PROXY_FACTORY_MADE)
    world["event"](proxy, TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)
    wire.receipts = {TX_DEPLOY_FACTORY: _receipt(TX_DEPLOY_FACTORY)}
    wire.creation = {PROXY_FACTORY_MADE: (TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)}
    # The indexer names the tx, but the address already had code.
    wire.code = {(PROXY_FACTORY_MADE, hex(BLOCK_DEPLOY_FACTORY - 1)): "0x60016000"}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_DEPLOY_FACTORY))
    witness = session.get(ContractCreationWitness, (1, PROXY_FACTORY_MADE))
    assert witness.code_absent_at_probe is False
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_FACTORY_MADE, event_block=BLOCK_DEPLOY_FACTORY, pair_event_count=1
    )
    assert uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["count"] == 1

    # Code absent but the indexer naming a DIFFERENT transaction is equally
    # inadmissible.
    witness.creation_tx_hash = "0x" + "ee" * 32
    witness.code_absent_at_probe = True
    session.commit()
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_FACTORY_MADE, event_block=BLOCK_DEPLOY_FACTORY, pair_event_count=1
    )


def test_creation_probe_is_taken_only_where_it_could_decide(world, wire):
    """The code probe is pinned to the block before the proxy's EARLIEST stored
    event, and is taken only when the indexer names that very transaction.

    Anywhere else the second witness has nothing to corroborate, so probing
    would produce a height with no verdict attached to it — and an unattached
    height is exactly the kind of stray fact a later reader mistakes for one.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_FACTORY_MADE)
    world["event"](proxy, TX_DEPLOY_FACTORY, BLOCK_DEPLOY_FACTORY)
    wire.receipts = {TX_DEPLOY_FACTORY: _receipt(TX_DEPLOY_FACTORY)}
    # The indexer names a transaction this proxy never emitted an event in.
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
    """A6 — a transaction that emitted two ``Upgraded`` logs for one proxy is a
    swap-and-restore, not a plain creation; excluding it would drop a real
    implementation change along with the creation."""
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
    """The stored rows cannot witness their own under-projection.

    If a swap-and-restore transaction lands only ONE of its two ``Upgraded``
    logs in ``upgrade_events``, the stored pair count reads "one event" and the
    deployment guard would exclude a transaction that also carried a real
    implementation change. The receipt's own per-proxy log count is the
    independent check, and the guard takes the larger of the two.

    **Latent, with zero live instances**: all 3 measured swap-and-restore pairs
    are fully projected and none of them is a creation transaction, so this
    arm never fires on the current corpus. It is here because the failure is
    silent when it does.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    # Only ONE row stored for a transaction whose receipt carries two.
    world["event"](proxy, TX_SWAP_AND_RESTORE, BLOCK_SWAP_AND_RESTORE, impl="0x" + "aa" * 20)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")
    wire.receipts = {TX_SWAP_AND_RESTORE: _receipt(TX_SWAP_AND_RESTORE)}
    wire.creation = {PROXY_SAFE_DIRECT: (TX_SWAP_AND_RESTORE, BLOCK_SWAP_AND_RESTORE)}
    wire.code = {(PROXY_SAFE_DIRECT, hex(BLOCK_SWAP_AND_RESTORE - 1)): "0x"}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SWAP_AND_RESTORE))
    witness = session.get(ContractCreationWitness, (1, PROXY_SAFE_DIRECT))
    assert row.receipt_upgraded_counts[PROXY_SAFE_DIRECT] == 2
    # Both creation witnesses agree, and the pair count from the stored rows is
    # 1 — everything the deployment rule needs, except that the receipt says the
    # transaction touched this proxy twice.
    assert witness.creation_tx_hash == TX_SWAP_AND_RESTORE
    assert witness.code_absent_at_probe is True
    assert not uh.event_is_deployment(
        row, witness, proxy_address=PROXY_SAFE_DIRECT, event_block=BLOCK_SWAP_AND_RESTORE, pair_event_count=1
    )
    assert uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["count"] == 1


def test_real_swap_and_restore_is_one_action_not_two(world, wire):
    """The live shape of the same pair: a real Safe transaction that emitted two
    ``Upgraded`` logs for one proxy. Two events, one exercise of authority."""
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


# ---------------------------------------------------------------------------
# T6 / T7 / T8 — the fail-closed arms
# ---------------------------------------------------------------------------


def test_unavailable_receipt_writes_no_row_and_drops_no_event(world, wire):
    """T6 — the event must not be dropped, defaulted, or reclassified."""
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
    """T7 — the 11 measured transactions on an unmodelled Safe.

    The emitter really is a Safe. Nothing in the persisted classification plane
    says so, and the fold does not get to decide that for itself: a marker log
    from an address we cannot independently type mints no verdict.
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


def test_planes_that_disagree_are_not_determined(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe")
    world["classify"](SAFE_DIRECT_EMITTER, "timelock")
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "not_determined"


def test_reverted_transaction_publishes_nothing_positive(world, wire):
    """T8 — a reverted transaction cannot have upgraded anything, so every
    positive is withheld even though the marker log shape is intact."""
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


# ---------------------------------------------------------------------------
# A4 — the classification height
# ---------------------------------------------------------------------------


def test_classification_block_is_not_determined_when_the_plane_has_none(world, wire):
    """The classifier's ``probe_block`` is absent on every current row, so the
    height at which the emitter was typed is unknown.

    That does not weaken the kind — it is still a keccak-matched marker plus a
    negative-control-gated classification — but it is why the kind never claims
    "and the emitter was a Safe AT the upgrade's block", which no receipt can
    prove.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", details={"address": SAFE_DIRECT_EMITTER})
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == "safe_direct"
    assert row.executor_classification_block is None


def test_classification_block_is_published_when_the_probe_recorded_one(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](
        SAFE_DIRECT_EMITTER,
        "safe",
        details={"safe_protection": {"probe_block": 25643300, "guard": "not_determined"}},
    )
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_classification_block == 25643300
    # The direction that matters: the classification is strictly LATER than the
    # upgrade it is being used to describe.
    assert row.executor_classification_block > row.block_number


def test_not_determined_probe_block_string_is_not_a_height(world, wire):
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", details={"safe_protection": {"probe_block": "not_determined"}})
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_classification_block is None


# ---------------------------------------------------------------------------
# T9 — the decoy question, answered honestly
# ---------------------------------------------------------------------------


def test_direct_upgrade_witnessed_block_is_published_and_decoy_is_not(world, wire):
    """Only the positive is publishable.

    History can show that a direct-Safe path WAS exercised, at a block. It
    cannot show the path is closed now: "no direct upgrade after the timelock's
    first use" is an absence of observed bypass. So ``timelock_is_decoy`` is
    ``not_determined`` in BOTH arms — when a later direct upgrade exists and
    when it does not.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DIRECT_ON_DUAL_PROXY, BLOCK_DIRECT_ON_DUAL_PROXY)
    world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)
    # This Safe carries zero rows on every plane in the real corpus, so the real
    # answer for its 11 transactions is not_determined (see the T7 test). Here
    # it is classified deliberately: the question under test is what the fold
    # does once the emitter IS typed.
    world["classify"](SAFE_UNMODELLED, "safe")
    world["classify"](TIMELOCK, "timelock")
    world["classify"](SAFE_ROUTING_THE_TIMELOCK, "safe")
    wire.receipts = {
        TX_DIRECT_ON_DUAL_PROXY: _receipt(TX_DIRECT_ON_DUAL_PROXY),
        TX_FANOUT: _receipt(TX_FANOUT),
    }
    _run_fold(session, wire, [proxy.id])

    basis = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    # The real corpus shape: the direct upgrade PREDATES the timelock's use, by
    # 7.8M blocks. It licenses no claim about the path being open or closed now.
    assert basis["direct_upgrade_witnessed_at_block"] == BLOCK_DIRECT_ON_DUAL_PROXY
    assert BLOCK_DIRECT_ON_DUAL_PROXY < BLOCK_FANOUT
    assert basis["timelock_is_decoy"] == "not_determined"
    assert basis["executor_kinds"] == {"safe_direct": 1, "timelock_routed": 1}

    # Arm two: a direct upgrade that POSTDATES the timelock's first use. The
    # observation changes; the published decoy verdict does not.
    later = session.query(UpgradeEvent).filter(UpgradeEvent.tx_hash == TX_DIRECT_ON_DUAL_PROXY).one()
    later.block_number = BLOCK_FANOUT + 1
    session.commit()
    basis_after = uh.upgrade_action_counts(session, [proxy.id])[proxy.id]["basis"]
    assert basis_after["timelock_is_decoy"] == "not_determined"


# ---------------------------------------------------------------------------
# T11 / A5 — the published count and its basis
# ---------------------------------------------------------------------------


def test_published_count_drops_the_deployment_and_keeps_the_unwitnessed(world, wire):
    """T11 — with the receipt fact the proxy publishes one fewer upgrade; with
    the fact absent it publishes the same number as before.

    The count is an UPPER BOUND either way: removing a PROVEN non-upgrade never
    over-claims, and leaving an unproven one in never under-claims.
    """
    session = world["session"]
    proxy = world["contract"](PROXY_ONE_HOP)
    world["event"](proxy, TX_DEPLOY_EOA, BLOCK_DEPLOY_EOA)
    world["event"](proxy, TX_ONE_HOP, BLOCK_ONE_HOP)
    world["event"](proxy, TX_FANOUT, BLOCK_FANOUT)

    # No receipt facts yet: three events, three actions — today's answer.
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
    """A5 — the number is RENDERED, so a zero would read as an earned negative.

    Zero here means only "no non-deployment event recorded", and the recording
    surface itself is unwitnessed: only the ERC-1967 topics are folded and
    ``old_impl`` is NULL on every backfilled row. The two proxies whose single
    stored event is their own creation must publish nothing, not "0 upgrades".
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
    """The aggregation the UI reads must carry the sidecar, not the bare
    number."""
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


# ---------------------------------------------------------------------------
# Chain scoping of the classification planes (fix 2)
#
# An address is an identity only WITHIN a chain. A CREATE2 twin sits at the same
# 20 bytes on mainnet and on Base and is two unrelated contracts; a plane row
# typed on one says nothing about the other. The fold reads the planes to mint a
# POSITIVE verdict, so an unscoped read is a cross-chain fail-open of exactly
# the class PR #158 closed elsewhere.
# ---------------------------------------------------------------------------


def test_off_chain_twin_does_not_classify_the_emitter(world, wire):
    """FALSIFIER: the ONLY row typing this address is anchored to a Base
    contract. The mainnet receipt must stay ``not_determined`` — no kind, no
    ``executor_address``, no classification block."""
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
    """RECALL: the identical seeding on the receipt's own chain reaches the same
    ``safe_direct`` verdict this file already pins elsewhere. The scoping cuts
    the off-chain row and nothing else."""
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
    """FALSIFIER: both chains type the address ``safe``, but only the Base row
    carries a probe height. Publishing it beside a mainnet row would cite a
    height measured on a chain this transaction was never on — so the field is
    absent, not borrowed."""
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
    """A contract whose chain is NULL is not determined to be on THIS chain, and
    a not-determined chain can never license a positive verdict."""
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
    """The mirror of the fail-open: the unscoped read also FAILED CLOSED wrongly.
    A Base row typing the twin ``timelock`` used to collide with the mainnet
    ``safe`` row and blank the verdict. It is a different contract, so it is not
    a disagreement at all."""
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


def test_same_chain_disagreement_still_blanks_the_verdict(world, wire):
    """RECALL of the fail-closed arm: two rows on the RECEIPT'S OWN chain that
    disagree are still an undecidable emitter."""
    session = world["session"]
    proxy = world["contract"](PROXY_SAFE_DIRECT)
    world["event"](proxy, TX_SAFE_DIRECT, BLOCK_SAFE_DIRECT)
    world["classify"](SAFE_DIRECT_EMITTER, "safe", chain="ethereum")
    world["classify"](SAFE_DIRECT_EMITTER, "timelock", chain="mainnet")  # registry alias for chain 1
    wire.receipts = {TX_SAFE_DIRECT: _receipt(TX_SAFE_DIRECT)}
    _run_fold(session, wire, [proxy.id])

    row = session.get(UpgradeTransaction, (1, TX_SAFE_DIRECT))
    assert row.executor_kind == uh.NOT_DETERMINED
    assert row.executor_address is None
