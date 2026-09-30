"""D6-accept: a role's holders are a proven lower bound, never a membership set.

The fold proposes candidates and a pinned ``hasRole`` read witnesses each. Corpus values were measured on the
local replica and re-verified on-chain at block 25643300.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from db.models import (
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    FIRST_INDEXED_BASIS_EXPLICIT,
    Contract,
    IndexedEventCursor,
    IndexedEventLog,
    RoleDefinition,
    RoleHolderPlane,
)
from services.clients.rpc import EthCallResult
from services.resolution import role_holder_plane as rhp
from utils.chains import DEFAULT_CONFIRMATION_DEPTH

REGISTRY = "0x6db24ee656843e3fe03eb8762a54d86186ba6b64"
SOLADY_REGISTRY = "0x62247d29b4b9becf4bb73e0c722cf6445cfc7ce9"

RG = rhp.ROLE_GRANTED_TOPIC0
RR = rhp.ROLE_REVOKED_TOPIC0
# Solady's role space; the role is at topic index 2, not 1.
ROLE_SET_TOPIC0 = "0xaddc47d7e02c95c00ec667676636d772a589ffbf0663cfd7cd4dd3d4758201b8"

ZERO_ROLE = "0x" + "00" * 32
PAUSER = "0x" + keccak(text="PAUSER_ROLE").hex()
OPERATING_ADMIN = "0x" + keccak(text="OPERATING_ADMIN_ROLE").hex()
TIMELOCK_ADMIN = "0x" + keccak(text="TIMELOCK_ADMIN_ROLE").hex()

ADMIN_HOLDER = "0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52"
REVOKED_A = "0xf8a86ea1ac39ec529814c377bd484387d395421e"
REVOKED_B = "0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5"
PAUSER_EXTRA = "0x9af1298993dc1f397973c62a5d47a284cf76844d"
OPS_HOLDER = "0xd8f3803d8412e61e04f53e1c9394e13ec8b32550"

PROBE_BLOCK = rhp.ProbeBlock(number=25643300, block_hash=b"\xab" * 32)

# What ``eth_call_batch`` returns for the four corpus addresses whose ``hasRole`` reverts.
MEASURED_REVERT = EthCallResult(False, "0x", None, "execution reverted")
TRUE_WORD = EthCallResult(True, "0x" + "0" * 63 + "1", None, None)
FALSE_WORD = EthCallResult(True, "0x" + "0" * 64, None, None)


def _word(value: str) -> str:
    return "0x" + value.lower().removeprefix("0x").rjust(64, "0")


def _log(
    topic0: str, role: str, account: str, *, block: int, log_index: int, address: str = REGISTRY
) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=address,
        topic0=topic0,
        tx_hash=(block * 1000 + log_index).to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x33"),
        transaction_index=0,
        topics=[topic0, _word(role), _word(account), _word(account)],
        data_words=[],
    )


def _cursor(topic0: str, *, complete: bool = True, address: str = REGISTRY, **kw: Any) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=address,
        topic0=topic0,
        last_indexed_block=kw.pop("last_indexed_block", 25641245),
        backfill_complete=complete,
        **kw,
    )


def _corpus_logs() -> list[IndexedEventLog]:
    return [
        _log(RG, ZERO_ROLE, REVOKED_A, block=20933133, log_index=62),
        _log(RG, PAUSER, REVOKED_A, block=20933133, log_index=63),
        _log(RG, PAUSER, PAUSER_EXTRA, block=20967384, log_index=572),
        _log(RR, ZERO_ROLE, REVOKED_A, block=20988447, log_index=438),
        _log(RG, ZERO_ROLE, REVOKED_B, block=20988447, log_index=439),
        _log(RR, ZERO_ROLE, REVOKED_B, block=21266100, log_index=137),
        _log(RG, ZERO_ROLE, ADMIN_HOLDER, block=21266100, log_index=138),
        _log(RG, OPERATING_ADMIN, OPS_HOLDER, block=22178081, log_index=369),
        _log(RG, PAUSER, ADMIN_HOLDER, block=22698347, log_index=334),
    ]


NAME_POOL = ("PAUSER_ROLE", "OPERATING_ADMIN_ROLE")


def _seed(session, *, logs=None, cursors=None):
    for log in logs if logs is not None else _corpus_logs():
        session.add(log)
    for cursor in cursors if cursors is not None else [_cursor(RG), _cursor(RR)]:
        session.add(cursor)
    session.flush()


def _run(
    session,
    monkeypatch,
    verdict_map: dict[tuple[str, str], EthCallResult],
    *,
    address: str = REGISTRY,
    names=NAME_POOL,
):

    def fake_batch(rpc_url, calls, block_tag, *, headers=None, chain_id=None):
        assert block_tag == hex(PROBE_BLOCK.number), "every probe must be pinned at one block"
        out = []
        for call in calls:
            data = call["data"]
            role = "0x" + data[10:74]
            account = "0x" + data[-40:]
            out.append(verdict_map.get((role, account), MEASURED_REVERT))
        return out

    monkeypatch.setattr(rhp, "eth_call_batch", fake_batch)
    return rhp.resolve_role_holder_planes(
        session,
        chain_id=1,
        registry_address=address,
        rpc_url="http://stub",
        probe_block=PROBE_BLOCK,
        candidate_names=names,
    )


def _by_role(rows):
    return {row["role_hash"]: row for row in rows}


def test_solady_roleset_logs_mint_no_row(db_session, monkeypatch):
    """Folded through OZ topic positions, the uint256 role reads the mapping's zero default and returns false
    successfully, which would publish 40 unqualified rows.
    """
    session = db_session
    logs = [
        IndexedEventLog(
            chain_id=1,
            event_address=SOLADY_REGISTRY,
            topic0=ROLE_SET_TOPIC0,
            tx_hash=(i).to_bytes(8, "big").rjust(32, b"\x00"),
            log_index=i,
            block_number=21000000 + i,
            block_hash=b"\x44" * 32,
            transaction_index=0,
            topics=[ROLE_SET_TOPIC0, _word(ADMIN_HOLDER), _word("0x01"), _word("0x01")],
            data_words=[],
        )
        for i in range(3)
    ]
    _seed(
        session,
        logs=logs,
        cursors=[_cursor(ROLE_SET_TOPIC0, address=SOLADY_REGISTRY)],
    )
    rows = _run(session, monkeypatch, {}, address=SOLADY_REGISTRY)
    assert rows == []


def test_fold_ignores_non_accesscontrol_topics():
    mixed = _corpus_logs() + [
        IndexedEventLog(
            chain_id=1,
            event_address=REGISTRY,
            topic0=ROLE_SET_TOPIC0,
            tx_hash=b"\x00" * 32,
            log_index=0,
            block_number=21000000,
            block_hash=b"\x44" * 32,
            transaction_index=0,
            topics=[ROLE_SET_TOPIC0, _word(ADMIN_HOLDER), _word("0x07"), _word("0x01")],
            data_words=[],
        )
    ]
    folded = rhp.fold_role_candidates(mixed)
    assert set(folded) == {ZERO_ROLE, PAUSER, OPERATING_ADMIN}
    assert _word("0x07") not in folded


def test_classify_candidate_keeps_three_distinct_states():
    """Asserted here because an implementation that ignores ``success`` looks identical end-to-end on an
    all-reverting registry.
    """
    assert rhp.classify_candidate(TRUE_WORD) == rhp.CANDIDATE_CONFIRMED
    assert rhp.classify_candidate(FALSE_WORD) == rhp.CANDIDATE_READ_COMPLETED_NOT_CONFIRMED
    assert rhp.classify_candidate(MEASURED_REVERT) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.CANDIDATE_UNCONFIRMED != rhp.CANDIDATE_READ_COMPLETED_NOT_CONFIRMED
    assert rhp.classify_candidate(EthCallResult(False, "0x", None, "transport: boom")) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.classify_candidate(EthCallResult(False, "0x", "0x", "reverted")) == rhp.CANDIDATE_UNCONFIRMED


def test_corpus_rows_publish_confirmed_lower_bound(db_session, monkeypatch):
    session = db_session
    _seed(session)
    verdicts = {
        (ZERO_ROLE, ADMIN_HOLDER): TRUE_WORD,
        (ZERO_ROLE, REVOKED_A): FALSE_WORD,
        (ZERO_ROLE, REVOKED_B): FALSE_WORD,
        (PAUSER, ADMIN_HOLDER): TRUE_WORD,
        (PAUSER, REVOKED_A): TRUE_WORD,
        (PAUSER, PAUSER_EXTRA): TRUE_WORD,
        (OPERATING_ADMIN, OPS_HOLDER): TRUE_WORD,
    }
    rows = _by_role(_run(session, monkeypatch, verdicts))
    assert set(rows) == {ZERO_ROLE, PAUSER, OPERATING_ADMIN}

    admin = rows[ZERO_ROLE]
    assert admin["holders"] == [ADMIN_HOLDER]
    assert admin["holders_basis"] == "pinned_has_role_confirmed"
    assert admin["coverage"] == "lower_bound"
    assert admin["as_of_block"] == 25643300
    assert admin["as_of_block_hash"] == b"\xab" * 32
    assert admin["candidate_count"] == 3
    assert admin["unconfirmed_candidate_count"] == 0
    assert admin["role_name"] == "DEFAULT_ADMIN_ROLE"
    assert admin["role_name_basis"] == "accesscontrol_default_admin_literal"

    pauser = rows[PAUSER]
    assert pauser["holders"] == sorted([ADMIN_HOLDER, REVOKED_A, PAUSER_EXTRA])
    assert pauser["role_name"] == "PAUSER_ROLE"
    assert pauser["role_name_basis"] == "keccak_preimage"

    ops = rows[OPERATING_ADMIN]
    assert ops["holders"] == [OPS_HOLDER]
    assert ops["role_name"] == "OPERATING_ADMIN_ROLE"

    assert {row["holder_set_exhaustive"] for row in rows.values()} == {"not_determined"}
    assert {row["cursor_first_indexed_block_basis"] for row in rows.values()} == {"not_determined"}
    assert {row["cursor_first_indexed_block"] for row in rows.values()} == {None}
    assert {row["cursor_page_completeness"] for row in rows.values()} == {"not_determined"}
    assert {row["cursor_last_indexed_block"] for row in rows.values()} == {25641245}


@pytest.mark.parametrize(
    "cursors",
    [
        pytest.param([_cursor(RG), _cursor(RR, complete=False)], id="revoked_cursor_cold"),
        pytest.param([_cursor(RG, complete=False), _cursor(RR)], id="granted_cursor_cold"),
        pytest.param([_cursor(RG)], id="revoked_cursor_missing"),
        pytest.param([], id="no_cursor_at_all"),
    ],
)
def test_cold_or_missing_cursor_withholds_every_holder_set(db_session, monkeypatch, cursors):
    session = db_session
    _seed(session, cursors=cursors)
    rows = _run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD})
    assert rows, "rows still exist — the roles were witnessed, only the floor is withheld"
    for row in rows:
        assert row["holders"] is None, "never an empty set, and never a floor from a known-partial fold"
        assert row["holders_basis"] == "not_determined"
        assert row["coverage"] == "partial"
        assert row["as_of_block"] is None
        assert row["candidate_count"] is None
        assert row["unconfirmed_candidate_count"] is None


@pytest.mark.parametrize(
    "verdicts",
    [
        # The 0xd5edf773 / USDC shape: warm cursors, no AccessControl beneath.
        pytest.param({}, id="all-candidates-revert"),
        # A fully revoked role publishes NULL, never ``[]``: a direct storage write would appear in neither the fold nor
        # this arm.
        pytest.param(
            {
                (role, account): FALSE_WORD
                for role in (ZERO_ROLE, PAUSER, OPERATING_ADMIN)
                for account in (ADMIN_HOLDER, REVOKED_A, REVOKED_B, PAUSER_EXTRA, OPS_HOLDER)
            },
            id="all-candidates-read-false",
        ),
    ],
)
def test_all_candidates_withhold(db_session, monkeypatch, verdicts):
    session = db_session
    _seed(session)
    rows = _run(session, monkeypatch, verdicts)
    for row in rows:
        assert row["holders"] is None
        assert row["holders_basis"] == "not_determined"
        assert row["coverage"] == "partial"


def test_all_false_and_all_revert_rows_are_indistinguishable(db_session, monkeypatch):
    """A2: "N probed, all completed, none confirmed" is ``[]``, so the all-false row must not differ from the
    all-revert row in any column.
    """
    session = db_session
    _seed(session)
    all_false = {
        (role, account): FALSE_WORD
        for role in (ZERO_ROLE, PAUSER, OPERATING_ADMIN)
        for account in (ADMIN_HOLDER, REVOKED_A, REVOKED_B, PAUSER_EXTRA, OPS_HOLDER)
    }
    false_rows = _by_role(_run(session, monkeypatch, all_false))
    revert_rows = _by_role(_run(session, monkeypatch, {}))
    assert set(false_rows) == set(revert_rows)
    for role_hash in false_rows:
        assert false_rows[role_hash] == revert_rows[role_hash]


def test_partial_reverts_still_publish_the_confirmed_floor(db_session, monkeypatch):
    session = db_session
    _seed(session)
    verdicts = {
        (PAUSER, ADMIN_HOLDER): TRUE_WORD,
        (PAUSER, PAUSER_EXTRA): MEASURED_REVERT,
        (PAUSER, REVOKED_A): MEASURED_REVERT,
    }
    row = _by_role(_run(session, monkeypatch, verdicts))[PAUSER]
    assert row["holders"] == [ADMIN_HOLDER]
    assert row["candidate_count"] == 3
    assert row["unconfirmed_candidate_count"] == 2, "the floor's residual stays visible"


def test_unpinnable_probe_block_withholds(db_session, monkeypatch):
    session = db_session
    _seed(session)
    monkeypatch.setattr(rhp, "pin_probe_block", lambda *a, **k: None)
    monkeypatch.setattr(rhp, "eth_call_batch", lambda *a, **k: pytest.fail("must not probe unpinned"))
    rows = rhp.resolve_role_holder_planes(
        session, chain_id=1, registry_address=REGISTRY, rpc_url="http://stub", probe_block=None
    )
    assert rows and all(row["holders"] is None and row["coverage"] == "partial" for row in rows)


def test_registry_with_no_role_logs_yields_no_rows(db_session, monkeypatch):
    session = db_session
    _seed(session, logs=[], cursors=[_cursor(RG), _cursor(RR)])
    assert _run(session, monkeypatch, {}) == []


def test_role_name_absent_without_a_preimage(db_session, monkeypatch):
    """TIMELOCK_ADMIN_ROLE has no ``role_definitions`` row, so it gets no name."""
    session = db_session
    _seed(session, logs=[_log(RG, TIMELOCK_ADMIN, ADMIN_HOLDER, block=19298624, log_index=121)])
    row = _by_role(_run(session, monkeypatch, {(TIMELOCK_ADMIN, ADMIN_HOLDER): TRUE_WORD}))[TIMELOCK_ADMIN]
    assert row["role_name"] is None
    assert row["role_name_basis"] == "not_determined"
    assert row["holders"] == [ADMIN_HOLDER], "the hash is the identity; the name is decoration"


@pytest.mark.parametrize(
    "role, pool, has_role_answered, expected",
    [
        # A role-shaped name may not be attached to a hash it does not hash to.
        pytest.param(
            "0x" + "de" * 32,
            ["PAUSER_ROLE", "DEFAULT_ADMIN_ROLE"],
            True,
            (None, "not_determined"),
            id="keccak-mismatch-refused",
        ),
        # Existing mis-minted rows persist until re-analysis; the keccak gate makes that harmless.
        pytest.param(
            PAUSER,
            ["OwnableStorageLocation", "AccessControlDefaultAdminRulesStorageLocation"],
            True,
            (None, "not_determined"),
            id="misparsed-storage-pointers-cannot-leak-a-name",
        ),
        # A6: the zero-word convention may not fire on an emitter proven not to implement ``hasRole``.
        pytest.param(
            ZERO_ROLE,
            [],
            True,
            ("DEFAULT_ADMIN_ROLE", "accesscontrol_default_admin_literal"),
            id="default-admin-answered",
        ),
        pytest.param(ZERO_ROLE, [], False, (None, "not_determined"), id="default-admin-unanswered"),
    ],
)
def test_resolve_role_name(role, pool, has_role_answered, expected):
    assert rhp.resolve_role_name(role, pool, has_role_answered=has_role_answered) == expected


def test_default_admin_name_withheld_when_registry_never_answers(db_session, monkeypatch):
    session = db_session
    _seed(session)
    row = _by_role(_run(session, monkeypatch, {}))[ZERO_ROLE]
    assert row["role_name"] is None
    assert row["role_name_basis"] == "not_determined"


def test_candidate_pool_reads_declared_names_across_contracts(db_session):
    """Events emit at the proxy but ``role_definitions`` hangs off the implementation, so the pool is not
    contract-scoped.
    """
    session = db_session
    contract = Contract(address=REGISTRY, chain="ethereum", contract_name="Impl", is_proxy=False)
    session.add(contract)
    session.flush()
    session.add(RoleDefinition(contract_id=contract.id, role_name="PAUSER_ROLE", declared_in="Impl"))
    session.add(RoleDefinition(contract_id=contract.id, role_name="OwnableStorageLocation", declared_in="Impl"))
    session.flush()

    pool = rhp.candidate_name_pool(session)
    assert "PAUSER_ROLE" in pool and "OwnableStorageLocation" in pool
    assert rhp.resolve_role_name(PAUSER, pool, has_role_answered=True) == ("PAUSER_ROLE", "keccak_preimage")
    assert rhp.resolve_role_name(TIMELOCK_ADMIN, pool, has_role_answered=True) == (None, "not_determined")
    session.rollback()


def test_fold_inactive_but_chain_true_is_admitted(db_session, monkeypatch):
    """The read wins in both directions.

    OZ expresses administration as membership in a different role, so this doesn't conflate the two.
    """
    session = db_session
    _seed(session)
    verdicts = {
        (ZERO_ROLE, ADMIN_HOLDER): TRUE_WORD,
        (ZERO_ROLE, REVOKED_A): TRUE_WORD,  # fold said revoked; chain says held
        (ZERO_ROLE, REVOKED_B): FALSE_WORD,
    }
    row = _by_role(_run(session, monkeypatch, verdicts))[ZERO_ROLE]
    assert row["holders"] == sorted([ADMIN_HOLDER, REVOKED_A])
    assert row["fold_chain_disagreements"] == [
        {
            "registry": REGISTRY,
            "role_hash": ZERO_ROLE,
            "address": REVOKED_A,
            "fold_state": "inactive",
            "chain_state": "true",
        }
    ]
    assert row["holder_set_exhaustive"] == "not_determined"


def test_fold_active_but_chain_false_is_omitted(db_session, monkeypatch):
    session = db_session
    _seed(session)
    verdicts = {
        (PAUSER, ADMIN_HOLDER): TRUE_WORD,
        (PAUSER, PAUSER_EXTRA): FALSE_WORD,  # fold said active; chain says no
        (PAUSER, REVOKED_A): TRUE_WORD,
    }
    row = _by_role(_run(session, monkeypatch, verdicts))[PAUSER]
    assert PAUSER_EXTRA not in (row["holders"] or [])
    assert row["fold_chain_disagreements"] == [
        {
            "registry": REGISTRY,
            "role_hash": PAUSER,
            "address": PAUSER_EXTRA,
            "fold_state": "active",
            "chain_state": "false",
        }
    ]


def test_disagreement_records_carry_no_cause(db_session, monkeypatch):
    """A9: "the fold missed a log" and "state changed after the cursor" are indistinguishable, so no cause key may
    appear.
    """
    session = db_session
    _seed(session)
    verdicts = {(PAUSER, ADMIN_HOLDER): TRUE_WORD, (PAUSER, PAUSER_EXTRA): FALSE_WORD, (PAUSER, REVOKED_A): TRUE_WORD}
    row = _by_role(_run(session, monkeypatch, verdicts))[PAUSER]
    for record in row["fold_chain_disagreements"]:
        assert set(record) == rhp.DISAGREEMENT_KEYS
    reverted = _by_role(_run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD}))[PAUSER]
    assert reverted["fold_chain_disagreements"] == []


@pytest.mark.parametrize(
    "cursor_kwargs, expected",
    [
        # A caller seed is not a witness.
        pytest.param(
            [
                {"first_indexed_block": 100, "first_indexed_block_basis": FIRST_INDEXED_BASIS_EXPLICIT},
                {"first_indexed_block": 100, "first_indexed_block_basis": FIRST_INDEXED_BASIS_EXPLICIT},
            ],
            {"cursor_first_indexed_block": None, "cursor_first_indexed_block_basis": "not_determined"},
            id="explicit-seed-dropped",
        ),
        # Coverage is from the higher of the two; a lower bound alone never licenses exhaustiveness.
        pytest.param(
            [
                {"first_indexed_block": 20933000, "first_indexed_block_basis": FIRST_INDEXED_BASIS_CREATION},
                {"first_indexed_block": 20933100, "first_indexed_block_basis": FIRST_INDEXED_BASIS_CREATION},
            ],
            {
                "cursor_first_indexed_block": 20933100,
                "cursor_first_indexed_block_basis": FIRST_INDEXED_BASIS_CREATION,
                "holder_set_exhaustive": "not_determined",
            },
            id="witnessed-carried",
        ),
        pytest.param(
            [{"enrollment_basis": ENROLLMENT_BASIS_TRACKED_TOPICS}] * 2,
            {
                "holders": [ADMIN_HOLDER],
                "cursor_enrollment_bases": {RG: ENROLLMENT_BASIS_TRACKED_TOPICS, RR: ENROLLMENT_BASIS_TRACKED_TOPICS},
                "holder_set_exhaustive": "not_determined",
            },
            id="tracked-topics-recorded-not-depended-on",
        ),
    ],
)
def test_cursor_lower_bound_basis(db_session, monkeypatch, cursor_kwargs, expected):
    session = db_session
    _seed(session, cursors=[_cursor(RG, **cursor_kwargs[0]), _cursor(RR, **cursor_kwargs[1])])
    row = _by_role(_run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD}))[PAUSER]
    assert {key: row[key] for key in expected} == expected


HEAD = 25643312


def _rpc_stub(calls: list[tuple[str, list[Any]]], *, head=hex(HEAD), block=None, fail_hash=False, fail_head=False):
    def fake(rpc_url, method, params, *a, **kw):
        calls.append((method, params))
        if method == "eth_blockNumber":
            if fail_head:
                raise RuntimeError("upstream down")
            return head
        if method == "eth_getBlockByNumber":
            if fail_hash:
                raise RuntimeError("no block")
            return block if block is not None else {"hash": "0x" + "cd" * 32}
        raise AssertionError(f"unexpected method {method}")

    return fake


def test_probe_block_is_confirmation_depth_below_head(monkeypatch):
    """A bare head can be reorged under a persisted ``as_of_block``, and ``"latest"`` is unrepeatable."""
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls))
    pinned = rhp.pin_probe_block("http://stub", chain_id=1)
    assert pinned is not None
    assert pinned.number == HEAD - DEFAULT_CONFIRMATION_DEPTH
    assert pinned.number == 25643300
    assert pinned.block_hash is not None
    assert pinned.block_hash == bytes.fromhex("cd" * 32)
    assert len(pinned.block_hash) == 32
    assert calls[1][0] == "eth_getBlockByNumber"
    assert calls[1][1] == [hex(HEAD - DEFAULT_CONFIRMATION_DEPTH), False]
    assert all("latest" not in str(params) for _, params in calls), "never latest"


@pytest.mark.parametrize(
    "stub_kwargs",
    [
        pytest.param({"fail_hash": True}, id="survives-an-unreadable-hash"),
        pytest.param({"block": {}}, id="hash-absent-from-payload-is-not-invented"),
    ],
)
def test_probe_block_without_a_hash(monkeypatch, stub_kwargs):
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, **stub_kwargs))
    pinned = rhp.pin_probe_block("http://stub", chain_id=1)
    assert pinned is not None
    assert pinned.number == HEAD - DEFAULT_CONFIRMATION_DEPTH
    assert pinned.block_hash is None


@pytest.mark.parametrize(
    "stub_kwargs",
    [
        pytest.param({"fail_head": True}, id="unreadable-head"),
        pytest.param({"head": hex(DEFAULT_CONFIRMATION_DEPTH)}, id="chain-shallower-than-confirmation-depth"),
    ],
)
def test_no_probe_block(monkeypatch, stub_kwargs):
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, **stub_kwargs))
    assert rhp.pin_probe_block("http://stub", chain_id=1) is None


def _valid_row(**overrides: Any) -> dict[str, Any]:
    row = {
        "chain_id": 1,
        "registry_address": REGISTRY,
        "role_hash": PAUSER,
        "holders": [ADMIN_HOLDER],
        "holders_basis": "pinned_has_role_confirmed",
        "holder_set_exhaustive": "not_determined",
        "as_of_block": 25643300,
        "as_of_block_hash": b"\xab" * 32,
        "cursor_first_indexed_block": None,
        "cursor_first_indexed_block_basis": "not_determined",
        "cursor_last_indexed_block": 25641245,
        "cursor_enrollment_bases": {},
        "cursor_page_completeness": "not_determined",
        "coverage": "lower_bound",
        "role_name": "PAUSER_ROLE",
        "role_name_basis": "keccak_preimage",
        "candidate_count": 1,
        "unconfirmed_candidate_count": 0,
        "fold_chain_disagreements": [],
    }
    row.update(overrides)
    return row


@pytest.mark.parametrize(
    "overrides,reason",
    [
        pytest.param({"holders": []}, "an empty holder set is the banned shape", id="empty_set"),
        pytest.param({"holder_set_exhaustive": "proven"}, "exhaustiveness is unprovable here", id="exhaustive_value"),
        pytest.param({"holders_basis": None}, "nullable basis would void the biconditional", id="basis_null"),
        pytest.param({"coverage": None}, "nullable coverage would void its domain check", id="coverage_null"),
        pytest.param({"role_name_basis": None}, "nullable name basis would void its biconditional", id="name_null"),
        pytest.param(
            {"cursor_first_indexed_block_basis": None}, "the lower bound needs a stated basis", id="lower_basis_null"
        ),
        pytest.param({"cursor_page_completeness": None}, "the page residual needs a state", id="pages_null"),
        pytest.param(
            {"holders": None, "holders_basis": "not_determined", "as_of_block": None, "coverage": "partial"},
            "counters must be NULL when there is no floor to qualify",
            id="counters_without_floor",
        ),
        pytest.param(
            {"holders": None, "as_of_block": None, "candidate_count": None, "unconfirmed_candidate_count": None},
            "a withheld floor may not keep a proven basis",
            id="null_holders_proven_basis",
        ),
        pytest.param({"coverage": "complete"}, "there is no complete coverage in this plane", id="coverage_complete"),
        pytest.param({"role_name": None}, "a name and its basis move together", id="name_without_basis"),
    ],
)
def test_database_refuses_unprovable_rows(db_session, overrides, reason):
    session = db_session
    session.add(RoleHolderPlane(**_valid_row(**overrides)))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


@pytest.mark.parametrize(
    "column",
    [
        "holder_set_exhaustive",
        "holders_basis",
        "coverage",
        "role_name_basis",
        "cursor_first_indexed_block_basis",
        "cursor_page_completeness",
    ],
)
def test_discriminators_reject_an_explicit_null(db_session, column):
    """A CHECK evaluating to NULL passes in Postgres, so NOT NULL is what binds.

    Raw SQL because the ORM's server_default would hide the hole.
    """
    session = db_session
    row = _valid_row()
    row[column] = None
    columns = ", ".join(row)
    params = ", ".join(f":{name}" for name in row)
    row["holders"] = json.dumps(row["holders"])
    row["cursor_enrollment_bases"] = json.dumps(row["cursor_enrollment_bases"])
    row["fold_chain_disagreements"] = json.dumps(row["fold_chain_disagreements"])
    with pytest.raises(IntegrityError):
        session.execute(text(f"INSERT INTO role_holder_planes ({columns}) VALUES ({params})"), row)
        session.flush()
    session.rollback()


def _withheld_orm_row(**overrides: Any) -> dict[str, Any]:
    return _valid_row(
        holders=None,
        holders_basis="not_determined",
        as_of_block=None,
        as_of_block_hash=None,
        coverage="partial",
        candidate_count=None,
        unconfirmed_candidate_count=None,
        fold_chain_disagreements=None,
        **overrides,
    )


def test_orm_writes_sql_null_not_the_jsonb_scalar_null(db_session):
    """Without ``none_as_null`` SQLAlchemy stores the jsonb scalar ``null``, a present payload to every SQL null
    test.
    """
    session = db_session
    session.add(RoleHolderPlane(**_withheld_orm_row()))
    session.flush()
    typeof, disagreements_typeof = session.execute(
        text(
            "SELECT jsonb_typeof(holders), jsonb_typeof(fold_chain_disagreements) "
            "FROM role_holder_planes WHERE role_hash = :r"
        ),
        {"r": PAUSER},
    ).one()
    assert typeof is None, "a withheld row must be SQL NULL, not the jsonb scalar 'null'"
    # The withheld predicate counts the scalar null, so naive IS NULL consumers would see evidence.
    assert disagreements_typeof is None, "a withheld disagreement ledger must be SQL NULL too"
    session.rollback()


def _raw_insert(session, holders_sql: str, **cols: str) -> None:
    defaults = {
        "holders_basis": "'not_determined'",
        "holder_set_exhaustive": "'not_determined'",
        "cursor_first_indexed_block": "NULL",
        "cursor_first_indexed_block_basis": "'not_determined'",
        "cursor_enrollment_bases": "'{}'::jsonb",
        "cursor_page_completeness": "'not_determined'",
        "coverage": "'partial'",
        "role_name_basis": "'not_determined'",
        "fold_chain_disagreements": "NULL",
    }
    defaults.update(cols)
    names = ", ".join(["chain_id", "registry_address", "role_hash", "holders", *defaults])
    values = ", ".join(["1", ":addr", ":role", holders_sql, *defaults.values()])
    session.execute(
        text(f"INSERT INTO role_holder_planes ({names}) VALUES ({values})"),
        {"addr": REGISTRY, "role": PAUSER},
    )
    session.flush()


def test_jsonb_scalar_null_is_treated_as_withheld(db_session):
    """Raw SQL can still write the scalar null, so it must count as withheld everywhere."""
    session = db_session
    _raw_insert(session, "'null'::jsonb")
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None
    session.rollback()


def test_jsonb_scalar_null_cannot_carry_a_proven_basis(db_session):
    session = db_session
    for extra in (
        {"holders_basis": "'pinned_has_role_confirmed'"},
        {"candidate_count": "3"},
        {"coverage": "'lower_bound'"},
    ):
        with pytest.raises(IntegrityError):
            _raw_insert(session, "'null'::jsonb", **extra)
        session.rollback()


def test_withheld_row_cannot_claim_no_disagreement(db_session):
    """R4: ``[]`` on a withheld row is an unearned negative, and on an all-false registry would suppress real
    disagreements.
    """
    session = db_session
    with pytest.raises(IntegrityError):
        _raw_insert(session, "NULL", fold_chain_disagreements="'[]'::jsonb")
    session.rollback()


def test_published_row_must_carry_a_disagreement_log(db_session):
    session = db_session
    with pytest.raises(IntegrityError):
        session.add(RoleHolderPlane(**_valid_row(fold_chain_disagreements=None)))
        session.flush()
    session.rollback()


def test_withheld_rows_carry_a_null_disagreement_log(db_session, monkeypatch):
    session = db_session
    _seed(session)
    for verdicts in ({}, {(r, a): FALSE_WORD for r in (ZERO_ROLE, PAUSER) for a in (ADMIN_HOLDER, REVOKED_A)}):
        for row in _run(session, monkeypatch, verdicts):
            if row["holders"] is None:
                assert row["fold_chain_disagreements"] is None


@pytest.mark.parametrize(
    "cols",
    [
        pytest.param({"cursor_page_completeness": "'bogus'"}, id="page_completeness_domain"),
        pytest.param({"cursor_first_indexed_block_basis": "'bogus'"}, id="lower_bound_basis_domain"),
        pytest.param(
            {"cursor_first_indexed_block_basis": "'explicit_seed'"},
            id="explicit_seed_is_not_storable",
        ),
        pytest.param(
            {"cursor_first_indexed_block_basis": "'creation_block_minus_one'"},
            id="witnessed_basis_without_a_block",
        ),
        pytest.param({"cursor_first_indexed_block": "999"}, id="lower_bound_block_without_a_basis"),
    ],
)
def test_cursor_bound_columns_are_domain_checked(db_session, cols):
    """R1 + R3: a ``creation_block_minus_one`` basis with no block is uncitable, and ``explicit_seed`` is a caller's
    number.
    """
    session = db_session
    with pytest.raises(IntegrityError):
        _raw_insert(session, "NULL", **cols)
    session.rollback()


def test_non_array_holders_are_rejected(db_session):
    session = db_session
    for payload in ("'\"0xabc\"'::jsonb", "'{}'::jsonb", "'7'::jsonb"):
        with pytest.raises(IntegrityError):
            _raw_insert(
                session,
                payload,
                holders_basis="'pinned_has_role_confirmed'",
                as_of_block="25643300",
                candidate_count="1",
                unconfirmed_candidate_count="0",
                coverage="'lower_bound'",
                fold_chain_disagreements="'[]'::jsonb",
            )
        session.rollback()


@pytest.mark.parametrize(
    "row, expected",
    [
        pytest.param(
            _valid_row(), {"holders": [ADMIN_HOLDER], "holder_set_exhaustive": "not_determined"}, id="valid-row"
        ),
        pytest.param(_withheld_orm_row(), {"holders": None, "fold_chain_disagreements": None}, id="withheld-row"),
        pytest.param(
            _valid_row(fold_chain_disagreements=[]),
            {"fold_chain_disagreements": []},
            id="published-empty-disagreement-log",
        ),
    ],
)
def test_row_round_trips(db_session, row, expected):
    session = db_session
    session.add(RoleHolderPlane(**row))
    session.flush()
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None
    assert {column: getattr(stored, column) for column in expected} == expected
    session.rollback()


def test_persist_upserts(db_session, monkeypatch):
    session = db_session
    _seed(session)
    rows = _run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD})
    assert rhp.persist_role_holder_planes(session, rows) == len(rows)
    assert rhp.persist_role_holder_planes(session, rows) == len(rows)
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None and stored.holders == [ADMIN_HOLDER]


# Tolerant decoders on a witness plane: a value nobody observed must not be coerced into one that looks observed.


def test_empty_word_is_never_padded_into_the_default_admin_role():
    """``"0x"`` left-padded is bit-identical to ``DEFAULT_ADMIN_ROLE_HASH``."""
    assert rhp._normalize_word("0x") is None
    assert rhp.resolve_role_name("0x", [], has_role_answered=True) == (None, "not_determined")
    assert rhp.resolve_role_name("0x00", [], has_role_answered=True) == (None, "not_determined")
    assert rhp.resolve_role_name("0xzz" + "0" * 62, [], has_role_answered=True) == (None, "not_determined")
    assert rhp.resolve_role_name(ZERO_ROLE, [], has_role_answered=True) == (
        "DEFAULT_ADMIN_ROLE",
        "accesscontrol_default_admin_literal",
    )
    assert rhp._normalize_word("0x" + "AB" * 32) == "0x" + "ab" * 32
    assert rhp.resolve_role_name(PAUSER, ["PAUSER_ROLE"], has_role_answered=False) == (
        "PAUSER_ROLE",
        "keccak_preimage",
    )


def test_an_empty_word_topic_folds_to_no_candidate(db_session, monkeypatch):
    log = _log(RG, ZERO_ROLE, ADMIN_HOLDER, block=19298624, log_index=1)
    log.topics = [RG, "0x", _word(ADMIN_HOLDER)]
    assert rhp.fold_role_candidates([log]) == {}


def test_block_hash_of_an_empty_return_is_absent_not_empty_bytes(monkeypatch):
    """``bytes.fromhex`` with no length check published ``b""``."""
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, block={"hash": "0x"}))
    pinned = rhp.pin_probe_block("http://stub", chain_id=1)
    assert pinned is not None
    assert pinned.block_hash is None
    assert pinned.block_hash != b""

    for truncated in ("0x" + "cd" * 31, "0x" + "cd" * 33, "0xnothex" + "0" * 58):
        calls.clear()
        monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, block={"hash": truncated}))
        short = rhp.pin_probe_block("http://stub", chain_id=1)
        assert short is not None and short.block_hash is None

    calls.clear()
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls))
    good = rhp.pin_probe_block("http://stub", chain_id=1)
    assert good is not None
    assert good.block_hash is not None
    assert good.block_hash == bytes.fromhex("cd" * 32)
    assert len(good.block_hash) == 32


def test_success_with_empty_returndata_is_a_failed_read(db_session, monkeypatch):
    """``decode_bool_word("0x")`` is False, so a no-data call published ``chain_state: "false"`` and satisfied
    ``has_role_answered``.
    """
    empty_success = EthCallResult(True, "0x", None, None)
    assert rhp.classify_candidate(empty_success) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.classify_candidate(EthCallResult(True, "0x0", None, None)) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.classify_candidate(EthCallResult(True, "0x" + "00" * 31, None, None)) == rhp.CANDIDATE_UNCONFIRMED

    session = db_session
    _seed(session, logs=[_log(RG, ZERO_ROLE, ADMIN_HOLDER, block=19298624, log_index=3)])
    rows = _run(session, monkeypatch, {(ZERO_ROLE, ADMIN_HOLDER): empty_success})

    row = _by_role(rows)[ZERO_ROLE]
    assert row["holders"] is None
    assert row["holders_basis"] == "not_determined"
    assert row["fold_chain_disagreements"] is None
    assert row["role_name"] is None
    assert row["role_name_basis"] == "not_determined"


def test_a_genuine_full_word_false_is_still_a_recorded_disagreement(db_session, monkeypatch):
    session = db_session
    _seed(
        session,
        logs=[
            _log(RG, ZERO_ROLE, ADMIN_HOLDER, block=19298624, log_index=3),
            _log(RG, PAUSER, PAUSER_EXTRA, block=19298625, log_index=4),
        ],
    )
    rows = _by_role(
        _run(
            session,
            monkeypatch,
            {(ZERO_ROLE, ADMIN_HOLDER): FALSE_WORD, (PAUSER, PAUSER_EXTRA): TRUE_WORD},
        )
    )
    disagreements = rows[PAUSER]["fold_chain_disagreements"]
    assert disagreements == []
    assert rows[ZERO_ROLE]["role_name"] is None  # withheld: no confirmed holder
    assert rows[PAUSER]["holders"] == [PAUSER_EXTRA]

    _seed(session, logs=[_log(RR, PAUSER, PAUSER_EXTRA, block=19298626, log_index=5)], cursors=[])
    again = _by_role(_run(session, monkeypatch, {(PAUSER, PAUSER_EXTRA): TRUE_WORD}))
    assert again[PAUSER]["fold_chain_disagreements"] == [
        {
            "registry": REGISTRY,
            "role_hash": PAUSER,
            "address": PAUSER_EXTRA,
            "fold_state": "inactive",
            "chain_state": "true",
        }
    ]
