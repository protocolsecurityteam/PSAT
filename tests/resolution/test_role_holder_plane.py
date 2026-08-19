"""D6-accept — a role's holders as a PROVEN LOWER BOUND, never a membership set.

The fold proposes candidates; a pinned ``hasRole`` read witnesses each one. Every
test here exists to pin one of the ways that could quietly become a set:

  * an empty array standing in for "nobody holds this role";
  * a reverting read decoded as false and published as a proven non-holder;
  * Solady's ``uint256`` role space folded through OZ's ``bytes32`` topic
    positions, where a cast role word reads the mapping's zero default and
    returns false SUCCESSFULLY — a completed read that witnesses nothing;
  * a name attached to a hash it is not the preimage of;
  * residual counters that let a reader reconstruct the banned empty set.

The corpus values pinned below were measured on the local replica and
re-verified on-chain at block 25643300 (20 protocol-1 probes, 20 agreeing).
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
from services.resolution import role_holder_plane as rhp
from utils.chains import DEFAULT_CONFIRMATION_DEPTH
from utils.rpc import EthCallResult

REGISTRY = "0x6db24ee656843e3fe03eb8762a54d86186ba6b64"
SOLADY_REGISTRY = "0x62247d29b4b9becf4bb73e0c722cf6445cfc7ce9"

RG = rhp.ROLE_GRANTED_TOPIC0
RR = rhp.ROLE_REVOKED_TOPIC0
# Solady ``RoleSet(address,uint256,bool)`` — present in the same corpus, in a
# different role identity space. role_topic_index=2, not 1.
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

# The exact tuple ``eth_call_batch`` produces for every one of the four corpus
# addresses whose ``hasRole`` reverts, measured at 25643300.
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
    """The measured protocol-1 CumulativeMerkleDrop proxy history."""
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
    """Resolve with ``eth_call_batch`` stubbed from a (role, account) map."""

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


# ---------------------------------------------------------------------------
# A1 — identity space
# ---------------------------------------------------------------------------


def test_solady_roleset_logs_mint_no_row(db_session, monkeypatch):
    """Solady's ``RoleSet`` shares the registry but not the role identity space.

    Folded through OZ's topic positions its ``uint256`` role becomes a bytes32
    key that ``hasRole`` answers from the mapping's ZERO DEFAULT — successfully,
    returning false. That is a completed read witnessing nothing, and it would
    publish 40 unqualified rows over roles that do have holders. No row is the
    honest outcome; row-absence means not_determined.
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
            # RoleSet(holder@1, role@2, active@3) — note role is at index 2.
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


# ---------------------------------------------------------------------------
# A3 — the classifier boundary, where the three states must stay three
# ---------------------------------------------------------------------------


def test_classify_candidate_keeps_three_distinct_states():
    """A read that completed and said no is not a read that never happened.

    Asserted at the classifier rather than through the resolver, because both a
    correct implementation and one that calls ``decode_bool_word`` without
    branching on ``success`` produce zero confirmations from an all-reverting
    registry — the end-to-end arm cannot tell them apart.
    """
    assert rhp.classify_candidate(TRUE_WORD) == rhp.CANDIDATE_CONFIRMED
    assert rhp.classify_candidate(FALSE_WORD) == rhp.CANDIDATE_READ_COMPLETED_NOT_CONFIRMED
    assert rhp.classify_candidate(MEASURED_REVERT) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.CANDIDATE_UNCONFIRMED != rhp.CANDIDATE_READ_COMPLETED_NOT_CONFIRMED
    # Transport failure carries no revert data and must land in the same state
    # as a revert — indeterminate, never an answer.
    assert rhp.classify_candidate(EthCallResult(False, "0x", None, "transport: boom")) == rhp.CANDIDATE_UNCONFIRMED
    # An empty return decodes to False; it must NOT be read as a completed no.
    assert rhp.classify_candidate(EthCallResult(False, "0x", "0x", "reverted")) == rhp.CANDIDATE_UNCONFIRMED


# ---------------------------------------------------------------------------
# The positive: a lower bound
# ---------------------------------------------------------------------------


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

    # Unconditional, on every row, regardless of anything above.
    assert {row["holder_set_exhaustive"] for row in rows.values()} == {"not_determined"}
    # Today's cursors witness no lower bound and no page completeness.
    assert {row["cursor_first_indexed_block_basis"] for row in rows.values()} == {"not_determined"}
    assert {row["cursor_first_indexed_block"] for row in rows.values()} == {None}
    assert {row["cursor_page_completeness"] for row in rows.values()} == {"not_determined"}
    assert {row["cursor_last_indexed_block"] for row in rows.values()} == {25641245}


# ---------------------------------------------------------------------------
# Fail-closed arms
# ---------------------------------------------------------------------------


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


def test_all_candidates_revert_withholds(db_session, monkeypatch):
    """The 0xd5edf773 / USDC shape: warm cursors, but no AccessControl beneath."""
    session = db_session
    _seed(session)
    rows = _run(session, monkeypatch, {})  # every probe falls through to MEASURED_REVERT
    for row in rows:
        assert row["holders"] is None
        assert row["holders_basis"] == "not_determined"
        assert row["coverage"] == "partial"


def test_all_candidates_read_false_withholds(db_session, monkeypatch):
    """A genuinely fully-revoked role publishes NULL, never ``[]``.

    We cannot prove nobody holds it: a direct storage write the recording
    surface never saw would not appear in either the fold or this arm.
    """
    session = db_session
    _seed(session)
    verdicts = {
        (role, account): FALSE_WORD
        for role in (ZERO_ROLE, PAUSER, OPERATING_ADMIN)
        for account in (ADMIN_HOLDER, REVOKED_A, REVOKED_B, PAUSER_EXTRA, OPS_HOLDER)
    }
    rows = _run(session, monkeypatch, verdicts)
    for row in rows:
        assert row["holders"] is None
        assert row["coverage"] == "partial"


def test_all_false_and_all_revert_rows_are_indistinguishable(db_session, monkeypatch):
    """A2 — the residual counters must not reconstruct the banned empty set.

    "N probed, every read completed, none confirmed" IS ``[]``. If the all-false
    row differed from the all-revert row in any column, a reader could recover
    it, and this plane would be publishing the diagnosis it refuses elsewhere.
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
    """No pinned height means no probe — never a retry against ``latest``."""
    session = db_session
    _seed(session)
    monkeypatch.setattr(rhp, "pin_probe_block", lambda *a, **k: None)
    monkeypatch.setattr(rhp, "eth_call_batch", lambda *a, **k: pytest.fail("must not probe unpinned"))
    rows = rhp.resolve_role_holder_planes(
        session, chain_id=1, registry_address=REGISTRY, rpc_url="http://stub", probe_block=None
    )
    assert rows and all(row["holders"] is None and row["coverage"] == "partial" for row in rows)


def test_registry_with_no_role_logs_yields_no_rows(db_session, monkeypatch):
    """Warm cursors, zero logs — row-absence, not "this registry has no roles"."""
    session = db_session
    _seed(session, logs=[], cursors=[_cursor(RG), _cursor(RR)])
    assert _run(session, monkeypatch, {}) == []


# ---------------------------------------------------------------------------
# role_name — a proven preimage, or the key is absent
# ---------------------------------------------------------------------------


def test_role_name_absent_without_a_preimage(db_session, monkeypatch):
    """TIMELOCK_ADMIN_ROLE is in no ``role_definitions`` row, so it gets no name.

    This falls out of the pool rather than being special-cased — and it is why
    B0b's anti-decoy credit stays CONFIDENCE.
    """
    session = db_session
    _seed(session, logs=[_log(RG, TIMELOCK_ADMIN, ADMIN_HOLDER, block=19298624, log_index=121)])
    row = _by_role(_run(session, monkeypatch, {(TIMELOCK_ADMIN, ADMIN_HOLDER): TRUE_WORD}))[TIMELOCK_ADMIN]
    assert row["role_name"] is None
    assert row["role_name_basis"] == "not_determined"
    assert row["holders"] == [ADMIN_HOLDER], "the hash is the identity; the name is decoration"


def test_keccak_mismatch_is_refused():
    """The hard ban: a role-shaped name may not be attached to a hash it does
    not hash to, however plausible it looks."""
    bogus = "0x" + "de" * 32
    assert rhp.resolve_role_name(bogus, ["PAUSER_ROLE", "DEFAULT_ADMIN_ROLE"], has_role_answered=True) == (
        None,
        "not_determined",
    )


def test_misparsed_storage_pointers_cannot_leak_a_name():
    """D6-reject stops MINTING these, but existing rows persist until their
    contract is re-analysed. The keccak gate is what makes that harmless."""
    pool = ["OwnableStorageLocation", "AccessControlDefaultAdminRulesStorageLocation"]
    assert rhp.resolve_role_name(PAUSER, pool, has_role_answered=True) == (None, "not_determined")


def test_default_admin_name_needs_an_answered_has_role():
    """A6 — the zero-word arm is a convention about AccessControl, so it may not
    fire on an emitter proven not to implement ``hasRole``."""
    assert rhp.resolve_role_name(ZERO_ROLE, [], has_role_answered=True) == (
        "DEFAULT_ADMIN_ROLE",
        "accesscontrol_default_admin_literal",
    )
    assert rhp.resolve_role_name(ZERO_ROLE, [], has_role_answered=False) == (None, "not_determined")


def test_default_admin_name_withheld_when_registry_never_answers(db_session, monkeypatch):
    session = db_session
    _seed(session)
    row = _by_role(_run(session, monkeypatch, {}))[ZERO_ROLE]
    assert row["role_name"] is None
    assert row["role_name_basis"] == "not_determined"


def test_candidate_pool_reads_declared_names_across_contracts(db_session):
    """The pool is not contract-scoped, and does not need to be.

    A preimage is a preimage whoever offered the string, so the name for the
    proxy's role may legitimately come from the IMPLEMENTATION's row — which is
    where it actually lives (the events are emitted at the proxy, while
    ``role_definitions`` hangs off the implementation contract).
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
    # The mis-parsed pointer is in the pool and still cannot be published.
    assert rhp.resolve_role_name(TIMELOCK_ADMIN, pool, has_role_answered=True) == (None, "not_determined")
    session.rollback()


def test_default_admin_role_name_is_not_its_own_keccak():
    """Pins why the zero-word arm must exist separately: the name does not hash
    to the hash it labels."""
    assert "0x" + keccak(text="DEFAULT_ADMIN_ROLE").hex() != ZERO_ROLE


# ---------------------------------------------------------------------------
# Disagreement — recorded, never diagnosed
# ---------------------------------------------------------------------------


def test_fold_inactive_but_chain_true_is_admitted(db_session, monkeypatch):
    """The read is the witness, so it wins in both directions.

    Admitting a fold-inactive address does not conflate administration with
    membership: OZ expresses "may administer X" as membership in a different
    bytes32, hence a different primary key.
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
    """A9 — the permitted key set, exactly.

    ``as_of_block`` sits above the cursor head, so "the fold missed a log" and
    "the state changed after the cursor stopped" are indistinguishable. No
    reason/cause/likely_* key may appear, and non-attribution must survive even
    if a future run closes that window by pinning the two heights equal.
    """
    session = db_session
    _seed(session)
    verdicts = {(PAUSER, ADMIN_HOLDER): TRUE_WORD, (PAUSER, PAUSER_EXTRA): FALSE_WORD, (PAUSER, REVOKED_A): TRUE_WORD}
    row = _by_role(_run(session, monkeypatch, verdicts))[PAUSER]
    for record in row["fold_chain_disagreements"]:
        assert set(record) == rhp.DISAGREEMENT_KEYS
    # A revert is not a disagreement — nothing was read to disagree with.
    reverted = _by_role(_run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD}))[PAUSER]
    assert reverted["fold_chain_disagreements"] == []


# ---------------------------------------------------------------------------
# Cursor bounds consumed from U10A
# ---------------------------------------------------------------------------


def test_explicit_seed_lower_bound_is_dropped(db_session, monkeypatch):
    """A seed a caller supplied is not a witness, and the number goes with the
    basis so nothing can cite what it may not."""
    session = db_session
    _seed(
        session,
        cursors=[
            _cursor(RG, first_indexed_block=100, first_indexed_block_basis=FIRST_INDEXED_BASIS_EXPLICIT),
            _cursor(RR, first_indexed_block=100, first_indexed_block_basis=FIRST_INDEXED_BASIS_EXPLICIT),
        ],
    )
    row = _by_role(_run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD}))[PAUSER]
    assert row["cursor_first_indexed_block"] is None
    assert row["cursor_first_indexed_block_basis"] == "not_determined"


def test_witnessed_lower_bound_is_carried(db_session, monkeypatch):
    session = db_session
    _seed(
        session,
        cursors=[
            _cursor(RG, first_indexed_block=20933000, first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION),
            _cursor(RR, first_indexed_block=20933100, first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION),
        ],
    )
    row = _by_role(_run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD}))[PAUSER]
    # Weakest link: the pair is only covered from the HIGHER of the two.
    assert row["cursor_first_indexed_block"] == 20933100
    assert row["cursor_first_indexed_block_basis"] == FIRST_INDEXED_BASIS_CREATION
    assert row["holder_set_exhaustive"] == "not_determined", "a lower bound alone licenses nothing"


def test_tracked_topics_basis_is_recorded_not_depended_on(db_session, monkeypatch):
    """An exactness-ineligible cursor still supports a lower bound, because a
    lower bound is not an exact empty. The basis is cited, not consumed."""
    session = db_session
    _seed(
        session,
        cursors=[
            _cursor(RG, enrollment_basis=ENROLLMENT_BASIS_TRACKED_TOPICS),
            _cursor(RR, enrollment_basis=ENROLLMENT_BASIS_TRACKED_TOPICS),
        ],
    )
    row = _by_role(_run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD}))[PAUSER]
    assert row["holders"] == [ADMIN_HOLDER]
    assert row["cursor_enrollment_bases"] == {RG: ENROLLMENT_BASIS_TRACKED_TOPICS, RR: ENROLLMENT_BASIS_TRACKED_TOPICS}
    assert row["holder_set_exhaustive"] == "not_determined"


# ---------------------------------------------------------------------------
# The pinned probe block itself (R2) — previously monkeypatched away everywhere
# ---------------------------------------------------------------------------


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
    """The height is head − DEFAULT_CONFIRMATION_DEPTH, and the block is asked
    for by NUMBER. A bare head can be reorged out from under a persisted
    `as_of_block`, and ``"latest"`` would make the citation unrepeatable."""
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


def test_probe_block_survives_an_unreadable_hash(monkeypatch):
    """The height stands on its own; only replay-after-reorg is weaker.

    This is why the register says the hash is persisted WHEN READABLE rather
    than unconditionally.
    """
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, fail_hash=True))
    pinned = rhp.pin_probe_block("http://stub", chain_id=1)
    assert pinned is not None
    assert pinned.number == HEAD - DEFAULT_CONFIRMATION_DEPTH
    assert pinned.block_hash is None


def test_probe_block_hash_absent_from_payload_is_not_invented(monkeypatch):
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, block={}))
    pinned = rhp.pin_probe_block("http://stub", chain_id=1)
    assert pinned is not None and pinned.block_hash is None


def test_unreadable_head_yields_no_probe_block(monkeypatch):
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, fail_head=True))
    assert rhp.pin_probe_block("http://stub", chain_id=1) is None


def test_chain_shallower_than_confirmation_depth_yields_no_probe_block(monkeypatch):
    calls: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls, head=hex(DEFAULT_CONFIRMATION_DEPTH)))
    assert rhp.pin_probe_block("http://stub", chain_id=1) is None


# ---------------------------------------------------------------------------
# The bans, enforced by the database
# ---------------------------------------------------------------------------


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
    """A CHECK that evaluates to NULL PASSES in Postgres.

    ``holder_set_exhaustive = 'not_determined'`` is satisfied by a NULL, as is
    every domain check and both biconditionals — so NOT NULL, not the CHECK, is
    what actually makes those constraints binding. Asserted through raw SQL
    because the ORM's server_default would quietly substitute a value for an
    omitted column and hide the hole.
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
    """``none_as_null``, pinned.

    Without it SQLAlchemy stores a Python None as the jsonb scalar ``null``,
    which is a PRESENT payload to every SQL null test — the repo-wide invariant
    in ``test_jsonb_null_predicates`` exists for exactly this. If it is ever
    dropped, this fails rather than silently changing what a withheld row means.
    ``jsonb_typeof`` returns SQL NULL for a SQL NULL and the string ``'null'``
    for the scalar, so it separates the two states the trap conflates.
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
    # The disagreement ledger needs the same guard and cannot borrow the one above:
    # its withheld predicate deliberately counts the scalar null, so the CHECKs stay
    # satisfied while every naive IS NULL consumer reads the row as carrying evidence.
    assert disagreements_typeof is None, "a withheld disagreement ledger must be SQL NULL too"
    session.rollback()


def _raw_insert(session, holders_sql: str, **cols: str) -> None:
    """Insert a withheld-shaped row with ``holders`` written as raw jsonb."""
    defaults = {
        "holders_basis": "'not_determined'",
        "holder_set_exhaustive": "'not_determined'",
        "cursor_first_indexed_block": "NULL",
        "cursor_first_indexed_block_basis": "'not_determined'",
        "cursor_enrollment_bases": "'{}'::jsonb",
        "cursor_page_completeness": "'not_determined'",
        "coverage": "'partial'",
        "role_name_basis": "'not_determined'",
        # NULL, matching the withheld shape these raw inserts build.
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
    """Raw SQL can still reach the column, so the trap is NEUTRALISED, not merely
    avoided: the scalar null counts as withheld everywhere, exactly like SQL NULL.

    Were it read as a payload instead, five constraints would stop
    discriminating at once and a row carrying no holders would satisfy the
    checks meant to require them.
    """
    session = db_session
    _raw_insert(session, "'null'::jsonb")
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None
    session.rollback()


def test_jsonb_scalar_null_cannot_carry_a_proven_basis(db_session):
    """The biconditional sees the scalar null as withheld, so pairing it with the
    pinned basis — or with a block, or with counters — is rejected."""
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
    """R4 — ``[]`` on a withheld row is an unearned negative.

    On an all-reverting registry nothing was read, so "no disagreement" is
    not_determined. On an all-false registry disagreements WERE observed, and
    publishing ``[]`` there would suppress them. Both must be NULL.
    """
    session = db_session
    with pytest.raises(IntegrityError):
        _raw_insert(session, "NULL", fold_chain_disagreements="'[]'::jsonb")
    session.rollback()


def test_published_row_must_carry_a_disagreement_log(db_session):
    """The converse: a published floor may not omit the log that qualifies it."""
    session = db_session
    with pytest.raises(IntegrityError):
        session.add(RoleHolderPlane(**_valid_row(fold_chain_disagreements=None)))
        session.flush()
    session.rollback()


def test_published_empty_disagreement_log_is_allowed(db_session):
    """On a published row ``[]`` is earned — scoped to the candidates whose
    reads completed, with ``unconfirmed_candidate_count`` carrying the rest."""
    session = db_session
    session.add(RoleHolderPlane(**_valid_row(fold_chain_disagreements=[])))
    session.flush()
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None and stored.fold_chain_disagreements == []
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
    ],
)
def test_cursor_bound_columns_are_domain_checked(db_session, cols):
    """R1 + R3 — gates that lived only in code, now in the schema.

    A basis of ``creation_block_minus_one`` with no block claims a height it
    cannot cite; ``explicit_seed`` is a caller's number and the writer
    normalises it away, so it must not be storable as a witness either.
    """
    session = db_session
    with pytest.raises(IntegrityError):
        _raw_insert(session, "NULL", **cols)
    session.rollback()


def test_lower_bound_block_without_a_basis_is_rejected(db_session):
    session = db_session
    with pytest.raises(IntegrityError):
        _raw_insert(session, "NULL", cursor_first_indexed_block="999")
    session.rollback()


def test_non_array_holders_are_rejected(db_session):
    """A jsonb string or object is neither a holder set nor a withheld marker."""
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


def test_valid_row_round_trips(db_session):
    session = db_session
    session.add(RoleHolderPlane(**_valid_row()))
    session.flush()
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None
    assert stored.holders == [ADMIN_HOLDER]
    assert stored.holder_set_exhaustive == "not_determined"


def test_withheld_row_round_trips(db_session):
    session = db_session
    session.add(RoleHolderPlane(**_withheld_orm_row()))
    session.flush()
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None and stored.holders is None
    assert stored.fold_chain_disagreements is None


def test_persist_upserts(db_session, monkeypatch):
    session = db_session
    _seed(session)
    rows = _run(session, monkeypatch, {(PAUSER, ADMIN_HOLDER): TRUE_WORD})
    assert rhp.persist_role_holder_planes(session, rows) == len(rows)
    assert rhp.persist_role_holder_planes(session, rows) == len(rows)
    stored = session.get(RoleHolderPlane, (1, REGISTRY, PAUSER))
    assert stored is not None and stored.holders == [ADMIN_HOLDER]


# ---------------------------------------------------------------------------
# Tolerant decoders on a registered witness plane (fix 3)
#
# Three instances of the same shape: a value nobody observed, padded/coerced
# into one that looks observed. Each one published a POSITIVE fact — a role
# name, a replay citation, "the chain answered false" — out of a read that
# answered nothing.
# ---------------------------------------------------------------------------


def test_empty_word_is_never_padded_into_the_default_admin_role():
    """FALSIFIER: ``"0x"`` left-padded is bit-identical to
    ``DEFAULT_ADMIN_ROLE_HASH``, so the tolerant normalizer turned a no-data
    read into the zero role AND its convention-based name — defeating the
    guard this file already asserts one function over."""
    assert rhp._normalize_word("0x") is None
    assert rhp.resolve_role_name("0x", [], has_role_answered=True) == (None, "not_determined")
    assert rhp.resolve_role_name("0x00", [], has_role_answered=True) == (None, "not_determined")
    assert rhp.resolve_role_name("0xzz" + "0" * 62, [], has_role_answered=True) == (None, "not_determined")
    # RECALL: a genuine zero WORD still earns the convention name.
    assert rhp.resolve_role_name(ZERO_ROLE, [], has_role_answered=True) == (
        "DEFAULT_ADMIN_ROLE",
        "accesscontrol_default_admin_literal",
    )
    # RECALL: a full-width word still folds and still resolves by preimage.
    assert rhp._normalize_word("0x" + "AB" * 32) == "0x" + "ab" * 32
    assert rhp.resolve_role_name(PAUSER, ["PAUSER_ROLE"], has_role_answered=False) == (
        "PAUSER_ROLE",
        "keccak_preimage",
    )


def test_an_empty_word_topic_folds_to_no_candidate(db_session, monkeypatch):
    """The fold's own entry point: a log whose role topic is ``"0x"`` must
    contribute no role, rather than a DEFAULT_ADMIN candidate."""
    log = _log(RG, ZERO_ROLE, ADMIN_HOLDER, block=19298624, log_index=1)
    log.topics = [RG, "0x", _word(ADMIN_HOLDER)]
    assert rhp.fold_role_candidates([log]) == {}


def test_block_hash_of_an_empty_return_is_absent_not_empty_bytes(monkeypatch):
    """FALSIFIER: the reorg/replay witness was decoded with ``bytes.fromhex``
    and no length check, so ``"0x"`` published ``b""`` — a citation a replaying
    reader cannot tell from one it never got."""
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

    # RECALL: a genuine 32-byte hash is still stored, at full width.
    calls.clear()
    monkeypatch.setattr(rhp, "rpc_request", _rpc_stub(calls))
    good = rhp.pin_probe_block("http://stub", chain_id=1)
    assert good is not None
    assert good.block_hash is not None
    assert good.block_hash == bytes.fromhex("cd" * 32)
    assert len(good.block_hash) == 32


def test_success_with_empty_returndata_is_a_failed_read(db_session, monkeypatch):
    """FALSIFIER: ``eth_call_batch`` reports a result it cannot read as
    ``EthCallResult(True, "0x", …)``. ``decode_bool_word("0x")`` is False, so a
    call that returned NO DATA published ``chain_state: "false"`` in the
    disagreement log AND satisfied ``has_role_answered``.
    """
    empty_success = EthCallResult(True, "0x", None, None)
    assert rhp.classify_candidate(empty_success) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.classify_candidate(EthCallResult(True, "0x0", None, None)) == rhp.CANDIDATE_UNCONFIRMED
    assert rhp.classify_candidate(EthCallResult(True, "0x" + "00" * 31, None, None)) == rhp.CANDIDATE_UNCONFIRMED

    session = db_session
    # One GRANTED log for the zero role: the fold believes the account active,
    # so a completed "false" would be a recorded disagreement.
    _seed(session, logs=[_log(RG, ZERO_ROLE, ADMIN_HOLDER, block=19298624, log_index=3)])
    rows = _run(session, monkeypatch, {(ZERO_ROLE, ADMIN_HOLDER): empty_success})

    row = _by_role(rows)[ZERO_ROLE]
    # Withheld, not published-false.
    assert row["holders"] is None
    assert row["holders_basis"] == "not_determined"
    assert row["fold_chain_disagreements"] is None
    # `has_role_answered` must NOT have been satisfied, so the zero-word naming
    # convention has nothing to stand on.
    assert row["role_name"] is None
    assert row["role_name_basis"] == "not_determined"


def test_a_genuine_full_word_false_is_still_a_recorded_disagreement(db_session, monkeypatch):
    """RECALL for the arm above: a completed read of a real 32-byte zero word
    still records ``chain_state: "false"``. The plane loses no disagreement."""
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
    # The false read completed, so the zero-word convention IS earned here.
    assert rows[ZERO_ROLE]["role_name"] is None  # withheld: no confirmed holder
    assert rows[PAUSER]["holders"] == [PAUSER_EXTRA]

    # And the disagreement itself, on a role whose fold/chain states differ.
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
