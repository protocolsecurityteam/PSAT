"""Who a role is proven to include, and why that is only ever a lower bound.

The plane is keyed ``(chain_id, registry_address, role_hash)``. Two surfaces
name the same ``(role, account)`` pair and neither is trusted to do the other's
job:

* the **fold** over ``RoleGranted``/``RoleRevoked`` logs PROPOSES candidates;
* a pinned ``hasRole(bytes32,address)`` read WITNESSES each one.

Only the read can put an address in ``holders``. That asymmetry is what makes
the result sound under a broken fold: a fold that misses grants, mis-orders
revokes, or stops early yields a SMALLER lower bound, never a wrong one. What it
costs is completeness, published permanently as ``holder_set_exhaustive``.

Because the fold is only a proposal, candidates are drawn from every address
that ever APPEARS for a role — granted and revoked alike — and the read decides.
An address the fold believes was revoked but whose ``hasRole`` returns true is
admitted: the read proves it. This does not conflate role administration with
role membership, because OZ expresses "may administer role X" as membership in a
*different* ``bytes32``, which is a different primary key.

What ``holders`` proves, stated exactly: **this address's own ``hasRole``
predicate returned true at ``as_of_block``.** That is a behavioural read of
deployed code, not a claim about the layout of ``_roles``. It is the right
predicate anyway — ``hasRole`` is the same virtual function ``_checkRole``
dispatches to, so an override that fools this read fools the gate identically.
This is also what separates this ACCEPT side from the ``external_set`` arm B4c
excised: there the callee's interface was the CALLING contract's declaration and
no independent surface corroborated it; here the canonical OZ topic0 emitted BY
that address and that address's OWN predicate independently name the same pair.

**Identity is the hash and only the hash.** Rows are minted from the OZ
AccessControl topic pair LITERALLY — not from ``role_store_standards`` — so that
one identity space is in play. Solady's ``RoleSet(address,uint256,bool)`` also
lives in that registry and carries a ``uint256`` role in a wholly different
space; folding it here would key rows by a word that, cast into the OZ
``bytes32`` mapping, reads the ZERO DEFAULT and returns false *successfully*.
That is a completed read standing in for a witness — a default masquerading as
evidence — and it would publish an unqualified nothing over roles that do have
holders. Solady logs therefore mint NO ROW, and row-absence means not_determined.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from eth_utils.crypto import keccak
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    FIRST_INDEXED_BASIS_CREATION,
    HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED,
    HOLDERS_BASIS_PINNED_HAS_ROLE,
    ROLE_COVERAGE_LOWER_BOUND,
    ROLE_COVERAGE_PARTIAL,
    ROLE_NAME_BASIS_AC_DEFAULT_ADMIN,
    ROLE_NAME_BASIS_KECCAK,
    ROLE_NAME_BASIS_NOT_DETERMINED,
    IndexedEventCursor,
    IndexedEventLog,
    RoleDefinition,
    RoleHolderPlane,
)
from services.resolution.absence_coverage import NOT_DETERMINED, absence_coverage
from services.resolution.repos.event_logs_rpc import default_result_cap
from utils.chains import DEFAULT_CONFIRMATION_DEPTH
from utils.rpc import EthCallResult, decode_bool_word, encode_address_word, eth_call_batch, rpc_request, selector

logger = logging.getLogger(__name__)

# The OZ AccessControl pair, written out rather than read from
# ``role_store_standards.spec_by_topic0()``. That map also carries Solady's
# ``RoleSet``, whose role word indexes a different identity space (see module
# docstring); consuming it would silently widen this plane by 78%.
ROLE_GRANTED_TOPIC0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
ROLE_REVOKED_TOPIC0 = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"
ACCESS_CONTROL_TOPIC0S = (ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0)

# ``RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)``
_ROLE_TOPIC_INDEX = 1
_ACCOUNT_TOPIC_INDEX = 2

HAS_ROLE_SELECTOR = selector("hasRole(bytes32,address)")

# AccessControl defines ``DEFAULT_ADMIN_ROLE`` as the literal zero word. Note it
# is NOT ``keccak("DEFAULT_ADMIN_ROLE")`` (that is 0x1effbbff…), so this name can
# never be attached by the preimage arm and needs its own, weaker basis.
DEFAULT_ADMIN_ROLE_HASH = "0x" + "00" * 32
DEFAULT_ADMIN_ROLE_NAME = "DEFAULT_ADMIN_ROLE"

# Per-candidate probe outcomes. Three states, and the last two must never
# collapse: a completed read returning false and a read that never happened are
# different facts, and only the first is a read at all.
CANDIDATE_CONFIRMED = "confirmed"
CANDIDATE_READ_COMPLETED_NOT_CONFIRMED = "read_completed_not_confirmed"
CANDIDATE_UNCONFIRMED = "unconfirmed"

# The only keys a disagreement record may carry. No key naming a cause belongs
# here: ``as_of_block`` sits above the cursor head, so "the fold missed a log"
# and "the state changed after the cursor stopped" are indistinguishable. If a
# future run ever pins the probe block AT the cursor head that window closes,
# but non-attribution must survive on principle — a cursor is an upper bound on
# what was READ, never a proof of what was EMITTED.
DISAGREEMENT_KEYS = frozenset({"registry", "role_hash", "address", "fold_state", "chain_state"})


@dataclass(frozen=True)
class ProbeBlock:
    """A confirmation-depth-deep height and its hash.

    Bare ``eth_blockNumber`` is not replayable: the head can be reorged out from
    under a persisted number, and then ``as_of_block`` cites a block that no
    longer exists on the canonical chain. The hash is what makes the citation
    checkable after the fact.
    """

    number: int
    block_hash: bytes | None


def classify_candidate(result: EthCallResult) -> str:
    """One ``hasRole`` outcome, as three states that never collapse into two.

    ``decode_bool_word`` returns False for a revert, an empty return and a short
    word alike, so calling it without first branching on ``success`` converts
    every failed read into a proven non-holder — the exact fail-open shape this
    plane exists to avoid. The branch is here, once, so no caller can skip it.
    """
    if not result.success:
        return CANDIDATE_UNCONFIRMED
    return CANDIDATE_CONFIRMED if decode_bool_word(result.return_data) else CANDIDATE_READ_COMPLETED_NOT_CONFIRMED


def fold_role_candidates(rows: Iterable[Any]) -> dict[str, dict[str, bool]]:
    """``role_hash -> {account: fold_believes_active}`` in log order.

    Last-write-wins per ``(role, account)``. Rows whose ``topic0`` is not one of
    the two AccessControl topics are dropped, so a Solady ``RoleSet`` in the same
    result set contributes nothing rather than being read with OZ's topic
    positions. The returned map keeps revoked accounts: they are candidates too,
    and the pinned read — not this fold — decides membership.
    """
    state: dict[str, dict[str, bool]] = {}
    for row in rows:
        topics = list(getattr(row, "topics", None) or [])
        if len(topics) <= _ACCOUNT_TOPIC_INDEX:
            continue
        topic0 = str(topics[0]).lower()
        if topic0 not in (ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0):
            continue
        role_hash = _normalize_word(topics[_ROLE_TOPIC_INDEX])
        account = _word_to_address(topics[_ACCOUNT_TOPIC_INDEX])
        if role_hash is None or account is None:
            continue
        state.setdefault(role_hash, {})[account] = topic0 == ROLE_GRANTED_TOPIC0
    return state


def resolve_role_name(
    role_hash: str, candidate_names: Iterable[str], *, has_role_answered: bool
) -> tuple[str | None, str]:
    """``(role_name, role_name_basis)`` — a proven preimage, or the key absent.

    What the ``keccak_preimage`` arm proves is a TOTAL fact about the hash: some
    string S satisfies ``keccak(S) == role_hash``, and collision resistance makes
    S the only such short string. It does NOT prove that this registry declares a
    constant named S — which is why the candidate pool may be drawn from anywhere
    without weakening the result, and why a candidate that fails the hash check
    is discarded no matter how role-shaped its name looks.

    The zero-word arm is a naming CONVENTION, not a preimage, so it carries its
    own weaker basis. It additionally requires that ``hasRole`` was answered by
    this registry at all: rows exist wherever the two topics were emitted, and an
    emitter that does not implement ``hasRole`` is not the AccessControl the
    convention describes.
    """
    normalized = _normalize_word(role_hash)
    for name in candidate_names:
        if not isinstance(name, str) or not name:
            continue
        if "0x" + keccak(text=name).hex() == normalized:
            return name, ROLE_NAME_BASIS_KECCAK
    if normalized == DEFAULT_ADMIN_ROLE_HASH and has_role_answered:
        return DEFAULT_ADMIN_ROLE_NAME, ROLE_NAME_BASIS_AC_DEFAULT_ADMIN
    return None, ROLE_NAME_BASIS_NOT_DETERMINED


def candidate_name_pool(session: Session) -> list[str]:
    """Distinct declared role names, as CANDIDATES only.

    Every one is filtered through the keccak check before it can be published,
    so a mis-parsed row (the ERC-7201 storage pointers D6-reject stops minting,
    which persist until their contract is re-analysed) cannot leak a name: its
    hash matches nothing. The pool is deliberately not chain- or contract-scoped
    — a preimage is a preimage regardless of who offered the string.
    """
    return sorted({name for (name,) in session.execute(select(RoleDefinition.role_name).distinct()) if name})


def pin_probe_block(rpc_url: str, *, chain_id: int) -> ProbeBlock | None:
    """A height at least ``DEFAULT_CONFIRMATION_DEPTH`` below head, plus its hash.

    Returns None on any failure. A probe with no pinned height is not run at all;
    it is never retried against ``"latest"``, which would publish a membership
    fact at an unrecorded and unrepeatable height.
    """
    try:
        head = int(str(rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)), 16)
    except Exception:
        logger.warning("could not pin a probe block; role holder plane withheld", exc_info=True)
        return None
    number = head - DEFAULT_CONFIRMATION_DEPTH
    if number <= 0:
        return None
    try:
        block = rpc_request(rpc_url, "eth_getBlockByNumber", [hex(number), False], chain_id=chain_id)
        raw = block.get("hash") if isinstance(block, Mapping) else None
        block_hash = bytes.fromhex(str(raw)[2:]) if isinstance(raw, str) and raw.startswith("0x") else None
    except Exception:
        # The height still stands on its own; only replay-after-reorg is weaker.
        logger.warning("pinned probe block %s but could not read its hash", number, exc_info=True)
        block_hash = None
    return ProbeBlock(number=number, block_hash=block_hash)


def probe_has_role(
    rpc_url: str,
    registry_address: str,
    probes: Sequence[tuple[str, str]],
    *,
    block_number: int,
    chain_id: int,
) -> list[str]:
    """Classify ``hasRole(role_hash, account)`` for each probe at a PINNED block.

    One JSON-RPC array request at one ``block_tag``, so every answer in the plane
    describes the same height. ``eth_call_batch`` is used rather than Multicall3
    because it preserves the per-call success/revert distinction that
    ``classify_candidate`` needs; aggregated through Multicall3 a revert and a
    false would arrive looking more alike than they are.
    """
    if not probes:
        return []
    verdicts: list[str] = [CANDIDATE_UNCONFIRMED] * len(probes)
    calls: list[dict[str, str]] = []
    slots: list[int] = []
    for index, (role_hash, account) in enumerate(probes):
        word = _normalize_word(role_hash)
        if word is None:
            # Never substitute a default role word here: probing the zero role
            # in place of an unparseable one would attribute DEFAULT_ADMIN's
            # holders to it. An unaskable question stays unanswered.
            continue
        calls.append({"to": registry_address, "data": HAS_ROLE_SELECTOR + word[2:] + encode_address_word(account)})
        slots.append(index)
    results = eth_call_batch(rpc_url, calls, hex(block_number), chain_id=chain_id)
    for slot, result in zip(slots, results):
        verdicts[slot] = classify_candidate(result)
    return verdicts


def _cursor_bounds(session: Session, *, chain_id: int, registry_address: str) -> dict[str, Any]:
    """Both AccessControl cursors' state, and whether the pair is warm.

    Warmth is read from ``backfill_complete`` on BOTH topics rather than from
    ``absence_coverage``'s ``warm`` list, which additionally requires exactness
    eligibility. That extra condition governs whether a cursor may support an
    exact EMPTY, and this plane never claims one — so the enrolment basis is
    recorded and cited here, not depended upon.
    """
    rows = list(
        session.execute(
            select(IndexedEventCursor)
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(IndexedEventCursor.event_address == registry_address.lower())
            .where(IndexedEventCursor.topic0.in_(ACCESS_CONTROL_TOPIC0S))
        ).scalars()
    )
    by_topic = {str(row.topic0).lower(): row for row in rows}
    both_warm = all(topic in by_topic and bool(by_topic[topic].backfill_complete) for topic in ACCESS_CONTROL_TOPIC0S)
    coverage_report = absence_coverage(
        session,
        chain_id=chain_id,
        address=registry_address,
        write_surface_topics=list(ACCESS_CONTROL_TOPIC0S),
        configured_cap=default_result_cap(),
    )
    lower_bound = coverage_report["range_lower_bound"]
    lower_basis = coverage_report["range_lower_bound_basis"]
    if lower_basis != FIRST_INDEXED_BASIS_CREATION:
        # An ``explicit_seed`` or a NULL is not a witness, and the number is
        # dropped with the basis so no consumer can cite what it may not.
        lower_bound = None
        lower_basis = NOT_DETERMINED
    last_blocks = [int(row.last_indexed_block) for row in rows if row.last_indexed_block is not None]
    return {
        "both_warm": both_warm,
        # Weakest link: the pair covers only as far as the shorter cursor.
        "last_indexed_block": min(last_blocks) if len(last_blocks) == len(ACCESS_CONTROL_TOPIC0S) else None,
        "first_indexed_block": lower_bound,
        "first_indexed_block_basis": lower_basis,
        "enrollment_bases": {topic: by_topic[topic].enrollment_basis for topic in sorted(by_topic)},
        "page_completeness": coverage_report["page_completeness"],
        # Consulted only to REFUSE. It is hard-wired False upstream, so this can
        # never license anything; reading it keeps the refusal explicit.
        "earned_negative_admissible": coverage_report["earned_negative_admissible"],
    }


def _withheld_row(
    *,
    chain_id: int,
    registry_address: str,
    role_hash: str,
    bounds: Mapping[str, Any],
    role_name: str | None,
    role_name_basis: str,
) -> dict[str, Any]:
    """A row that publishes no lower bound.

    Every counter is NULL, and so is the disagreement log. A cold surface, an
    all-reverting registry and a registry where every read completed and
    confirmed nobody are the SAME row here, on purpose: distinguishing them
    would let a reader reconstruct "N probed, all completed, none held" — the
    banned empty set, spelled out in columns.

    The disagreement log is NULL rather than ``[]`` for a second, independent
    reason. On an all-reverting registry nothing was read, so "no disagreement
    was observed" is not_determined, not an earned negative. On an all-false
    registry disagreements genuinely WERE observed, and they are withheld along
    with the floor they qualify rather than silently dropped. Either way ``[]``
    would assert something unproven — an unearned negative one column over from
    the empty set the table makes unrepresentable.
    """
    return {
        "chain_id": chain_id,
        "registry_address": registry_address.lower(),
        "role_hash": role_hash,
        "holders": None,
        "holders_basis": NOT_DETERMINED,
        "holder_set_exhaustive": HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED,
        "as_of_block": None,
        "as_of_block_hash": None,
        "cursor_first_indexed_block": bounds["first_indexed_block"],
        "cursor_first_indexed_block_basis": bounds["first_indexed_block_basis"],
        "cursor_last_indexed_block": bounds["last_indexed_block"],
        "cursor_enrollment_bases": dict(bounds["enrollment_bases"]),
        "cursor_page_completeness": bounds["page_completeness"],
        "coverage": ROLE_COVERAGE_PARTIAL,
        "role_name": role_name,
        "role_name_basis": role_name_basis,
        "candidate_count": None,
        "unconfirmed_candidate_count": None,
        "fold_chain_disagreements": None,
    }


def resolve_role_holder_planes(
    session: Session,
    *,
    chain_id: int,
    registry_address: str,
    rpc_url: str,
    probe_block: ProbeBlock | None = None,
    candidate_names: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Every ``(role_hash)`` this registry has emitted, resolved to a lower bound.

    A registry that emitted no AccessControl role log yields NO ROWS, and that
    absence means not_determined — never "this registry has no roles". The four
    corpus registries carrying warm role cursors and zero logs (two of them
    protocol-1, and ``hasRole`` reverts on all four) are exactly this case.
    """
    registry_address = registry_address.lower()
    repo_rows = list(
        session.execute(
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(IndexedEventLog.event_address == registry_address)
            .where(IndexedEventLog.topic0.in_(ACCESS_CONTROL_TOPIC0S))
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        ).scalars()
    )
    folded = fold_role_candidates(repo_rows)
    if not folded:
        return []

    bounds = _cursor_bounds(session, chain_id=chain_id, registry_address=registry_address)
    names = list(candidate_names) if candidate_names is not None else candidate_name_pool(session)

    def withhold_all() -> list[dict[str, Any]]:
        """No read happened, so the zero-word convention has nothing to stand on
        either — every name falls back to the keccak arm or to not_determined."""
        out = []
        for role_hash in sorted(folded):
            name, basis = resolve_role_name(role_hash, names, has_role_answered=False)
            out.append(
                _withheld_row(
                    chain_id=chain_id,
                    registry_address=registry_address,
                    role_hash=role_hash,
                    bounds=bounds,
                    role_name=name,
                    role_name_basis=basis,
                )
            )
        return out

    # A cold or missing cursor on either topic withholds every lower bound for
    # this registry. The candidate set is knowingly incomplete, and a floor
    # published from it invites a reader to treat its size as a count.
    if not bounds["both_warm"]:
        return withhold_all()

    if probe_block is None:
        probe_block = pin_probe_block(rpc_url, chain_id=chain_id)
    if probe_block is None:
        return withhold_all()

    probes = [(role_hash, account) for role_hash in sorted(folded) for account in sorted(folded[role_hash])]
    verdicts = probe_has_role(rpc_url, registry_address, probes, block_number=probe_block.number, chain_id=chain_id)
    by_role: dict[str, list[tuple[str, str]]] = {}
    for (role_hash, account), verdict in zip(probes, verdicts):
        by_role.setdefault(role_hash, []).append((account, verdict))

    # The zero-word arm needs proof this registry answers ``hasRole`` at all.
    # Any completed call against it is that proof, whatever the answer was.
    has_role_answered = any(v != CANDIDATE_UNCONFIRMED for v in verdicts)

    rows: list[dict[str, Any]] = []
    for role_hash in sorted(folded):
        outcomes = by_role.get(role_hash, [])
        confirmed = sorted(account for account, verdict in outcomes if verdict == CANDIDATE_CONFIRMED)
        unconfirmed = sum(1 for _, verdict in outcomes if verdict == CANDIDATE_UNCONFIRMED)
        if not confirmed:
            # The zero-word arm is withheld on a withheld row even where the
            # reads DID complete. Publishing it here would leak the one bit A2
            # forbids: a reader seeing the DEFAULT_ADMIN name beside a NULL
            # holder set would know every read completed, which reconstructs "N
            # probed, all answered, none held" — the banned empty set. The
            # keccak arm is unaffected, because a preimage is a fact about the
            # hash and says nothing about whether any call succeeded.
            withheld_name, withheld_basis = resolve_role_name(role_hash, names, has_role_answered=False)
            rows.append(
                _withheld_row(
                    chain_id=chain_id,
                    registry_address=registry_address,
                    role_hash=role_hash,
                    bounds=bounds,
                    role_name=withheld_name,
                    role_name_basis=withheld_basis,
                )
            )
            continue
        role_name, role_name_basis = resolve_role_name(role_hash, names, has_role_answered=has_role_answered)
        disagreements = [
            {
                "registry": registry_address,
                "role_hash": role_hash,
                "address": account,
                "fold_state": "active" if folded[role_hash][account] else "inactive",
                "chain_state": "true" if verdict == CANDIDATE_CONFIRMED else "false",
            }
            for account, verdict in outcomes
            if verdict != CANDIDATE_UNCONFIRMED and folded[role_hash][account] is not (verdict == CANDIDATE_CONFIRMED)
        ]
        rows.append(
            {
                "chain_id": chain_id,
                "registry_address": registry_address,
                "role_hash": role_hash,
                "holders": confirmed,
                "holders_basis": HOLDERS_BASIS_PINNED_HAS_ROLE,
                "holder_set_exhaustive": HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED,
                "as_of_block": probe_block.number,
                "as_of_block_hash": probe_block.block_hash,
                "cursor_first_indexed_block": bounds["first_indexed_block"],
                "cursor_first_indexed_block_basis": bounds["first_indexed_block_basis"],
                "cursor_last_indexed_block": bounds["last_indexed_block"],
                "cursor_enrollment_bases": dict(bounds["enrollment_bases"]),
                "cursor_page_completeness": bounds["page_completeness"],
                "coverage": ROLE_COVERAGE_LOWER_BOUND,
                "role_name": role_name,
                "role_name_basis": role_name_basis,
                "candidate_count": len(outcomes),
                "unconfirmed_candidate_count": unconfirmed,
                "fold_chain_disagreements": disagreements,
            }
        )
    return rows


def persist_role_holder_planes(session: Session, rows: Sequence[Mapping[str, Any]]) -> int:
    """Upsert resolved rows. Returns the number written."""
    written = 0
    for row in rows:
        existing = session.get(RoleHolderPlane, (row["chain_id"], row["registry_address"], row["role_hash"]))
        if existing is None:
            session.add(RoleHolderPlane(**dict(row)))
        else:
            for key, value in row.items():
                setattr(existing, key, value)
        written += 1
    session.flush()
    return written


def _normalize_word(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:].lower()
    if len(body) > 64:
        return None
    return "0x" + body.rjust(64, "0")


def _word_to_address(raw: Any) -> str | None:
    word = _normalize_word(raw)
    if word is None:
        return None
    return "0x" + word[-40:]
