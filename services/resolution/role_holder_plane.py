"""Who a role is proven to include, and why that is only ever a lower bound.

Keyed ``(chain_id, registry_address, role_hash)``. The ``RoleGranted``/``RoleRevoked`` fold proposes candidates; a
pinned ``hasRole(bytes32,address)`` read witnesses each. Only the read admits a holder, so a broken fold yields a
smaller lower bound, never a wrong one; completeness is published as ``holder_set_exhaustive``.

Candidates include revoked addresses too, since the read decides. ``holders`` proves the address's own ``hasRole``
returned true at ``as_of_block``, the same virtual function ``_checkRole`` dispatches to. Unlike the excised
``external_set`` arm, the event topic and the predicate are two independent surfaces from the same contract.

Rows use the OZ AccessControl topic pair literally, not ``role_store_standards``: Solady's ``RoleSet`` uses a
``uint256`` role in a different space, and probing it through ``bytes32`` would read the zero default and return a
successful false. Solady logs mint no row; absence means not_determined.
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
from services.clients.rpc import (
    EthCallResult,
    decode_bool_word,
    encode_address_word,
    eth_call_batch,
    rpc_request,
    selector,
)
from services.resolution.absence_coverage import absence_coverage
from services.resolution.repos.event_logs_rpc import default_result_cap
from utils.chains import DEFAULT_CONFIRMATION_DEPTH
from utils.logging import record_degraded
from utils.scoring_status import NOT_DETERMINED

logger = logging.getLogger(__name__)

# Written out rather than taken from ``role_store_standards.spec_by_topic0()``, which also carries Solady's ``RoleSet``
# (see module docstring).
ROLE_GRANTED_TOPIC0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
ROLE_REVOKED_TOPIC0 = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"
ACCESS_CONTROL_TOPIC0S = (ROLE_GRANTED_TOPIC0, ROLE_REVOKED_TOPIC0)

_ROLE_TOPIC_INDEX = 1
_ACCOUNT_TOPIC_INDEX = 2

HAS_ROLE_SELECTOR = selector("hasRole(bytes32,address)")

# ``DEFAULT_ADMIN_ROLE`` is the zero word, not ``keccak("DEFAULT_ADMIN_ROLE")``, so it needs its own weaker naming
# basis.
DEFAULT_ADMIN_ROLE_HASH = "0x" + "00" * 32
DEFAULT_ADMIN_ROLE_NAME = "DEFAULT_ADMIN_ROLE"

_HEX_DIGITS = frozenset("0123456789abcdef")
# Exactly 32 bytes; ``bytes.fromhex("")`` is ``b""``, indistinguishable from a missing hash.
_BLOCK_HASH_BYTES = 32

# A completed false read and a read that never happened must never collapse.
CANDIDATE_CONFIRMED = "confirmed"
CANDIDATE_READ_COMPLETED_NOT_CONFIRMED = "read_completed_not_confirmed"
CANDIDATE_UNCONFIRMED = "unconfirmed"

# No cause key belongs here: ``as_of_block`` is above the cursor head, so a missed log and a later state change are
# indistinguishable. A cursor bounds what was read, not what was emitted.
DISAGREEMENT_KEYS = frozenset({"registry", "role_hash", "address", "fold_state", "chain_state"})


@dataclass(frozen=True)
class ProbeBlock:
    """A confirmation-depth-deep height and its hash, so the citation stays checkable after a reorg."""

    number: int
    block_hash: bytes | None


def classify_candidate(result: EthCallResult) -> str:
    """One ``hasRole`` outcome in three states.

    ``decode_bool_word`` returns False for reverts, empty and short returns alike, so ``success`` must be checked first
    or failed reads become proven non-holders. ``success`` isn't sufficient either: ``eth_call_batch`` reports
    unreadable results as ``EthCallResult(True, "0x", …)``. Exactly one 32-byte word is required.
    """
    if not result.success:
        return CANDIDATE_UNCONFIRMED
    word = _normalize_word(result.return_data)
    if word is None:
        return CANDIDATE_UNCONFIRMED
    return CANDIDATE_CONFIRMED if decode_bool_word(word) else CANDIDATE_READ_COMPLETED_NOT_CONFIRMED


def fold_role_candidates(rows: Iterable[Any]) -> dict[str, dict[str, bool]]:
    """``role_hash -> {account: fold_believes_active}`` in log order, last-write-wins.

    Non-AccessControl topics (e.g. Solady ``RoleSet``) are dropped. Revoked accounts stay as candidates.
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


def _role_topic(row: Any) -> str | None:
    topics = list(getattr(row, "topics", None) or [])
    if len(topics) <= _ROLE_TOPIC_INDEX:
        return None
    return _normalize_word(topics[_ROLE_TOPIC_INDEX])


def resolve_role_name(
    role_hash: str, candidate_names: Iterable[str], *, has_role_answered: bool
) -> tuple[str | None, str]:
    """``(role_name, role_name_basis)``: a proven preimage, or absent.

    ``keccak_preimage`` proves ``keccak(S) == role_hash`` (so candidates can come from anywhere), not that this registry
    declares S. The zero-word arm is only a convention with a weaker basis, and additionally requires that this registry
    answered ``hasRole``.
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
    """Distinct declared role names as candidates only.

    Everything passes the keccak check, so mis-parsed rows can't leak. Deliberately not scoped by chain or contract.
    """
    return sorted({name for (name,) in session.execute(select(RoleDefinition.role_name).distinct()) if name})


def pin_probe_block(rpc_url: str, *, chain_id: int) -> ProbeBlock | None:
    """A height at least ``DEFAULT_CONFIRMATION_DEPTH`` below head, plus its hash.

    None on failure; the probe is then skipped, never retried at ``"latest"``.
    """
    try:
        head = int(str(rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)), 16)
    except Exception as exc:
        record_degraded(phase="pin_probe_block_head", exc=exc, context={"chain_id": chain_id})
        logger.warning("could not pin a probe block; role holder plane withheld", exc_info=True)
        return None
    number = head - DEFAULT_CONFIRMATION_DEPTH
    if number <= 0:
        return None
    try:
        block = rpc_request(rpc_url, "eth_getBlockByNumber", [hex(number), False], chain_id=chain_id)
        raw = block.get("hash") if isinstance(block, Mapping) else None
        block_hash = _decode_block_hash(raw)
    except Exception as exc:
        # The height stands; only replay after a reorg is weaker.
        record_degraded(
            phase="pin_probe_block_hash",
            exc=exc,
            context={"chain_id": chain_id, "block_number": number},
        )
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
    """Classify ``hasRole(role_hash, account)`` for each probe at a pinned block.

    One JSON-RPC batch at one height; not Multicall3, which would blur reverts and falses.
    """
    if not probes:
        return []
    verdicts: list[str] = [CANDIDATE_UNCONFIRMED] * len(probes)
    calls: list[dict[str, str]] = []
    slots: list[int] = []
    for index, (role_hash, account) in enumerate(probes):
        word = _normalize_word(role_hash)
        if word is None:
            # Never substitute the zero role for an unparseable one; that would attribute DEFAULT_ADMIN's holders to it.
            continue
        calls.append({"to": registry_address, "data": HAS_ROLE_SELECTOR + word[2:] + encode_address_word(account)})
        slots.append(index)
    results = eth_call_batch(rpc_url, calls, hex(block_number), chain_id=chain_id)
    for slot, result in zip(slots, results):
        verdicts[slot] = classify_candidate(result)
    return verdicts


def _cursor_bounds(session: Session, *, chain_id: int, registry_address: str) -> dict[str, Any]:
    """Both AccessControl cursors' state and whether both are warm (``backfill_complete``).

    Exactness eligibility isn't required since this plane never claims an exact empty; the basis is recorded, not
    depended on.
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
        # Not a witness; drop the number with the basis.
        lower_bound = None
        lower_basis = NOT_DETERMINED
    last_blocks = [int(row.last_indexed_block) for row in rows if row.last_indexed_block is not None]
    return {
        "both_warm": both_warm,
        # The pair covers only as far as the shorter cursor.
        "last_indexed_block": min(last_blocks) if len(last_blocks) == len(ACCESS_CONTROL_TOPIC0S) else None,
        "first_indexed_block": lower_bound,
        "first_indexed_block_basis": lower_basis,
        "enrollment_bases": {topic: by_topic[topic].enrollment_basis for topic in sorted(by_topic)},
        "page_completeness": coverage_report["page_completeness"],
        # Hard-wired False upstream; read only to keep the refusal explicit.
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

    All counters and the disagreement log are NULL. Cold surfaces, all-reverting registries and all-false registries
    look identical on purpose; distinguishing them would reconstruct the banned empty set. The log is NULL rather than
    ``[]`` because "no disagreement" would be unproven too.
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
    """Every role hash this registry has emitted, resolved to a lower bound.

    A registry with no AccessControl logs yields no rows, meaning not_determined, not "no roles".
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
    undecodable_rows = [row for row in repo_rows if getattr(row, "data_hex", None) is not None]
    undecodable = len(undecodable_rows)
    folded = fold_role_candidates(row for row in repo_rows if getattr(row, "data_hex", None) is None)
    # An undecodable row's role topic still names a role this registry emitted; its account is not taken as a candidate.
    undecodable_roles = {
        role_hash
        for role_hash in (_role_topic(row) for row in undecodable_rows)
        if role_hash is not None and role_hash not in folded
    }
    if not folded and not undecodable_roles:
        return []

    bounds = _cursor_bounds(session, chain_id=chain_id, registry_address=registry_address)
    names = list(candidate_names) if candidate_names is not None else candidate_name_pool(session)

    def withhold_all() -> list[dict[str, Any]]:
        """No read happened, so the zero-word convention has nothing to stand on."""
        out = []
        for role_hash in sorted(set(folded) | undecodable_roles):
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

    # Either cursor cold withholds every lower bound: the candidate set is knowingly incomplete. So does a row no ABI
    # decodes, which may be a grant or revoke the fold can't read.
    if not bounds["both_warm"]:
        return withhold_all()
    if undecodable:
        logger.warning(
            "role registry has undecodable AccessControl rows; every holder set withheld",
            extra={"chain_id": chain_id, "registry_address": registry_address, "undecodable_rows": undecodable},
        )
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

    # Any completed call proves this registry answers ``hasRole``.
    has_role_answered = any(v != CANDIDATE_UNCONFIRMED for v in verdicts)

    rows: list[dict[str, Any]] = []
    for role_hash in sorted(folded):
        outcomes = by_role.get(role_hash, [])
        confirmed = sorted(account for account, verdict in outcomes if verdict == CANDIDATE_CONFIRMED)
        unconfirmed = sum(1 for _, verdict in outcomes if verdict == CANDIDATE_UNCONFIRMED)
        if not confirmed:
            # Withheld even when reads completed: the DEFAULT_ADMIN name beside a NULL holder set would reveal that
            # every read completed with no holders. The keccak arm is unaffected.
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
    """A full 32-byte word, lowercased, or ``None``.

    No lenient path: padding ``"0x"`` produced the zero role hash and minted DEFAULT_ADMIN holders from an unobserved
    word.
    """
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) != 64:
        return None
    lowered = body.lower()
    # ``bytes.fromhex`` and ``int(..., 16)`` tolerate whitespace, so check the alphabet explicitly.
    if any(char not in _HEX_DIGITS for char in lowered):
        return None
    return "0x" + lowered


def _word_to_address(raw: Any) -> str | None:
    word = _normalize_word(raw)
    if word is None:
        return None
    return "0x" + word[-40:]


def _decode_block_hash(raw: Any) -> bytes | None:
    """The pinned block's hash as 32 bytes, or ``None``; a short or empty value is no citation."""
    word = _normalize_word(raw)
    if word is None:
        return None
    digest = bytes.fromhex(word[2:])
    return digest if len(digest) == _BLOCK_HASH_BYTES else None
