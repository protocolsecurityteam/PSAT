"""Solmate ``RolesAuthority`` adapter.

Resolves ``authority.canCall(user, target, sig)`` from the authority's indexed events:

    RoleCapabilityUpdated(uint8 indexed role, address indexed target, bytes4 indexed sig, bool enabled)
    PublicCapabilityUpdated(address indexed target, bytes4 indexed sig, bool enabled)
    UserRoleUpdated(address indexed user, uint8 indexed role, bool enabled)

``canCall`` is true iff the capability is public or some enabled role for it is held by ``user``. That two-event join is
beyond ``EventIndexedAdapter``, hence a named adapter over the same ``IndexedEventLog`` backend.
"""

from __future__ import annotations

import logging
from typing import Any, TypeGuard

from eth_utils.crypto import keccak

from utils.evm import CANCALL_SIGNATURE

from ..capabilities import CapabilityExpr, Condition, ExternalCheck
from . import EvaluationContext

logger = logging.getLogger(__name__)


def _t0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


ROLE_CAPABILITY_UPDATED = _t0("RoleCapabilityUpdated(uint8,address,bytes4,bool)")
PUBLIC_CAPABILITY_UPDATED = _t0("PublicCapabilityUpdated(address,bytes4,bool)")
USER_ROLE_UPDATED = _t0("UserRoleUpdated(address,uint8,bool)")
_ROLE_TOPICS = [ROLE_CAPABILITY_UPDATED, PUBLIC_CAPABILITY_UPDATED, USER_ROLE_UPDATED]

CANCALL_SELECTOR = "0x" + keccak(text=CANCALL_SIGNATURE).hex()[:8]


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


# OZ AccessManager shares canCall's selector (0xb7009613), so confirm from bytecode: RolesAuthority declares these
# getters, AccessManager declares ``getTargetFunctionRole``.
_ROLES_AUTHORITY_MARKER_SELECTORS = (
    _sel("getRolesWithCapability(address,bytes4)"),
    _sel("doesUserHaveRole(address,uint8)"),
)
_OTHER_CANCALL_STANDARD_SELECTORS = (_sel("getTargetFunctionRole(address,bytes4)"),)  # OZ AccessManager
_CONFIRMED_SCORE = 90
# Used when confirmation isn't possible; a confirmed adapter (90) outranks it, so another canCall standard isn't starved
# by registration order.
_PROVISIONAL_SCORE = 40


class SolmateRolesAuthorityAdapter:
    """Resolves a Solmate ``canCall`` check into the concrete caller set for the function under analysis."""

    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        signature = descriptor.get("callee_signature")
        selector = descriptor.get("callee_selector")
        is_cancall = (isinstance(signature, str) and signature.replace(" ", "") == CANCALL_SIGNATURE) or (
            isinstance(selector, str) and selector.lower() == CANCALL_SELECTOR
        )
        if not is_cancall:
            return 0
        # Full confidence only for a confirmed RolesAuthority; decline other canCall standards; claim provisionally when
        # we can't probe.
        authority = _resolve_authority_address(descriptor, ctx)
        repo = getattr(ctx, "bytecode", None)
        if authority is None or repo is None:
            return _PROVISIONAL_SCORE
        if any(_safe_has_selector(repo, ctx, authority, s) for s in _ROLES_AUTHORITY_MARKER_SELECTORS):
            return _CONFIRMED_SCORE
        if any(_safe_has_selector(repo, ctx, authority, s) for s in _OTHER_CANCALL_STANDARD_SELECTORS):
            return 0
        return _PROVISIONAL_SCORE

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        authority = _resolve_authority_address(descriptor, ctx)
        target = (ctx.contract_address or "").lower() or None
        selector = _resolve_target_selector(descriptor, ctx)
        repo = ctx.event_log_repo or (ctx.meta.get("event_log_repo") if ctx.meta else None)
        iter_rows = getattr(repo, "iter_event_rows", None) if repo is not None else None

        basis: list[str] = []
        if authority is None:
            basis.append("authority_unresolved")
        if target is None:
            basis.append("target_unresolved")
        if selector is None:
            basis.append("selector_unresolved")
        if iter_rows is None:
            basis.append("no_event_log_repo")
        if authority is None or target is None or selector is None or iter_rows is None:
            return _check_only(authority, descriptor, basis)

        try:
            rows = iter_rows(chain_id=ctx.chain_id, event_address=authority, topic0s=_ROLE_TOPICS, block=ctx.block)
        except Exception:
            return _check_only(authority, descriptor, ["event_log_backend_error"])

        roles_for_target_sig: set[int] = set()
        public = False
        users_by_role: dict[int, set[str]] = {}
        # Rows must be in log order so toggles fold to the final state.
        for row in rows:
            topics = list(getattr(row, "topics", None) or [])
            data_words = list(getattr(row, "data_words", None) or [])
            if not topics:
                continue
            topic0 = str(topics[0]).lower()
            enabled = _word_bool(data_words[0]) if data_words else False
            if topic0 == ROLE_CAPABILITY_UPDATED and len(topics) >= 4:
                if _word_addr(topics[2]) == target and _word_selector(topics[3]) == selector:
                    role = _word_int(topics[1])
                    roles_for_target_sig.add(role) if enabled else roles_for_target_sig.discard(role)
            elif topic0 == PUBLIC_CAPABILITY_UPDATED and len(topics) >= 3:
                if _word_addr(topics[1]) == target and _word_selector(topics[2]) == selector:
                    public = enabled
            elif topic0 == USER_ROLE_UPDATED and len(topics) >= 3:
                user = _word_addr(topics[1])
                if user is not None:
                    bucket = users_by_role.setdefault(_word_int(topics[2]), set())
                    bucket.add(user) if enabled else bucket.discard(user)

        if public:
            logger.debug(
                "solmate_roles decision",
                extra={
                    "adapter": "solmate_roles_authority",
                    "address": authority,
                    "decision": "public",
                    "reason": "public_capability",
                },
            )
            return CapabilityExpr.conditional_universal(
                Condition(kind="business", description="public RolesAuthority capability")
            )

        members: set[str] = set()
        for role in roles_for_target_sig:
            members |= users_by_role.get(role, set())

        last_block = _min_indexed_block(repo, ctx.chain_id, authority)
        trace = [
            {
                "step": "solmate_roles_authority",
                "authority": authority,
                "target": target,
                "selector": selector,
                "roles": sorted(roles_for_target_sig),
            }
        ]
        if last_block is None:
            # Not indexed to head: a partial set would freeze and an empty one would falsely say "nobody". Always defer;
            # ``no_index_cursor`` is marked for the reconciler.
            return _check_only(authority, descriptor, ["no_index_cursor"])
        if not rows:
            # Indexed but no role events: can't confirm this is a RolesAuthority, so fail closed to a probe.
            return _check_only(authority, descriptor, ["authority_unconfirmed_no_role_events"])
        logger.debug(
            "solmate_roles decision",
            extra={
                "adapter": "solmate_roles_authority",
                "address": authority,
                "decision": "finite_set",
                "reason": "canCall_enumerated",
                "members": len(members),
                "roles": sorted(roles_for_target_sig),
            },
        )
        return CapabilityExpr.finite_set(
            sorted(members),
            quality="exact",
            confidence="enumerable",
            last_indexed_block=last_block,
            trace=trace,
        )


def _check_only(authority: str | None, descriptor: dict, basis: list[str]) -> CapabilityExpr:
    extra: dict[str, Any] = {"basis": basis, "adapter": "solmate_roles_authority"}
    # Only ``no_index_cursor`` waits on the index; marking the settled bases would make the reconciler loop forever.
    if "no_index_cursor" in basis:
        extra["deferred_pending_index"] = True
    logger.debug(
        "solmate_roles decision",
        extra={
            "adapter": "solmate_roles_authority",
            "address": authority,
            "decision": "deferred" if "no_index_cursor" in basis else "external_check",
            "reason": ",".join(basis),
        },
    )
    return CapabilityExpr.external_check_only(
        ExternalCheck(
            target_address=authority,
            target_call_selector=descriptor.get("callee_selector") or CANCALL_SELECTOR,
            extra=extra,
        )
    )


def _safe_has_selector(repo: Any, ctx: EvaluationContext, address: str, selector: str) -> bool:
    fn = getattr(repo, "has_selector", None)
    if not callable(fn):
        return False
    try:
        return bool(fn(chain_id=getattr(ctx, "chain_id", 1), contract_address=address, selector=selector))
    except Exception:
        return False


def _resolve_authority_address(descriptor: dict, ctx: EvaluationContext) -> str | None:
    authority = descriptor.get("authority_contract") or {}
    raw = authority.get("address")
    if _is_nonzero_address(raw):
        return raw.lower()
    source = authority.get("address_source") or {}
    if source.get("source") == "state_variable":
        name = source.get("state_variable_name")
        value = (ctx.state_var_values or {}).get(name) if isinstance(name, str) else None
        if _is_nonzero_address(value):
            return value.lower()
    return None


def _resolve_target_selector(descriptor: dict, ctx: EvaluationContext) -> str | None:
    """The selector being authorized: ``requiresAuth`` passes ``msg.sig``, carried on the CallFrame, else a
    single-entry ``selector_context``.
    """
    frame = ctx.call_frame
    if frame is not None:
        for value in (getattr(frame, "current_function_selector", None), getattr(frame, "current_msg_sig", None)):
            if _is_selector(value):
                return value.lower()
    selector_context = descriptor.get("selector_context") or {}
    selectors = selector_context.get("selectors") or []
    if len(selectors) == 1 and _is_selector(selectors[0]):
        return selectors[0].lower()
    return None


def _min_indexed_block(repo: Any, chain_id: int, event_address: str) -> int | None:
    getter = getattr(repo, "min_indexed_block", None)
    if not callable(getter):
        return None
    try:
        value = getter(chain_id=chain_id, event_address=event_address, topic0s=_ROLE_TOPICS)
    except Exception:
        return None
    return value if isinstance(value, int) else None


def _is_address(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 42


_ZERO_ADDRESS = "0x" + "0" * 40


def _is_nonzero_address(value: Any) -> TypeGuard[str]:
    # A zero authority settles to ``authority_unresolved`` rather than a deferral on a cursor that will never exist.
    return _is_address(value) and value.lower() != _ZERO_ADDRESS


def _is_selector(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 10


def _word_addr(word: Any) -> str | None:
    if not isinstance(word, str) or len(word) < 40:
        return None
    return "0x" + word[-40:].lower()


def _word_selector(word: Any) -> str | None:
    if not isinstance(word, str) or not word.startswith("0x") or len(word) < 10:
        return None
    return word[:10].lower()


def _word_int(word: Any) -> int:
    try:
        return int(word, 16)
    except (TypeError, ValueError):
        return -1


def _word_bool(word: Any) -> bool:
    try:
        return int(word, 16) != 0
    except (TypeError, ValueError):
        return False
