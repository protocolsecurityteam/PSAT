"""Solmate ``RolesAuthority`` adapter.

Resolves ``authority.canCall(user, target, sig)`` — the Solmate ``Auth``
``requiresAuth`` authorization path — by reconstructing the
``RolesAuthority`` capability/user state from the authority's indexed
events:

    RoleCapabilityUpdated(uint8 indexed role, address indexed target, bytes4 indexed sig, bool enabled)
    PublicCapabilityUpdated(address indexed target, bytes4 indexed sig, bool enabled)
    UserRoleUpdated(address indexed user, uint8 indexed role, bool enabled)

``canCall(user, target, sig)`` is true iff the ``(target, sig)``
capability is public, or some role enabled for ``(target, sig)`` is held
by ``user``. The generic ``EventIndexedAdapter`` folds a single event into
a present-set keyed by one member; it cannot express this two-event join
(capability ⋈ user-role), so this is a *named* adapter. It reads the same
``IndexedEventLog`` backend the indexer populates from the descriptor's
``enumeration_hint`` — no separate fetch path.
"""

from __future__ import annotations

import logging
from typing import Any, TypeGuard

from eth_utils.crypto import keccak

from ..capabilities import CapabilityExpr, Condition, Confidence, ExternalCheck, MembershipQuality
from . import EvaluationContext

logger = logging.getLogger(__name__)


def _t0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


ROLE_CAPABILITY_UPDATED = _t0("RoleCapabilityUpdated(uint8,address,bytes4,bool)")
PUBLIC_CAPABILITY_UPDATED = _t0("PublicCapabilityUpdated(address,bytes4,bool)")
USER_ROLE_UPDATED = _t0("UserRoleUpdated(address,uint8,bool)")
_ROLE_TOPICS = [ROLE_CAPABILITY_UPDATED, PUBLIC_CAPABILITY_UPDATED, USER_ROLE_UPDATED]

CANCALL_SIGNATURE = "canCall(address,address,bytes4)"
CANCALL_SELECTOR = "0x" + keccak(text=CANCALL_SIGNATURE).hex()[:8]


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


# ``canCall(address,address,bytes4)`` is NOT unique to Solmate — OZ AccessManager
# exposes the same selector (0xb7009613). Disambiguate from the authority's
# bytecode: a Solmate RolesAuthority declares these getters; an OZ AccessManager
# declares ``getTargetFunctionRole``. ``matches()`` confirms RolesAuthority before
# claiming the descriptor at full confidence, and declines a recognized different
# canCall standard so its own adapter can win the tie.
_ROLES_AUTHORITY_MARKER_SELECTORS = (
    _sel("getRolesWithCapability(address,bytes4)"),
    _sel("doesUserHaveRole(address,uint8)"),
)
_OTHER_CANCALL_STANDARD_SELECTORS = (_sel("getTargetFunctionRole(address,bytes4)"),)  # OZ AccessManager
_CONFIRMED_SCORE = 90
# Claimed when confirmation isn't possible (no bytecode repo / unresolved
# authority): Solmate is still the only wired canCall standard, but a *confirmed*
# adapter (score 90) outranks this, so a second canCall standard drops in cleanly
# instead of being starved by a registration-order tie.
_PROVISIONAL_SCORE = 40


class SolmateRolesAuthorityAdapter:
    """Resolves a Solmate ``canCall`` external-bool check into the concrete
    caller set authorized for the function under analysis."""

    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        signature = descriptor.get("callee_signature")
        selector = descriptor.get("callee_selector")
        is_cancall = (isinstance(signature, str) and signature.replace(" ", "") == CANCALL_SIGNATURE) or (
            isinstance(selector, str) and selector.lower() == CANCALL_SELECTOR
        )
        if not is_cancall:
            return 0
        # canCall's selector is shared with OZ AccessManager, so the signature
        # alone can't claim this is Solmate. Confirm from the authority's bytecode:
        # full confidence only for a real RolesAuthority; decline a recognized
        # different canCall standard (so its adapter wins); claim provisionally
        # when we can't probe.
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
        except Exception as exc:
            logger.error(
                "Solmate RolesAuthority event-log backend failed chain_id=%s authority=%s: %s",
                ctx.chain_id,
                authority,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            raise RuntimeError(
                f"Solmate RolesAuthority event-log backend failed chain_id={ctx.chain_id} authority={authority}"
            ) from exc

        roles_for_target_sig: set[int] = set()
        public = False
        users_by_role: dict[int, set[str]] = {}
        # Rows MUST be in log order (block, tx_index, log_index) so enable/disable
        # toggles fold to the final state.
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
            # Capability is open to everyone — anyone may call.
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
            # The authority's role events aren't durably indexed to head yet (no
            # backfill_complete cursor). Any fold now is at best a lower bound — more grants
            # may sit in the un-indexed tail — and a bare finite_set here carries nothing the
            # reconciler can converge on: a partial set would freeze a never-self-healing
            # answer, an empty one would assert a false "nobody can call". Defer
            # unconditionally; ``no_index_cursor`` is marked ``deferred_pending_index`` so
            # ``deferred_reconciler`` re-resolves this to the exact set once backfill
            # completes (rather than emitting a sticky ``lower_bound`` the self-heal misses).
            return _check_only(authority, descriptor, ["no_index_cursor"])
        if not rows:
            # Indexed, but the authority emitted NONE of the three RolesAuthority
            # role events. We can't confirm it actually is a Solmate
            # RolesAuthority whose canCall semantics this adapter faithfully
            # models — it may be a custom Authority with entirely different logic
            # — so asserting an exact-empty set would be a false "nobody". Fail
            # closed to a probe; this adapter is correct-by-construction only for
            # confirmed RolesAuthorities.
            return _check_only(authority, descriptor, ["authority_unconfirmed_no_role_events"])
        return CapabilityExpr.finite_set(
            sorted(members),
            quality=MembershipQuality.EXACT,
            confidence=Confidence.ENUMERABLE,
            last_indexed_block=last_block,
            trace=trace,
        )


def _check_only(authority: str | None, descriptor: dict, basis: list[str]) -> CapabilityExpr:
    extra: dict[str, Any] = {"basis": basis, "adapter": "solmate_roles_authority"}
    # Tag index-cold deferrals so the deferred-resolution reconciler re-resolves
    # this function once the authority's role events finish indexing.
    # ``no_index_cursor`` is the only basis here that is *waiting on the durable
    # index*; the others are settled answers (``*_unresolved`` = missing context,
    # ``authority_unconfirmed_no_role_events`` = a warm authority that emitted no
    # role events), so they are deliberately NOT marked — marking them would make
    # the reconciler re-resolve forever.
    if "no_index_cursor" in basis:
        extra["deferred_pending_index"] = True
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
        return bool(fn(chain_id=ctx.chain_id, contract_address=address, selector=selector))
    except Exception as exc:
        logger.error(
            "Solmate RolesAuthority bytecode selector check failed chain_id=%s address=%s selector=%s: %s",
            ctx.chain_id,
            address,
            selector,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        raise RuntimeError(
            f"Solmate RolesAuthority bytecode selector check failed chain_id={ctx.chain_id} address={address}"
        ) from exc


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
    """The selector of the function being authorized — Solmate's ``requiresAuth``
    passes ``msg.sig``, so it's the function under analysis, carried on the
    CallFrame. Falls back to a single-entry ``selector_context``."""
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
    except Exception as exc:
        logger.error(
            "Solmate RolesAuthority min indexed block lookup failed chain_id=%s address=%s: %s",
            chain_id,
            event_address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        raise RuntimeError(
            f"Solmate RolesAuthority min indexed block lookup failed chain_id={chain_id} address={event_address}"
        ) from exc
    return value if isinstance(value, int) else None


def _is_address(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 42


_ZERO_ADDRESS = "0x" + "0" * 40


def _is_nonzero_address(value: Any) -> TypeGuard[str]:
    # A renounced/unset authority is the zero address. Treat it as "no authority"
    # so the function settles to ``authority_unresolved`` (a non-deferred external
    # check) instead of stranding a ``no_index_cursor`` deferral that waits forever
    # on a 0x0 event cursor the indexer will never seed.
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
