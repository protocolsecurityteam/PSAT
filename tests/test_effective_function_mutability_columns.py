"""The state-mutability witness is persisted, and it keeps three states.

``effective_functions`` had no view/pure column, so the only way to ask "does
this write state" was ``effect_targets`` — a display field that concatenates
state-write variable names with dotted external-call heads. On the analysis
database 501 of its 1642 populated rows carry only call heads, so a populated
value asserts a state write that was never proven.

The effects stage already computes ``sinks`` / ``state_writes`` /
``state_changing`` / ``writer_selectors`` per function, and did so on 2415/2415
records across the 107 stored production ``effects`` artifacts. These tests pin
that those four now reach the row through the artifact the worker actually hands
the writer, and — the part that matters — that the row can still say "nobody
looked" and "the record contradicts itself".

Every fixture below is copied from a production ``effects`` artifact in the
``psat-artifacts`` bucket; the job id is named on each one.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import case, func, select, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.jsonb import JSONB_UNSET, JSONB_WRITTEN_NULL, jsonb_state  # noqa: E402
from db.models import Contract, EffectiveFunction  # noqa: E402
from services.policy.effective_permissions import (  # noqa: E402
    MUTABILITY_FIELDS,
    _function_records_from_semantic_artifacts,
    _mutability_fields,
    build_effective_permissions,
)
from services.policy.effective_permissions_writer import write_effective_function_rows  # noqa: E402

# ---------------------------------------------------------------------------
# Production shapes.
# ---------------------------------------------------------------------------

# POSITIVE CONTROL — job ee44f242, EtherFiRedemptionManager.
# A role-gated, token-moving admin function whose ``state_writes`` is EMPTY:
# every sink is an external call. The guard-origin sink is the ``roleRegistry``
# check that rejects an unauthorized caller with ``OnlyOperatingMultisig()``.
_SWEEP_DUST: dict[str, Any] = {
    "function": "sweepDust(address,address)",
    "selector": "0xa9fb82d6",
    "abi_signature": "sweepDust(address,address)",
    "effect_labels": ["asset_send"],
    "effect_targets": ["_token.balanceOf", "_token.safeTransfer", "token.functionCall", "target.call"],
    "action_summary": "Sends assets.",
    "state_changing": True,
    "state_writes": [],
    "writer_selectors": [],
    "sinks": [
        {
            "id": "sweepDust(address,address):sink0:external_call:_token.balanceOf",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "_token.balanceOf",
            "selector": "0x70a08231",
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink1:external_call:_token.safeTransfer",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "_token.safeTransfer",
            "selector": "0xd0c407e1",
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink2:external_call:token.functionCall",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "token.functionCall",
            "selector": "0x241b5886",
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink3:external_call:target.call",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "target.call",
            "selector": None,
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink4:external_call:roleRegistry.onlyOperatingMultisig",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "roleRegistry.onlyOperatingMultisig",
            "selector": "0x71645909",
            "origin": "guard",
        },
    ],
}

# NEGATIVE CONTROL — job 06111502, AccountantWithRateProviders.
# A genuine view whose ``effect_targets`` is nonetheless populated with three
# external-call heads: through ``effect_targets`` alone it is indistinguishable
# from ``sweepDust``. It carries NO derived state write, so nothing about it is
# withheld — it must come through as proven-absent, not as not-determined.
_GET_RATE_IN_QUOTE: dict[str, Any] = {
    "function": "getRateInQuote(ERC20)",
    "selector": "0x1ce6e471",
    "abi_signature": "getRateInQuote(ERC20)",
    "effect_labels": ["external_contract_call"],
    "effect_targets": ["quote.decimals", "REF_136.getRate", "oneQuote.mulDivDown"],
    "action_summary": "Calls out.",
    "state_changing": False,
    "state_writes": [],
    "writer_selectors": [],
    "sinks": [
        {
            "id": "getRateInQuote(ERC20):sink0:external_call:quote.decimals",
            "function": "getRateInQuote(ERC20)",
            "kind": "external_call",
            "target": "quote.decimals",
            "selector": "0x313ce567",
            "origin": "body",
        },
        {
            "id": "getRateInQuote(ERC20):sink1:external_call:REF_136.getRate",
            "function": "getRateInQuote(ERC20)",
            "kind": "external_call",
            "target": "REF_136.getRate",
            "selector": "0x679aefce",
            "origin": "body",
        },
    ],
}

# A proven mutator, so the columns are shown to discriminate in all directions.
# Job 06111502, AccountantWithRateProviders.
_UPDATE_EXCHANGE_RATE: dict[str, Any] = {
    "function": "updateExchangeRate(uint96)",
    "selector": "0x3458113d",
    "abi_signature": "updateExchangeRate(uint96)",
    "effect_labels": ["external_contract_call"],
    "effect_targets": ["vault.totalSupply", "accountantState"],
    "action_summary": "Writes state.",
    "state_changing": True,
    "state_writes": [
        {
            "var": "accountantState",
            "declared_type": "AccountantWithRateProviders.AccountantState",
            "member_path": [],
            "granularity": "var",
            "hygiene_class": "normal",
            "origin": "body",
        }
    ],
    "writer_selectors": ["0x3458113d"],
    "sinks": [
        {
            "id": "updateExchangeRate(uint96):sink2:state_write:accountantState",
            "function": "updateExchangeRate(uint96)",
            "kind": "state_write",
            "target": "accountantState",
            "selector": None,
            "origin": "body",
        },
    ],
}

# SENTINEL A — job 16aa62fb, WETH9. ``fallback()`` IS ``deposit()``: it takes
# ETH and writes ``balanceOf``. ``state_changing`` is ``false`` in the artifact
# only because the function has no selector. 36 fallback/receive records exist
# across the 107 artifacts and 15 of them carry a proven state write.
_WETH9_FALLBACK: dict[str, Any] = {
    "function": "fallback()",
    "selector": "0x552079dc",
    "abi_signature": "fallback()",
    "effect_labels": [],
    "effect_targets": ["balanceOf"],
    "action_summary": "Performs a contract action.",
    "state_changing": False,
    "state_writes": [
        {
            "var": "balanceOf",
            "declared_type": "mapping(address => uint256)",
            "member_path": [],
            "granularity": "var",
            "hygiene_class": "normal",
            "origin": "body",
        }
    ],
    "writer_selectors": [],
    "sinks": [
        {
            "id": "fallback():sink0:state_write:balanceOf",
            "function": "fallback()",
            "kind": "state_write",
            "target": "balanceOf",
            "selector": None,
            "origin": "body",
        }
    ],
}

# SENTINEL B — job 06111502, EtherFiRateLimiter. A ``view`` getter over an
# OZ-v5 namespaced storage slot. The compiler forbids SSTORE in a view, so the
# derived "write" of ``PAUSABLE_STORAGE_SLOT`` contradicts ``state_changing``.
# 100 such records exist across the 107 artifacts, and ``assembly_state_access``
# is false on every one of them, so no existing flag catches this.
_PAUSED_VIEW: dict[str, Any] = {
    "function": "paused()",
    "selector": "0x5c975abb",
    "abi_signature": "paused()",
    "effect_labels": [],
    "effect_targets": ["PAUSABLE_STORAGE_SLOT"],
    "action_summary": "Performs a contract action.",
    "state_changing": False,
    "assembly_state_access": False,
    "state_writes": [
        {
            "var": "PAUSABLE_STORAGE_SLOT",
            "declared_type": "bytes32",
            "member_path": [],
            "granularity": "var",
            "hygiene_class": "normal",
            "origin": "body",
        }
    ],
    "writer_selectors": ["0x5c975abb"],
    "sinks": [
        {
            "id": "paused():sink0:state_write:PAUSABLE_STORAGE_SLOT",
            "function": "paused()",
            "kind": "state_write",
            "target": "PAUSABLE_STORAGE_SLOT",
            "selector": None,
            "origin": "body",
        }
    ],
}

_EFFECTS = {
    rec["function"]: rec
    for rec in (_SWEEP_DUST, _GET_RATE_IN_QUOTE, _UPDATE_EXCHANGE_RATE, _WETH9_FALLBACK, _PAUSED_VIEW)
}


def _records(effects_by_function: dict[str, Any], capability_dicts: dict[str, Any] | None = None):
    recs = _function_records_from_semantic_artifacts(
        capability_dicts=capability_dicts or {},
        effects_by_function=effects_by_function,
        predicate_trees_by_function={},
        resolver_output_available=True,
    )
    for rec in recs:
        rec.setdefault("abi_signature", rec["function"])
    return {rec["function"]: rec for rec in recs}


# ---------------------------------------------------------------------------
# The three states, at the record layer.
# ---------------------------------------------------------------------------


def test_proven_present_carries_the_state_write() -> None:
    rec = _records(_EFFECTS)["updateExchangeRate(uint96)"]
    assert rec["state_changing"] is True
    assert rec["state_writes"] == _UPDATE_EXCHANGE_RATE["state_writes"]
    assert rec["writer_selectors"] == ["0x3458113d"]


def test_proven_absent_is_an_empty_list_not_none() -> None:
    """The effects stage looked and found no state write. That is a fact, and it
    must not be served in the same shape as "nobody looked"."""
    rec = _records(_EFFECTS)["getRateInQuote(ERC20)"]
    assert rec["state_writes"] == []
    assert rec["state_writes"] is not None
    assert rec["state_changing"] is False


def test_not_determined_is_none_when_no_effects_record_covers_the_signature() -> None:
    """The production condition: ``policy_worker`` passes ``effects=None``
    whenever the effects artifact is not a dict and the stage then CONTINUES
    (it records a degradation, it does not raise). Every signature then arrives
    from capabilities/trees with no effects record behind it, and those rows
    must say not-determined, not "proven no state write"."""
    recs = _records({}, capability_dicts={"mystery()": {"kind": "policy_check"}})
    rec = recs["mystery()"]
    assert rec["state_changing"] is None
    assert rec["state_writes"] is None
    assert rec["sinks"] is None
    assert rec["writer_selectors"] is None
    # The legacy display field still collapses to []; that collapse is exactly
    # why these four columns exist and it is deliberately left alone here.
    assert rec["effect_targets"] == []


def test_malformed_effects_value_is_not_determined_not_empty() -> None:
    """A present-but-wrong-typed value is not evidence of emptiness.

    Truthiness would read ``"nope"`` as a populated list and ``"yes"`` as True;
    ``or []`` would read a malformed value as a proven-empty one. Both are
    manufactured facts, so the type check falls through to not-determined."""
    assert _mutability_fields(
        {"function": "f()", "state_changing": "yes", "state_writes": "nope", "sinks": 3, "writer_selectors": [7]}
    ) == {
        "state_changing": None,
        "state_writes": None,
        "sinks": None,
        "writer_selectors": None,
    }
    # An empty dict — no effects record at all — is the same answer.
    assert _mutability_fields({}) == {
        "state_changing": None,
        "state_writes": None,
        "sinks": None,
        "writer_selectors": None,
    }


# ---------------------------------------------------------------------------
# The two sentinels, with the production populations they were measured on.
# ---------------------------------------------------------------------------


def test_sentinel_fallback_receive_mutability_is_not_determined_not_false() -> None:
    """WETH9's ``fallback()`` writes ``balanceOf``. Persisting the artifact's
    ``state_changing: false`` verbatim would publish a proven absence directly
    on top of a proven presence.

    ``_is_state_changing_entry_point`` returns False for fallback/receive
    because they carry no selector — a statement about dispatch, not about
    mutability. 36 records in the production artifacts take this branch; 15 of
    them carry a state write."""
    rec = _records(_EFFECTS)["fallback()"]

    assert rec["state_changing"] is None, "a no-selector entry point is not a proven view"
    # The writes themselves are real and are NOT withheld: the sentinel narrows
    # one field, it does not blank the row.
    assert rec["state_writes"] == _WETH9_FALLBACK["state_writes"]
    assert rec["state_writes"][0]["var"] == "balanceOf"
    assert rec["sinks"] == _WETH9_FALLBACK["sinks"]


def test_sentinel_view_contradicted_by_its_own_derived_writes_is_not_determined() -> None:
    """``paused()`` is typed ``view``; the compiler forbids SSTORE there. A
    derived write of ``PAUSABLE_STORAGE_SLOT`` is the lowering of an OZ-v5
    namespaced-slot READ, and publishing it would put a fresh, false
    proven-present claim into a brand-new column.

    100 records in the production artifacts take this branch, and
    ``assembly_state_access`` is false on all 100 — the existing flag does not
    see them. ``sinks`` is withheld with them because it carries the identical
    claim under a ``state_write`` kind tag."""
    rec = _records(_EFFECTS)["paused()"]

    assert rec["state_changing"] is False, "the compiler's view typing is the fact that survives"
    assert rec["state_writes"] is None
    assert rec["sinks"] is None
    assert rec["writer_selectors"] is None


def test_a_view_with_no_derived_write_is_not_swept_up_by_the_contradiction_rule() -> None:
    """The discriminating control for the sentinel above: same
    ``state_changing: False``, no contradiction, so nothing is withheld. A rule
    keyed on view-ness alone instead of on the contradiction would blank this
    row's two external-call sinks and be untestable from the sentinel's own
    fixture."""
    rec = _records(_EFFECTS)["getRateInQuote(ERC20)"]
    assert rec["state_writes"] == []
    assert rec["sinks"] == _GET_RATE_IN_QUOTE["sinks"]
    assert rec["writer_selectors"] == []


# ---------------------------------------------------------------------------
# The controls.
# ---------------------------------------------------------------------------


def test_positive_control_sweep_dust_stays_a_proven_actor_with_zero_state_writes() -> None:
    """``sweepDust`` moves tokens under a role gate and writes NO state.

    A persistence design that recorded only ``state_writes`` would publish it as
    indistinguishable from a pure view, and any consumer that retargets "has a
    sink" onto the state-write list drops it. The kind-tagged ``sinks`` column is
    what keeps it visible, so this test pins the sinks, not just the flag.
    """
    rec = _records(_EFFECTS)["sweepDust(address,address)"]

    assert rec["state_changing"] is True
    assert rec["state_writes"] == []  # proven-absent, and that is correct here
    assert rec["writer_selectors"] == []

    kinds = {(s["kind"], s["origin"]) for s in rec["sinks"]}
    assert ("external_call", "body") in kinds
    # The guard-origin sink is the on-chain gate (OnlyOperatingMultisig) and must
    # survive persistence: it is how a consumer tells a gated actor from an open one.
    assert ("external_call", "guard") in kinds
    # The external-call heads are the sole evidence behind the asset-send label;
    # adding the columns must not destroy them.
    assert "_token.safeTransfer" in {s["target"] for s in rec["sinks"]}
    assert len(rec["sinks"]) == 5


def test_negative_control_view_gains_no_state_write_evidence() -> None:
    """``getRateInQuote`` is a view whose ``effect_targets`` is populated with
    three call heads — through that field alone it is indistinguishable from
    ``sweepDust``. The new columns must separate them and must not invent a
    write."""
    recs = _records(_EFFECTS)
    view = recs["getRateInQuote(ERC20)"]
    actor = recs["sweepDust(address,address)"]

    assert view["state_writes"] == []
    assert view["writer_selectors"] == []
    assert not any(s["kind"] == "state_write" for s in view["sinks"])

    # Both have an equally populated effect_targets and an empty state_writes;
    # ``state_changing`` is the discriminator that did not exist before.
    assert bool(view["effect_targets"]) and bool(actor["effect_targets"])
    assert view["state_writes"] == actor["state_writes"] == []
    assert view["state_changing"] is False and actor["state_changing"] is True


def test_a_state_write_only_filter_would_suppress_the_positive_control() -> None:
    """Pins the trap for whoever retargets ``selection.py``'s "has a sink".

    This is not a hypothetical: ``sweepDust`` is the documented positive control
    and its state-write list is empty. If this test ever fails because
    ``sweepDust`` acquired a state write, the retarget became safe — until then,
    the filter must key on sinks or on ``state_changing``.
    """
    recs = _records(_EFFECTS)

    def has_state_write(rec: dict[str, Any]) -> bool:
        return bool(rec["state_writes"])

    def acts(rec: dict[str, Any]) -> bool:
        return bool([s for s in (rec["sinks"] or []) if s["origin"] == "body"])

    assert not has_state_write(recs["sweepDust(address,address)"])  # the trap
    assert acts(recs["sweepDust(address,address)"])  # the correct predicate keeps it
    assert acts(recs["updateExchangeRate(uint96)"])
    # and it still excludes nothing it should not: the view has body sinks too,
    # so a sink-only filter is not sufficient on its own — state_changing is.
    assert acts(recs["getRateInQuote(ERC20)"])
    assert recs["getRateInQuote(ERC20)"]["state_changing"] is False


# ---------------------------------------------------------------------------
# The artifact hop. ``policy_worker`` hands the writer ``ep_data["functions"]``,
# NOT the record dicts above — a field that stops at the record layer is NULL in
# production while every test on this page passes.
# ---------------------------------------------------------------------------


def _target_analysis() -> dict[str, Any]:
    return {"subject": {"address": "0x" + "9" * 40, "name": "W06Fixture"}}


def test_the_witness_survives_the_effective_permissions_artifact() -> None:
    payload = build_effective_permissions(
        _target_analysis(),
        capability_resolver_output={},
        effects={"functions": _EFFECTS},
    )
    by_sig = {fn["function"]: fn for fn in payload["functions"]}

    # ``.get`` throughout: the keys are NotRequired on the artifact TypedDict
    # because artifacts written before this commit do not carry them, and a
    # subscript would type-error on that honesty.
    assert by_sig["sweepDust(address,address)"].get("state_changing") is True
    assert by_sig["sweepDust(address,address)"].get("state_writes") == []
    assert len(by_sig["sweepDust(address,address)"].get("sinks") or []) == 5
    assert by_sig["updateExchangeRate(uint96)"].get("writer_selectors") == ["0x3458113d"]
    assert by_sig["getRateInQuote(ERC20)"].get("state_changing") is False
    # Both sentinels survive the hop too, still saying not-determined.
    assert by_sig["fallback()"].get("state_changing") is None
    assert by_sig["paused()"].get("state_writes") is None


def test_artifact_with_no_effects_input_publishes_not_determined_everywhere() -> None:
    """``build_effective_permissions(effects=None)`` is what the worker calls
    when the effects artifact is missing. Every function must then be
    not-determined on all four."""
    payload = build_effective_permissions(
        _target_analysis(),
        capability_resolver_output={"mystery()": {"kind": "policy_check"}},
        effects=None,
    )
    fn = payload["functions"][0]
    assert fn["function"] == "mystery()"
    assert [fn.get(key) for key in MUTABILITY_FIELDS] == [None, None, None, None]


# ---------------------------------------------------------------------------
# The DB row. Postgres-only: the point is SQL NULL vs the jsonb scalar null.
# ---------------------------------------------------------------------------


@pytest.fixture
def _contract(db_session):
    contract = Contract(address="0x" + "9" * 40, chain="ethereum", contract_name="W06Fixture")
    db_session.add(contract)
    db_session.flush()
    yield contract
    db_session.query(EffectiveFunction).filter_by(contract_id=contract.id).delete()
    db_session.delete(contract)
    db_session.commit()


def jsonb_state_of(db_session, contract, column: str, signature: str) -> str:
    return db_session.scalar(
        select(jsonb_state(getattr(EffectiveFunction, column))).where(
            EffectiveFunction.contract_id == contract.id,
            EffectiveFunction.abi_signature == signature,
        )
    )


def _write(db_session, contract, records: dict[str, Any]) -> None:
    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=list(records.values()),
        capability_by_function={},
    )
    db_session.commit()


def test_columns_reach_the_row(db_session, _contract) -> None:
    _write(db_session, _contract, _records(_EFFECTS))
    rows = {r.abi_signature: r for r in db_session.query(EffectiveFunction).filter_by(contract_id=_contract.id).all()}

    sweep = rows["sweepDust(address,address)"]
    assert sweep.state_changing is True
    assert sweep.state_writes == []
    assert sweep.writer_selectors == []
    assert {(s["kind"], s["origin"]) for s in sweep.sinks} >= {("external_call", "body"), ("external_call", "guard")}

    view = rows["getRateInQuote(ERC20)"]
    assert view.state_changing is False
    assert view.state_writes == []

    mutator = rows["updateExchangeRate(uint96)"]
    assert mutator.state_changing is True
    assert mutator.state_writes[0]["var"] == "accountantState"
    assert mutator.writer_selectors == ["0x3458113d"]


def test_not_determined_is_sql_null_and_never_the_jsonb_scalar_null(db_session, _contract) -> None:
    """``conditions`` on this same table is the jsonb scalar ``null`` on 780 of
    its 1773 rows, because SQLAlchemy serializes Python ``None`` into a JSONB
    column as JSON ``null`` unless told otherwise. Every ``IS NULL`` audit over
    such a column silently returns zero. The new columns declare
    ``none_as_null=True`` so not-determined is a real SQL NULL; this test is what
    keeps that declaration from being dropped as decoration.
    """
    _write(db_session, _contract, _records({}, capability_dicts={"mystery()": {"kind": "policy_check"}}))

    row = db_session.query(EffectiveFunction).filter_by(contract_id=_contract.id).one()
    assert row.state_changing is None
    assert row.state_writes is None
    assert row.sinks is None
    assert row.writer_selectors is None

    typeofs = db_session.execute(
        text(
            "select jsonb_typeof(state_writes), jsonb_typeof(sinks), "
            "       state_writes is null, sinks is null "
            "from effective_functions where contract_id = :cid"
        ),
        {"cid": _contract.id},
    ).one()
    # jsonb_typeof over a SQL NULL is NULL; over a jsonb scalar null it is 'null'.
    assert typeofs[0] is None, "state_writes was written as the jsonb scalar null"
    assert typeofs[1] is None, "sinks was written as the jsonb scalar null"
    assert typeofs[2] is True and typeofs[3] is True

    # Said once more in ``db/jsonb.py``'s vocabulary: these columns must only ever
    # reach the ``unset`` empty state, never ``written-null``. Two empty states
    # where one is meant is how the 780 ``conditions`` rows happened.
    assert jsonb_state_of(db_session, _contract, "state_writes", "mystery()") == JSONB_UNSET
    assert jsonb_state_of(db_session, _contract, "sinks", "mystery()") == JSONB_UNSET
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(EffectiveFunction)
            .where(
                EffectiveFunction.contract_id == _contract.id,
                jsonb_state(EffectiveFunction.state_writes) == JSONB_WRITTEN_NULL,
            )
        )
        == 0
    )


def test_the_view_contradiction_sentinel_reaches_the_row_as_sql_null(db_session, _contract) -> None:
    """The sentinel has to survive the ORM too: a ``None`` handed to a JSONB
    column without ``none_as_null=True`` lands as the jsonb scalar ``null`` and
    the withheld claim becomes a *written* one."""
    _write(db_session, _contract, _records(_EFFECTS))
    row = db_session.query(EffectiveFunction).filter_by(contract_id=_contract.id, abi_signature="paused()").one()
    assert row.state_changing is False
    assert row.state_writes is None and row.sinks is None and row.writer_selectors is None
    assert jsonb_state_of(db_session, _contract, "state_writes", "paused()") == JSONB_UNSET

    fallback = db_session.query(EffectiveFunction).filter_by(contract_id=_contract.id, abi_signature="fallback()").one()
    assert fallback.state_changing is None
    assert fallback.state_writes[0]["var"] == "balanceOf"


def test_all_three_states_are_distinguishable_in_one_query(db_session, _contract) -> None:
    """Proven-present, proven-absent and not-determined must be separable by
    a consumer. One SQL query, three different answers."""
    records = _records(_EFFECTS)
    records.update(_records({}, capability_dicts={"mystery()": {"kind": "policy_check"}}))
    _write(db_session, _contract, records)

    # Through ``jsonb_state``, not a raw SQL null test: a bare ``IS NULL`` over a
    # JSONB column is forbidden by convention, and rightly — it is only correct here because
    # of ``none_as_null=True``, which is a property of one column declaration and
    # not something a reader of the query can see.
    rows = db_session.execute(
        select(
            EffectiveFunction.abi_signature,
            case(
                (jsonb_state(EffectiveFunction.state_writes) == JSONB_UNSET, "not_determined"),
                (func.jsonb_array_length(EffectiveFunction.state_writes) == 0, "proven_absent"),
                else_="proven_present",
            ),
        ).where(EffectiveFunction.contract_id == _contract.id)
    ).all()
    verdicts = dict(rows)

    assert verdicts["updateExchangeRate(uint96)"] == "proven_present"
    assert verdicts["sweepDust(address,address)"] == "proven_absent"
    assert verdicts["getRateInQuote(ERC20)"] == "proven_absent"
    assert verdicts["mystery()"] == "not_determined"
    assert verdicts["paused()"] == "not_determined"
    assert len(set(verdicts.values())) == 3
