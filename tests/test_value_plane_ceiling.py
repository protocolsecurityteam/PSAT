"""The sheet ceiling resolver: what a node's own balance sheet bounds.

``planes.ceiling_for`` answers the value-side half of the code-control ceiling
rule — is this node's sheet determined, is its asset list whole, and is its key
one two proxies share — and the corpus cannot exercise it. Protocol 1 carries no
proven-empty sheet and no ambiguous alias, so two of the seven reasons have zero
carriers there and the unregistered-sheet-state guard has none anywhere. Every
reason is therefore pinned here over hand-built planes instead.

The one that matters most is ``proven_empty``. A sheet whose every quantity is
witnessed zero is an EARNED NEGATIVE — the ceiling is provably $0 — and both of
the obvious admission tests get it wrong in opposite directions: ``total() is
not None`` admits it without recording that the $0 was proven, and
``sheet_state() == SHEET_PRICED`` refuses it and publishes not_determined where
a proven zero exists. The resolver has to admit it under its own token, and the
tests below fail if either shortcut is ever substituted.
"""

from __future__ import annotations

import pytest

from services.scoring import planes as P

KEY = "ethereum::0x" + "a" * 40
OTHER = "ethereum::0x" + "b" * 40


def _plane(
    *,
    per_asset: dict[str, dict[str, float]] | None = None,
    per_asset_state: dict[str, dict[str, str]] | None = None,
    alias: dict[str, str] | None = None,
    alias_ambiguous: set[str] | None = None,
    asset_set_truncated: set[str] | None = None,
) -> P.ValuePlane:
    plane = P.ValuePlane()
    plane.per_asset = per_asset or {}
    plane.per_asset_state = per_asset_state or {}
    plane.alias = alias or {}
    plane.alias_ambiguous = alias_ambiguous or set()
    plane.asset_set_truncated = asset_set_truncated or set()
    plane.contract_entities = set(plane.per_asset) | set(plane.per_asset_state)
    return plane


def _priced() -> P.ValuePlane:
    return _plane(
        per_asset={KEY: {"weth": 3_000_000.0, "usdc": 1.5}},
        per_asset_state={KEY: {"weth": P.ASSET_PRICED, "usdc": P.ASSET_PRICED}},
    )


def _proven_empty() -> P.ValuePlane:
    return _plane(per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}})


def _below_resolution() -> P.ValuePlane:
    return _plane(per_asset_state={KEY: {"weth": P.ASSET_BELOW_RESOLUTION}})


def _unpriced() -> P.ValuePlane:
    return _plane(per_asset_state={KEY: {"weth": P.ASSET_UNPRICED}})


def _no_rows() -> P.ValuePlane:
    return _plane()


def _ambiguous() -> P.ValuePlane:
    """An implementation two proxies share, holding a priced balance of its own.

    Priced on purpose: the ambiguity must refuse a sheet that would otherwise
    have admitted, or the conjunct is only ever exercised where it changes
    nothing.
    """
    return _plane(
        per_asset={KEY: {"weth": 3_000_000.0}},
        per_asset_state={KEY: {"weth": P.ASSET_PRICED}},
        alias_ambiguous={KEY},
    )


def _truncated() -> P.ValuePlane:
    """A PRICED sheet whose asset list was read at the endpoint's page cap.

    Priced on purpose, for the reason ``_ambiguous`` is: the truncation must
    refuse a sheet that would otherwise have admitted, or the conjunct is only
    ever exercised where it changes nothing.
    """
    return _plane(
        per_asset={KEY: {"weth": 3_000_000.0}},
        per_asset_state={KEY: {"weth": P.ASSET_PRICED}},
        asset_set_truncated={KEY},
    )


ALL_SHAPES = {
    "priced": (_priced, 3_000_001.5, P.CEILING_ADMITTED),
    "proven_empty": (_proven_empty, 0.0, P.CEILING_PROVEN_EMPTY),
    "below_resolution": (_below_resolution, None, P.CEILING_BELOW_RESOLUTION),
    "unpriced": (_unpriced, None, P.CEILING_UNPRICED),
    "asset_list_truncated": (_truncated, None, P.CEILING_ASSET_LIST_TRUNCATED),
    "no_rows": (_no_rows, None, P.CEILING_NO_ROWS),
    "alias_ambiguous": (_ambiguous, None, P.CEILING_ALIAS_AMBIGUOUS),
}


@pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
def test_every_sheet_shape_answers_under_its_own_reason(shape: str):
    build, expected_usd, expected_reason = ALL_SHAPES[shape]
    usd, reason = P.ceiling_for(build(), KEY)
    assert (usd, reason) == (expected_usd, expected_reason)


def test_the_seven_shapes_cover_the_whole_vocabulary():
    """No reason may ship without a case: an unexercised token is a claim."""
    assert {reason for _, _, reason in ALL_SHAPES.values()} == set(P.CEILING_REASONS)


@pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
def test_a_number_is_returned_on_exactly_the_admitting_reasons(shape: str):
    """``usd is not None`` and the reason token must never disagree.

    The caller is allowed to branch on either. If a refusal ever carried a
    figure, a not_determined magnitude would be published as a bound; if an
    admit ever carried ``None``, a proven $0 ceiling would vanish into the
    fallthrough.
    """
    build, _, _ = ALL_SHAPES[shape]
    usd, reason = P.ceiling_for(build(), KEY)
    assert reason in P.CEILING_REASONS
    assert (usd is not None) == (reason in P.CEILING_ADMITTING_REASONS)


def test_a_proven_empty_sheet_admits_a_zero_rather_than_refusing():
    """The earned negative, stated as the two shortcuts that get it wrong."""
    plane = _proven_empty()
    assert plane.sheet_state(KEY) == P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state(KEY) != P.SHEET_PRICED
    assert plane.total(KEY) == 0.0

    usd, reason = P.ceiling_for(plane, KEY)
    assert usd == 0.0
    assert reason == P.CEILING_PROVEN_EMPTY
    assert reason in P.CEILING_ADMITTING_REASONS
    assert reason != P.CEILING_ADMITTED


def test_the_three_undetermined_sheets_refuse_under_three_different_reasons():
    """Dust, unpriced and never-observed are three gaps, not one."""
    answers = {
        P.ceiling_for(_below_resolution(), KEY),
        P.ceiling_for(_unpriced(), KEY),
        P.ceiling_for(_no_rows(), KEY),
    }
    assert answers == {
        (None, P.CEILING_BELOW_RESOLUTION),
        (None, P.CEILING_UNPRICED),
        (None, P.CEILING_NO_ROWS),
    }


def test_an_ambiguous_implementation_refuses_however_the_key_was_folded():
    """The refusal survives the caller's canonicalisation.

    An implementation two proxies share is aliased onto nothing, so
    ``canonical()`` is the identity on it and folding first cannot launder the
    ambiguity away. The caller passes a canonical key; this is why that is safe.
    """
    plane = _ambiguous()
    assert plane.canonical(KEY) == KEY
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ALIAS_AMBIGUOUS)
    assert P.ceiling_for(plane, plane.canonical(KEY)) == (None, P.CEILING_ALIAS_AMBIGUOUS)


def test_the_ceiling_is_read_at_the_canonical_key():
    """An implementation's ceiling is the proxy's sheet, counted once."""
    plane = _plane(
        per_asset={OTHER: {"weth": 12.0}},
        per_asset_state={OTHER: {"weth": P.ASSET_PRICED}},
        alias={KEY: OTHER},
    )
    assert P.ceiling_for(plane, KEY) == (12.0, P.CEILING_ADMITTED)
    assert P.ceiling_for(plane, OTHER) == (12.0, P.CEILING_ADMITTED)


def test_a_truncated_asset_list_refuses_the_sheet_that_would_otherwise_admit():
    """A page-capped list is a FLOOR over the holdings, never an at-most.

    The state cannot carry this: the same rows read whole and read cut off both
    answer ``priced``, so the truncation has to refuse ahead of the state or a
    prefix of an asset list gets published as a bound on the whole of it.
    """
    plane = _truncated()
    assert plane.sheet_state(KEY) == P.SHEET_PRICED
    assert plane.total(KEY) == 3_000_000.0

    usd, reason = P.ceiling_for(plane, KEY)
    assert (usd, reason) == (None, P.CEILING_ASSET_LIST_TRUNCATED)
    assert reason not in P.CEILING_ADMITTING_REASONS


def test_a_truncated_list_refuses_a_proven_empty_sheet_too():
    """The earned negative is earned over the list that was READ.

    "Every asset on this sheet is witnessed zero" is not "this entity holds
    nothing" when the sheet stops at entry 100 — so the $0 admit is refused for
    the same reason the priced one is, and under the same token.
    """
    plane = _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_truncated={KEY},
    )
    assert plane.sheet_state(KEY) == P.SHEET_PROVEN_EMPTY
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ASSET_LIST_TRUNCATED)


def test_truncation_is_read_at_the_canonical_key_in_both_directions():
    """One sheet, so one truncation: it cannot be laundered by which key is asked.

    The proxy and its implementation are the one entity whose rows are folded
    together, and a capped read of that entity truncates the list whichever key
    the caller arrives with.
    """
    plane = _plane(
        per_asset={OTHER: {"weth": 12.0}},
        per_asset_state={OTHER: {"weth": P.ASSET_PRICED}},
        alias={KEY: OTHER},
        asset_set_truncated={OTHER},
    )
    assert plane.asset_set_is_truncated(KEY) and plane.asset_set_is_truncated(OTHER)
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ASSET_LIST_TRUNCATED)
    assert P.ceiling_for(plane, OTHER) == (None, P.CEILING_ASSET_LIST_TRUNCATED)


def test_an_untruncated_sheet_is_not_thereby_claimed_complete():
    """Absence from the set is the absence of a witness, in one direction only.

    A page shorter than the cap proves this read was not cut off and never that
    the index behind it is whole, so the plane carries the truncated case alone
    and the ceiling that admits beside it rests on the sheet's own state — the
    same admission it rested on before this conjunct existed.
    """
    plane = _priced()
    assert plane.asset_set_truncated == set()
    assert plane.asset_set_is_truncated(KEY) is False
    assert P.ceiling_for(plane, KEY) == (3_000_001.5, P.CEILING_ADMITTED)


def test_an_unregistered_sheet_state_raises_instead_of_refusing_under_a_borrowed_reason(
    monkeypatch: pytest.MonkeyPatch,
):
    """A sixth sheet state must not inherit a fifth state's disclosure.

    ``_CEILING_REFUSALS`` is read without a default for this reason: a ``.get``
    fallback would publish "no rows were ever observed" about a fact nobody has
    classified, and the refusal tokens are the pipeline work list.
    """
    monkeypatch.setattr(P.ValuePlane, "sheet_state", lambda self, key: "sheet_state_nobody_registered")
    with pytest.raises(ValueError, match="no registered ceiling reason"):
        P.ceiling_for(_no_rows(), KEY)


def test_the_resolver_answers_the_value_conjuncts_only():
    """It never sees a capability, so it can never have checked one.

    Guards the docstring's contract by construction: the signature carries a
    plane and a key and nothing else, so a caller cannot read an admitted
    ceiling as "code control was proven here".
    """
    import inspect

    assert list(inspect.signature(P.ceiling_for).parameters) == ["plane", "key"]
