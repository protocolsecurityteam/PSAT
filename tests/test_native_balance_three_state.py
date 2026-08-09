"""B2 — the native/asset three-state, and the blast radius of delivering it.

B2's own damage population is 0 rows, so nothing here is calibrated on the
corpus; every arm is argued from the code contract. What these tests defend is
the DELIVERY: the discriminator had to land somewhere that does not make
``contract_balances`` row existence mean something new, because
``services.effects.selection`` consumes that existence as "this deployment holds
this asset" and that set feeds the published reach rows.

The second half of the file is the reader side, which is where this unit's own
gap-widening risk actually lives: an absence manufactured by a failed fetch, a
retention prune, or a view predicate becomes a published ``$0.00`` two hops
downstream.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, cast

import pytest
from sqlalchemy import func, select

from db.models import (
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    ContractBalanceLatest,
    EffectiveFunction,
    Protocol,
)
from services.effects.selection import (
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP,
    HOLDINGS_COMPLETENESS_NOT_DETERMINED,
    _asset_holdings_by_deployment,
    _completeness_from_fetch,
    _token_holdings_by_contract,
    build_authority_graph,
)
from services.monitoring.balance_reads import (
    balance_history_depth,
    contracts_missing_current_rows,
    native_balance_fact,
    native_status_for,
    positive_raw_balance,
    prune_balance_fetches,
)
from services.monitoring.tvl import _read_existing_balances
from tests.conftest import requires_postgres
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    ASSET_SET_STATUSES,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
    SWEEP_STATUS_COMPLETED,
)
from utils.etherscan import TOKEN_BALANCE_PAGE_SIZE

_P = "0x00000000000000000000000000000000000d"


def _addr(suffix: str) -> str:
    return (_P + suffix).ljust(42, "0")[:42]


def _protocol(session, name: str) -> Protocol:
    p = Protocol(name=name)
    session.add(p)
    session.flush()
    return p


def _contract(session, protocol_id: int, address: str) -> Contract:
    c = Contract(protocol_id=protocol_id, address=address, chain="ethereum", contract_name="C")
    session.add(c)
    session.flush()
    return c


def _fetch(
    session,
    contract: Contract,
    *,
    native: str = NATIVE_STATUS_PROVEN_NONZERO,
    assets: str = ASSET_SET_STATUS_RETURNED_ASSETS,
    block: int | None = None,
    page_length: int | None = None,
    observed: str | None = None,
    source: str | None = None,
    basis: str | None = None,
    sweep_status: str | None = None,
    swept_from: int | None = None,
    swept_through: int | None = None,
    typed: list | None = None,
) -> ContractBalanceFetch:
    f = ContractBalanceFetch(
        contract_id=contract.id,
        chain_id=1,
        observed_address=observed or contract.address,
        block_number=block,
        native_status=native,
        asset_set_status=assets,
        asset_page_length=page_length,
        asset_set_source=source,
        asset_set_basis=basis,
        sweep_status=sweep_status,
        swept_from_block=swept_from,
        swept_through_block=swept_through,
        typed_assets=typed,
        writer=BALANCE_WRITER_TVL,
    )
    session.add(f)
    session.flush()
    return f


def _row(
    session,
    contract: Contract,
    *,
    token: str | None,
    raw: str = "1000",
    usd: float | None = 10.0,
    fetch: ContractBalanceFetch | None = None,
) -> ContractBalance:
    b = ContractBalance(
        contract_id=contract.id,
        token_address=token,
        token_symbol="T",
        decimals=18,
        raw_balance=raw,
        usd_value=usd,
        observed_address=contract.address if fetch else None,
        fetch_id=fetch.id if fetch else None,
    )
    session.add(b)
    session.flush()
    return b


def _view_ids(session, contract_id: int) -> set[int]:
    return set(
        session.execute(select(ContractBalanceLatest.id).where(ContractBalanceLatest.contract_id == contract_id))
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# The status vocabulary itself
# ---------------------------------------------------------------------------


class TestNativeStatusVocabulary:
    def test_every_failure_shape_lands_on_a_non_polarity(self):
        assert native_status_for(wei=None, pinned=True, failed=True) == NATIVE_STATUS_FETCH_FAILED
        assert native_status_for(wei=None, pinned=False, failed=False) == NATIVE_STATUS_FETCH_FAILED
        # A zero is only ever a PROVEN zero with a height behind it.
        assert native_status_for(wei=0, pinned=True, failed=False) == NATIVE_STATUS_PROVEN_ZERO
        assert native_status_for(wei=0, pinned=False, failed=False) == NATIVE_STATUS_NOT_DETERMINED
        assert native_status_for(wei=5, pinned=False, failed=False) == NATIVE_STATUS_PROVEN_NONZERO

    def test_the_fact_is_the_pair_never_the_status_alone(self):
        """``proven_nonzero`` means two different things at NULL and non-NULL block."""
        assert native_balance_fact(NATIVE_STATUS_PROVEN_NONZERO, None) == "nonzero_at_unrecorded_height"
        assert native_balance_fact(NATIVE_STATUS_PROVEN_NONZERO, 25643300) == "proven_nonzero_at_block_25643300"
        assert native_balance_fact(NATIVE_STATUS_PROVEN_ZERO, 25643300) == "proven_zero_at_block_25643300"
        # Both non-facts collapse to the same honest answer.
        assert native_balance_fact(NATIVE_STATUS_FETCH_FAILED, None) == "not_determined"
        assert native_balance_fact(NATIVE_STATUS_NOT_DETERMINED, None) == "not_determined"
        # Even constructed in memory, a blockless proven_zero asserts nothing.
        assert native_balance_fact(NATIVE_STATUS_PROVEN_ZERO, None) == "not_determined"


class TestCompletenessMappingIsTotalAndCannotSayComplete:
    """A13 — the merged ``asset_set_status`` must not leak a whole-list reading."""

    @pytest.mark.parametrize("status", ASSET_SET_STATUSES + (None,))
    def test_total_over_the_whole_vocabulary(self, status):
        out = _completeness_from_fetch(status)
        assert out in (HOLDINGS_COMPLETENESS_AT_PAGE_CAP, HOLDINGS_COMPLETENESS_NOT_DETERMINED)
        # There is no "complete" member to return, and that is the invariant:
        # a status other than at-cap is consistent with a whole list AND with a
        # list the fetch simply never proved whole.
        assert out != "complete"

    def test_returned_assets_is_not_determined(self):
        assert _completeness_from_fetch(ASSET_SET_STATUS_RETURNED_ASSETS) == HOLDINGS_COMPLETENESS_NOT_DETERMINED

    def test_only_the_status_witnesses_the_cap(self):
        """The fetch's own status, and never a length.

        The fetch pages the endpoint to exhaustion, so an exhausted list of exactly
        ``TOKEN_BALANCE_PAGE_SIZE`` entries — or more — was never cut off. Only
        ``at_page_cap`` says the stored list is a prefix.
        """
        assert _completeness_from_fetch(ASSET_SET_STATUS_AT_PAGE_CAP) == HOLDINGS_COMPLETENESS_AT_PAGE_CAP
        assert _completeness_from_fetch(ASSET_SET_STATUS_RETURNED_ASSETS) == HOLDINGS_COMPLETENESS_NOT_DETERMINED


class TestPositiveQuantityGuardFailsClosedWithoutRaising:
    """A10 — an unparseable stored quantity excludes the row, never crashes."""

    @pytest.mark.parametrize("raw", ["1", "1000000000000000000"])
    def test_positive(self, raw):
        assert positive_raw_balance(raw) is True

    @pytest.mark.parametrize("raw", ["0", "", None, "not-a-number", "1.5", "0x10", "-3"])
    def test_excluded_and_never_raises(self, raw):
        assert positive_raw_balance(raw) is False


class TestHistoryDepthValidation:
    """A4 — depth 0 would prune every fetch and resurrect the legacy rows."""

    def test_default(self, monkeypatch):
        monkeypatch.delenv("PSAT_BALANCE_HISTORY_DEPTH", raising=False)
        assert balance_history_depth() == 10

    @pytest.mark.parametrize("bad", ["0", "-1", "nonsense"])
    def test_rejects_below_one(self, monkeypatch, bad):
        monkeypatch.setenv("PSAT_BALANCE_HISTORY_DEPTH", bad)
        with pytest.raises(ValueError):
            balance_history_depth()


# ---------------------------------------------------------------------------
# The view
# ---------------------------------------------------------------------------


@requires_postgres
class TestViewLegacyArm:
    """A1 — a FAILED first fetch must not delete history from the view."""

    def test_legacy_rows_survive_an_all_failed_first_fetch(self, db_session):
        proto = _protocol(db_session, "3s-legacy")
        c = _contract(db_session, proto.id, _addr("11"))
        legacy = _row(db_session, c, token=None)
        legacy_tok = _row(db_session, c, token="0x" + "aa" * 20)
        db_session.commit()
        assert _view_ids(db_session, c.id) == {legacy.id, legacy_tok.id}

        _fetch(db_session, c, native=NATIVE_STATUS_FETCH_FAILED, assets=ASSET_SET_STATUS_FETCH_FAILED)
        db_session.commit()

        # A failed fetch learned nothing, so the last thing that WAS observed is
        # still the best available answer.
        assert _view_ids(db_session, c.id) == {legacy.id, legacy_tok.id}

    def test_a_successful_fetch_does_supersede_the_legacy_rows(self, db_session):
        proto = _protocol(db_session, "3s-legacy-super")
        c = _contract(db_session, proto.id, _addr("12"))
        _row(db_session, c, token=None)
        f = _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_RETURNED_EMPTY)
        fresh = _row(db_session, c, token=None, fetch=f)
        db_session.commit()
        assert _view_ids(db_session, c.id) == {fresh.id}


@requires_postgres
class TestViewIsPerRowClass:
    """A2 — a token-class failure must not withdraw the native holding."""

    def test_native_from_f2_tokens_from_f1(self, db_session):
        proto = _protocol(db_session, "3s-perclass")
        c = _contract(db_session, proto.id, _addr("21"))

        f1 = _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_RETURNED_ASSETS)
        f1_native = _row(db_session, c, token=None, fetch=f1)
        f1_tok = _row(db_session, c, token="0x" + "bb" * 20, fetch=f1)

        f2 = _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_FETCH_FAILED)
        f2_native = _row(db_session, c, token=None, fetch=f2)
        db_session.commit()

        # The newer fetch wins the class it observed; the older one keeps the
        # class the newer one failed at. Zero rows come from the failed class.
        assert _view_ids(db_session, c.id) == {f2_native.id, f1_tok.id}
        assert f1_native.id not in _view_ids(db_session, c.id)


@requires_postgres
class TestViewSynthesizesNothing:
    """A3 — the view is a pure projection: no join may multiply or invent a row."""

    def _assert_projection(self, db_session):
        base_ids = set(db_session.execute(select(ContractBalance.id)).scalars().all())
        view_ids = set(db_session.execute(select(ContractBalanceLatest.id)).scalars().all())
        assert view_ids <= base_ids
        base_n = db_session.execute(select(func.count()).select_from(ContractBalance)).scalar_one()
        view_n = db_session.execute(select(func.count()).select_from(ContractBalanceLatest)).scalar_one()
        assert view_n <= base_n
        # And no id is duplicated by the UNION arms.
        dupes = db_session.execute(
            select(ContractBalanceLatest.id).group_by(ContractBalanceLatest.id).having(func.count() > 1)
        ).all()
        assert dupes == []

    def test_legacy_only_corpus(self, db_session):
        proto = _protocol(db_session, "3s-proj-legacy")
        c = _contract(db_session, proto.id, _addr("31"))
        _row(db_session, c, token=None)
        _row(db_session, c, token="0x" + "cc" * 20)
        db_session.commit()
        self._assert_projection(db_session)

    def test_mixed_corpus(self, db_session):
        proto = _protocol(db_session, "3s-proj-mixed")
        c = _contract(db_session, proto.id, _addr("32"))
        _row(db_session, c, token=None)  # legacy
        f1 = _fetch(db_session, c)
        _row(db_session, c, token=None, fetch=f1)
        _row(db_session, c, token="0x" + "dd" * 20, fetch=f1)
        f2 = _fetch(db_session, c, assets=ASSET_SET_STATUS_FETCH_FAILED)
        _row(db_session, c, token=None, fetch=f2)
        db_session.commit()
        self._assert_projection(db_session)


@requires_postgres
class TestRetentionNeverEvictsThePublishedObservation:
    """A4 — ``depth`` consecutive failures must not CASCADE away the last good fetch."""

    def test_good_fetch_survives_depth_failures(self, db_session, monkeypatch):
        monkeypatch.setenv("PSAT_BALANCE_HISTORY_DEPTH", "3")
        proto = _protocol(db_session, "3s-retention")
        c = _contract(db_session, proto.id, _addr("41"))

        good = _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_RETURNED_ASSETS)
        good_row = _row(db_session, c, token=None, fetch=good)
        db_session.commit()

        for _ in range(6):
            _fetch(db_session, c, native=NATIVE_STATUS_FETCH_FAILED, assets=ASSET_SET_STATUS_FETCH_FAILED)
            db_session.flush()
            prune_balance_fetches(db_session, c.id, c.address)
        db_session.commit()

        surviving = set(
            db_session.execute(select(ContractBalanceFetch.id).where(ContractBalanceFetch.contract_id == c.id))
            .scalars()
            .all()
        )
        assert good.id in surviving
        # The rows it published are still there, and still what the view returns.
        assert _view_ids(db_session, c.id) == {good_row.id}

    def test_pruning_does_bound_growth(self, db_session, monkeypatch):
        monkeypatch.setenv("PSAT_BALANCE_HISTORY_DEPTH", "2")
        proto = _protocol(db_session, "3s-retention-bound")
        c = _contract(db_session, proto.id, _addr("42"))
        for _ in range(8):
            _fetch(db_session, c)
            db_session.flush()
            prune_balance_fetches(db_session, c.id, c.address)
        db_session.commit()
        n = db_session.execute(
            select(func.count()).select_from(ContractBalanceFetch).where(ContractBalanceFetch.contract_id == c.id)
        ).scalar_one()
        assert n == 2


# ---------------------------------------------------------------------------
# The readers — where this unit's own gap-widening risk lives
# ---------------------------------------------------------------------------


@requires_postgres
class TestFailedFetchIsAbsentNotZero:
    """A11 — an absent balance must not become a published ``$0.00`` floor.

    ``recipes._add_reach`` publishes ``graph.deployment_balance.get(acting,
    _ZERO_USD)`` as ``observed_reach_floor_usd``. A LEFT JOIN, or a 0 entry for a
    contract whose fetch failed, would put a confident-looking zero on a function
    that may move millions.
    """

    def test_contract_with_only_a_failed_fetch_has_no_balance_key(self, db_session):
        proto = _protocol(db_session, "3s-absent")
        holder = _contract(db_session, proto.id, _addr("51"))
        failed = _contract(db_session, proto.id, _addr("52"))
        f = _fetch(db_session, holder)
        _row(db_session, holder, token=None, usd=100.0, fetch=f)
        _fetch(db_session, failed, native=NATIVE_STATUS_FETCH_FAILED, assets=ASSET_SET_STATUS_FETCH_FAILED)
        db_session.commit()

        graph = build_authority_graph(db_session, proto.id)
        assert _addr("51").lower() in graph.balance
        # ABSENT, not 0. The distinction is the whole point.
        assert _addr("52").lower() not in graph.balance
        assert _addr("52").lower() not in graph.deployment_balance


@requires_postgres
class TestHoldingsRequireAPositiveWitness:
    """The delivery trap: row EXISTENCE must not mean "holds this asset"."""

    def test_zero_and_unparseable_rows_are_not_holdings(self, db_session):
        proto = _protocol(db_session, "3s-guard")
        c = _contract(db_session, proto.id, _addr("61"))
        f = _fetch(db_session, c)
        _row(db_session, c, token=None, raw="0", usd=None, fetch=f)
        _row(db_session, c, token="0x" + "11" * 20, raw="junk", usd=None, fetch=f)
        real = _row(db_session, c, token="0x" + "22" * 20, raw="5", usd=7.0, fetch=f)
        db_session.commit()

        holdings = _asset_holdings_by_deployment(db_session, proto.id)
        assets = {h.asset for hs in holdings.values() for h in hs}
        assert assets == {"0x" + "22" * 20}
        assert real.raw_balance == "5"

    def test_a_fetch_row_never_becomes_a_holding(self, db_session):
        """The three-state lives on a plane whose rows are not holdings at all."""
        proto = _protocol(db_session, "3s-plane")
        c = _contract(db_session, proto.id, _addr("62"))
        _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_ZERO, block=25643300, assets=ASSET_SET_STATUS_RETURNED_EMPTY)
        db_session.commit()

        assert _asset_holdings_by_deployment(db_session, proto.id) == {}
        assert _token_holdings_by_contract(db_session, proto.id, 5) == {}


@requires_postgres
class TestReachInputsOnAMixedFetchContract:
    """A14(c) — the whole reader chain over a contract that HAS fetches.

    The corpus-wide differential can only show the legacy path is untouched
    (every new column is NULL on all 1617 rows). This is the arm that exercises
    the new plane end to end and pins the exact tuple.
    """

    def test_exact_asset_holding_tuple(self, db_session):
        proto = _protocol(db_session, "3s-mixed-chain")
        c = _contract(db_session, proto.id, _addr("71"))
        tok = "0x" + "77" * 20

        old = _fetch(db_session, c, assets=ASSET_SET_STATUS_RETURNED_ASSETS)
        _row(db_session, c, token=tok, raw="10", usd=5.0, fetch=old)
        new = _fetch(db_session, c, assets=ASSET_SET_STATUS_RETURNED_ASSETS, page_length=4)
        _row(db_session, c, token=tok, raw="10", usd=9.0, fetch=new)
        _row(db_session, c, token=None, raw="2", usd=None, fetch=new)
        db_session.commit()

        holdings = _asset_holdings_by_deployment(db_session, proto.id)
        got = sorted((h.holder, h.asset, h.usd_value, h.completeness) for h in holdings[_addr("71").lower()])
        # Sorted by (holder, asset): the token address precedes the native
        # emitter sentinel. The newer fetch's PRICED copy wins the MAX, and the
        # native row is unpriced — carried as None, never as 0.
        assert got == [
            (_addr("71").lower(), tok, 9.0, "not_determined"),
            (_addr("71").lower(), "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", None, "not_determined"),
        ]

    def test_a_capped_sibling_weakens_the_whole_holder(self, db_session):
        """A13 — weakest wins. One capped fetch means the holder's list may be short."""
        proto = _protocol(db_session, "3s-weakest")
        proxy = _contract(db_session, proto.id, _addr("81"))
        sibling = _contract(db_session, proto.id, _addr("82"))
        # Both code rows run behind the ONE proxy, which is the holder key
        # ``_deployment_by_contract`` builds from ``effective_functions``.
        for c in (proxy, sibling):
            db_session.add(
                EffectiveFunction(
                    contract_id=c.id,
                    function_name="f",
                    deployment_address=proxy.address,
                )
            )
        db_session.flush()

        clean = _fetch(db_session, proxy, assets=ASSET_SET_STATUS_RETURNED_ASSETS, page_length=3)
        _row(db_session, proxy, token="0x" + "91" * 20, raw="1", usd=1.0, fetch=clean)
        capped = _fetch(db_session, sibling, assets=ASSET_SET_STATUS_AT_PAGE_CAP, page_length=100)
        _row(db_session, sibling, token="0x" + "92" * 20, raw="1", usd=1.0, fetch=capped)
        db_session.commit()

        holdings = _asset_holdings_by_deployment(db_session, proto.id)
        items = holdings[proxy.address.lower()]
        assert {h.asset for h in items} == {"0x" + "91" * 20, "0x" + "92" * 20}
        # WEAKEST WINS: the clean sibling does not launder the capped one.
        assert {h.completeness for h in items} == {HOLDINGS_COMPLETENESS_AT_PAGE_CAP}


@requires_postgres
class TestSnapshotDoesNotPublishAFailedReadAsMoney:
    """A12 — the read-existing branch must not report a lower total as complete."""

    def test_failed_contract_is_omitted_and_flags_partial(self, db_session):
        proto = _protocol(db_session, "3s-snapshot")
        good = _contract(db_session, proto.id, _addr("a1"))
        bad = _contract(db_session, proto.id, _addr("a2"))
        f = _fetch(db_session, good)
        _row(db_session, good, token=None, usd=250.0, fetch=f)
        _fetch(db_session, bad, native=NATIVE_STATUS_FETCH_FAILED, assets=ASSET_SET_STATUS_FETCH_FAILED)
        db_session.commit()

        breakdown, partial = _read_existing_balances(db_session, proto.id)

        assert partial is True
        # No ``total_usd: 0.0`` entry for the contract whose read failed: that
        # number would enter TvlSnapshot.total_usd as a measurement.
        keys = {k for k in breakdown}
        assert not any(_addr("a2") in k for k in keys)
        assert any(_addr("a1") in k for k in keys)
        assert [v["total_usd"] for k, v in breakdown.items() if _addr("a1") in k] == [250.0]

    def test_missing_set_is_empty_when_nothing_was_ever_fetched(self, db_session):
        """A contract with no fetch plane at all is not a FAILED contract."""
        proto = _protocol(db_session, "3s-snapshot-legacy")
        c = _contract(db_session, proto.id, _addr("a3"))
        _row(db_session, c, token=None, usd=5.0)
        db_session.commit()
        assert contracts_missing_current_rows(db_session, [c.id]) == set()
        _breakdown, partial = _read_existing_balances(db_session, proto.id)
        assert partial is False


@requires_postgres
class TestAbsentNativeRowIsNeverZero:
    """The reject-list item itself: an absent native row must not read as $0.

    The production consumer is ``recipes._add_reach``, which returns before
    writing anything when the holder set is empty — so the key that means
    "measured reach" is ABSENT rather than present-and-zero.
    """

    def test_no_holder_entry_and_no_zero_valued_pair(self, db_session):
        from services.effects.recipes import _add_reach

        proto = _protocol(db_session, "3s-absent-native")
        c = _contract(db_session, proto.id, _addr("b1"))
        _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_ZERO, block=25643300)
        db_session.commit()

        holdings = _asset_holdings_by_deployment(db_session, proto.id)
        assert holdings.get(_addr("b1").lower()) is None

        concrete: dict = {}
        # The base call is never touched on this branch: ``_add_reach`` returns
        # before reading it when the holder set is empty.
        _add_reach(concrete, cast(Any, object()), (), 0.0, None)
        # Not "$0 of reach" — no reach claim of any kind.
        assert concrete == {}
        assert "observed_reach_value_usd" not in concrete
        assert "reach_determined" not in concrete


@requires_postgres
class TestRowlessNonFailedFetchIsAnIntegrityViolation:
    """R3 — a class status that outruns its rows must flip ``partial``.

    The writers can no longer produce this shape (a non-failed class status is a
    promise its row set was written), so it is constructed directly here. If it
    ever appears again the view will publish the class from a row set nobody
    wrote, and the snapshot must refuse to call that a measurement.
    """

    def test_proven_nonzero_with_no_native_row_is_missing(self, db_session):
        proto = _protocol(db_session, "3s-rowless")
        c = _contract(db_session, proto.id, _addr("c1"))
        good = _fetch(db_session, c)
        _row(db_session, c, token=None, usd=99.0, fetch=good)
        # A later fetch claiming a positive native quantity, with no row.
        _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_RETURNED_EMPTY)
        db_session.commit()

        assert contracts_missing_current_rows(db_session, [c.id]) == {c.id}
        _breakdown, partial = _read_existing_balances(db_session, proto.id)
        assert partial is True

    def test_proven_zero_with_no_native_row_is_NOT_missing(self, db_session):
        """The empty row set IS the observation here — no violation."""
        proto = _protocol(db_session, "3s-rowless-zero")
        c = _contract(db_session, proto.id, _addr("c2"))
        _fetch(
            db_session,
            c,
            native=NATIVE_STATUS_PROVEN_ZERO,
            block=25643300,
            assets=ASSET_SET_STATUS_RETURNED_EMPTY,
        )
        db_session.commit()
        assert contracts_missing_current_rows(db_session, [c.id]) == set()

    def test_returned_assets_with_no_rows_is_NOT_missing(self, db_session):
        """A page whose every entry was zero-balance is a real observation.

        ``get_token_balances_page`` drops those entries, so ``returned_assets``
        with zero persisted rows is reachable without any integrity break — which
        is why there is no asset-class analogue of the native rule.
        """
        proto = _protocol(db_session, "3s-rowless-assets")
        c = _contract(db_session, proto.id, _addr("c3"))
        _fetch(
            db_session,
            c,
            native=NATIVE_STATUS_PROVEN_ZERO,
            block=25643300,
            assets=ASSET_SET_STATUS_RETURNED_ASSETS,
            page_length=5,
        )
        db_session.commit()
        assert contracts_missing_current_rows(db_session, [c.id]) == set()


@requires_postgres
class TestViewCurrencyIsPerContractNotPerObservedAddress:
    """R4 — documented semantics, pinned.

    The view resolves currency per ``contract_id`` and IGNORES
    ``observed_address``: a contract fetched at two different addresses publishes
    whichever writer wrote LAST. That is deliberate — it preserves the
    pre-migration last-writer-wins DELETE semantics, and per-address currency
    would publish both address' rows at once, double-counting the proxy/impl
    pairs in ``build_authority_graph``'s per-contract sum.
    """

    def test_last_writer_wins_across_two_observed_addresses(self, db_session):
        proto = _protocol(db_session, "3s-two-addrs")
        c = _contract(db_session, proto.id, _addr("d1"))
        proxy = _addr("d2")

        at_self = _fetch(db_session, c, observed=c.address)
        self_row = _row(db_session, c, token=None, usd=10.0, fetch=at_self)
        at_proxy = _fetch(db_session, c, observed=proxy)
        proxy_row = _row(db_session, c, token=None, usd=999.0, fetch=at_proxy)
        db_session.commit()

        # Exactly ONE native row is current, and it is the later write — not the
        # union of both addresses.
        assert _view_ids(db_session, c.id) == {proxy_row.id}
        assert self_row.id not in _view_ids(db_session, c.id)

        # And the per-contract sum is that one row, never 10 + 999. Compared as a
        # NUMBER: the sum stays exact Decimal all the way through, but its scale
        # is the storage column's and carries no claim, so pinning the rendering
        # would pin the column width rather than the arithmetic under test.
        graph = build_authority_graph(db_session, proto.id)
        assert graph.balance[c.address.lower()] == Decimal("999.00")


@requires_postgres
class TestValuePlaneReadsAssetSetCompleteness:
    """The scorer's half of the at-cap fact: it reaches the sheet, not just the row.

    ``asset_set_status`` was written by the producers and read by nothing on the
    scoring side, so a sheet assembled from a list cut off at entry 100
    published the same state as one assembled from a whole list — and
    ``ceiling_for`` bounded a move from above with a prefix of the holdings. The
    plane carries the truncated case per ENTITY so the ceiling can refuse it.
    """

    def test_the_latest_at_cap_fetch_marks_the_entity_truncated(self, db_session):
        from services.scoring.planes import load_value_plane

        proto = _protocol(db_session, "3s-plane-atcap")
        capped = _contract(db_session, proto.id, _addr("e1"))
        whole = _contract(db_session, proto.id, _addr("e2"))
        _fetch(
            db_session,
            capped,
            assets=ASSET_SET_STATUS_AT_PAGE_CAP,
            page_length=TOKEN_BALANCE_PAGE_SIZE,
        )
        _fetch(db_session, whole, assets=ASSET_SET_STATUS_RETURNED_ASSETS, page_length=5)
        db_session.commit()

        plane = load_value_plane(db_session, proto.id)
        assert plane.asset_set_is_truncated(f"ethereum::{capped.address.lower()}")
        # The other contract is not marked — and not thereby claimed complete.
        assert plane.asset_set_is_truncated(f"ethereum::{whole.address.lower()}") is False

    def test_a_later_uncapped_read_supersedes_the_capped_one(self, db_session):
        """LATEST fetch, so re-reading a shorter list withdraws the refusal."""
        from services.scoring.planes import load_value_plane

        proto = _protocol(db_session, "3s-plane-atcap-super")
        c = _contract(db_session, proto.id, _addr("e3"))
        _fetch(db_session, c, assets=ASSET_SET_STATUS_AT_PAGE_CAP, page_length=TOKEN_BALANCE_PAGE_SIZE)
        db_session.commit()
        assert load_value_plane(db_session, proto.id).asset_set_truncated

        _fetch(db_session, c, assets=ASSET_SET_STATUS_RETURNED_ASSETS, page_length=7)
        db_session.commit()
        assert load_value_plane(db_session, proto.id).asset_set_truncated == set()

    def test_a_capped_implementation_truncates_the_proxy_sheet_it_folds_onto(self, db_session):
        """One sheet: the alias fold makes the two accounts one asset list."""
        from services.scoring.planes import load_value_plane

        proto = _protocol(db_session, "3s-plane-atcap-alias")
        impl_address = _addr("e5")
        proxy = _contract(db_session, proto.id, _addr("e4"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        _fetch(db_session, proxy, assets=ASSET_SET_STATUS_RETURNED_ASSETS, page_length=3)
        _fetch(db_session, impl, assets=ASSET_SET_STATUS_AT_PAGE_CAP, page_length=TOKEN_BALANCE_PAGE_SIZE)
        db_session.commit()

        plane = load_value_plane(db_session, proto.id)
        proxy_key = f"ethereum::{proxy.address.lower()}"
        assert plane.canonical(f"ethereum::{impl_address.lower()}") == proxy_key
        assert plane.asset_set_truncated == {proxy_key}


@requires_postgres
class TestValuePlaneReadsAChainScanAsAnEmptySheet:
    """The other half of the completeness fact: the earned POSITIVE.

    ``asset_set_truncated`` carries "this list is a prefix". Nothing carried
    "this list is everything", so a contract whose every quantity was witnessed
    zero still published ``no_rows`` — an absence where a measurement had been
    made — and ``ceiling_for`` refused it under "no balance was ever observed".
    The witness is the chain's own transfer history through a named block, and it
    is the ONLY one: a third-party index answering "no tokens" is the trigger
    that sends the producer to the chain, never the proof (§2 of
    SHEET_OBSERVATION_SPEC.md).
    """

    SCAN_BASIS = "chain log sweep of Transfer/TransferSingle/TransferBatch, blocks 0-21000000"

    def _swept(self, session, contract, *, assets=ASSET_SET_STATUS_RETURNED_EMPTY, typed=None, native_block=99):
        return _fetch(
            session,
            contract,
            native=NATIVE_STATUS_PROVEN_ZERO,
            block=native_block,
            assets=assets,
            source=ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            basis=self.SCAN_BASIS,
            sweep_status=SWEEP_STATUS_COMPLETED,
            swept_from=0,
            swept_through=21_000_000,
            typed=typed if typed is not None else [],
        )

    def test_a_completed_scan_plus_a_pinned_zero_native_publishes_a_proven_empty_sheet(self, db_session):
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-swept")
        c = _contract(db_session, proto.id, _addr("f1"))
        self._swept(db_session, c)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{c.address.lower()}"
        assert plane.asset_set_is_proven_complete(key) is True
        assert plane.sheet_state(key) == P.SHEET_PROVEN_EMPTY
        assert plane.total(key) == 0.0
        assert P.ceiling_for(plane, key) == (0.0, P.CEILING_PROVEN_EMPTY)
        # The published record is the CARRIER's, not a sentence written here.
        record = plane.asset_set_proven_complete[key]
        assert record["swept_through_block"] == 21_000_000 and record["swept_from_block"] == 0
        assert record["basis"] == [self.SCAN_BASIS]
        assert plane.provenance["asset_set_completeness"]["sheets_published_empty"] == 1

    def test_the_etherscan_negative_alone_publishes_nothing(self, db_session):
        """No scan, same empty answer, same pinned zero — and no $0.

        This is §2's ruling as a test: the index's empty list is a completeness
        claim about the index, and under-indexing is precisely its failure mode.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-unswept")
        c = _contract(db_session, proto.id, _addr("f2"))
        _fetch(
            db_session,
            c,
            native=NATIVE_STATUS_PROVEN_ZERO,
            block=99,
            assets=ASSET_SET_STATUS_RETURNED_EMPTY,
            source=ASSET_SET_SOURCE_ETHERSCAN_PAGES,
        )
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{c.address.lower()}"
        assert plane.native_fact[key].startswith("proven_zero")
        assert plane.asset_set_is_proven_complete(key) is False
        assert plane.sheet_state(key) == P.SHEET_NO_ROWS
        assert plane.total(key) is None
        assert P.ceiling_for(plane, key) == (None, P.CEILING_NO_ROWS)

    @pytest.mark.parametrize("answer", [ASSET_SET_STATUS_RETURNED_EMPTY, ASSET_SET_STATUS_RETURNED_ASSETS])
    def test_the_scan_publishes_whatever_the_index_answered(self, db_session, answer: str):
        """The Etherscan status is not a conjunct in either direction.

        An at-cap sheet that swept clean, a persistent failure that swept clean
        and an entity that never got its own index answer are all publishable
        once the SCAN proves them empty — so the sheet state reads the scan and
        never the answer that triggered it.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, f"3s-plane-anyanswer-{answer}")
        c = _contract(db_session, proto.id, _addr("f3"))
        self._swept(db_session, c, assets=answer)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        assert plane.sheet_state(f"ethereum::{c.address.lower()}") == P.SHEET_PROVEN_EMPTY

    def test_an_unreadable_typed_receipt_refuses_the_empty_sheet(self, db_session):
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-typed")
        c = _contract(db_session, proto.id, _addr("f4"))
        self._swept(
            db_session,
            c,
            typed=[{"address": _addr("aa"), "kind": "typed", "quantity_readable": False, "quantity": None}],
        )
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{c.address.lower()}"
        assert plane.unresolved_typed_receipts(key)
        assert plane.proven_empty_refusal(key) == P.EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED
        assert plane.sheet_state(key) == P.SHEET_UNPRICED
        assert plane.total(key) is None

    def test_a_typed_receipt_read_back_to_zero_is_a_resolved_one(self, db_session):
        """Arrived and provably gone. The evidence resolved, so it refuses nothing."""
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-typed-zero")
        c = _contract(db_session, proto.id, _addr("f5"))
        self._swept(
            db_session,
            c,
            typed=[{"address": _addr("ab"), "kind": "typed", "quantity_readable": True, "quantity": "0"}],
        )
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{c.address.lower()}"
        assert plane.unresolved_typed_receipts(key) == []
        assert plane.sheet_state(key) == P.SHEET_PROVEN_EMPTY

    def test_a_malformed_typed_record_refuses_rather_than_degrading_to_empty(self, db_session):
        """Evidence nobody can read is not evidence of nothing."""
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-typed-bad")
        c = _contract(db_session, proto.id, _addr("f6"))
        self._swept(db_session, c, typed=[{"kind": "typed"}])
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        assert plane.sheet_state(f"ethereum::{c.address.lower()}") == P.SHEET_UNPRICED

    def test_an_unscanned_account_of_the_same_sheet_refuses_it(self, db_session):
        """The alias fold makes two accounts one asset list, so both must be scanned.

        No exemption for an implementation nothing has read: its rows fold into
        this sheet, so publishing the sheet empty asserts that its address holds
        nothing, and nobody looked. The refusal carries its own token and names
        the address, because one producer cycle closes it.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-halfswept")
        impl_address = _addr("f8")
        proxy = _contract(db_session, proto.id, _addr("f7"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        self._swept(db_session, proxy)
        impl_fetch = _fetch(
            db_session,
            impl,
            native=NATIVE_STATUS_PROVEN_NONZERO,
            assets=ASSET_SET_STATUS_RETURNED_ASSETS,
            source=ASSET_SET_SOURCE_ETHERSCAN_PAGES,
        )
        _row(db_session, impl, token=_addr("cc"), raw="5", usd=None, fetch=impl_fetch)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        proxy_key = f"ethereum::{proxy.address.lower()}"
        assert plane.canonical(f"ethereum::{impl_address.lower()}") == proxy_key
        assert plane.asset_set_is_proven_complete(proxy_key) is False
        assert plane.asset_set_accounts_unscanned[proxy_key] == [impl_address.lower()]
        assert plane.proven_empty_refusal(proxy_key) == P.EMPTY_REFUSED_UNSCANNED_ACCOUNT
        assert plane.sheet_state(proxy_key) == P.SHEET_UNPRICED

    def test_a_capped_account_contradicts_the_scan_and_the_refusal_wins(self, db_session):
        """Two witnesses of one sheet that disagree prove nothing together."""
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-contradiction")
        impl_address = _addr("fa")
        proxy = _contract(db_session, proto.id, _addr("f9"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        self._swept(db_session, proxy)
        _fetch(
            db_session,
            impl,
            assets=ASSET_SET_STATUS_AT_PAGE_CAP,
            page_length=TOKEN_BALANCE_PAGE_SIZE,
            source=ASSET_SET_SOURCE_ETHERSCAN_PAGES,
        )
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        proxy_key = f"ethereum::{proxy.address.lower()}"
        assert plane.asset_set_is_truncated(proxy_key) is True
        assert plane.asset_set_is_proven_complete(proxy_key) is False
        # No completeness witness, so the pinned zero native never becomes a
        # sheet reading and the sheet is back to having observed nothing.
        assert plane.sheet_state(proxy_key) == P.SHEET_NO_ROWS
        assert P.ceiling_for(plane, proxy_key) == (None, P.CEILING_ASSET_LIST_TRUNCATED)

    def test_an_implementation_nobody_ever_read_refuses_the_sheet(self, db_session):
        """The fail-open this rule closes, in its live shape.

        The implementation has one fetch and it was observed AT THE PROXY — the
        divergent-address policy's legacy. Nothing has ever read the
        implementation's own address, so the proxy's sheet cannot be shown whole
        however cleanly the proxy itself sweeps, and "we never looked" is
        not_determined rather than $0.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-unread-impl")
        impl_address = _addr("fc")
        proxy = _contract(db_session, proto.id, _addr("fb"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        self._swept(db_session, proxy)
        # The implementation's only fetch: a read of the PROXY, filed here.
        _fetch(
            db_session,
            impl,
            native=NATIVE_STATUS_PROVEN_ZERO,
            block=99,
            assets=ASSET_SET_STATUS_FETCH_FAILED,
            observed=proxy.address,
        )
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        proxy_key = f"ethereum::{proxy.address.lower()}"
        assert plane.asset_set_is_proven_complete(proxy_key) is False
        assert plane.proven_empty_refusal(proxy_key) == P.EMPTY_REFUSED_UNSCANNED_ACCOUNT
        assert plane.sheet_state(proxy_key) == P.SHEET_NO_ROWS

        # One producer cycle at the implementation's OWN address closes it.
        self._swept(db_session, impl)
        db_session.commit()
        reread = P.load_value_plane(db_session, proto.id)
        assert reread.asset_set_is_proven_complete(proxy_key) is True
        record = reread.asset_set_proven_complete[proxy_key]
        assert record["accounts_scanned"] == record["accounts_folded"] == 2
        assert reread.sheet_state(proxy_key) == P.SHEET_PROVEN_EMPTY

    def test_a_scan_filed_against_a_row_but_issued_elsewhere_scans_nothing(self, db_session):
        """A fetch names the contract it belongs to and the address it read.

        The recipient-topic filter that makes a scan a proof is built from the
        second, so a scan of one address filed against another contract's row
        proves nothing about that contract's address.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-foreign-scan")
        c = _contract(db_session, proto.id, _addr("fd"))
        other = _addr("fe")
        f = self._swept(db_session, c)
        f.observed_address = other
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{c.address.lower()}"
        assert plane.asset_set_is_proven_complete(key) is False
        assert plane.sheet_state(key) == P.SHEET_NO_ROWS

    def test_two_accounts_that_disagree_about_the_native_balance_publish_neither(self, db_session):
        """A folded account's zero is not this entity's zero.

        Live shape: a proxy holding ETH read ``proven_nonzero`` at its own
        address while its implementation row carried a stale ``proven_zero``, and
        the higher ``contracts.id`` won the map. The polarities disagree, one of
        them is wrong about this entity, and the plane cannot say which — so it
        publishes the third state and the sheet earns no empty.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-native-disagree")
        impl_address = _addr("e8")
        proxy = _contract(db_session, proto.id, _addr("e7"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        proxy_fetch = self._swept(db_session, proxy, native_block=200)
        proxy_fetch.native_status = NATIVE_STATUS_PROVEN_NONZERO
        self._swept(db_session, impl, native_block=100)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        proxy_key = f"ethereum::{proxy.address.lower()}"
        assert plane.asset_set_is_proven_complete(proxy_key) is True
        assert plane.native_fact[proxy_key] == "not_determined"
        assert plane.sheet_state(proxy_key) == P.SHEET_NO_ROWS
        assert plane.provenance["asset_set_completeness"]["native_facts_refused_on_cross_account_disagreement"] == 1

    def test_the_entitys_own_account_is_what_answers_its_native_balance(self, db_session):
        """Agreeing polarities, different heights: the entity's own read wins.

        Both accounts say proven_zero, so nothing is refused — but the block
        published is the one read AT the entity, not whichever folded row sorted
        last.
        """
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-native-own")
        impl_address = _addr("ea")
        proxy = _contract(db_session, proto.id, _addr("e9"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        self._swept(db_session, proxy, native_block=777)
        self._swept(db_session, impl, native_block=111)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        proxy_key = f"ethereum::{proxy.address.lower()}"
        assert plane.native_fact[proxy_key] == "proven_zero_at_block_777"
        assert plane.sheet_state(proxy_key) == P.SHEET_PROVEN_EMPTY
