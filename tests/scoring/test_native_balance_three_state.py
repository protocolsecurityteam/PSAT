"""B2's damage population is 0 rows, so every arm is argued from the contract.

``contract_balances`` row existence means "holds this asset" to ``services.effects.selection``, and an absence from a
failed fetch, prune or view predicate must not become a published ``$0.00`` downstream.
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
    ControlGraphNode,
    EffectiveFunction,
    Protocol,
)
from services.clients.etherscan import TOKEN_BALANCE_PAGE_SIZE
from services.effects.selection import (
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP,
    HOLDINGS_COMPLETENESS_NOT_DETERMINED,
    _asset_holdings_by_deployment,
    _completeness_from_fetch,
    _token_holdings_by_contract,
    build_authority_graph,
)
from services.monitoring.balance_reads import (
    ObservationSubject,
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
    BALANCE_SOURCE_PINNED_NATIVE_READ,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
    SWEEP_STATUS_COMPLETED,
)

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


class TestNativeStatusVocabulary:
    def test_every_failure_shape_lands_on_a_non_polarity(self):
        assert native_status_for(wei=None, pinned=True, failed=True) == NATIVE_STATUS_FETCH_FAILED
        assert native_status_for(wei=None, pinned=False, failed=False) == NATIVE_STATUS_FETCH_FAILED
        assert native_status_for(wei=0, pinned=True, failed=False) == NATIVE_STATUS_PROVEN_ZERO
        assert native_status_for(wei=0, pinned=False, failed=False) == NATIVE_STATUS_NOT_DETERMINED
        assert native_status_for(wei=5, pinned=False, failed=False) == NATIVE_STATUS_PROVEN_NONZERO

    def test_the_fact_is_the_pair_never_the_status_alone(self):
        assert native_balance_fact(NATIVE_STATUS_PROVEN_NONZERO, None) == "nonzero_at_unrecorded_height"
        assert native_balance_fact(NATIVE_STATUS_PROVEN_NONZERO, 25643300) == "proven_nonzero_at_block_25643300"
        assert native_balance_fact(NATIVE_STATUS_PROVEN_ZERO, 25643300) == "proven_zero_at_block_25643300"
        assert native_balance_fact(NATIVE_STATUS_FETCH_FAILED, None) == "not_determined"
        assert native_balance_fact(NATIVE_STATUS_NOT_DETERMINED, None) == "not_determined"
        assert native_balance_fact(NATIVE_STATUS_PROVEN_ZERO, None) == "not_determined"


class TestCompletenessMappingIsTotalAndCannotSayComplete:
    """A13."""

    @pytest.mark.parametrize("status", ASSET_SET_STATUSES + (None,))
    def test_total_over_the_whole_vocabulary(self, status):
        out = _completeness_from_fetch(status)
        assert out in (HOLDINGS_COMPLETENESS_AT_PAGE_CAP, HOLDINGS_COMPLETENESS_NOT_DETERMINED)
        # A non-cap status is consistent with both a whole list and an unproven one.
        assert out != "complete"

    def test_only_the_status_witnesses_the_cap(self):
        """The fetch pages to exhaustion, so only ``at_page_cap`` says the list is a prefix, never a length."""
        assert _completeness_from_fetch(ASSET_SET_STATUS_AT_PAGE_CAP) == HOLDINGS_COMPLETENESS_AT_PAGE_CAP
        assert _completeness_from_fetch(ASSET_SET_STATUS_RETURNED_ASSETS) == HOLDINGS_COMPLETENESS_NOT_DETERMINED


class TestPositiveQuantityGuardFailsClosedWithoutRaising:
    """A10."""

    @pytest.mark.parametrize("raw", ["1", "1000000000000000000"])
    def test_positive(self, raw):
        assert positive_raw_balance(raw) is True

    @pytest.mark.parametrize("raw", ["0", "", None, "not-a-number", "1.5", "0x10", "-3"])
    def test_excluded_and_never_raises(self, raw):
        assert positive_raw_balance(raw) is False


class TestHistoryDepthValidation:
    """A4: depth 0 would prune every fetch and resurrect the legacy rows."""

    @pytest.mark.parametrize("bad", ["0", "-1", "nonsense"])
    def test_rejects_below_one(self, monkeypatch, bad):
        monkeypatch.setenv("PSAT_BALANCE_HISTORY_DEPTH", bad)
        with pytest.raises(ValueError):
            balance_history_depth()


@requires_postgres
class TestViewLegacyArm:
    """A1."""

    def test_legacy_rows_survive_an_all_failed_first_fetch(self, db_session):
        proto = _protocol(db_session, "3s-legacy")
        c = _contract(db_session, proto.id, _addr("11"))
        legacy = _row(db_session, c, token=None)
        legacy_tok = _row(db_session, c, token="0x" + "aa" * 20)
        db_session.commit()
        assert _view_ids(db_session, c.id) == {legacy.id, legacy_tok.id}

        _fetch(db_session, c, native=NATIVE_STATUS_FETCH_FAILED, assets=ASSET_SET_STATUS_FETCH_FAILED)
        db_session.commit()

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
    """A2."""

    def test_native_from_f2_tokens_from_f1(self, db_session):
        proto = _protocol(db_session, "3s-perclass")
        c = _contract(db_session, proto.id, _addr("21"))

        f1 = _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_RETURNED_ASSETS)
        f1_native = _row(db_session, c, token=None, fetch=f1)
        f1_tok = _row(db_session, c, token="0x" + "bb" * 20, fetch=f1)

        f2 = _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_FETCH_FAILED)
        f2_native = _row(db_session, c, token=None, fetch=f2)
        db_session.commit()

        assert _view_ids(db_session, c.id) == {f2_native.id, f1_tok.id}
        assert f1_native.id not in _view_ids(db_session, c.id)


@requires_postgres
class TestViewSynthesizesNothing:
    """A3."""

    def _assert_projection(self, db_session):
        base_ids = set(db_session.execute(select(ContractBalance.id)).scalars().all())
        view_ids = set(db_session.execute(select(ContractBalanceLatest.id)).scalars().all())
        assert view_ids <= base_ids
        base_n = db_session.execute(select(func.count()).select_from(ContractBalance)).scalar_one()
        view_n = db_session.execute(select(func.count()).select_from(ContractBalanceLatest)).scalar_one()
        assert view_n <= base_n
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
    """A4."""

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
            prune_balance_fetches(db_session, ObservationSubject.of_contract(c), c.address)
        db_session.commit()

        surviving = set(
            db_session.execute(select(ContractBalanceFetch.id).where(ContractBalanceFetch.contract_id == c.id))
            .scalars()
            .all()
        )
        assert good.id in surviving
        assert _view_ids(db_session, c.id) == {good_row.id}

    def test_pruning_does_bound_growth(self, db_session, monkeypatch):
        monkeypatch.setenv("PSAT_BALANCE_HISTORY_DEPTH", "2")
        proto = _protocol(db_session, "3s-retention-bound")
        c = _contract(db_session, proto.id, _addr("42"))
        for _ in range(8):
            _fetch(db_session, c)
            db_session.flush()
            prune_balance_fetches(db_session, ObservationSubject.of_contract(c), c.address)
        db_session.commit()
        n = db_session.execute(
            select(func.count()).select_from(ContractBalanceFetch).where(ContractBalanceFetch.contract_id == c.id)
        ).scalar_one()
        assert n == 2


@requires_postgres
class TestFailedFetchIsAbsentNotZero:
    """A11: ``recipes._add_reach`` defaults to ``_ZERO_USD``, so a LEFT JOIN or a 0 for a failed fetch would publish
    a confident zero.
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
        assert _addr("52").lower() not in graph.balance
        assert _addr("52").lower() not in graph.deployment_balance


@requires_postgres
class TestHoldingsRequireAPositiveWitness:

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
        proto = _protocol(db_session, "3s-plane")
        c = _contract(db_session, proto.id, _addr("62"))
        _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_ZERO, block=25643300, assets=ASSET_SET_STATUS_RETURNED_EMPTY)
        db_session.commit()

        assert _asset_holdings_by_deployment(db_session, proto.id) == {}
        assert _token_holdings_by_contract(db_session, proto.id, 5) == {}


@requires_postgres
class TestReachInputsOnAMixedFetchContract:
    """A14(c): the corpus differential only covers the legacy path (new columns are NULL on all 1617 rows)."""

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
        # The priced copy wins the MAX; the unpriced native row is None, never 0.
        assert got == [
            (_addr("71").lower(), tok, 9.0, "not_determined"),
            (_addr("71").lower(), "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", None, "not_determined"),
        ]

    def test_a_capped_sibling_weakens_the_whole_holder(self, db_session):
        """A13."""
        proto = _protocol(db_session, "3s-weakest")
        proxy = _contract(db_session, proto.id, _addr("81"))
        sibling = _contract(db_session, proto.id, _addr("82"))
        # ``_deployment_by_contract`` keys both code rows on the one proxy.
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
        assert {h.completeness for h in items} == {HOLDINGS_COMPLETENESS_AT_PAGE_CAP}


@requires_postgres
class TestSnapshotDoesNotPublishAFailedReadAsMoney:
    """A12."""

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
        # That number would enter TvlSnapshot.total_usd as a measurement.
        keys = {k for k in breakdown}
        assert not any(_addr("a2") in k for k in keys)
        assert any(_addr("a1") in k for k in keys)
        assert [v["total_usd"] for k, v in breakdown.items() if _addr("a1") in k] == [250.0]

    def test_missing_set_is_empty_when_nothing_was_ever_fetched(self, db_session):
        proto = _protocol(db_session, "3s-snapshot-legacy")
        c = _contract(db_session, proto.id, _addr("a3"))
        _row(db_session, c, token=None, usd=5.0)
        db_session.commit()
        assert contracts_missing_current_rows(db_session, [c.id]) == set()
        _breakdown, partial = _read_existing_balances(db_session, proto.id)
        assert partial is True  # Legacy observation times are unknown.


@requires_postgres
class TestAbsentNativeRowIsNeverZero:
    """``recipes._add_reach`` returns before writing when the holder set is empty."""

    def test_no_holder_entry_and_no_zero_valued_pair(self, db_session):
        from services.effects.recipes import _add_reach

        proto = _protocol(db_session, "3s-absent-native")
        c = _contract(db_session, proto.id, _addr("b1"))
        _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_ZERO, block=25643300)
        db_session.commit()

        holdings = _asset_holdings_by_deployment(db_session, proto.id)
        assert holdings.get(_addr("b1").lower()) is None

        concrete: dict = {}
        _add_reach(concrete, cast(Any, object()), (), 0.0, None)
        assert concrete == {}
        assert "observed_reach_value_usd" not in concrete
        assert "reach_determined" not in concrete


@requires_postgres
class TestRowlessNonFailedFetchIsAnIntegrityViolation:
    """R3: writers can't produce this shape anymore, so it's built directly; if it reappears the snapshot must refuse
    it.
    """

    def test_proven_nonzero_with_no_native_row_is_missing(self, db_session):
        proto = _protocol(db_session, "3s-rowless")
        c = _contract(db_session, proto.id, _addr("c1"))
        good = _fetch(db_session, c)
        _row(db_session, c, token=None, usd=99.0, fetch=good)
        _fetch(db_session, c, native=NATIVE_STATUS_PROVEN_NONZERO, assets=ASSET_SET_STATUS_RETURNED_EMPTY)
        db_session.commit()

        assert contracts_missing_current_rows(db_session, [c.id]) == {c.id}
        _breakdown, partial = _read_existing_balances(db_session, proto.id)
        assert partial is True

    def test_proven_zero_with_no_native_row_is_NOT_missing(self, db_session):
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
        """``get_token_balances_page`` drops zero-balance entries, so no rows is reachable without an integrity
        break.
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
    """R4: currency is per ``contract_id`` and last-writer-wins, matching pre-migration semantics; per-address would
    double-count proxy/impl pairs in ``build_authority_graph``.
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

        assert _view_ids(db_session, c.id) == {proxy_row.id}
        assert self_row.id not in _view_ids(db_session, c.id)

        # Compared as a number: the Decimal scale is the column's and carries no claim.
        graph = build_authority_graph(db_session, proto.id)
        assert graph.balance[c.address.lower()] == Decimal("999.00")


@requires_postgres
class TestValuePlaneReadsAssetSetCompleteness:
    """``asset_set_status`` was never read by scoring, so ``ceiling_for`` bounded a move with a prefix of the
    holdings.
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
        assert plane.asset_set_is_truncated(f"ethereum::{whole.address.lower()}") is False

    def test_a_later_uncapped_read_supersedes_the_capped_one(self, db_session):
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

    Nothing carried "this list is everything", so a contract whose every quantity
    was witnessed zero still published ``no_rows`` (an absence where a
    measurement had been made) and ``ceiling_for`` refused it under "no balance
    was ever observed". The witness is the chain's own transfer history through a
    named block, and the ONLY one: a third-party index answering "no tokens"
    triggers the producer to go to the chain, never proves.
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
        record = plane.asset_set_proven_complete[key]
        assert record["swept_through_block"] == 21_000_000 and record["swept_from_block"] == 0
        assert record["basis"] == [self.SCAN_BASIS]
        assert plane.provenance["asset_set_completeness"]["sheets_published_empty"] == 1

    def test_the_etherscan_negative_alone_publishes_nothing(self, db_session):
        """No scan, same empty answer, same pinned zero, and no $0.

        Index completeness: the index's empty list is a completeness claim
        about the index, and under-indexing is precisely its failure mode.
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
        """The sheet state reads the scan, never the answer that triggered it."""
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
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-typed-bad")
        c = _contract(db_session, proto.id, _addr("f6"))
        self._swept(db_session, c, typed=[{"kind": "typed"}])
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        assert plane.sheet_state(f"ethereum::{c.address.lower()}") == P.SHEET_UNPRICED

    def test_an_unscanned_account_of_the_same_sheet_refuses_it(self, db_session):
        """Folded accounts are one asset list; the refusal names the unscanned address because one producer cycle
        closes it.
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
        assert plane.sheet_state(proxy_key) == P.SHEET_NO_ROWS
        assert P.ceiling_for(plane, proxy_key) == (None, P.CEILING_ASSET_LIST_TRUNCATED)

    def test_an_implementation_nobody_ever_read_refuses_the_sheet(self, db_session):
        """The implementation's only fetch was observed at the proxy, so nobody read its own address."""
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-unread-impl")
        impl_address = _addr("fc")
        proxy = _contract(db_session, proto.id, _addr("fb"))
        proxy.implementation = impl_address
        impl = _contract(db_session, proto.id, impl_address)
        db_session.flush()
        self._swept(db_session, proxy)
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

        self._swept(db_session, impl)
        db_session.commit()
        reread = P.load_value_plane(db_session, proto.id)
        assert reread.asset_set_is_proven_complete(proxy_key) is True
        record = reread.asset_set_proven_complete[proxy_key]
        assert record["accounts_scanned"] == record["accounts_folded"] == 2
        assert reread.sheet_state(proxy_key) == P.SHEET_PROVEN_EMPTY

    def test_a_scan_filed_against_a_row_but_issued_elsewhere_scans_nothing(self, db_session):
        """The scan's recipient-topic filter is built from the address read."""
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
        """Live: a proxy read ``proven_nonzero`` while its impl carried a stale ``proven_zero``, and the higher id
        won.
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


@requires_postgres
class TestValuePlaneReadsEntityKeyedSheets:
    """Proven-codeless principals have no ``contracts`` row; their records are keyed on ``(chain, address)`` and read
    through the same conjunction.
    """

    SCAN_BASIS = "chain log sweep of Transfer/TransferSingle/TransferBatch, blocks 0-21000000"

    def _eoa_node(self, session, protocol_id: int, host: Contract, address: str) -> None:
        session.add(
            ControlGraphNode(
                contract_id=host.id,
                address=address,
                node_type="owner",
                resolved_type="eoa",
            )
        )
        session.flush()

    def _entity_fetch(self, session, address: str, *, typed=None, native=NATIVE_STATUS_PROVEN_ZERO):
        f = ContractBalanceFetch(
            contract_id=None,
            entity_chain="ethereum",
            entity_address=address.lower(),
            chain_id=1,
            observed_address=address.lower(),
            block_number=99,
            native_status=native,
            asset_set_status=ASSET_SET_STATUS_RETURNED_EMPTY,
            asset_set_source=ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            asset_set_basis=self.SCAN_BASIS,
            sweep_status=SWEEP_STATUS_COMPLETED,
            swept_from_block=0,
            swept_through_block=21_000_000,
            typed_assets=typed if typed is not None else [],
            writer=BALANCE_WRITER_TVL,
        )
        session.add(f)
        session.flush()
        return f

    def _entity_native_row(self, session, address: str, fetch, *, raw: str = "0") -> None:
        session.add(
            ContractBalance(
                contract_id=None,
                entity_chain="ethereum",
                entity_address=address.lower(),
                token_address=None,
                decimals=18,
                raw_balance=raw,
                usd_value=0.0 if raw == "0" else 1.0,
                observed_address=address.lower(),
                block_number=99,
                fetch_id=fetch.id,
                source=BALANCE_SOURCE_PINNED_NATIVE_READ,
            )
        )
        session.flush()

    def test_a_swept_clean_entity_holder_publishes_a_proven_empty_sheet(self, db_session):
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-entity-empty")
        host = _contract(db_session, proto.id, _addr("g1"))
        eoa = _addr("g2")
        self._eoa_node(db_session, proto.id, host, eoa)
        fetch = self._entity_fetch(db_session, eoa)
        self._entity_native_row(db_session, eoa, fetch)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{eoa.lower()}"
        assert plane.asset_set_is_proven_complete(key) is True
        record = plane.asset_set_proven_complete[key]
        assert (record["accounts_scanned"], record["accounts_folded"]) == (1, 1)
        assert record["accounts"] == [eoa.lower()]
        assert plane.sheet_state(key) == P.SHEET_PROVEN_EMPTY
        assert plane.total(key) == 0.0
        assert key not in plane.contract_entities
        assert plane.provenance["contract_entities"] == len(plane.contract_entities)

    def test_an_entity_holder_with_an_unreadable_typed_receipt_is_refused(self, db_session):
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-entity-typed")
        host = _contract(db_session, proto.id, _addr("g3"))
        eoa = _addr("g4")
        self._eoa_node(db_session, proto.id, host, eoa)
        fetch = self._entity_fetch(
            db_session,
            eoa,
            typed=[{"address": _addr("aa"), "kind": "typed", "quantity_readable": False, "quantity": None}],
        )
        self._entity_native_row(db_session, eoa, fetch)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{eoa.lower()}"
        assert plane.proven_empty_refusal(key) == P.EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED
        assert plane.sheet_state(key) != P.SHEET_PROVEN_EMPTY

    def test_an_entity_outside_the_earned_eoa_witness_is_not_read_at_all(self, db_session):
        """Admission is by getCode witness, never by row existence."""
        from services.scoring import planes as P

        proto = _protocol(db_session, "3s-plane-entity-unwitnessed")
        _contract(db_session, proto.id, _addr("g5"))
        stranger = _addr("g6")
        fetch = self._entity_fetch(db_session, stranger)
        self._entity_native_row(db_session, stranger, fetch)
        db_session.commit()

        plane = P.load_value_plane(db_session, proto.id)
        key = f"ethereum::{stranger.lower()}"
        assert plane.sheet_state(key) == P.SHEET_NO_ROWS
        assert plane.total(key) is None


@requires_postgres
def test_token_only_refresh_preserves_previous_native_zero_evidence(db_session):
    from services.scoring import planes as P

    proto = _protocol(db_session, "native-zero-token-only")
    contract = _contract(db_session, proto.id, _addr("f1"))
    _fetch(db_session, contract, native=NATIVE_STATUS_PROVEN_ZERO, block=25643300)
    _fetch(db_session, contract, native="unattempted", assets=ASSET_SET_STATUS_RETURNED_ASSETS)
    db_session.commit()
    plane = P.load_value_plane(db_session, proto.id)
    state = P.native_value_state(plane, f"ethereum::{contract.address}")
    assert state.state == "proven_zero"
    assert state.value == 0.0
