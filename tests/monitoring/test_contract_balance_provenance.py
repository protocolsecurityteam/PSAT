"""B1: a height is published only for a quantity read at it, an address only because the read was issued against it,
and every failure lands on not-determined instead of destroying what was known.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text, true, update

from db.models import (
    BalanceCollectionState,
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    ContractBalanceLatest,
    Protocol,
)
from services.monitoring.balance_observation import NativeReading
from services.monitoring.balance_reads import PINNED_FINALITY_MARGIN
from services.monitoring.tvl import refresh_contract_balances
from tests.conftest import requires_postgres
from tests.support.balance_stubs import failed_page, page
from utils.balance_status import (
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
)

# The tests replay the wire at this reference height.
BLOCK = 25643300
HEAD = BLOCK + PINNED_FINALITY_MARGIN

_P = "0x00000000000000000000000000000000000b"


def _addr(suffix: str) -> str:
    return (_P + suffix).ljust(42, "0")[:42]


def _word(value: int) -> str:
    return "0x" + f"{value:064x}"


def _protocol(session, name: str) -> Protocol:
    proto = Protocol(name=name)
    session.add(proto)
    session.flush()
    return proto


def _contract(session, protocol_id: int, address: str, chain: str = "ethereum") -> Contract:
    c = Contract(protocol_id=protocol_id, address=address, chain=chain, contract_name="C")
    session.add(c)
    session.flush()
    return c


def _stub_pinned(monkeypatch, balances: dict[str, int] | None, *, head: int = HEAD, raw: dict | None = None):
    """``raw`` pins the short/empty returndata the decoder must refuse."""
    monkeypatch.setattr(
        "services.monitoring.balance_reads.rpc_request",
        lambda url, method, params, **kw: hex(head),
    )

    def _agg3(url, calls, block_tag, **kw):
        assert block_tag == hex(head - PINNED_FINALITY_MARGIN), block_tag
        out = []
        for _target, calldata in calls:
            address = "0x" + calldata[-40:]
            if raw is not None and address in raw:
                out.append(raw[address])
            elif balances is not None and address in balances:
                out.append((True, _word(balances[address])))
            else:
                out.append((False, "0x"))
        return out

    monkeypatch.setattr("services.monitoring.balance_reads.multicall3_aggregate3", _agg3)


def _stub_unpinned(monkeypatch):
    monkeypatch.setattr(
        "services.monitoring.balance_reads.rpc_request",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no rpc")),
    )


def _stub_etherscan(monkeypatch, *, wei, token_page=None):
    def _bal(address, chain_id=1):
        if isinstance(wei, BaseException):
            raise wei
        return wei

    monkeypatch.setattr("services.clients.etherscan.get_eth_balance", _bal)
    monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
    # The resolution worker calls the native quote directly.
    monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda chain_id=1: 2000.0)
    monkeypatch.setattr(
        "services.clients.etherscan.get_token_balances_page",
        lambda address, chain_id=1: token_page if token_page is not None else page([]),
    )


def _fetches(session, contract_id: int, read_class: str | None = None) -> list[ContractBalanceFetch]:
    return list(
        session.execute(
            select(ContractBalanceFetch)
            .where(ContractBalanceFetch.contract_id == contract_id)
            .where(
                ContractBalanceFetch.native_status != "unattempted"
                if read_class == "native"
                else ContractBalanceFetch.asset_set_status != "unattempted"
                if read_class == "tokens"
                else true()
            )
            .order_by(ContractBalanceFetch.id)
        ).scalars()
    )


def _make_due(session):
    session.execute(
        update(BalanceCollectionState).values(next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    session.commit()


def _refresh_due(session, protocol_id):
    _make_due(session)
    return refresh_contract_balances(session, protocol_id)


def _rows(session, contract_id: int) -> list[ContractBalance]:
    return list(
        session.execute(
            select(ContractBalance).where(ContractBalance.contract_id == contract_id).order_by(ContractBalance.id)
        ).scalars()
    )


def _view(session, contract_id: int) -> list[ContractBalanceLatest]:
    return list(
        session.execute(
            select(ContractBalanceLatest)
            .where(ContractBalanceLatest.contract_id == contract_id)
            .order_by(ContractBalanceLatest.id)
        ).scalars()
    )


@requires_postgres
class TestPinnedRowIsByteExact:
    def test_pinned_native_row(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-pinned")
        addr = _addr("11")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {addr: 3_000_000_000_000_000_000})
        _stub_etherscan(monkeypatch, wei=999)  # must NOT be used — pinned wins

        _refresh_due(db_session, proto.id)

        rows = _rows(db_session, c.id)
        assert len(rows) == 1
        row = rows[0]
        assert (row.token_address, row.raw_balance, row.block_number, row.observed_address) == (
            None,
            "3000000000000000000",
            BLOCK,
            addr,
        )
        # The quantity has a height, the price does not.
        assert row.price_block_number is None
        assert row.price_usd == 2000.0

        fetch = _fetches(db_session, c.id, "native")[0]
        assert (fetch.native_status, fetch.block_number, fetch.observed_address, fetch.writer) == (
            NATIVE_STATUS_PROVEN_NONZERO,
            BLOCK,
            addr,
            BALANCE_WRITER_TVL,
        )
        assert row.fetch_id == fetch.id


@requires_postgres
class TestPinnedFailureIsNonDestructive:
    def test_reader_raise_leaves_prior_rows_and_block_untouched(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-nondestructive")
        addr = _addr("21")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {addr: 5_000_000_000_000_000_000})
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)
        before = [(r.id, r.raw_balance, r.block_number) for r in _rows(db_session, c.id)]
        assert before and before[0][2] == BLOCK

        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=RuntimeError("boom"), token_page=failed_page())
        _refresh_due(db_session, proto.id)

        after = [(r.id, r.raw_balance, r.block_number) for r in _rows(db_session, c.id)]
        assert after == before

        fetch = _fetches(db_session, c.id, "native")[-1]
        assert fetch.native_status == NATIVE_STATUS_FETCH_FAILED
        assert fetch.asset_set_status == "unattempted"
        assert _fetches(db_session, c.id, "tokens")[-1].asset_set_status == ASSET_SET_STATUS_FETCH_FAILED
        assert fetch.block_number is None
        assert [r.id for r in _view(db_session, c.id)] == [before[0][0]]


@requires_postgres
class TestUnpinnedZeroIsNotAProvenZero:
    def test_pinned_zero_vs_unpinned_zero(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-zero")
        pinned_c = _contract(db_session, proto.id, _addr("31"))
        db_session.commit()

        _stub_pinned(monkeypatch, {_addr("31"): 0})
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)
        f = _fetches(db_session, pinned_c.id, "native")[0]
        assert (f.native_status, f.block_number) == (NATIVE_STATUS_PROVEN_ZERO, BLOCK)
        # A proven zero at a named height is an observation, though not a holding; holders ask ``positive_raw_balance``.
        pinned_rows = [(r.raw_balance, r.block_number, r.token_address) for r in _rows(db_session, pinned_c.id)]
        assert pinned_rows == [("0", BLOCK, None)]

        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)
        f2 = _fetches(db_session, pinned_c.id, "native")[-1]
        assert (f2.native_status, f2.block_number) == (NATIVE_STATUS_NOT_DETERMINED, None)
        # A zero at an unrecorded moment proves nothing, so nothing is written.
        assert [(r.raw_balance, r.block_number, r.token_address) for r in _rows(db_session, pinned_c.id)] == pinned_rows

    def test_db_refuses_a_blockless_proven_zero(self, db_session):
        proto = _protocol(db_session, "prov-zero-ck")
        c = _contract(db_session, proto.id, _addr("32"))
        db_session.commit()
        with pytest.raises(Exception) as exc:
            db_session.execute(
                text(
                    "INSERT INTO contract_balance_fetches "
                    "(contract_id, chain_id, observed_address, block_number, native_status, "
                    " asset_set_status, writer) "
                    "VALUES (:cid, 1, :a, NULL, 'proven_zero', 'returned_empty', 'tvl')"
                ),
                {"cid": c.id, "a": _addr("32")},
            )
        assert "ck_cbf_proven_zero_requires_block" in str(exc.value)
        db_session.rollback()


@requires_postgres
class TestErc20FailureIsNotAnEmptyHolding:
    def test_failed_token_fetch_keeps_existing_rows(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-tokfail")
        addr = _addr("41")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        tok = {
            "token_address": "0x" + "cc" * 20,
            "token_name": "USDC",
            "token_symbol": "USDC",
            "decimals": 6,
            "balance": 1_000_000,
            "price_usd": 1.0,
            "usd_value": 1.0,
        }
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=0, token_page=page([tok]))
        _refresh_due(db_session, proto.id)
        first = [r.id for r in _rows(db_session, c.id)]
        assert len(first) == 1

        _stub_etherscan(monkeypatch, wei=0, token_page=failed_page())
        _refresh_due(db_session, proto.id)

        assert [r.id for r in _rows(db_session, c.id)] == first
        assert [r.id for r in _view(db_session, c.id)] == first
        f = _fetches(db_session, c.id)[-1]
        assert (f.asset_set_status, f.asset_page_length) == (ASSET_SET_STATUS_FETCH_FAILED, None)


@requires_postgres
class TestSwallowPathsReachFetchFailed:
    """Arm 5: both tvl.py swallows followed by the destructive DELETE published an absence from a failed read."""

    def test_native_swallow(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-swallow-native")
        c = _contract(db_session, proto.id, _addr("51"))
        db_session.commit()
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=RuntimeError("eth down"), token_page=page([]))
        _refresh_due(db_session, proto.id)
        f = _fetches(db_session, c.id, "native")[0]
        assert f.native_status == NATIVE_STATUS_FETCH_FAILED
        assert f.native_status != NATIVE_STATUS_PROVEN_ZERO
        assert f.asset_set_status == "unattempted"
        assert _fetches(db_session, c.id, "tokens")[-1].asset_set_status == ASSET_SET_STATUS_RETURNED_EMPTY
        assert _rows(db_session, c.id) == []

    def test_erc20_swallow(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-swallow-erc20")
        c = _contract(db_session, proto.id, _addr("52"))
        db_session.commit()
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=1, token_page=failed_page())
        _refresh_due(db_session, proto.id)
        f = _fetches(db_session, c.id, "tokens")[0]
        assert f.asset_set_status == ASSET_SET_STATUS_FETCH_FAILED
        assert f.asset_set_status != ASSET_SET_STATUS_RETURNED_EMPTY


@requires_postgres
class TestEmptyPageVsFailedPage:
    def test_distinct_statuses_and_page_lengths(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-empty")
        c = _contract(db_session, proto.id, _addr("61"))
        db_session.commit()
        _stub_unpinned(monkeypatch)

        _stub_etherscan(monkeypatch, wei=0, token_page=page([]))
        _refresh_due(db_session, proto.id)
        _stub_etherscan(monkeypatch, wei=0, token_page=failed_page())
        _refresh_due(db_session, proto.id)

        empty, failed = _fetches(db_session, c.id, "tokens")
        assert (empty.asset_set_status, empty.asset_page_length) == (ASSET_SET_STATUS_RETURNED_EMPTY, 0)
        assert (failed.asset_set_status, failed.asset_page_length) == (ASSET_SET_STATUS_FETCH_FAILED, None)


@requires_postgres
class TestAtPageCapAsksTheRawPage:
    """Arm 7: zero-balance entries are dropped, so the stored-row count can't answer the cap question."""

    def test_full_page_with_dropped_entries(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-cap")
        c = _contract(db_session, proto.id, _addr("71"))
        db_session.commit()
        rows = [
            {
                "token_address": "0x" + f"{i:040x}",
                "token_name": "T",
                "token_symbol": "T",
                "decimals": 18,
                "balance": 5,
                "price_usd": None,
                "usd_value": None,
            }
            for i in range(60)
        ]
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=0, token_page=page(rows, page_length=100))
        _refresh_due(db_session, proto.id)

        f = _fetches(db_session, c.id, "tokens")[0]
        assert f.asset_set_status == "at_page_cap"
        assert f.asset_page_length == 100
        assert len(_rows(db_session, c.id)) == 60


@requires_postgres
class TestObservedAddressPerWriter:
    """Arms 8/9: a fetch row's ``observed_address`` is its own contract's address (the old divergence filed a proxy's
    ETH on the implementation row, then evicted it).
    """

    def test_tvl_records_the_contract_address_even_for_a_proxy(self, db_session, monkeypatch):
        """The TVL loop never reads ``request['proxy_address']``."""
        proto = _protocol(db_session, "prov-obs-tvl")
        proxy_addr = _addr("81")
        impl_addr = _addr("82")
        proxy = _contract(db_session, proto.id, proxy_addr)
        proxy.is_proxy = True
        proxy.implementation = impl_addr
        _contract(db_session, proto.id, impl_addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {proxy_addr: 7})
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)

        fetches = _fetches(db_session, proxy.id)
        assert len(fetches) == 2
        assert fetches[0].observed_address == proxy_addr
        assert [r.observed_address for r in _rows(db_session, proxy.id)] == [proxy_addr]

    def test_the_resolution_worker_files_a_proxy_read_against_the_proxy_row(self, db_session, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.resolution_worker import ResolutionWorker

        proto = _protocol(db_session, "prov-obs-res")
        proxy_addr = _addr("83")
        impl_addr = _addr("84")
        proxy = _contract(db_session, proto.id, proxy_addr)
        impl = _contract(db_session, proto.id, impl_addr)
        db_session.commit()

        worker = ResolutionWorker()
        job = SimpleNamespace(id="j", address=impl_addr, request={"proxy_address": proxy_addr}, chain_id=1)

        read_at: list[str] = []
        _stub_pinned(monkeypatch, {proxy_addr: 4})
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda a, **k: read_at.append(a) or 0)
        monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda *a, **k: 1.0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda *a, **k: 1.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(db_session, job, impl, chain_id=1)

        assert read_at == []  # A pinned native answer suppresses the redundant fallback.
        fetches = _fetches(db_session, proxy.id)
        assert len(fetches) == 2
        assert fetches[0].observed_address == proxy_addr
        assert fetches[0].block_number == BLOCK
        assert [r.observed_address for r in _rows(db_session, proxy.id)] == [proxy_addr]
        assert [r.block_number for r in _rows(db_session, proxy.id)] == [BLOCK]
        assert _fetches(db_session, impl.id) == []
        assert _rows(db_session, impl.id) == []


@requires_postgres
class TestShortReturndataIsNotZero:
    """Arm 10: ``aggregate3`` succeeds on empty data."""

    @pytest.mark.parametrize("returndata", ["0x", "0x00", _word(0)[:-2]])
    def test_short_word_falls_back_to_unpinned(self, db_session, monkeypatch, returndata):
        proto = _protocol(db_session, f"prov-short-{len(returndata)}")
        addr = _addr("91")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, None, raw={addr: (True, returndata)})
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)

        f = _fetches(db_session, c.id, "native")[0]
        assert f.native_status == NATIVE_STATUS_NOT_DETERMINED
        assert f.native_status != NATIVE_STATUS_PROVEN_ZERO
        assert f.block_number is None


@requires_postgres
class TestTokenRowsNeverInheritTheNativeHeight:
    def test_token_rows_have_null_block(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-tokblock")
        addr = _addr("a1")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        tok = {
            "token_address": "0x" + "ab" * 20,
            "token_name": "T",
            "token_symbol": "T",
            "decimals": 18,
            "balance": 9,
            "price_usd": 1.0,
            "usd_value": 9.0,
        }
        _stub_pinned(monkeypatch, {addr: 8})
        _stub_etherscan(monkeypatch, wei=0, token_page=page([tok]))
        _refresh_due(db_session, proto.id)

        rows = {r.token_address: r for r in _rows(db_session, c.id)}
        assert rows[None].block_number == BLOCK
        assert rows[tok["token_address"]].block_number is None
        view = {r.token_address: r for r in _view(db_session, c.id)}
        assert view[tok["token_address"]].block_number is None

    @pytest.mark.parametrize(
        ("slug", "addr_suffix", "sql", "extra_params", "constraint"),
        [
            pytest.param(
                "prov-tokblock-ck",
                "a2",
                "INSERT INTO contract_balances "
                "(contract_id, token_address, decimals, raw_balance, block_number) "
                "VALUES (:cid, :t, 18, '1', 100)",
                {"t": "0x" + "ab" * 20},
                "ck_contract_balances_token_block_null",
                id="token_row_carrying_a_block",
            ),
            pytest.param(
                "prov-priceblock-ck",
                "a3",
                "INSERT INTO contract_balances "
                "(contract_id, decimals, raw_balance, price_block_number) VALUES (:cid, 18, '1', 100)",
                {},
                "ck_contract_balances_price_block_null",
                id="price_height",
            ),
        ],
    )
    def test_db_refuses(self, db_session, slug, addr_suffix, sql, extra_params, constraint):
        proto = _protocol(db_session, slug)
        c = _contract(db_session, proto.id, _addr(addr_suffix))
        db_session.commit()
        with pytest.raises(Exception) as exc:
            db_session.execute(text(sql), {"cid": c.id, **extra_params})
        assert constraint in str(exc.value)
        db_session.rollback()


@requires_postgres
class TestInsertOnlyHistory:
    def test_both_rows_persist_view_returns_latest(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-insertonly")
        addr = _addr("b1")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {addr: 1}, head=HEAD)
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)
        _stub_pinned(monkeypatch, {addr: 2}, head=HEAD + 1)
        _refresh_due(db_session, proto.id)

        rows = _rows(db_session, c.id)
        assert [(r.raw_balance, r.block_number) for r in rows] == [("1", BLOCK), ("2", BLOCK + 1)]
        view = _view(db_session, c.id)
        assert [(r.raw_balance, r.block_number) for r in view] == [("2", BLOCK + 1)]


@requires_postgres
class TestSoldAssetDisappears:
    """Arm 13: the latest fetch's rows are the observed set."""

    def test_asset_absent_from_the_new_fetch_leaves_the_view(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-sold")
        addr = _addr("c1")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()
        tok = {
            "token_address": "0x" + "ee" * 20,
            "token_name": "T",
            "token_symbol": "T",
            "decimals": 18,
            "balance": 3,
            "price_usd": 1.0,
            "usd_value": 3.0,
        }
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=0, token_page=page([tok]))
        _refresh_due(db_session, proto.id)
        assert len(_view(db_session, c.id)) == 1

        _stub_etherscan(monkeypatch, wei=0, token_page=page([]))
        _refresh_due(db_session, proto.id)

        assert _view(db_session, c.id) == []
        assert len(_rows(db_session, c.id)) == 1


@requires_postgres
class TestHalvesFailIndependently:
    """R1 / F-1: the worker's Etherscan calls fail independently, and an early return after the fetch row published a
    row-less class that withdrew prior holdings.
    """

    def _worker_fetch(self, db_session, monkeypatch, contract, *, native_raises, pinned):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.resolution_worker import ResolutionWorker

        tok = {
            "token_address": "0x" + "f1" * 20,
            "token_name": "T",
            "token_symbol": "T",
            "decimals": 18,
            "balance": 42,
            "price_usd": 1.0,
            "usd_value": 42.0,
        }
        if pinned:
            _stub_pinned(monkeypatch, {contract.address: 6})
        else:
            _stub_unpinned(monkeypatch)
        _stub_etherscan(
            monkeypatch,
            wei=RuntimeError("eth down") if native_raises else 0,
            token_page=page([tok]),
        )
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)
        worker = ResolutionWorker()
        job = SimpleNamespace(id="j1", address=contract.address, request={}, chain_id=1)
        _make_due(db_session)
        cast(Any, worker)._fetch_balances(db_session, job, contract, chain_id=1)

    def test_token_half_succeeding_persists_its_rows(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-f1")
        addr = _addr("d1")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        self._worker_fetch(db_session, monkeypatch, c, native_raises=False, pinned=True)
        prior_view = _view(db_session, c.id)
        assert {r.token_address for r in prior_view} == {None, "0x" + "f1" * 20}

        self._worker_fetch(db_session, monkeypatch, c, native_raises=True, pinned=True)

        fetch = _fetches(db_session, c.id)[-1]
        view = _view(db_session, c.id)
        by_class = {r.token_address: r for r in view}

        for row_class, status in (
            (None, fetch.native_status),
            ("0x" + "f1" * 20, fetch.asset_set_status),
        ):
            if status not in ("fetch_failed", "unattempted"):
                assert row_class in by_class, f"{status} promised rows for {row_class} and wrote none"
                assert by_class[row_class].fetch_id == fetch.id

        assert {r.token_address for r in view} == {None, "0x" + "f1" * 20}
        assert by_class[None].raw_balance == "6"
        assert by_class[None].block_number == BLOCK

    def test_native_half_failing_outright_leaves_the_prior_native_holding(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-f1-nofallback")
        addr = _addr("d2")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        self._worker_fetch(db_session, monkeypatch, c, native_raises=False, pinned=True)
        first_native = [r for r in _view(db_session, c.id) if r.token_address is None]
        assert len(first_native) == 1

        self._worker_fetch(db_session, monkeypatch, c, native_raises=True, pinned=False)

        fetch = _fetches(db_session, c.id, "native")[-1]
        assert fetch.native_status == NATIVE_STATUS_FETCH_FAILED
        assert fetch.asset_set_status == "unattempted"
        assert _fetches(db_session, c.id, "tokens")[-1].asset_set_status == ASSET_SET_STATUS_RETURNED_ASSETS
        view_native = [r for r in _view(db_session, c.id) if r.token_address is None]
        assert [r.id for r in view_native] == [r.id for r in first_native]


def _entity_view(session, chain: str, address: str) -> list[ContractBalanceLatest]:
    return list(
        session.execute(
            select(ContractBalanceLatest)
            .where(
                ContractBalanceLatest.contract_id.is_(None),
                ContractBalanceLatest.entity_chain == chain,
                ContractBalanceLatest.entity_address == address,
            )
            .order_by(ContractBalanceLatest.id)
        ).scalars()
    )


def _observe_entity(session, chain: str, address: str, *, wei: int, block: int | None, failed_assets: bool = False):
    from services.monitoring.balance_observation import record_observation
    from services.monitoring.balance_reads import ObservationSubject

    return record_observation(
        session,
        subject=ObservationSubject.of_entity(chain, address),
        chain_id=1,
        native=NativeReading(wei=wei, block_number=block, failed=False, price_usd=2000.0, symbol="ETH", name="Ether"),
        page=failed_page() if failed_assets else page([]),
        writer=BALANCE_WRITER_TVL,
    )


@requires_postgres
class TestEntityKeyedRecordsReachTheView:
    """The view's contract_id join is NULL for entity-keyed rows, which were stored but invisible."""

    def test_an_entity_keyed_row_is_returned_by_the_view(self, db_session):
        address = _addr("e1")
        recorded = _observe_entity(db_session, "ethereum", address, wei=7, block=BLOCK)
        db_session.flush()
        assert recorded.fetch.contract_id is None
        assert (recorded.fetch.entity_chain, recorded.fetch.entity_address) == ("ethereum", address)

        view = _entity_view(db_session, "ethereum", address)
        assert [(r.raw_balance, r.block_number) for r in view] == [("7", BLOCK)]
        assert [r.observed_address for r in view] == [address]

    def test_the_later_non_failed_fetch_wins_the_entity_arm_wholesale(self, db_session):
        address = _addr("e2")
        _observe_entity(db_session, "ethereum", address, wei=1, block=BLOCK)
        db_session.flush()
        _observe_entity(db_session, "ethereum", address, wei=2, block=BLOCK + 1)
        db_session.flush()

        view = _entity_view(db_session, "ethereum", address)
        assert [(r.raw_balance, r.block_number) for r in view] == [("2", BLOCK + 1)]
        stored = db_session.execute(
            select(ContractBalance).where(ContractBalance.entity_address == address).order_by(ContractBalance.id)
        ).scalars()
        assert [r.raw_balance for r in stored] == ["1", "2"]

    def test_a_failed_asset_class_does_not_withdraw_the_entity_native_row(self, db_session):
        address = _addr("e3")
        _observe_entity(db_session, "ethereum", address, wei=5, block=BLOCK)
        db_session.flush()
        _observe_entity(db_session, "ethereum", address, wei=6, block=BLOCK + 1, failed_assets=True)
        db_session.flush()
        # Same per-class rule as the contract arm.
        view = _entity_view(db_session, "ethereum", address)
        assert [(r.raw_balance, r.token_address) for r in view] == [("6", None)]

    def test_one_address_two_subjects_never_share_rows(self, db_session, monkeypatch):
        """The identity is the subject, not the address."""
        proto = _protocol(db_session, "prov-entity-collision")
        address = _addr("e4")
        c = _contract(db_session, proto.id, address)
        db_session.commit()
        _stub_pinned(monkeypatch, {address: 11}, head=HEAD)
        _stub_etherscan(monkeypatch, wei=0)
        _refresh_due(db_session, proto.id)

        _observe_entity(db_session, "ethereum", address, wei=99, block=BLOCK + 5)
        db_session.flush()

        assert [r.raw_balance for r in _view(db_session, c.id)] == ["11"]
        assert [r.raw_balance for r in _entity_view(db_session, "ethereum", address)] == ["99"]

    def test_a_row_must_carry_exactly_one_subject_key(self, db_session):
        proto = _protocol(db_session, "prov-entity-check")
        c = _contract(db_session, proto.id, _addr("e5"))
        db_session.commit()
        for kwargs in (
            {"contract_id": c.id, "entity_chain": "ethereum", "entity_address": _addr("e5")},
            {"contract_id": None, "entity_chain": None, "entity_address": None},
            {"contract_id": None, "entity_chain": "ethereum", "entity_address": None},
        ):
            db_session.add(ContractBalance(token_address=None, decimals=18, raw_balance="1", **kwargs))
            with pytest.raises(Exception) as exc:
                db_session.flush()
            assert "exactly_one_subject_key" in str(exc.value)
            db_session.rollback()
