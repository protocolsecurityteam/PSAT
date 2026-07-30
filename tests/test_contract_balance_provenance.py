"""B1 — balance provenance: observed address, observation height, insert-only.

The governing rule these arms encode: a value is published as a positive fact
only when the evidence proves it. Here that means a height is published only for
a quantity that was READ at that height, an address is published only because it
was the address the read was issued against, and every failure lands on an
explicit not-determined state instead of destroying what was previously known.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from db.models import Contract, ContractBalance, ContractBalanceFetch, ContractBalanceLatest, Protocol
from services.monitoring.balance_reads import PINNED_FINALITY_MARGIN
from services.monitoring.tvl import refresh_contract_balances
from tests.conftest import requires_postgres
from tests.support.balance_stubs import failed_page, page
from utils.balance_status import (
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
)

# The investigation's reference height. Every pinned read in this unit
# reproduces here, and the tests replay the wire rather than touching it.
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
    """Replay the pinned wire: ``eth_blockNumber`` then one ``aggregate3``.

    ``balances`` maps address -> wei and is encoded as full 32-byte words.
    ``raw`` overrides the per-address returndata verbatim, so an arm can pin the
    short/empty-returndata shapes the decoder must refuse.
    """
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
    """No pinned path available — the height cannot be established."""
    monkeypatch.setattr(
        "services.monitoring.balance_reads.rpc_request",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no rpc")),
    )


def _stub_etherscan(monkeypatch, *, wei, token_page=None):
    def _bal(address, chain_id=1):
        if isinstance(wei, BaseException):
            raise wei
        return wei

    monkeypatch.setattr("utils.etherscan.get_eth_balance", _bal)
    monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
    monkeypatch.setattr(
        "utils.etherscan.get_token_balances_page",
        lambda address, chain_id=1: token_page if token_page is not None else page([]),
    )


def _fetches(session, contract_id: int) -> list[ContractBalanceFetch]:
    return list(
        session.execute(
            select(ContractBalanceFetch)
            .where(ContractBalanceFetch.contract_id == contract_id)
            .order_by(ContractBalanceFetch.id)
        ).scalars()
    )


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
    """Arm 1 — the pinned happy path, pinned to the exact persisted tuple."""

    def test_pinned_native_row(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-pinned")
        addr = _addr("11")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {addr: 3_000_000_000_000_000_000})
        _stub_etherscan(monkeypatch, wei=999)  # must NOT be used — pinned wins

        refresh_contract_balances(db_session, proto.id)

        rows = _rows(db_session, c.id)
        assert len(rows) == 1
        row = rows[0]
        assert (row.token_address, row.raw_balance, row.block_number, row.observed_address) == (
            None,
            "3000000000000000000",
            BLOCK,
            addr,
        )
        # The anti-inheritance guard: the quantity has a height, the PRICE does
        # not, and nothing may substitute one for the other.
        assert row.price_block_number is None
        assert row.price_usd == 2000.0

        fetch = _fetches(db_session, c.id)[0]
        assert (fetch.native_status, fetch.block_number, fetch.observed_address, fetch.writer) == (
            NATIVE_STATUS_PROVEN_NONZERO,
            BLOCK,
            addr,
            BALANCE_WRITER_TVL,
        )
        assert row.fetch_id == fetch.id


@requires_postgres
class TestPinnedFailureIsNonDestructive:
    """Arm 2 — a failing reader deletes nothing and writes no holding."""

    def test_reader_raise_leaves_prior_rows_and_block_untouched(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-nondestructive")
        addr = _addr("21")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {addr: 5_000_000_000_000_000_000})
        _stub_etherscan(monkeypatch, wei=0)
        refresh_contract_balances(db_session, proto.id)
        before = [(r.id, r.raw_balance, r.block_number) for r in _rows(db_session, c.id)]
        assert before and before[0][2] == BLOCK

        # Everything fails on the second cycle.
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=RuntimeError("boom"), token_page=failed_page())
        refresh_contract_balances(db_session, proto.id)

        after = [(r.id, r.raw_balance, r.block_number) for r in _rows(db_session, c.id)]
        # No row deleted, no row written, the pre-existing block untouched.
        assert after == before

        fetch = _fetches(db_session, c.id)[-1]
        assert fetch.native_status == NATIVE_STATUS_FETCH_FAILED
        assert fetch.asset_set_status == ASSET_SET_STATUS_FETCH_FAILED
        assert fetch.block_number is None
        # And the view still publishes the last good observation.
        assert [r.id for r in _view(db_session, c.id)] == [before[0][0]]


@requires_postgres
class TestUnpinnedZeroIsNotAProvenZero:
    """Arm 3 — the same zero from two paths is two different facts."""

    def test_pinned_zero_vs_unpinned_zero(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-zero")
        pinned_c = _contract(db_session, proto.id, _addr("31"))
        db_session.commit()

        _stub_pinned(monkeypatch, {_addr("31"): 0})
        _stub_etherscan(monkeypatch, wei=0)
        refresh_contract_balances(db_session, proto.id)
        f = _fetches(db_session, pinned_c.id)[0]
        assert (f.native_status, f.block_number) == (NATIVE_STATUS_PROVEN_ZERO, BLOCK)
        # A proven zero is still not a holding.
        assert _rows(db_session, pinned_c.id) == []

        # Same observed value, unpinned path.
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=0)
        refresh_contract_balances(db_session, proto.id)
        f2 = _fetches(db_session, pinned_c.id)[-1]
        assert (f2.native_status, f2.block_number) == (NATIVE_STATUS_NOT_DETERMINED, None)

    def test_db_refuses_a_blockless_proven_zero(self, db_session):
        """The gate is a constraint, not writer discipline."""
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
    """Arm 4 — a failed asset fetch never withdraws the stored holdings."""

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
        refresh_contract_balances(db_session, proto.id)
        first = [r.id for r in _rows(db_session, c.id)]
        assert len(first) == 1

        _stub_etherscan(monkeypatch, wei=0, token_page=failed_page())
        refresh_contract_balances(db_session, proto.id)

        assert [r.id for r in _rows(db_session, c.id)] == first
        assert [r.id for r in _view(db_session, c.id)] == first
        f = _fetches(db_session, c.id)[-1]
        assert (f.asset_set_status, f.asset_page_length) == (ASSET_SET_STATUS_FETCH_FAILED, None)


@requires_postgres
class TestSwallowPathsReachFetchFailed:
    """Arm 5 — BOTH tvl.py swallows, independently.

    The native swallow set ``eth_wei = 0`` and the ERC-20 swallow set
    ``token_list = []``; either one followed by the destructive DELETE published
    a proven-sounding absence out of a failed read.
    """

    def test_native_swallow(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-swallow-native")
        c = _contract(db_session, proto.id, _addr("51"))
        db_session.commit()
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=RuntimeError("eth down"), token_page=page([]))
        refresh_contract_balances(db_session, proto.id)
        f = _fetches(db_session, c.id)[0]
        assert f.native_status == NATIVE_STATUS_FETCH_FAILED
        assert f.native_status != NATIVE_STATUS_PROVEN_ZERO
        assert f.asset_set_status == ASSET_SET_STATUS_RETURNED_EMPTY
        assert _rows(db_session, c.id) == []

    def test_erc20_swallow(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-swallow-erc20")
        c = _contract(db_session, proto.id, _addr("52"))
        db_session.commit()
        _stub_unpinned(monkeypatch)
        _stub_etherscan(monkeypatch, wei=1, token_page=failed_page())
        refresh_contract_balances(db_session, proto.id)
        f = _fetches(db_session, c.id)[0]
        assert f.asset_set_status == ASSET_SET_STATUS_FETCH_FAILED
        assert f.asset_set_status != ASSET_SET_STATUS_RETURNED_EMPTY


@requires_postgres
class TestEmptyPageVsFailedPage:
    """Arm 6 — a clean empty page and a failed fetch are distinct states."""

    def test_distinct_statuses_and_page_lengths(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-empty")
        c = _contract(db_session, proto.id, _addr("61"))
        db_session.commit()
        _stub_unpinned(monkeypatch)

        _stub_etherscan(monkeypatch, wei=0, token_page=page([]))
        refresh_contract_balances(db_session, proto.id)
        _stub_etherscan(monkeypatch, wei=0, token_page=failed_page())
        refresh_contract_balances(db_session, proto.id)

        empty, failed = _fetches(db_session, c.id)
        assert (empty.asset_set_status, empty.asset_page_length) == (ASSET_SET_STATUS_RETURNED_EMPTY, 0)
        assert (failed.asset_set_status, failed.asset_page_length) == (ASSET_SET_STATUS_FETCH_FAILED, None)


@requires_postgres
class TestAtPageCapAsksTheRawPage:
    """Arm 7 — the cap is a fact about the ENDPOINT's page, not the stored rows.

    The producer drops every zero-balance entry, so a full page with any such
    entry stores fewer rows than the cap and a stored-row count reads as "not
    truncated" — the signal destroyed one line above where it used to be read.
    """

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
        refresh_contract_balances(db_session, proto.id)

        f = _fetches(db_session, c.id)[0]
        assert f.asset_set_status == "at_page_cap"
        assert f.asset_page_length == 100
        assert len(_rows(db_session, c.id)) == 60


@requires_postgres
class TestObservedAddressPerWriter:
    """Arms 8/9 — the two writers observe different addresses, on purpose."""

    def test_tvl_records_the_contract_address_even_for_a_proxy(self, db_session, monkeypatch):
        """The TVL loop never reads ``request['proxy_address']``.

        Only the resolution worker does. Recording the proxy here would attribute
        the read to an address this writer never issued it against.
        """
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
        refresh_contract_balances(db_session, proto.id)

        fetches = _fetches(db_session, proxy.id)
        assert len(fetches) == 1
        assert fetches[0].observed_address == proxy_addr
        assert [r.observed_address for r in _rows(db_session, proxy.id)] == [proxy_addr]

    def test_resolution_worker_records_the_proxy_it_read(self, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast
        from unittest.mock import MagicMock

        from workers.resolution_worker import ResolutionWorker

        impl = "0x" + "11" * 20
        proxy = "0x" + "22" * 20
        worker = ResolutionWorker()
        session = MagicMock()
        job = SimpleNamespace(id="j", address=impl, request={"proxy_address": proxy}, chain_id=1)

        monkeypatch.setattr("services.monitoring.balance_reads.rpc_request", lambda *a, **k: hex(HEAD))
        monkeypatch.setattr(
            "services.monitoring.balance_reads.multicall3_aggregate3",
            lambda url, calls, block_tag, **kw: [(True, _word(4))],
        )
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda a, **k: 0)
        monkeypatch.setattr("utils.etherscan.get_native_price", lambda *a, **k: 1.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, SimpleNamespace(id=42), chain_id=1)

        added = [c.args[0] for c in session.add.call_args_list if c.args]
        fetch = [o for o in added if isinstance(o, ContractBalanceFetch)][0]
        balances = [o for o in added if isinstance(o, ContractBalance)]
        assert fetch.observed_address == proxy
        assert fetch.block_number == BLOCK
        assert [b.observed_address for b in balances] == [proxy]
        assert [b.block_number for b in balances] == [BLOCK]


@requires_postgres
class TestShortReturndataIsNotZero:
    """Arm 10 — ``(success=True, "0x")`` is a failure, never a proven zero.

    ``aggregate3`` reports success for a call that returned no data. Decoding
    that as 0 would mint a proven zero from an empty return: a default standing
    in for a witness.
    """

    @pytest.mark.parametrize("returndata", ["0x", "0x00", _word(0)[:-2]])
    def test_short_word_falls_back_to_unpinned(self, db_session, monkeypatch, returndata):
        proto = _protocol(db_session, f"prov-short-{len(returndata)}")
        addr = _addr("91")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, None, raw={addr: (True, returndata)})
        _stub_etherscan(monkeypatch, wei=0)
        refresh_contract_balances(db_session, proto.id)

        f = _fetches(db_session, c.id)[0]
        assert f.native_status == NATIVE_STATUS_NOT_DETERMINED
        assert f.native_status != NATIVE_STATUS_PROVEN_ZERO
        assert f.block_number is None


@requires_postgres
class TestTokenRowsNeverInheritTheNativeHeight:
    """Arm 11 — a pinned native read does not lend its height to ERC-20 rows."""

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
        refresh_contract_balances(db_session, proto.id)

        rows = {r.token_address: r for r in _rows(db_session, c.id)}
        assert rows[None].block_number == BLOCK
        assert rows[tok["token_address"]].block_number is None
        # And the fetch's native height is not projected onto the token row by
        # the view either.
        view = {r.token_address: r for r in _view(db_session, c.id)}
        assert view[tok["token_address"]].block_number is None

    def test_db_refuses_a_token_row_carrying_a_block(self, db_session):
        proto = _protocol(db_session, "prov-tokblock-ck")
        c = _contract(db_session, proto.id, _addr("a2"))
        db_session.commit()
        with pytest.raises(Exception) as exc:
            db_session.execute(
                text(
                    "INSERT INTO contract_balances "
                    "(contract_id, token_address, decimals, raw_balance, block_number) "
                    "VALUES (:cid, :t, 18, '1', 100)"
                ),
                {"cid": c.id, "t": "0x" + "ab" * 20},
            )
        assert "ck_contract_balances_token_block_null" in str(exc.value)
        db_session.rollback()

    def test_db_refuses_a_price_height(self, db_session):
        proto = _protocol(db_session, "prov-priceblock-ck")
        c = _contract(db_session, proto.id, _addr("a3"))
        db_session.commit()
        with pytest.raises(Exception) as exc:
            db_session.execute(
                text(
                    "INSERT INTO contract_balances "
                    "(contract_id, decimals, raw_balance, price_block_number) VALUES (:cid, 18, '1', 100)"
                ),
                {"cid": c.id},
            )
        assert "ck_contract_balances_price_block_null" in str(exc.value)
        db_session.rollback()


@requires_postgres
class TestInsertOnlyHistory:
    """Arm 12 — two heights coexist and the view returns exactly the newer one."""

    def test_both_rows_persist_view_returns_latest(self, db_session, monkeypatch):
        proto = _protocol(db_session, "prov-insertonly")
        addr = _addr("b1")
        c = _contract(db_session, proto.id, addr)
        db_session.commit()

        _stub_pinned(monkeypatch, {addr: 1}, head=HEAD)
        _stub_etherscan(monkeypatch, wei=0)
        refresh_contract_balances(db_session, proto.id)
        _stub_pinned(monkeypatch, {addr: 2}, head=HEAD + 1)
        refresh_contract_balances(db_session, proto.id)

        rows = _rows(db_session, c.id)
        assert [(r.raw_balance, r.block_number) for r in rows] == [("1", BLOCK), ("2", BLOCK + 1)]
        view = _view(db_session, c.id)
        assert [(r.raw_balance, r.block_number) for r in view] == [("2", BLOCK + 1)]


@requires_postgres
class TestSoldAssetDisappears:
    """Arm 13 — insert-only must not republish a holding that is gone.

    The latest fetch's rows ARE the set it observed; a per-asset "latest row"
    view would keep a sold asset alive forever.
    """

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
        refresh_contract_balances(db_session, proto.id)
        assert len(_view(db_session, c.id)) == 1

        _stub_etherscan(monkeypatch, wei=0, token_page=page([]))
        refresh_contract_balances(db_session, proto.id)

        assert _view(db_session, c.id) == []
        # ...but the history is still there. Insert-only means nothing is lost.
        assert len(_rows(db_session, c.id)) == 1
