"""B1: a height is published only for a quantity read at it, an address only because the read was issued against it,
and every failure lands on not-determined instead of destroying what was known.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, true, update

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
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
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


@requires_postgres
class TestObservedAddressPerWriter:
    """Arms 8/9: a fetch row's ``observed_address`` is its own contract's address (the old divergence filed a proxy's
    ETH on the implementation row, then evicted it).
    """

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
