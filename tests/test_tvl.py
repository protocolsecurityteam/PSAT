"""Tests for protocol-wide TVL tracking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from db.models import Contract, ContractBalance, Protocol, TvlSnapshot
from services.monitoring.tvl import (
    _get_protocol_addresses,
    fetch_defillama_tvl,
    refresh_all_protocols,
    refresh_contract_balances,
    take_tvl_snapshot,
)
from tests.conftest import requires_postgres

# Unique address helpers — each test class gets its own prefix to avoid
# unique-constraint collisions across tests sharing the same DB.
_ADDR_PREFIX = {
    "get_addrs": "0x0000000000000000000000000000000000001",
    "refresh": "0x0000000000000000000000000000000000002",
    "failure": "0x0000000000000000000000000000000000003",
    "snap_both": "0x0000000000000000000000000000000000004",
    "snap_onchain": "0x0000000000000000000000000000000000005",
    "all_protos": "0x0000000000000000000000000000000000006",
}


def _addr(prefix_key: str, suffix: str) -> str:
    base = _ADDR_PREFIX[prefix_key]
    return (base + suffix).ljust(42, "0")[:42]


@pytest.fixture()
def _cleanup(db_session):
    """Ensure test rows are cleaned up even on failure."""
    yield
    db_session.rollback()
    db_session.query(TvlSnapshot).delete()
    db_session.query(ContractBalance).delete()
    db_session.query(Contract).delete()
    db_session.query(Protocol).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# Unit tests (no DB needed)
# ---------------------------------------------------------------------------


class TestFetchDefillamaTvl:
    """Test DefiLlama TVL fetching with mocked HTTP."""

    @patch("services.monitoring.tvl.requests.get")
    @patch("services.discovery.protocol_resolver.resolve_protocol")
    def test_happy_path(self, mock_resolve, mock_get):
        mock_resolve.return_value = {"slug": "aave-v3"}
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "tvl": 12_000_000_000.50,
                "currentChainTvls": {
                    "Ethereum": 8_000_000_000,
                    "Arbitrum": 2_000_000_000,
                    "borrowed-Ethereum": 5_000_000_000,
                },
            },
        )

        result = fetch_defillama_tvl("Aave")
        assert result is not None
        assert result["tvl"] == 12_000_000_000.50
        assert "Ethereum" in result["chain_breakdown"]
        assert "Arbitrum" in result["chain_breakdown"]
        assert "borrowed-Ethereum" not in result["chain_breakdown"]

    @patch("services.discovery.protocol_resolver.resolve_protocol")
    def test_no_slug(self, mock_resolve):
        mock_resolve.return_value = {"slug": None}
        assert fetch_defillama_tvl("UnknownProtocol") is None

    @patch("services.monitoring.tvl.requests.get")
    @patch("services.discovery.protocol_resolver.resolve_protocol")
    def test_http_failure(self, mock_resolve, mock_get):
        mock_resolve.return_value = {"slug": "aave-v3"}
        mock_get.side_effect = Exception("timeout")
        assert fetch_defillama_tvl("Aave") is None


# ---------------------------------------------------------------------------
# DB tests — require PostgreSQL
# ---------------------------------------------------------------------------


@requires_postgres
class TestGetProtocolAddresses:
    def test_excludes_implementation_behind_proxy(self, db_session, _cleanup):
        protocol = Protocol(name="TestProto_getaddrs")
        db_session.add(protocol)
        db_session.flush()

        proxy_addr = _addr("get_addrs", "a1")
        impl_addr = _addr("get_addrs", "b2")
        regular_addr = _addr("get_addrs", "c3")

        proxy = Contract(
            address=proxy_addr,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_name="Proxy",
            is_proxy=True,
            implementation=impl_addr,
        )
        impl = Contract(address=impl_addr, chain="ethereum", protocol_id=protocol.id, contract_name="Impl")
        regular = Contract(address=regular_addr, chain="ethereum", protocol_id=protocol.id, contract_name="Regular")
        db_session.add_all([proxy, impl, regular])
        db_session.commit()

        addresses = _get_protocol_addresses(db_session, protocol.id)
        addr_set = {c.address.lower() for c in addresses}

        assert proxy_addr.lower() in addr_set
        assert regular_addr.lower() in addr_set
        assert impl_addr.lower() not in addr_set


@requires_postgres
class TestRefreshContractBalances:
    def test_stores_balances_and_returns_breakdown(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="TestProto_refresh")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("refresh", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 2_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr(
            "utils.etherscan.get_token_balances",
            lambda address, chain_id=1: [
                {
                    "token_address": "0x" + "dd" * 20,
                    "token_name": "USDC",
                    "token_symbol": "USDC",
                    "decimals": 6,
                    "balance": 500_000_000,
                    "price_usd": 1.0,
                    "usd_value": 500.0,
                }
            ],
        )

        breakdown = refresh_contract_balances(db_session, protocol.id)

        assert addr.lower() in breakdown
        assert breakdown[addr.lower()]["total_usd"] == 4500.0
        assert breakdown[addr.lower()]["name"] == "Vault"

        balances = db_session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).all()
        assert len(balances) == 2
        assert {b.token_symbol for b in balances} == {"ETH", "USDC"}

    def test_handles_balance_failure_gracefully(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="TestProto_failure")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("failure", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        def _raise(addr, chain_id=1):
            raise RuntimeError("RPC failed")

        monkeypatch.setattr("utils.etherscan.get_eth_balance", _raise)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances", _raise)

        breakdown = refresh_contract_balances(db_session, protocol.id)

        assert addr.lower() in breakdown
        assert breakdown[addr.lower()]["total_usd"] == 0.0


@requires_postgres
class TestTakeTvlSnapshot:
    def test_creates_snapshot_with_both_sources(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="Aave_snap_both")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("snap_both", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Pool")
        db_session.add(contract)
        db_session.commit()

        monkeypatch.setattr(
            "services.monitoring.tvl.fetch_defillama_tvl",
            lambda name: {"tvl": 10_000_000.0, "chain_breakdown": {"Ethereum": 10_000_000.0}},
        )
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 1_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 3000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances", lambda address, chain_id=1: [])

        snapshot = take_tvl_snapshot(db_session, protocol.id)

        assert snapshot is not None
        assert snapshot.source == "both"
        assert snapshot.total_usd is not None and float(snapshot.total_usd) == 3000.0
        assert snapshot.defillama_tvl is not None and float(snapshot.defillama_tvl) == 10_000_000.0
        assert snapshot.chain_breakdown == {"Ethereum": 10_000_000.0}
        assert snapshot.contract_breakdown is not None

    def test_on_chain_only_when_no_defillama(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="Unknown_snap_onchain")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("snap_onchain", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances", lambda address, chain_id=1: [])

        snapshot = take_tvl_snapshot(db_session, protocol.id)

        assert snapshot is not None
        assert snapshot.source == "on_chain"
        assert snapshot.defillama_tvl is None

    def test_returns_none_for_missing_protocol(self, db_session):
        assert take_tvl_snapshot(db_session, 999999) is None


@requires_postgres
class TestRefreshAllProtocols:
    def test_snapshots_all_protocols(self, db_session, monkeypatch, _cleanup):
        p1 = Protocol(name="Proto1_all")
        p2 = Protocol(name="Proto2_all")
        db_session.add_all([p1, p2])
        db_session.flush()

        for i, p in enumerate([p1, p2]):
            db_session.add(
                Contract(
                    address=_addr("all_protos", f"{p.id:02x}{i}"),
                    chain="ethereum",
                    protocol_id=p.id,
                    contract_name=f"Contract_{p.id}",
                )
            )
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances", lambda address, chain_id=1: [])

        count = refresh_all_protocols(db_session)
        assert count == 2

        snapshots = db_session.query(TvlSnapshot).all()
        assert len(snapshots) == 2

    def test_rotation_oldest_and_no_snapshot_first_capped(self, db_session, monkeypatch, _cleanup):
        from datetime import datetime, timezone

        recent = datetime(2025, 1, 1, tzinfo=timezone.utc)
        p_a = Protocol(name="RotA")
        p_b = Protocol(name="RotB")
        p_c = Protocol(name="RotC")
        p_d = Protocol(name="RotD")
        db_session.add_all([p_a, p_b, p_c, p_d])
        db_session.flush()

        # p_a/p_b/p_d carry aged snapshots (beyond MIN_SNAPSHOT_INTERVAL);
        # p_c has none, so it must sort first.
        db_session.add(
            TvlSnapshot(protocol_id=p_a.id, timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc), source="on_chain")
        )
        db_session.add(
            TvlSnapshot(protocol_id=p_b.id, timestamp=datetime(2021, 1, 1, tzinfo=timezone.utc), source="on_chain")
        )
        db_session.add(
            TvlSnapshot(protocol_id=p_d.id, timestamp=datetime(2022, 1, 1, tzinfo=timezone.utc), source="on_chain")
        )
        db_session.commit()

        monkeypatch.setenv("PSAT_TVL_PROTOCOLS_PER_PASS", "2")
        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances", lambda address, chain_id=1: [])

        count = refresh_all_protocols(db_session)
        assert count == 2  # cap honored

        def _fresh(pid: int) -> bool:
            return (
                db_session.query(TvlSnapshot)
                .filter(TvlSnapshot.protocol_id == pid, TvlSnapshot.timestamp > recent)
                .count()
                > 0
            )

        # no-snapshot (p_c) + oldest existing (p_a) selected; p_b/p_d beyond the cap.
        assert _fresh(p_c.id)
        assert _fresh(p_a.id)
        assert not _fresh(p_b.id)
        assert not _fresh(p_d.id)


# ---------------------------------------------------------------------------
# Issue: duplicate snapshot dedup
# ---------------------------------------------------------------------------


@requires_postgres
class TestSnapshotDedup:
    """Two rapid take_tvl_snapshot calls should not produce duplicate rows."""

    def test_back_to_back_snapshots_deduped(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="DedupProto")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("all_protos", "dd")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="V"))
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances", lambda address, chain_id=1: [])

        s1 = take_tvl_snapshot(db_session, protocol.id)
        s2 = take_tvl_snapshot(db_session, protocol.id)

        assert s1 is not None
        # Second call within the minimum interval should be skipped
        assert s2 is None

        rows = db_session.query(TvlSnapshot).filter(TvlSnapshot.protocol_id == protocol.id).all()
        assert len(rows) == 1


@requires_postgres
class TestEthPriceDegradationDB:
    """ETH price failure should log which contracts are affected."""

    def test_price_failure_logs_contract_count(self, db_session, monkeypatch, _cleanup, caplog):
        import logging

        protocol = Protocol(name="PriceFail")
        db_session.add(protocol)
        db_session.flush()

        addr1 = _addr("snap_both", "e1")
        addr2 = _addr("snap_both", "e2")
        db_session.add(Contract(address=addr1, chain="ethereum", protocol_id=protocol.id, contract_name="V1"))
        db_session.add(Contract(address=addr2, chain="ethereum", protocol_id=protocol.id, contract_name="V2"))
        db_session.commit()

        def _raise_price(chain_id=1):
            raise RuntimeError("down")

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 5_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", _raise_price)
        monkeypatch.setattr("utils.etherscan.get_token_balances", lambda address, chain_id=1: [])

        with caplog.at_level(logging.WARNING, logger="services.monitoring.tvl"):
            breakdown = refresh_contract_balances(db_session, protocol.id)

        # All contracts should still appear but with $0 ETH value
        assert len(breakdown) == 2

        # The log message should mention the number of contracts affected
        assert any("2 contract(s)" in r.message for r in caplog.records), (
            f"Expected log mentioning '2 contract(s)' affected, got: {[r.message for r in caplog.records]}"
        )
