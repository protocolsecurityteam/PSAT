from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from db.models import (
    BalanceCollectionState,
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    ControlGraphNode,
    Protocol,
    TvlSnapshot,
)
from services.aggregations.company_overview import _entity_key
from services.monitoring import tvl as tvl_module
from services.monitoring.tvl import (
    DEFAULT_ENTITY_BALANCE_INTERVAL,
    _get_protocol_addresses,
    _read_existing_balances,
    fetch_defillama_tvl,
    proven_codeless_holders,
    refresh_all_protocols,
    refresh_contract_balances,
    refresh_entity_balances,
    refresh_entity_balances_if_due,
    take_tvl_snapshot,
)
from tests.conftest import requires_postgres
from tests.support.balance_stubs import page, pinned_native_unavailable
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    BALANCE_WRITER_TVL,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_PROVEN_ZERO,
    SWEEP_STATUS_COMPLETED,
)

_ADDR_PREFIX = {
    "get_addrs": "0x0000000000000000000000000000000000001",
    "refresh": "0x0000000000000000000000000000000000002",
    "failure": "0x0000000000000000000000000000000000003",
    "snap_both": "0x0000000000000000000000000000000000004",
    "snap_onchain": "0x0000000000000000000000000000000000005",
    "all_protos": "0x0000000000000000000000000000000000006",
    "native": "0x0000000000000000000000000000000000007",
    "native_fail": "0x0000000000000000000000000000000000008",
    "twin": "0x0000000000000000000000000000000000009",
    "ethfail": "0x000000000000000000000000000000000000a",
    "failfetch": "0x000000000000000000000000000000000000b",
    "pzero": "0x000000000000000000000000000000000000c",
    "readpz": "0x000000000000000000000000000000000000d",
}


def _addr(prefix_key: str, suffix: str) -> str:
    base = _ADDR_PREFIX[prefix_key]
    return (base + suffix).ljust(42, "0")[:42]


@pytest.fixture(autouse=True)
def _no_pinned_native(monkeypatch):
    """None of these exercises the pinned read, so it's stubbed unavailable."""
    pinned_native_unavailable(monkeypatch)


@pytest.fixture()
def _no_escalation(monkeypatch):
    history = MagicMock(side_effect=AssertionError("routine history forbidden"))
    monkeypatch.setattr("services.clients.rpc.rpc_request", history)
    yield
    history.assert_not_called()


@pytest.fixture()
def _cleanup(db_session):
    db_session.query(BalanceCollectionState).delete()
    db_session.commit()
    yield
    db_session.rollback()
    db_session.query(BalanceCollectionState).delete()
    db_session.query(TvlSnapshot).delete()
    db_session.query(ContractBalance).delete()
    db_session.query(Contract).delete()
    db_session.query(Protocol).delete()
    db_session.commit()


class TestFetchDefillamaTvl:
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

    @pytest.mark.parametrize(
        ("resolved", "get_error"),
        [
            pytest.param({"slug": None}, None, id="no_slug"),
            pytest.param({"slug": "aave-v3"}, Exception("timeout"), id="http_failure"),
        ],
    )
    @patch("services.monitoring.tvl.requests.get")
    @patch("services.discovery.protocol_resolver.resolve_protocol")
    def test_failure_returns_none(self, mock_resolve, mock_get, resolved, get_error):
        mock_resolve.return_value = resolved
        mock_get.side_effect = get_error
        assert fetch_defillama_tvl("Aave") is None


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

    def test_the_implementation_of_a_SCANNING_proxy_is_read_at_its_own_address(self, db_session, _cleanup):
        """A complete asset list claims both addresses, so a scanning proxy pulls its implementation back in."""
        protocol = Protocol(name="TestProto_scanimpl")
        db_session.add(protocol)
        db_session.flush()

        scanning_proxy_addr = _addr("get_addrs", "a1")
        scanning_impl_addr = _addr("get_addrs", "a2")
        quiet_proxy_addr = _addr("get_addrs", "a3")
        quiet_impl_addr = _addr("get_addrs", "a4")

        scanning_proxy = Contract(
            address=scanning_proxy_addr,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_name="ScanningProxy",
            is_proxy=True,
            implementation=scanning_impl_addr,
        )
        quiet_proxy = Contract(
            address=quiet_proxy_addr,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_name="QuietProxy",
            is_proxy=True,
            implementation=quiet_impl_addr,
        )
        db_session.add_all(
            [
                scanning_proxy,
                quiet_proxy,
                Contract(
                    address=scanning_impl_addr,
                    chain="ethereum",
                    protocol_id=protocol.id,
                    contract_name="ScanningImpl",
                ),
                Contract(address=quiet_impl_addr, chain="ethereum", protocol_id=protocol.id, contract_name="QuietImpl"),
            ]
        )
        db_session.flush()
        db_session.add(
            ContractBalanceFetch(
                contract_id=scanning_proxy.id,
                chain_id=1,
                observed_address=scanning_proxy_addr,
                block_number=12,
                native_status=NATIVE_STATUS_PROVEN_ZERO,
                asset_set_status=ASSET_SET_STATUS_RETURNED_EMPTY,
                asset_set_source=ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
                sweep_status=SWEEP_STATUS_COMPLETED,
                swept_from_block=0,
                swept_through_block=12,
                typed_assets=[],
                writer=BALANCE_WRITER_TVL,
            )
        )
        db_session.add(
            ContractBalanceFetch(
                contract_id=quiet_proxy.id,
                chain_id=1,
                observed_address=quiet_proxy_addr,
                native_status=NATIVE_STATUS_PROVEN_ZERO,
                block_number=12,
                asset_set_status=ASSET_SET_STATUS_RETURNED_EMPTY,
                writer=BALANCE_WRITER_TVL,
            )
        )
        db_session.commit()

        kept = {c.address.lower() for c in _get_protocol_addresses(db_session, protocol.id)}
        assert scanning_proxy_addr.lower() in kept and quiet_proxy_addr.lower() in kept
        assert scanning_impl_addr.lower() in kept
        assert quiet_impl_addr.lower() not in kept

    def test_impl_twin_on_other_chain_not_excluded(self, db_session, _cleanup):
        # The impl exclusion is per chain.
        protocol = Protocol(name="TestProto_impltwin")
        db_session.add(protocol)
        db_session.flush()

        proxy_addr = _addr("get_addrs", "d9")
        impl_addr = _addr("get_addrs", "e9")

        proxy = Contract(
            address=proxy_addr,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_name="Proxy",
            is_proxy=True,
            implementation=impl_addr,
        )
        eth_impl = Contract(address=impl_addr, chain="ethereum", protocol_id=protocol.id, contract_name="EthImpl")
        base_twin = Contract(address=impl_addr, chain="base", protocol_id=protocol.id, contract_name="BaseStandalone")
        db_session.add_all([proxy, eth_impl, base_twin])
        db_session.commit()

        addresses = _get_protocol_addresses(db_session, protocol.id)
        kept = {(c.address.lower(), c.chain) for c in addresses}

        assert (proxy_addr.lower(), "ethereum") in kept
        assert (impl_addr.lower(), "base") in kept
        assert (impl_addr.lower(), "ethereum") not in kept


@requires_postgres
class TestRefreshContractBalances:
    def test_stores_balances_and_returns_breakdown(self, db_session, monkeypatch, _cleanup, _no_escalation):
        protocol = Protocol(name="TestProto_refresh")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("refresh", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 2_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr(
            "services.clients.etherscan.get_token_balances_page",
            lambda address, chain_id=1: page(
                [
                    {
                        "token_address": "0x" + "dd" * 20,
                        "token_name": "USDC",
                        "token_symbol": "USDC",
                        "decimals": 6,
                        "balance": 500_000_000,
                        "price_usd": 1.0,
                        "usd_value": 500.0,
                    }
                ]
            ),
        )

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        key = _entity_key("ethereum", addr)
        assert key in breakdown
        assert breakdown[key]["total_usd"] == 4500.0
        assert breakdown[key]["name"] == "Vault"

        balances = db_session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).all()
        assert len(balances) == 2
        assert {b.token_symbol for b in balances} == {"ETH", "USDC"}

    def test_positive_dust_is_preserved_and_unpriced_is_unknown(
        self, db_session, monkeypatch, _cleanup, _no_escalation
    ):
        protocol = Protocol(name="TestProto_priced_zero")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("pzero", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 1_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr(
            "services.clients.etherscan.get_token_balances_page",
            lambda address, chain_id=1: page(
                [
                    {
                        "token_address": "0x" + "ee" * 20,
                        "token_name": "DustCoin",
                        "token_symbol": "DUST",
                        "decimals": 18,
                        "balance": 1,
                        "price_usd": 1.0,
                        "usd_value": 1e-18,
                    },
                    {
                        "token_address": "0x" + "ff" * 20,
                        "token_name": "NoPriceCoin",
                        "token_symbol": "NOPRICE",
                        "decimals": 18,
                        "balance": 123,
                        "price_usd": None,
                        "usd_value": None,
                    },
                ]
            ),
        )

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is True  # the positive unpriced token remains a valuation gap
        key = _entity_key("ethereum", addr)
        assert breakdown[key]["total_usd"] == 2000.0
        published = {t["symbol"]: t["usd_value"] for t in breakdown[key]["tokens"]}
        assert published == {"ETH": 2000.0, "DUST": 1e-18}

        balances = db_session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).all()
        assert {b.token_symbol for b in balances} == {"ETH", "DUST", "NOPRICE"}

    def test_handles_balance_failure_gracefully(self, db_session, monkeypatch, _cleanup):
        """A failed read used to publish ``total_usd: 0.0``, the same as holding nothing."""
        protocol = Protocol(name="TestProto_failure")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("failure", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        def _raise(addr, chain_id=1):
            raise RuntimeError("RPC failed")

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", _raise)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", _raise)

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        key = _entity_key("ethereum", addr)
        assert key not in breakdown
        assert breakdown == {}
        assert partial is True
        fetches = db_session.query(ContractBalanceFetch).filter(ContractBalanceFetch.contract_id == contract.id).all()
        assert len(fetches) == 2
        assert sum(f.native_status == NATIVE_STATUS_FETCH_FAILED for f in fetches) == 1
        assert sum(f.asset_set_status == ASSET_SET_STATUS_FETCH_FAILED for f in fetches) == 1


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
        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 1_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 3000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        snapshot, _ = take_tvl_snapshot(db_session, protocol.id)

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
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        snapshot, _ = take_tvl_snapshot(db_session, protocol.id)

        assert snapshot is not None
        assert snapshot.source == "on_chain"
        assert snapshot.defillama_tvl is None

    def test_returns_none_for_missing_protocol(self, db_session):
        snapshot, partial = take_tvl_snapshot(db_session, 999999)
        assert snapshot is None
        assert partial is False


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
                    # ``_addr`` truncates to 42 chars, so shared hex prefixes collided.
                    address=_addr("all_protos", f"b{i}"),
                    chain="ethereum",
                    protocol_id=p.id,
                    contract_name=f"Contract_{p.id}",
                )
            )
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

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

        db_session.add(
            TvlSnapshot(protocol_id=p_a.id, timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc), source="on_chain")
        )
        db_session.add(
            TvlSnapshot(protocol_id=p_b.id, timestamp=datetime(2021, 1, 1, tzinfo=timezone.utc), source="on_chain")
        )
        db_session.add(
            TvlSnapshot(protocol_id=p_d.id, timestamp=datetime(2022, 1, 1, tzinfo=timezone.utc), source="on_chain")
        )
        p_a.last_balance_attempt_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        p_b.last_balance_attempt_at = datetime(2021, 1, 1, tzinfo=timezone.utc)
        p_d.last_balance_attempt_at = datetime(2022, 1, 1, tzinfo=timezone.utc)
        db_session.commit()

        monkeypatch.setenv("PSAT_TVL_PROTOCOLS_PER_PASS", "2")
        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        count = refresh_all_protocols(db_session)
        assert count == 2  # cap honored

        def _fresh(pid: int) -> bool:
            return (
                db_session.query(TvlSnapshot)
                .filter(TvlSnapshot.protocol_id == pid, TvlSnapshot.timestamp > recent)
                .count()
                > 0
            )

        assert _fresh(p_c.id)
        assert _fresh(p_a.id)
        assert not _fresh(p_b.id)
        assert not _fresh(p_d.id)


@requires_postgres
class TestSnapshotDedup:
    def test_back_to_back_snapshots_deduped(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="DedupProto")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("all_protos", "dd")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="V"))
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        s1, _ = take_tvl_snapshot(db_session, protocol.id)
        s2, _ = take_tvl_snapshot(db_session, protocol.id)

        assert s1 is not None
        assert s2 is None

        rows = db_session.query(TvlSnapshot).filter(TvlSnapshot.protocol_id == protocol.id).all()
        assert len(rows) == 1


@requires_postgres
class TestNativeAssetPricingDispatch:
    """Native USD pricing dispatches on the contract's chain: ETH-native chains reuse
    the mainnet quote; a non-ETH chain is priced via ``get_native_price`` and skipped
    (partial-flagged), never ETH-quoted, when unavailable."""

    def _mock_eth_native(self, monkeypatch, *, wei: int) -> None:
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: wei)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

    @pytest.mark.parametrize(
        ("name", "chain", "tag", "contract_name", "wei", "expected_total", "expected_price"),
        [
            pytest.param(
                "BaseNativeProto", "base", "b1", "BaseVault", 2_000_000_000_000_000_000, 4000.0, 2000.0, id="base"
            ),
            pytest.param(
                "NullChainProto", None, "n1", "LegacyVault", 1_000_000_000_000_000_000, 2000.0, 2000.0, id="null_chain"
            ),
        ],
    )
    def test_eth_native_contract_priced_at_eth_quote(
        self,
        db_session,
        monkeypatch,
        _cleanup,
        _no_escalation,
        name,
        chain,
        tag,
        contract_name,
        wei,
        expected_total,
        expected_price,
    ):
        protocol = Protocol(name=name)
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("native", tag)
        db_session.add(Contract(address=addr, chain=chain, protocol_id=protocol.id, contract_name=contract_name))
        db_session.commit()

        self._mock_eth_native(monkeypatch, wei=wei)
        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key(chain, addr)]["total_usd"] == expected_total
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1
        assert rows[0].token_symbol == "ETH"
        assert float(rows[0].price_usd) == expected_price

    def test_polygon_contract_priced_at_pol_quote(self, db_session, monkeypatch, _cleanup, _no_escalation):
        protocol = Protocol(name="PolygonProto")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("native_fail", "p1")
        db_session.add(Contract(address=addr, chain="polygon", protocol_id=protocol.id, contract_name="PolyVault"))
        db_session.commit()

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 100_000_000_000_000_000_000
        )
        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0
        )  # mainnet quote, unused here
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))
        monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda chain_id: 0.0826)

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key("polygon", addr)]["total_usd"] == 8.26
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1
        assert rows[0].token_symbol == "POL"
        assert float(rows[0].price_usd) == 0.0826

    def test_unpriceable_chain_skips_contract_and_flags_partial(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="MixedChainProto")
        db_session.add(protocol)
        db_session.flush()

        eth_addr = _addr("native", "e5")
        poly_addr = _addr("native_fail", "p5")
        db_session.add(Contract(address=eth_addr, chain="ethereum", protocol_id=protocol.id, contract_name="EthV"))
        db_session.add(Contract(address=poly_addr, chain="polygon", protocol_id=protocol.id, contract_name="PolyV"))
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        self._mock_eth_native(monkeypatch, wei=1_000_000_000_000_000_000)  # 1 ETH each

        def _price_down(chain_id):
            raise RuntimeError("stats endpoint down")

        monkeypatch.setattr("services.clients.etherscan.get_native_price", _price_down)

        cycles: list[dict] = []
        monkeypatch.setattr("services.monitoring.tvl.emit_monitor_cycle", lambda *a, **k: cycles.append(k))

        count = refresh_all_protocols(db_session)

        assert count == 1
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 2
        polygon = next(r for r in rows if r.token_symbol != "ETH")
        assert polygon.raw_balance == str(10**18)
        assert polygon.usd_value is None

        assert len(cycles) == 1
        assert cycles[0]["partial"] is True
        assert cycles[0]["note"] == "1_partial"


@requires_postgres
class TestEthPriceDegradationDB:
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

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 5_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", _raise_price)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        with caplog.at_level(logging.WARNING, logger="services.monitoring.tvl"):
            breakdown, _ = refresh_contract_balances(db_session, protocol.id)

        # An unpriced holding is not worth $0.
        assert len(breakdown) == 2
        assert all(entry["total_usd"] is None and entry["unpriced_count"] == 1 for entry in breakdown.values())
        assert any("native quote unavailable" in r.message for r in caplog.records)


@requires_postgres
class TestContractBreakdownCompositeKey:
    """Keyed ``"<chain>::<address>"`` so twins don't collapse."""

    @staticmethod
    def _chain_varying_eth_balance(address, chain_id=1):
        # Distinct per-chain balances, so a last-wins collapse is detectable.
        return 1_000_000_000_000_000_000 if chain_id == 1 else 2_000_000_000_000_000_000

    def _two_chain_twin(self, db_session):
        protocol = Protocol(name="TwinProto")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("twin", "a1")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="EthVault"))
        db_session.add(Contract(address=addr, chain="base", protocol_id=protocol.id, contract_name="BaseVault"))
        db_session.commit()
        return protocol, addr

    def test_refresh_keeps_both_chains(self, db_session, monkeypatch, _cleanup, _no_escalation):
        protocol, addr = self._two_chain_twin(db_session)
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", self._chain_varying_eth_balance)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        eth_key = _entity_key("ethereum", addr)
        base_key = _entity_key("base", addr)
        assert set(breakdown) == {eth_key, base_key}
        assert breakdown[eth_key]["total_usd"] == 2000.0
        assert breakdown[base_key]["total_usd"] == 4000.0
        on_chain_total = sum(e.get("total_usd", 0) for e in breakdown.values())
        assert on_chain_total == 6000.0

    def test_read_existing_keeps_both_chains(self, db_session, _cleanup):
        protocol, addr = self._two_chain_twin(db_session)
        contracts = _get_protocol_addresses(db_session, protocol.id)
        by_chain = {c.chain: c for c in contracts}
        db_session.add(
            ContractBalance(
                contract_id=by_chain["ethereum"].id,
                token_address=None,
                token_name="Ether",
                token_symbol="ETH",
                decimals=18,
                raw_balance="1000000000000000000",
                price_usd=2000.0,
                usd_value=2000.0,
            )
        )
        db_session.add(
            ContractBalance(
                contract_id=by_chain["base"].id,
                token_address=None,
                token_name="Ether",
                token_symbol="ETH",
                decimals=18,
                raw_balance="2000000000000000000",
                price_usd=2000.0,
                usd_value=4000.0,
            )
        )
        db_session.commit()

        breakdown, partial = _read_existing_balances(db_session, protocol.id)

        eth_key = _entity_key("ethereum", addr)
        base_key = _entity_key("base", addr)
        assert set(breakdown) == {eth_key, base_key}
        assert breakdown[eth_key]["total_usd"] == 2000.0
        assert breakdown[base_key]["total_usd"] == 4000.0
        assert partial is True
        assert all(entry["stale"] for entry in breakdown.values())

    def test_read_existing_priced_zero_is_published_unpriced_is_not(self, db_session, _cleanup):
        """Same distinction as the refresh branch: a stored
        priced zero is a witnessed holding of nothing and publishes as 0.0;
        a NULL ``usd_value`` stays out of the served figures."""
        protocol = Protocol(name="TestProto_read_pzero")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("readpz", "a1")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault"))
        db_session.commit()
        contract = _get_protocol_addresses(db_session, protocol.id)[0]
        db_session.add(
            ContractBalance(
                contract_id=contract.id,
                token_address="0x" + "ee" * 20,
                token_name="ZeroCoin",
                token_symbol="ZERO",
                decimals=6,
                raw_balance="0",
                price_usd=1.0,
                usd_value=0.0,
            )
        )
        db_session.add(
            ContractBalance(
                contract_id=contract.id,
                token_address="0x" + "ff" * 20,
                token_name="NoPriceCoin",
                token_symbol="NOPRICE",
                decimals=18,
                raw_balance="123",
                price_usd=None,
                usd_value=None,
            )
        )
        db_session.commit()

        breakdown, partial = _read_existing_balances(db_session, protocol.id)

        key = _entity_key("ethereum", addr)
        assert breakdown[key]["total_usd"] == 0.0
        assert {t["symbol"]: t["usd_value"] for t in breakdown[key]["tokens"]} == {"ZERO": 0.0}
        assert breakdown[key]["unpriced_count"] == 1
        assert partial is True

    def test_snapshot_total_sums_both_chains(self, db_session, monkeypatch, _cleanup, _no_escalation):
        protocol, _addr_unused = self._two_chain_twin(db_session)
        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", self._chain_varying_eth_balance)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        snapshot, partial = take_tvl_snapshot(db_session, protocol.id)

        assert snapshot is not None
        assert partial is False
        assert snapshot.total_usd is not None and float(snapshot.total_usd) == 6000.0
        assert snapshot.contract_breakdown is not None and len(snapshot.contract_breakdown) == 2


@requires_postgres
class TestMainnetEthQuoteFailurePartial:
    """Symmetric with the non-ETH native-quote path."""

    def test_refresh_flags_partial_when_eth_quote_fails(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="EthQuoteFailProto")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("ethfail", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        def _raise_price(chain_id=1):
            raise RuntimeError("stats endpoint down")

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 3_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", _raise_price)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        rows = db_session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).all()
        assert len(rows) == 1 and rows[0].token_symbol == "ETH"
        assert rows[0].price_usd is None and rows[0].usd_value is None
        assert partial is True
        # Omitted rather than published at 0.0, as the non-ETH branch already does.
        assert breakdown[_entity_key("ethereum", addr)]["total_usd"] is None
        assert breakdown[_entity_key("ethereum", addr)]["unpriced_count"] == 1

    def test_cycle_heartbeat_flags_partial(self, db_session, monkeypatch, _cleanup):
        protocol = Protocol(name="EthQuoteFailCycle")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("ethfail", "c1")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault"))
        db_session.commit()

        def _raise_price(chain_id=1):
            raise RuntimeError("down")

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 3_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", _raise_price)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        cycles: list[dict] = []
        monkeypatch.setattr("services.monitoring.tvl.emit_monitor_cycle", lambda *a, **k: cycles.append(k))

        count = refresh_all_protocols(db_session)

        assert count == 1
        assert len(cycles) == 1
        assert cycles[0]["partial"] is True
        assert cycles[0]["note"] == "1_partial"


@requires_postgres
class TestFailedReadIsNotAMeasuredZero:
    """The failure lives only in the fetch plane, so 0.0 would read as "holds nothing"."""

    @staticmethod
    def _one_good_one_failing(monkeypatch, good_addr: str, bad_addr: str):
        def _balance(address, chain_id=1):
            if address.lower() == bad_addr.lower():
                raise RuntimeError("RPC failed")
            return 1_000_000_000_000_000_000

        def _tokens(address, chain_id=1):
            if address.lower() == bad_addr.lower():
                raise RuntimeError("Etherscan failed")
            return page([])

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", _balance)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", _tokens)

    def test_snapshot_omits_the_failed_contract_and_totals_only_the_measured_one(
        self, db_session, monkeypatch, _cleanup
    ):
        protocol = Protocol(name="FailedReadProto")
        db_session.add(protocol)
        db_session.flush()
        good = _addr("failfetch", "a1")
        bad = _addr("failfetch", "b2")
        db_session.add(Contract(address=good, chain="ethereum", protocol_id=protocol.id, contract_name="GoodVault"))
        db_session.add(Contract(address=bad, chain="ethereum", protocol_id=protocol.id, contract_name="BadVault"))
        db_session.commit()

        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        self._one_good_one_failing(monkeypatch, good, bad)

        snapshot, partial = take_tvl_snapshot(db_session, protocol.id)

        assert snapshot is not None
        assert partial is True
        breakdown = snapshot.contract_breakdown or {}
        assert _entity_key("ethereum", bad) not in breakdown
        assert breakdown[_entity_key("ethereum", good)]["total_usd"] == 2000.0
        assert snapshot.total_usd is not None and float(snapshot.total_usd) == 2000.0

    def test_a_genuine_zero_is_still_published(self, db_session, monkeypatch, _cleanup, _no_escalation):
        """Otherwise "not measured" and "measured empty" collapse from the other side."""
        protocol = Protocol(name="GenuineZeroProto")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("failfetch", "c3")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="EmptyVault"))
        db_session.commit()

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        monkeypatch.setattr(
            "services.monitoring.balance_collection.pinned_native_balances",
            lambda addresses, **kw: (123, {address.lower(): 0 for address in addresses}),
        )
        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key("ethereum", addr)]["total_usd"] == 0.0
        assert breakdown[_entity_key("ethereum", addr)]["tokens"] == [{"symbol": "ETH", "usd_value": 0.0}]

    def test_token_read_failure_keeps_native_subset_with_partial_disclosure(self, db_session, monkeypatch, _cleanup):
        """A native-only total would understate while looking measured."""
        protocol = Protocol(name="TokenFailOnlyProto")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("failfetch", "d4")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault"))
        db_session.commit()

        def _raise_tokens(address, chain_id=1):
            raise RuntimeError("Etherscan failed")

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 1_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", _raise_tokens)

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        observed = breakdown[_entity_key("ethereum", addr)]
        assert observed["total_usd"] == 2000.0
        assert observed["partial"] is True
        assert observed["coverage"] == "provider_observed_subset"
        assert partial is True
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1 and rows[0].token_symbol == "ETH"


@requires_postgres
class TestProvenCodelessHolderPopulation:
    """Holders come from the earned ``eth_getCode`` witness only, and every decline carries a reason."""

    PREFIX = "0x000000000000000000000000000000000000e"

    def _addr(self, suffix: str) -> str:
        return (self.PREFIX + suffix).ljust(42, "0")[:42]

    def _fixture(self, db_session, monkeypatch, *, rpc: bool = True):
        monkeypatch.setattr(
            "services.monitoring.tvl.rpc_url_for_chain_id",
            lambda chain_id: "http://rpc.invalid" if rpc else None,
        )
        proto = Protocol(name=f"TestProto_codeless_{self._addr('0')[-6:]}")
        db_session.add(proto)
        db_session.flush()
        host = Contract(protocol_id=proto.id, address=self._addr("1"), chain="ethereum", contract_name="Host")
        db_session.add(host)
        db_session.flush()
        return proto, host

    def _node(self, db_session, host, address: str, resolved_type: str | None) -> None:
        db_session.add(
            ControlGraphNode(contract_id=host.id, address=address, node_type="owner", resolved_type=resolved_type)
        )
        db_session.flush()

    def test_only_the_earned_eoa_witness_is_in_the_population(self, db_session, monkeypatch, _cleanup):
        proto, host = self._fixture(db_session, monkeypatch)
        eoa = self._addr("2")
        self._node(db_session, host, eoa, "eoa")
        # Sweeping an unprobed node as an EOA would let a name stand in for a getCode never issued.
        self._node(db_session, host, self._addr("3"), "unknown")
        self._node(db_session, host, self._addr("4"), "contract")
        self._node(db_session, host, self._addr("5"), None)
        db_session.commit()

        holders, excluded = proven_codeless_holders(db_session, proto.id)
        assert [h.entity_key for h in holders] == [f"ethereum::{eoa}"]
        # They were never candidates, so they aren't "excluded".
        assert excluded == []

    def test_an_eoa_node_that_also_carries_an_unknown_node_stays_in(self, db_session, monkeypatch, _cleanup):
        proto, host = self._fixture(db_session, monkeypatch)
        eoa = self._addr("6")
        self._node(db_session, host, eoa, "eoa")
        self._node(db_session, host, eoa, "unknown")
        db_session.commit()

        holders, _excluded = proven_codeless_holders(db_session, proto.id)
        assert [h.entity_key for h in holders] == [f"ethereum::{eoa}"]

    def test_an_address_with_its_own_contracts_row_is_never_a_second_subject(self, db_session, monkeypatch, _cleanup):
        """Reading one address as two subjects would count one witness twice."""
        proto, host = self._fixture(db_session, monkeypatch)
        self._node(db_session, host, host.address, "eoa")
        db_session.commit()

        holders, excluded = proven_codeless_holders(db_session, proto.id)
        assert holders == []
        assert [(e.entity_key, e.reason) for e in excluded] == [
            (f"ethereum::{host.address}", "already observed through its own contracts row")
        ]

    def test_an_entity_the_producer_cannot_reach_is_excluded_with_its_reason(self, db_session, monkeypatch, _cleanup):
        proto, host = self._fixture(db_session, monkeypatch, rpc=False)
        eoa = self._addr("7")
        self._node(db_session, host, eoa, "eoa")
        db_session.commit()

        holders, excluded = proven_codeless_holders(db_session, proto.id)
        assert holders == []
        assert [e.entity_key for e in excluded] == [f"ethereum::{eoa}"]
        assert "no RPC URL configured" in excluded[0].reason

    def test_every_candidate_is_a_holder_or_an_exclusion_with_a_reason(self, db_session, monkeypatch, _cleanup):
        """The output lists partition ``load_proven_eoa_entities``."""
        from services.scoring.planes import load_proven_eoa_entities

        proto, host = self._fixture(db_session, monkeypatch)
        self._node(db_session, host, self._addr("8"), "eoa")
        self._node(db_session, host, host.address, "eoa")
        db_session.commit()

        candidates = load_proven_eoa_entities(db_session, proto.id)
        holders, excluded = proven_codeless_holders(db_session, proto.id)
        assert {h.entity_key for h in holders} | {e.entity_key for e in excluded} == candidates
        assert all(e.reason for e in excluded)

    def test_a_holder_already_carrying_rows_stays_in_the_population(self, db_session, monkeypatch, _cleanup):
        """Filtering on "no sheet yet" would read each holder once and stall the cursor."""
        proto, host = self._fixture(db_session, monkeypatch)
        eoa = self._addr("9")
        self._node(db_session, host, eoa, "eoa")
        db_session.add(
            ContractBalanceFetch(
                contract_id=None,
                entity_chain="ethereum",
                entity_address=eoa,
                chain_id=1,
                observed_address=eoa,
                native_status=NATIVE_STATUS_FETCH_FAILED,
                asset_set_status=ASSET_SET_STATUS_RETURNED_EMPTY,
                writer=BALANCE_WRITER_TVL,
            )
        )
        db_session.commit()

        holders, _excluded = proven_codeless_holders(db_session, proto.id)
        assert [h.entity_key for h in holders] == [f"ethereum::{eoa}"]

    def test_the_producer_writes_entity_keyed_records_for_the_population(self, db_session, monkeypatch, _cleanup):
        """Reading an entity holder mints no ``contracts`` row."""
        proto, host = self._fixture(db_session, monkeypatch)
        eoa = self._addr("a")
        self._node(db_session, host, eoa, "eoa")
        db_session.commit()
        contracts_before = db_session.query(Contract).count()

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))
        # An empty page is a trigger, never a proof.

        report = refresh_entity_balances(db_session, proto.id)
        assert [h.entity_key for h in report.holders] == [f"ethereum::{eoa}"]
        assert report.excluded == []
        assert report.collection is not None
        assert report.collection.attempted == 2

        fetch = (
            db_session.query(ContractBalanceFetch)
            .filter(ContractBalanceFetch.entity_address == eoa)
            .order_by(ContractBalanceFetch.id.desc())
            .first()
        )
        assert fetch is not None
        assert fetch.contract_id is None
        assert (fetch.entity_chain, fetch.entity_address) == ("ethereum", eoa)
        assert fetch.observed_address == eoa
        assert fetch.asset_set_source == ASSET_SET_SOURCE_ETHERSCAN_PAGES
        assert db_session.query(Contract).count() == contracts_before


@requires_postgres
class TestEntityCohortInTheCycle:
    """The cohort is read daily on its own counter, never the contract sweep's."""

    PREFIX = "0x000000000000000000000000000000000000f"

    def _addr(self, suffix: str) -> str:
        return (self.PREFIX + suffix).ljust(42, "0")[:42]

    def _fixture(self, db_session, monkeypatch, tag: str):
        """Entity fetch rows escape teardown's cascade, so each test gets its own addresses."""
        monkeypatch.setattr("services.monitoring.tvl.rpc_url_for_chain_id", lambda chain_id: "http://rpc.invalid")
        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("services.clients.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))
        proto = Protocol(name=f"TestProto_cohort_{tag}")
        db_session.add(proto)
        db_session.flush()
        host = Contract(protocol_id=proto.id, address=self._addr(f"{tag}1"), chain="ethereum", contract_name="Host")
        db_session.add(host)
        db_session.flush()
        eoa = self._addr(f"{tag}2")
        db_session.add(ControlGraphNode(contract_id=host.id, address=eoa, node_type="owner", resolved_type="eoa"))
        db_session.commit()
        db_session.query(ContractBalanceFetch).filter(
            ContractBalanceFetch.entity_address.like(f"{self.PREFIX}{tag}%")
        ).delete(synchronize_session=False)
        db_session.commit()
        return proto, host, eoa

    def _readings(self, db_session, eoa: str) -> int:
        return (
            db_session.query(ContractBalanceFetch)
            .filter(
                ContractBalanceFetch.entity_address == eoa,
                ContractBalanceFetch.asset_set_status != "unattempted",
            )
            .count()
        )

    def _age(self, db_session, *addresses: str, seconds: int) -> None:
        from datetime import datetime, timedelta, timezone

        db_session.query(ContractBalanceFetch).filter(ContractBalanceFetch.entity_address.in_(addresses)).update(
            {ContractBalanceFetch.fetched_at: datetime.now(timezone.utc) - timedelta(seconds=seconds)},
            synchronize_session=False,
        )
        past = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        db_session.query(BalanceCollectionState).filter(BalanceCollectionState.address.in_(addresses)).update(
            {BalanceCollectionState.observed_at: past, BalanceCollectionState.next_attempt_at: past},
            synchronize_session=False,
        )
        db_session.commit()

    def _eoa_node(self, db_session, host, address: str) -> None:
        db_session.add(ControlGraphNode(contract_id=host.id, address=address, node_type="owner", resolved_type="eoa"))
        db_session.commit()

    def test_the_cohort_is_read_daily_and_the_snapshot_keeps_its_own_clock(self, db_session, monkeypatch, _cleanup):
        proto, _host, eoa = self._fixture(db_session, monkeypatch, "a")
        contract_sweeps: list[int] = []
        real_contract_refresh = tvl_module.refresh_contract_balances

        def _counting_contract_refresh(session, protocol_id, **kwargs):
            contract_sweeps.append(protocol_id)
            return real_contract_refresh(session, protocol_id, **kwargs)

        monkeypatch.setattr("services.monitoring.tvl.refresh_contract_balances", _counting_contract_refresh)

        refresh_all_protocols(db_session)
        assert self._readings(db_session, eoa) == 1
        assert contract_sweeps == [proto.id]

        refresh_all_protocols(db_session)
        assert self._readings(db_session, eoa) == 1
        assert contract_sweeps == [proto.id]

        self._age(db_session, eoa, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)

        refresh_all_protocols(db_session)
        assert self._readings(db_session, eoa) == 2
        assert contract_sweeps == [proto.id]

    def test_the_window_is_measured_against_the_cohorts_own_rows(self, db_session, monkeypatch, _cleanup):

        proto, _host, eoa = self._fixture(db_session, monkeypatch, "b")

        first = refresh_entity_balances_if_due(db_session, proto.id)
        assert first is not None and [h.entity_key for h in first.holders] == [f"ethereum::{eoa}"]

        reused = refresh_entity_balances_if_due(db_session, proto.id)
        assert reused is not None and reused.collection is not None
        assert reused.collection.attempted == 0
        assert reused.collection.reused == 2
        self._age(db_session, eoa, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)
        due = refresh_entity_balances_if_due(db_session, proto.id)
        assert due is not None and due.collection is not None
        assert due.collection.attempted == 2
        assert self._readings(db_session, eoa) == 2

    def test_a_shared_members_fresh_row_cannot_mask_a_stale_exclusive_one(self, db_session, monkeypatch, _cleanup):
        """The anchor is the cohort's oldest reading; anchoring on the newest would let a shared row mask another
        protocol's stale one.
        """
        proto_b, host_b, exclusive = self._fixture(db_session, monkeypatch, "d")
        shared = self._addr("d9")
        self._eoa_node(db_session, host_b, shared)
        proto_a = Protocol(name="TestProto_cohort_d_other")
        db_session.add(proto_a)
        db_session.flush()
        host_a = Contract(protocol_id=proto_a.id, address=self._addr("d3"), chain="ethereum", contract_name="HostA")
        db_session.add(host_a)
        db_session.flush()
        self._eoa_node(db_session, host_a, shared)

        assert refresh_entity_balances_if_due(db_session, proto_b.id) is not None
        assert (self._readings(db_session, exclusive), self._readings(db_session, shared)) == (1, 1)

        self._age(db_session, exclusive, shared, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)
        assert refresh_entity_balances_if_due(db_session, proto_a.id) is not None
        assert (self._readings(db_session, exclusive), self._readings(db_session, shared)) == (1, 2)

        assert refresh_entity_balances_if_due(db_session, proto_b.id) is not None
        assert self._readings(db_session, exclusive) == 2

    def test_never_read_holder_is_due_without_refetching_fresh_cohort(self, db_session, monkeypatch, _cleanup):
        """No reading is a third state; treating it as infinitely old would re-open the cohort every tick."""
        proto, host, first_eoa = self._fixture(db_session, monkeypatch, "e")
        assert refresh_entity_balances_if_due(db_session, proto.id) is not None

        newcomer = self._addr("e9")
        self._eoa_node(db_session, host, newcomer)

        newcomer_pass = refresh_entity_balances_if_due(db_session, proto.id)
        assert newcomer_pass is not None and newcomer_pass.collection is not None
        assert newcomer_pass.collection.attempted == 2
        assert newcomer_pass.collection.reused == 2
        assert self._readings(db_session, newcomer) == 1

        self._age(db_session, first_eoa, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)
        assert refresh_entity_balances_if_due(db_session, proto.id) is not None
        assert (self._readings(db_session, first_eoa), self._readings(db_session, newcomer)) == (2, 1)

    def test_neither_contract_nor_entity_collection_invokes_history(self, db_session, monkeypatch, _cleanup):
        _proto, _host, eoa = self._fixture(db_session, monkeypatch, "c")
        history = MagicMock(side_effect=AssertionError("routine history forbidden"))
        monkeypatch.setattr("services.clients.rpc.rpc_request", history)
        refresh_all_protocols(db_session)
        history.assert_not_called()
        assert self._readings(db_session, eoa) == 1  # helper counts the independent token unit
