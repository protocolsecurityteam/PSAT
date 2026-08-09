"""Tests for protocol-wide TVL tracking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from db.models import (
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    ControlGraphNode,
    Protocol,
    TvlSnapshot,
)
from services.aggregations.company_overview import _entity_key
from services.monitoring import tvl as tvl_module
from services.monitoring.asset_sweep import SweepCost
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

# Unique address helpers — each test class gets its own prefix to avoid
# unique-constraint collisions across tests sharing the same DB.
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
    """Every balance test here stubs Etherscan only; pin the second native wire too.

    No test in this module exercises the pinned read, so the whole module takes
    the unpinned path — the one its expectations were written against.
    """
    pinned_native_unavailable(monkeypatch)


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

    def test_the_implementation_of_a_SCANNING_proxy_is_read_at_its_own_address(self, db_session, _cleanup):
        """The value plane folds the two addresses into one sheet, and a sheet
        that publishes an asset list as COMPLETE claims it of both. Nothing could
        earn that while the implementation's own address was never read — so a
        proxy carrying a completed chain scan pulls its implementation back into
        the population. An implementation whose proxy is NOT scanning stays out:
        the exception is the completeness claim, not a general re-admission."""
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
        # A base standalone contract sharing an address with an ethereum proxy's
        # implementation must NOT be dropped from balance collection: the
        # exclusion is per-chain (impl-behind-proxy on its OWN chain only), so
        # the base twin still gets a balance row + breakdown entry.
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

        # proxy kept; eth impl-behind-proxy excluded; base twin at same address INCLUDED.
        assert (proxy_addr.lower(), "ethereum") in kept
        assert (impl_addr.lower(), "base") in kept
        assert (impl_addr.lower(), "ethereum") not in kept


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
            "utils.etherscan.get_token_balances_page",
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

    def test_priced_zero_is_published_unpriced_is_not(self, db_session, monkeypatch, _cleanup):
        """A priced ``usd_value == 0.0`` is a witnessed zero and enters the
        breakdown; an unpriced ``usd_value: None`` does not — the two must be
        distinguishable (readiness §2.3). Row storage is unaffected either way."""
        protocol = Protocol(name="TestProto_priced_zero")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("pzero", "a1")
        contract = Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault")
        db_session.add(contract)
        db_session.commit()

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 1_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr(
            "utils.etherscan.get_token_balances_page",
            lambda address, chain_id=1: page(
                [
                    {
                        "token_address": "0x" + "ee" * 20,
                        "token_name": "ZeroCoin",
                        "token_symbol": "ZERO",
                        "decimals": 6,
                        "balance": 0,
                        "price_usd": 1.0,
                        "usd_value": 0.0,
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

        assert partial is False
        key = _entity_key("ethereum", addr)
        assert breakdown[key]["total_usd"] == 2000.0
        published = {t["symbol"]: t["usd_value"] for t in breakdown[key]["tokens"]}
        assert published == {"ETH": 2000.0, "ZERO": 0.0}

        balances = db_session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).all()
        assert {b.token_symbol for b in balances} == {"ETH", "ZERO", "NOPRICE"}

    def test_handles_balance_failure_gracefully(self, db_session, monkeypatch, _cleanup):
        """Both reads fail ⇒ the contract is OMITTED and the cycle is partial.

        It used to be published with ``total_usd: 0.0``, which is the same value
        a contract that genuinely holds nothing gets, and which enters
        ``TvlSnapshot.total_usd`` and the served breakdown with no discriminator
        — a failed read turned into a measured money figure. Same rule as the
        sibling read-existing branch (``_read_existing_balances``).
        """
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
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", _raise)

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        key = _entity_key("ethereum", addr)
        assert key not in breakdown
        assert breakdown == {}
        assert partial is True
        # The failure still has its durable trace in the fetch plane.
        fetches = db_session.query(ContractBalanceFetch).filter(ContractBalanceFetch.contract_id == contract.id).all()
        assert len(fetches) == 1
        assert fetches[0].native_status == NATIVE_STATUS_FETCH_FAILED
        assert fetches[0].asset_set_status == ASSET_SET_STATUS_FETCH_FAILED


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
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

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
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

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
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

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
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

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
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        s1, _ = take_tvl_snapshot(db_session, protocol.id)
        s2, _ = take_tvl_snapshot(db_session, protocol.id)

        assert s1 is not None
        # Second call within the minimum interval should be skipped
        assert s2 is None

        rows = db_session.query(TvlSnapshot).filter(TvlSnapshot.protocol_id == protocol.id).all()
        assert len(rows) == 1


class TestGetNativePrice:
    """``get_native_price`` picks the per-chain stats action and reads the price
    from the ``*usd`` field, never inferring the asset from the response key."""

    def test_eth_native_uses_ethprice_action(self, monkeypatch):
        import utils.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(module=module, action=action, chain_id=chain_id)
            # ethprice carries ethbtc + ethusd + *_timestamp siblings; only the
            # bare ``*usd`` field is the price.
            return {
                "result": {
                    "ethbtc": "0.05",
                    "ethbtc_timestamp": "1",
                    "ethusd": "1841.99",
                    "ethusd_timestamp": "2",
                }
            }

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(1)

        assert price == 1841.99
        assert captured == {"module": "stats", "action": "ethprice", "chain_id": 1}

    def test_polygon_pol_priced_under_lying_ethusd_key(self, monkeypatch):
        # Polygon's POL price comes back under "ethusd"; generic *usd parse must
        # read it without inferring "ETH" from the key.
        import utils.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(action=action, chain_id=chain_id)
            return {"result": {"ethbtc": "0", "ethusd": "0.0826", "ethusd_timestamp": "1"}}

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(137)

        assert price == 0.0826
        assert captured == {"action": "ethprice", "chain_id": 137}

    def test_bsc_uses_bnbprice_action(self, monkeypatch):
        # BSC rejects "ethprice": the registry override must drive the call to
        # "bnbprice", whose value is (mislabeled) under "ethusd".
        import utils.etherscan as es

        captured: dict[str, object] = {}

        def _fake_get(module, action, chain_id, **params):
            captured.update(module=module, action=action, chain_id=chain_id)
            return {"result": {"ethusd": "567.97"}}

        monkeypatch.setattr(es, "get", _fake_get)
        price = es.get_native_price(56)

        assert price == 567.97
        assert captured == {"module": "stats", "action": "bnbprice", "chain_id": 56}

    def test_missing_usd_field_raises(self, monkeypatch):
        import utils.etherscan as es

        monkeypatch.setattr(es, "get", lambda *a, **k: {"result": {"ethbtc": "0.05"}})
        with pytest.raises(RuntimeError):
            es.get_native_price(1)

    def test_get_eth_price_delegates_to_native(self, monkeypatch):
        import utils.etherscan as es

        monkeypatch.setattr(es, "get", lambda *a, **k: {"result": {"ethusd": "2000.0"}})
        assert es.get_eth_price(1) == 2000.0


@requires_postgres
class TestNativeAssetPricingDispatch:
    """Native-asset USD pricing dispatches on the contract's chain (inv. 5):
    each contract's native balance is valued in its OWN chain's coin. ETH-native
    chains reuse the mainnet ETH/USD quote; a non-ETH chain is priced per-chain
    via ``get_native_price`` and is skipped (partial-flagged) — never ETH-quoted
    — when that price is unavailable."""

    def _mock_eth_native(self, monkeypatch, *, wei: int) -> None:
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: wei)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

    def test_base_contract_priced_at_eth_quote(self, db_session, monkeypatch, _cleanup):
        # Base is ETH-native → byte-identical to mainnet pricing.
        protocol = Protocol(name="BaseNativeProto")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("native", "b1")
        db_session.add(Contract(address=addr, chain="base", protocol_id=protocol.id, contract_name="BaseVault"))
        db_session.commit()

        self._mock_eth_native(monkeypatch, wei=2_000_000_000_000_000_000)  # 2 ETH
        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key("base", addr)]["total_usd"] == 4000.0
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1
        assert rows[0].token_symbol == "ETH"
        assert float(rows[0].price_usd) == 2000.0

    def test_null_chain_contract_priced_as_eth(self, db_session, monkeypatch, _cleanup):
        # Legacy NULL chain coalesces to mainnet → ETH pricing preserved.
        protocol = Protocol(name="NullChainProto")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("native", "n1")
        db_session.add(Contract(address=addr, chain=None, protocol_id=protocol.id, contract_name="LegacyVault"))
        db_session.commit()

        self._mock_eth_native(monkeypatch, wei=1_000_000_000_000_000_000)  # 1 ETH
        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key(None, addr)]["total_usd"] == 2000.0
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1 and rows[0].token_symbol == "ETH"

    def test_polygon_contract_priced_at_pol_quote(self, db_session, monkeypatch, _cleanup):
        # Regression: polygon (native POL) must be priced at its OWN coin's USD
        # quote and recorded under the POL symbol — never raised, never ETH-quoted.
        protocol = Protocol(name="PolygonProto")
        db_session.add(protocol)
        db_session.flush()

        addr = _addr("native_fail", "p1")
        db_session.add(Contract(address=addr, chain="polygon", protocol_id=protocol.id, contract_name="PolyVault"))
        db_session.commit()

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 100_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)  # mainnet quote, unused here
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))
        # POL/USD (probed value); the balance is 100 POL → $8.26.
        monkeypatch.setattr("utils.etherscan.get_native_price", lambda chain_id: 0.0826)

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key("polygon", addr)]["total_usd"] == 8.26
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1
        assert rows[0].token_symbol == "POL"
        assert float(rows[0].price_usd) == 0.0826

    def test_unpriceable_chain_skips_contract_and_flags_partial(self, db_session, monkeypatch, _cleanup):
        # A non-ETH chain whose native price can't be fetched must not wedge the
        # protocol: the failing contract is skipped (no row, no wrong quote), the
        # ETH sibling still snapshots, and the cycle is flagged partial.
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

        monkeypatch.setattr("utils.etherscan.get_native_price", _price_down)

        cycles: list[dict] = []
        monkeypatch.setattr("services.monitoring.tvl.emit_monitor_cycle", lambda *a, **k: cycles.append(k))

        count = refresh_all_protocols(db_session)

        # Snapshot still written (the protocol completed with its ETH contract).
        assert count == 1
        rows = db_session.query(ContractBalance).all()
        # Only the ETH contract got a balance row; the polygon one was skipped.
        assert len(rows) == 1
        assert rows[0].token_symbol == "ETH"
        assert {r.token_symbol for r in rows} == {"ETH"}

        # Operator-visible degraded cycle: exactly one partial heartbeat emitted.
        assert len(cycles) == 1
        assert cycles[0]["partial"] is True
        assert cycles[0]["note"] == "1_partial"


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
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        with caplog.at_level(logging.WARNING, logger="services.monitoring.tvl"):
            breakdown, _ = refresh_contract_balances(db_session, protocol.id)

        # Both contracts hold 5 ETH that could not be valued. Neither appears:
        # an unpriced holding is not a holding worth $0, and $0 is what the
        # breakdown would have carried into the headline figure.
        assert breakdown == {}

        # The log message should mention the number of contracts affected
        assert any("2 contract(s)" in r.message for r in caplog.records), (
            f"Expected log mentioning '2 contract(s)' affected, got: {[r.message for r in caplog.records]}"
        )


@requires_postgres
class TestContractBreakdownCompositeKey:
    """A CREATE2 twin (same address on ≥2 of a protocol's chains) must not
    collapse in the snapshot ``contract_breakdown``. The breakdown is keyed by
    the composite ``"<chain>::<address>"`` entity token so each chain's balance
    keeps its own entry and ``on_chain_total`` sums both (reviewer finding 1)."""

    @staticmethod
    def _chain_varying_eth_balance(address, chain_id=1):
        # ethereum (1) → 1 ETH, base (8453) → 2 ETH: distinct per-chain balances
        # so a last-wins collapse under-counts detectably.
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

    def test_refresh_keeps_both_chains(self, db_session, monkeypatch, _cleanup):
        protocol, addr = self._two_chain_twin(db_session)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", self._chain_varying_eth_balance)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

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
        # These are legacy-shaped rows (no fetch recorded), and the view still
        # publishes them: an absent fetch plane is not a failed one.
        assert partial is False

    def test_read_existing_priced_zero_is_published_unpriced_is_not(self, db_session, _cleanup):
        """Same distinction as the refresh branch (readiness §2.3): a stored
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
        assert partial is False

    def test_snapshot_total_sums_both_chains(self, db_session, monkeypatch, _cleanup):
        protocol, _addr_unused = self._two_chain_twin(db_session)
        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", self._chain_varying_eth_balance)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        snapshot, partial = take_tvl_snapshot(db_session, protocol.id)

        assert snapshot is not None
        assert partial is False
        assert snapshot.total_usd is not None and float(snapshot.total_usd) == 6000.0
        assert snapshot.contract_breakdown is not None and len(snapshot.contract_breakdown) == 2


@requires_postgres
class TestMainnetEthQuoteFailurePartial:
    """A failed upfront mainnet ETH/USD quote leaves ETH-native balances written
    with NULL prices; the cycle must be flagged ``partial`` — symmetric with the
    non-ETH native-quote path (reviewer finding 5)."""

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

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 3_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", _raise_price)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        # Balance row still written (behavior preserved), but with NULL price...
        rows = db_session.query(ContractBalance).filter(ContractBalance.contract_id == contract.id).all()
        assert len(rows) == 1 and rows[0].token_symbol == "ETH"
        assert rows[0].price_usd is None and rows[0].usd_value is None
        # ...and the cycle is flagged partial.
        assert partial is True
        # The 3 ETH it holds has no USD figure, so the contract is omitted from
        # the breakdown rather than published at ``total_usd: 0.0`` — the same
        # omission the non-ETH branch already does when its native quote fails.
        assert _entity_key("ethereum", addr) not in breakdown

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
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 3_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", _raise_price)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        cycles: list[dict] = []
        monkeypatch.setattr("services.monitoring.tvl.emit_monitor_cycle", lambda *a, **k: cycles.append(k))

        count = refresh_all_protocols(db_session)

        assert count == 1
        assert len(cycles) == 1
        assert cycles[0]["partial"] is True
        assert cycles[0]["note"] == "1_partial"


@requires_postgres
class TestFailedReadIsNotAMeasuredZero:
    """A contract whose reads failed must not reach the snapshot as ``0.0``.

    The failure was recorded only in the fetch plane and the cycle's ``partial``
    flag; ``TvlSnapshot.total_usd`` and the served ``contract_breakdown``
    (routers/protocols.py) carry no discriminator, so a published ``0.0`` is
    read downstream as "this contract holds nothing" — an absence turned into a
    money figure. The sibling read-existing branch was already fixed for exactly
    this; this pins the refresh branch.
    """

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

        monkeypatch.setattr("utils.etherscan.get_eth_balance", _balance)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", _tokens)

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
        # The headline number is the ONE measured contract, not that contract
        # plus a fabricated zero.
        assert snapshot.total_usd is not None and float(snapshot.total_usd) == 2000.0

    def test_a_genuine_zero_is_still_published(self, db_session, monkeypatch, _cleanup):
        """Recall pin: a contract that really holds nothing keeps its ``0.0``.

        Omission must mean "not measured", so a measured empty contract has to
        stay in the breakdown or the two states collapse again from the other
        side.
        """
        protocol = Protocol(name="GenuineZeroProto")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("failfetch", "c3")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="EmptyVault"))
        db_session.commit()

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert partial is False
        assert breakdown[_entity_key("ethereum", addr)]["total_usd"] == 0.0
        assert breakdown[_entity_key("ethereum", addr)]["tokens"] == []

    def test_token_read_failure_alone_also_omits(self, db_session, monkeypatch, _cleanup):
        """One unpublishable row class is enough — the same rule
        ``contracts_missing_current_rows`` applies on the sibling branch. A total
        built from the native leg only would understate the contract while
        looking measured."""
        protocol = Protocol(name="TokenFailOnlyProto")
        db_session.add(protocol)
        db_session.flush()
        addr = _addr("failfetch", "d4")
        db_session.add(Contract(address=addr, chain="ethereum", protocol_id=protocol.id, contract_name="Vault"))
        db_session.commit()

        def _raise_tokens(address, chain_id=1):
            raise RuntimeError("Etherscan failed")

        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 1_000_000_000_000_000_000)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", _raise_tokens)

        breakdown, partial = refresh_contract_balances(db_session, protocol.id)

        assert breakdown == {}
        assert partial is True
        # The measured native leg is still persisted; only the published total
        # is withheld.
        rows = db_session.query(ContractBalance).all()
        assert len(rows) == 1 and rows[0].token_symbol == "ETH"


@requires_postgres
class TestProvenCodelessHolderPopulation:
    """Who ``refresh_entity_balances`` reads, and why nobody else is in it.

    The population is the earned ``eth_getCode`` witness and nothing looser: a
    node is in it because an empty code read put ``resolved_type = 'eoa'`` on it,
    never because a name, a relation or a row suggests an EOA. Everything the
    producer declines to read comes back as an ``ExcludedHolder`` carrying the
    reason, because a population that quietly shrinks is indistinguishable from
    one that was never that size.
    """

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
        # The three kinds that are NOT the witness. ``unknown`` is the one that
        # matters: a node nobody probed carries it, and sweeping it as an EOA
        # would be a name standing in for the getCode that was never issued.
        self._node(db_session, host, self._addr("3"), "unknown")
        self._node(db_session, host, self._addr("4"), "contract")
        self._node(db_session, host, self._addr("5"), None)
        db_session.commit()

        holders, excluded = proven_codeless_holders(db_session, proto.id)
        assert [h.entity_key for h in holders] == [f"ethereum::{eoa}"]
        # The three non-EOAs are not "excluded" either — they were never
        # candidates, so publishing a reason for them would misreport the
        # predicate as a filter over every node.
        assert excluded == []

    def test_an_eoa_node_that_also_carries_an_unknown_node_stays_in(self, db_session, monkeypatch, _cleanup):
        """An unprobed sibling does not retract an earned witness.

        ``resolved_type='eoa'`` is only written after an empty ``eth_getCode``.
        A second node for the same address that nobody probed says nothing about
        the address, so it cannot withdraw what the probe established.
        """
        proto, host = self._fixture(db_session, monkeypatch)
        eoa = self._addr("6")
        self._node(db_session, host, eoa, "eoa")
        self._node(db_session, host, eoa, "unknown")
        db_session.commit()

        holders, _excluded = proven_codeless_holders(db_session, proto.id)
        assert [h.entity_key for h in holders] == [f"ethereum::{eoa}"]

    def test_an_address_with_its_own_contracts_row_is_never_a_second_subject(self, db_session, monkeypatch, _cleanup):
        """The guard at the heart of the carrier.

        One address read as a contract subject AND as an entity subject would
        fold TWO accounts onto one entity key, and the sheet's "every folded
        account was scanned at its own address" conjunct would then be asking
        about the same account twice — a completeness claim that counts one
        witness as two. The address is read through its ``contracts`` row, and
        the entity population declines it WITH the reason.
        """
        proto, host = self._fixture(db_session, monkeypatch)
        # The host contract's own address, also reached as an owner node.
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
        """Nothing leaves the population silently.

        The candidate set is the plane's own ``load_proven_eoa_entities``; this
        pins that the two output lists partition it, so a future guard cannot
        drop an address without either reading it or saying why.
        """
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
        """``no_rows`` is the LEVER's framing, deliberately not a producer filter.

        Filtering the population on "has no sheet yet" would read each holder
        exactly once and never again: the cursor would stop advancing, and a
        proven-empty sheet published through block N would stand for a holder
        that has since been paid. The producer's population is the witness; what
        bounds the cost is the sweep cursor, not a one-shot population.
        """
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
        """End to end, offline: the population is what gets written, keyed on itself.

        Also the carrier's own invariant, asserted where it is produced rather
        than only where it is consumed: reading an entity holder mints no
        ``contracts`` row.
        """
        proto, host = self._fixture(db_session, monkeypatch)
        eoa = self._addr("a")
        self._node(db_session, host, eoa, "eoa")
        db_session.commit()
        contracts_before = db_session.query(Contract).count()

        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))
        # The escalation fires (an empty page is a trigger, never a proof) and
        # the scan is what would answer it; this test pins the RECORD, so the
        # scan is stubbed to no outcome and the sheet stays honestly unproven.
        monkeypatch.setattr("services.monitoring.tvl.run_sweeps", lambda requests, **kw: ({}, SweepCost()))

        report = refresh_entity_balances(db_session, proto.id)
        assert [h.entity_key for h in report.holders] == [f"ethereum::{eoa}"]
        assert report.excluded == []
        assert report.etherscan_pages == 1

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
        # No sweep answered, so no completeness is claimed and the source stays
        # the third-party index's.
        assert fetch.asset_set_source == ASSET_SET_SOURCE_ETHERSCAN_PAGES
        assert db_session.query(Contract).count() == contracts_before


@requires_postgres
class TestEntityCohortInTheCycle:
    """The daily arm of the TVL cycle, and why it spends nothing the sweep needs.

    Two facts are pinned here, both about wiring rather than about what a
    balance means. The cohort of proven-codeless principals is read on ITS
    schedule — once a day, measured against its own fetch rows — while the
    snapshot keeps the clock it always had. And the requests that reading costs
    are counted somewhere else: a counter handed to the entity pass, never the
    one the contract sweep's ceiling is being spent against.
    """

    PREFIX = "0x000000000000000000000000000000000000f"

    def _addr(self, suffix: str) -> str:
        return (self.PREFIX + suffix).ljust(42, "0")[:42]

    def _fixture(self, db_session, monkeypatch, tag: str):
        """One protocol, one deployment, one proven-codeless owner.

        *tag* gives each test its own addresses on purpose: an entity-keyed
        fetch row hangs off ``(chain, address)`` and no ``contracts`` row, so
        the session teardown's cascade never reaches it and a shared address
        would let one test's reading answer the next test's cadence question.
        """
        monkeypatch.setattr("services.monitoring.tvl.rpc_url_for_chain_id", lambda chain_id: "http://rpc.invalid")
        monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda name: None)
        monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda address, chain_id=1: 0)
        monkeypatch.setattr("utils.etherscan.get_eth_price", lambda chain_id=1: 2000.0)
        monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda address, chain_id=1: page([]))
        proto = Protocol(name=f"TestProto_cohort_{tag}")
        db_session.add(proto)
        db_session.flush()
        host = Contract(protocol_id=proto.id, address=self._addr(f"{tag}1"), chain="ethereum", contract_name="Host")
        db_session.add(host)
        db_session.flush()
        eoa = self._addr(f"{tag}2")
        db_session.add(ControlGraphNode(contract_id=host.id, address=eoa, node_type="owner", resolved_type="eoa"))
        db_session.commit()
        # State the precondition instead of inheriting it. The session teardown
        # sweeps these rows, but a DB polluted by a build that predates that
        # sweep would hand the first test of the run a cohort already fresh, and
        # a cadence test that reads someone else's answer is not a test.
        db_session.query(ContractBalanceFetch).filter(
            ContractBalanceFetch.entity_address.like(f"{self.PREFIX}{tag}%")
        ).delete(synchronize_session=False)
        db_session.commit()
        return proto, host, eoa

    def _readings(self, db_session, eoa: str) -> int:
        return db_session.query(ContractBalanceFetch).filter(ContractBalanceFetch.entity_address == eoa).count()

    def _age(self, db_session, *addresses: str, seconds: int) -> None:
        from datetime import datetime, timedelta, timezone

        db_session.query(ContractBalanceFetch).filter(ContractBalanceFetch.entity_address.in_(addresses)).update(
            {ContractBalanceFetch.fetched_at: datetime.now(timezone.utc) - timedelta(seconds=seconds)},
            synchronize_session=False,
        )
        db_session.commit()

    def _eoa_node(self, db_session, host, address: str) -> None:
        db_session.add(ControlGraphNode(contract_id=host.id, address=address, node_type="owner", resolved_type="eoa"))
        db_session.commit()

    def test_the_cohort_is_read_daily_and_the_snapshot_keeps_its_own_clock(self, db_session, monkeypatch, _cleanup):
        """Cadence (a): the entity arm fires on the day, the contract arm does not move.

        Three ticks of the cycle. The first reads both. The second is inside
        BOTH windows and reads neither. The third comes after the cohort's
        reading has aged past a day and nothing else has changed — so the entity
        arm fires again while the contract sweep, whose
        ``MIN_SNAPSHOT_INTERVAL`` dedupe is untouched, still declines.
        """
        proto, _host, eoa = self._fixture(db_session, monkeypatch, "a")
        contract_sweeps: list[int] = []
        real_contract_refresh = tvl_module.refresh_contract_balances

        def _counting_contract_refresh(session, protocol_id):
            contract_sweeps.append(protocol_id)
            return real_contract_refresh(session, protocol_id)

        monkeypatch.setattr("services.monitoring.tvl.refresh_contract_balances", _counting_contract_refresh)
        monkeypatch.setattr("services.monitoring.tvl.run_sweeps", lambda requests, **kw: ({}, SweepCost()))

        refresh_all_protocols(db_session)
        assert self._readings(db_session, eoa) == 1
        assert contract_sweeps == [proto.id]

        refresh_all_protocols(db_session)
        assert self._readings(db_session, eoa) == 1
        assert contract_sweeps == [proto.id]

        self._age(db_session, eoa, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)

        refresh_all_protocols(db_session)
        assert self._readings(db_session, eoa) == 2
        # The entity arm moved and the contract arm did not: two clocks, and
        # this is the tick that tells them apart.
        assert contract_sweeps == [proto.id]

    def test_the_window_is_measured_against_the_cohorts_own_rows(self, db_session, monkeypatch, _cleanup):
        """What "daily" is anchored to: the cohort's own readings, rolling.

        Not a wall-clock day and not loop-local state — the rows the producer
        itself wrote. A cohort read inside the window returns ``None`` (the pass
        did not run); one outside it reads again.
        """
        from datetime import datetime, timedelta, timezone

        proto, _host, eoa = self._fixture(db_session, monkeypatch, "b")
        monkeypatch.setattr("services.monitoring.tvl.run_sweeps", lambda requests, **kw: ({}, SweepCost()))

        first = refresh_entity_balances_if_due(db_session, proto.id)
        assert first is not None and [h.entity_key for h in first.holders] == [f"ethereum::{eoa}"]

        now = datetime.now(timezone.utc)
        assert refresh_entity_balances_if_due(db_session, proto.id, now=now + timedelta(hours=23)) is None
        assert refresh_entity_balances_if_due(db_session, proto.id, now=now + timedelta(hours=25)) is not None
        assert self._readings(db_session, eoa) == 2

    def test_a_shared_members_fresh_row_cannot_mask_a_stale_exclusive_one(self, db_session, monkeypatch, _cleanup):
        """The anchor is the cohort's OLDEST reading, and this is why.

        A fetch row's identity is ``(chain, address)`` and carries no protocol,
        but the cohort is protocol-scoped — so an EOA reached from two
        protocols' control graphs is one row that either protocol's pass
        refreshes. Anchored on the newest reading, protocol A's daily pass would
        keep that row fresh and protocol B's exclusive holder would never be
        read again. Here B goes stale, A refreshes only the shared member, and B
        must still be due for the holder A cannot reach.
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
        monkeypatch.setattr("services.monitoring.tvl.run_sweeps", lambda requests, **kw: ({}, SweepCost()))

        assert refresh_entity_balances_if_due(db_session, proto_b.id) is not None
        assert (self._readings(db_session, exclusive), self._readings(db_session, shared)) == (1, 1)

        self._age(db_session, exclusive, shared, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)
        # A's cohort is the shared member alone; its pass refreshes that row and
        # can reach nothing of B's.
        assert refresh_entity_balances_if_due(db_session, proto_a.id) is not None
        assert (self._readings(db_session, exclusive), self._readings(db_session, shared)) == (1, 2)

        assert refresh_entity_balances_if_due(db_session, proto_b.id) is not None
        assert self._readings(db_session, exclusive) == 2

    def test_a_holder_that_was_never_read_is_not_a_stale_reading(self, db_session, monkeypatch, _cleanup):
        """No reading is a third state, and it is not a floor of zero.

        A holder discovered after the last pass has no reading at all. Folding
        that absence into the anchor as an infinitely old one would re-open the
        cohort on every tick and spend the day's requests hourly. It waits for
        the pass the cohort's own age opens — and then it is read.
        """
        proto, host, first_eoa = self._fixture(db_session, monkeypatch, "e")
        monkeypatch.setattr("services.monitoring.tvl.run_sweeps", lambda requests, **kw: ({}, SweepCost()))
        assert refresh_entity_balances_if_due(db_session, proto.id) is not None

        newcomer = self._addr("e9")
        self._eoa_node(db_session, host, newcomer)

        assert refresh_entity_balances_if_due(db_session, proto.id) is None
        assert self._readings(db_session, newcomer) == 0

        self._age(db_session, first_eoa, seconds=DEFAULT_ENTITY_BALANCE_INTERVAL + 60)
        assert refresh_entity_balances_if_due(db_session, proto.id) is not None
        assert (self._readings(db_session, first_eoa), self._readings(db_session, newcomer)) == (2, 1)

    def test_the_cohort_spends_a_counter_the_contract_sweep_never_sees(self, db_session, monkeypatch, _cleanup):
        """Budget isolation (b): two counters, each starting at zero.

        ``SWEEP_REQUEST_BUDGET`` is a ceiling on whatever counter ``run_sweeps``
        carries, so one counter shared across the two cohorts would be the daily
        entity pass spending the hourly sweep's allowance. Each arm is recorded
        as it arrives and made to spend a distinguishable amount: were the
        sweep's counter ever passed along, the entity arm would arrive already
        spent and both totals would read the sum. The property predates this
        wiring — ``run_sweeps`` mints a counter per call — and the point of
        pinning it is that the daily arm now depends on it.
        """
        _proto, _host, eoa = self._fixture(db_session, monkeypatch, "c")
        seen: list[tuple[str, SweepCost, int, bool, int]] = []
        spend = {"contract": 3, "entity": 7}

        def _recording_run_sweeps(requests, *, rpc_url_for, cost=None):
            counter = cost if cost is not None else SweepCost()
            kind = "entity" if requests and all(r.subject.is_entity for r in requests) else "contract"
            seen.append((kind, counter, counter.total, cost is not None, len(requests)))
            counter.get_logs += spend[kind]
            return {}, counter

        monkeypatch.setattr("services.monitoring.tvl.run_sweeps", _recording_run_sweeps)

        refresh_all_protocols(db_session)

        # Ordering unchanged: the contract sweep still runs first, and both arms
        # really did have something to sweep (an empty list would make the
        # labelling below vacuous).
        assert [k for k, _c, _t, _e, _n in seen] == ["contract", "entity"]
        assert all(n > 0 for _k, _c, _t, _e, n in seen)
        by_kind = {k: (counter, arrival, explicit) for k, counter, arrival, explicit, _n in seen}
        contract_counter, contract_arrival, _ = by_kind["contract"]
        entity_counter, entity_arrival, entity_explicit = by_kind["entity"]

        assert contract_counter is not entity_counter
        # Stated at the call site rather than left to a default two modules
        # away, so a change to that default cannot silently merge the two.
        assert entity_explicit is True
        assert (contract_arrival, entity_arrival) == (0, 0)
        assert (contract_counter.total, entity_counter.total) == (3, 7)
        assert self._readings(db_session, eoa) == 1
