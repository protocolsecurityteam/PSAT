"""Tests for protocol-wide TVL tracking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from db.models import Contract, ContractBalance, ContractBalanceFetch, Protocol, TvlSnapshot
from services.aggregations.company_overview import _entity_key
from services.monitoring.tvl import (
    _get_protocol_addresses,
    _read_existing_balances,
    fetch_defillama_tvl,
    refresh_all_protocols,
    refresh_contract_balances,
    take_tvl_snapshot,
)
from tests.conftest import requires_postgres
from tests.support.balance_stubs import page, pinned_native_unavailable
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
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
