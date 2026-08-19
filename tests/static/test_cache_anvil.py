"""Anvil-based integration tests -- real RPC proxy cache verification.

These tests deploy a minimal EIP-1967 proxy on a local Anvil node and
exercise the _check_proxy_cache / _apply_proxy_cache / resolve_current_implementation
code path with real storage slot reads instead of mocks.
"""

from __future__ import annotations

import shutil
import signal
import socket
import subprocess
import time as _time

import pytest

from tests.cache_helpers import db_session, requires_postgres  # noqa: F401

_HAS_ANVIL = shutil.which("anvil") is not None

pytestmark = requires_postgres


@pytest.fixture(autouse=True)
def _stub_dynamic_tx_fetch(monkeypatch):
    """Offline: the dependency phase pulls a contract's tx list from Etherscan to
    seed dynamic-dependency tracing; the cache-upgrade test needs no dynamic deps."""
    monkeypatch.setattr(
        "services.discovery.dynamic_dependencies.fetch_contract_transactions",
        lambda *a, **k: [],
    )


# EIP-1967 implementation storage slot
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# Two distinct fake implementation addresses
_ANVIL_IMPL_A = "0x1111111111111111111111111111111111111111"
_ANVIL_IMPL_B = "0x2222222222222222222222222222222222222222"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def anvil_rpc():
    """Start a local Anvil instance and return its RPC URL.

    Yields ``http://127.0.0.1:<port>`` and tears down when done.
    """
    port = _find_free_port()
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    rpc_url = f"http://127.0.0.1:{port}"

    # Wait for Anvil to be ready (up to 5 seconds)
    import requests

    for _ in range(50):
        try:
            resp = requests.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                timeout=1,
            )
            if resp.status_code == 200:
                break
        except Exception:
            pass
        _time.sleep(0.1)
    else:
        proc.kill()
        pytest.skip("Anvil did not start in time")

    try:
        yield rpc_url
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _deploy_minimal_contract(rpc_url: str) -> str:
    """Deploy the smallest possible contract on Anvil and return its address.

    Uses Anvil's first pre-funded account (index 0) to deploy.
    Bytecode: stores 0x01 at memory[0] and returns 1 byte of runtime code.
    """
    import requests

    deploy_bytecode = "0x600160005360016000f3"

    # Get the first account
    resp = requests.post(
        rpc_url,
        json={"jsonrpc": "2.0", "method": "eth_accounts", "params": [], "id": 1},
        timeout=5,
    )
    accounts = resp.json()["result"]
    deployer = accounts[0]

    # Send deployment transaction
    resp = requests.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{"from": deployer, "data": deploy_bytecode, "gas": "0x100000"}],
            "id": 2,
        },
        timeout=5,
    )
    tx_hash = resp.json()["result"]

    # Wait for receipt (Anvil auto-mines but be safe)
    for _ in range(10):
        resp = requests.post(
            rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_getTransactionReceipt", "params": [tx_hash], "id": 3},
            timeout=5,
        )
        receipt = resp.json().get("result")
        if receipt is not None:
            return receipt["contractAddress"]
        _time.sleep(0.1)

    raise RuntimeError(f"Transaction {tx_hash} not mined after waiting")


def _set_storage(rpc_url: str, address: str, slot: str, value: str) -> None:
    """Set a storage slot on Anvil using anvil_setStorageAt."""
    import requests

    # Pad the value to 32 bytes
    padded_value = "0x" + value.replace("0x", "").lower().zfill(64)
    resp = requests.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "method": "anvil_setStorageAt",
            "params": [address, slot, padded_value],
            "id": 1,
        },
        timeout=5,
    )
    result = resp.json()
    assert "error" not in result, f"anvil_setStorageAt failed: {result}"


@pytest.mark.skipif(not _HAS_ANVIL, reason="anvil not found")
class TestAnvilProxyCache:
    """Integration tests that exercise real EIP-1967 storage slot reads via Anvil."""

    def test_resolve_current_implementation_reads_real_slot(self, anvil_rpc):
        """resolve_current_implementation reads the EIP-1967 slot from a real node."""
        from services.monitoring.proxy_watcher import resolve_current_implementation

        proxy_addr = _deploy_minimal_contract(anvil_rpc)
        _set_storage(anvil_rpc, proxy_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_A)

        result = resolve_current_implementation(proxy_addr, anvil_rpc, proxy_type="eip1967")
        assert result is not None
        assert result.lower() == _ANVIL_IMPL_A.lower()

    def test_resolve_current_implementation_detects_change(self, anvil_rpc):
        """After changing the slot, resolve_current_implementation returns the new address."""
        from services.monitoring.proxy_watcher import resolve_current_implementation

        proxy_addr = _deploy_minimal_contract(anvil_rpc)

        _set_storage(anvil_rpc, proxy_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_A)
        result_a = resolve_current_implementation(proxy_addr, anvil_rpc, proxy_type="eip1967")
        assert result_a is not None
        assert result_a.lower() == _ANVIL_IMPL_A.lower()

        _set_storage(anvil_rpc, proxy_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_B)
        result_b = resolve_current_implementation(proxy_addr, anvil_rpc, proxy_type="eip1967")
        assert result_b is not None
        assert result_b.lower() == _ANVIL_IMPL_B.lower()

    def test_resolve_current_implementation_empty_slot(self, anvil_rpc):
        """Empty slot returns None."""
        from services.monitoring.proxy_watcher import resolve_current_implementation

        proxy_addr = _deploy_minimal_contract(anvil_rpc)
        # Don't set the slot -- it defaults to zero
        result = resolve_current_implementation(proxy_addr, anvil_rpc, proxy_type="eip1967")
        assert result is None

    def test_check_proxy_cache_unchanged_impl_via_anvil(self, db_session, anvil_rpc):
        """_check_proxy_cache returns cached classification when the on-chain
        implementation matches the cached one -- exercising real RPC."""

        from db.models import Contract
        from db.queue import create_job
        from workers.static_worker import _check_proxy_cache

        # Deploy a contract and set it as a proxy pointing to IMPL_A
        proxy_addr = _deploy_minimal_contract(anvil_rpc)
        _set_storage(anvil_rpc, proxy_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_A)

        # Create source job with proxy info matching the on-chain state
        source_job = create_job(db_session, {"address": proxy_addr})
        src_contract = Contract(
            job_id=source_job.id,
            address=proxy_addr,
            contract_name="Proxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=_ANVIL_IMPL_A,
        )
        db_session.add(src_contract)
        db_session.flush()

        # Create target job flagged as cached
        target_job = create_job(
            db_session,
            {
                "address": proxy_addr,
                "rpc_url": anvil_rpc,
                "static_cached": True,
                "cache_source_job_id": str(source_job.id),
            },
        )
        target_contract = Contract(
            job_id=target_job.id,
            address=proxy_addr,
            contract_name="Proxy",
        )
        db_session.add(target_contract)
        db_session.flush()

        # _check_proxy_cache should return the cached classification (impl unchanged)
        result = _check_proxy_cache(db_session, target_job, target_contract)
        assert result is not None
        assert result["type"] == "proxy"
        assert result["proxy_type"] == "eip1967"

        # Verify target contract was updated with proxy fields
        db_session.refresh(target_contract)
        assert target_contract.is_proxy is True
        assert target_contract.implementation is not None
        assert target_contract.implementation.lower() == _ANVIL_IMPL_A.lower()

    def test_check_proxy_cache_detects_upgrade_via_anvil(self, db_session, anvil_rpc):
        """_check_proxy_cache returns None when on-chain implementation differs
        from cached -- exercising real RPC upgrade detection."""
        from db.models import Contract
        from db.queue import create_job
        from workers.static_worker import _check_proxy_cache

        proxy_addr = _deploy_minimal_contract(anvil_rpc)
        # On-chain: impl is now B
        _set_storage(anvil_rpc, proxy_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_B)

        # Source job says impl was A (stale cache)
        source_job = create_job(db_session, {"address": proxy_addr})
        src_contract = Contract(
            job_id=source_job.id,
            address=proxy_addr,
            contract_name="Proxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=_ANVIL_IMPL_A,
        )
        db_session.add(src_contract)
        db_session.flush()

        target_job = create_job(
            db_session,
            {
                "address": proxy_addr,
                "rpc_url": anvil_rpc,
                "static_cached": True,
                "cache_source_job_id": str(source_job.id),
            },
        )
        target_contract = Contract(
            job_id=target_job.id,
            address=proxy_addr,
            contract_name="Proxy",
        )
        db_session.add(target_contract)
        db_session.flush()

        # Should detect upgrade and return None
        result = _check_proxy_cache(db_session, target_job, target_contract)
        assert result is None

    def test_check_proxy_cache_non_proxy_via_anvil(self, db_session, anvil_rpc):
        """_check_proxy_cache for a non-proxy source returns regular without RPC."""
        from db.models import Contract
        from db.queue import create_job
        from workers.static_worker import _check_proxy_cache

        proxy_addr = _deploy_minimal_contract(anvil_rpc)

        source_job = create_job(db_session, {"address": proxy_addr})
        src_contract = Contract(
            job_id=source_job.id,
            address=proxy_addr,
            contract_name="NonProxy",
            is_proxy=False,
        )
        db_session.add(src_contract)
        db_session.flush()

        target_job = create_job(
            db_session,
            {
                "address": proxy_addr,
                "rpc_url": anvil_rpc,
                "static_cached": True,
                "cache_source_job_id": str(source_job.id),
            },
        )
        target_contract = Contract(
            job_id=target_job.id,
            address=proxy_addr,
            contract_name="NonProxy",
        )
        db_session.add(target_contract)
        db_session.flush()

        result = _check_proxy_cache(db_session, target_job, target_contract)
        assert result is not None
        assert result["type"] == "regular"

    def test_check_proxy_cache_immutable_eip1167_no_rpc_via_anvil(self, db_session, anvil_rpc):
        """_check_proxy_cache for eip1167 (immutable) reuses cache without RPC."""
        from db.models import Contract
        from db.queue import create_job
        from workers.static_worker import _check_proxy_cache

        proxy_addr = _deploy_minimal_contract(anvil_rpc)

        source_job = create_job(db_session, {"address": proxy_addr})
        src_contract = Contract(
            job_id=source_job.id,
            address=proxy_addr,
            contract_name="Clone",
            is_proxy=True,
            proxy_type="eip1167",
            implementation=_ANVIL_IMPL_A,
        )
        db_session.add(src_contract)
        db_session.flush()

        target_job = create_job(
            db_session,
            {
                "address": proxy_addr,
                "rpc_url": anvil_rpc,
                "static_cached": True,
                "cache_source_job_id": str(source_job.id),
            },
        )
        target_contract = Contract(
            job_id=target_job.id,
            address=proxy_addr,
            contract_name="Clone",
        )
        db_session.add(target_contract)
        db_session.flush()

        result = _check_proxy_cache(db_session, target_job, target_contract)
        assert result is not None
        assert result["type"] == "proxy"
        assert result["proxy_type"] == "eip1167"
        db_session.refresh(target_contract)
        assert target_contract.implementation is not None
        assert target_contract.implementation.lower() == _ANVIL_IMPL_A.lower()

    def test_dependency_proxy_cache_detects_upgrade_via_anvil(self, db_session, anvil_rpc, monkeypatch, tmp_path):
        """After a proxy dependency is upgraded on-chain, re-running the
        dependency phase should detect the stale cached classification and
        re-classify the dependency with the current implementation address."""
        from db.models import Contract
        from db.queue import create_job, get_artifact, store_artifact

        # Deploy a target contract and a proxy dependency on Anvil
        target_addr = _deploy_minimal_contract(anvil_rpc).lower()
        dep_addr = _deploy_minimal_contract(anvil_rpc).lower()

        # Set the dependency's EIP-1967 implementation slot to IMPL_A
        _set_storage(anvil_rpc, dep_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_A)

        # Create a job with RPC pointing to Anvil
        job = create_job(db_session, {"address": target_addr, "rpc_url": anvil_rpc})
        contract = Contract(
            job_id=job.id,
            address=target_addr,
            contract_name="Target",
            compiler_version="v0.8.24",
            language="solidity",
            evm_version="shanghai",
            optimization=True,
            optimization_runs=200,
            source_format="flat",
            source_file_count=1,
            remappings=[],
        )
        db_session.add(contract)
        db_session.commit()

        # Store cached static dependencies containing the proxy dep
        store_artifact(
            db_session,
            job.id,
            "static_dependencies",
            data={
                "address": target_addr,
                "dependencies": [dep_addr],
                "rpc": anvil_rpc,
            },
        )

        # Store cached classifications from "previous run" with impl = IMPL_A
        store_artifact(
            db_session,
            job.id,
            "classifications",
            data={
                "address": target_addr,
                "rpc": anvil_rpc,
                "classifications": {
                    target_addr: {"address": target_addr, "type": "regular"},
                    dep_addr: {
                        "address": dep_addr,
                        "type": "proxy",
                        "proxy_type": "eip1967",
                        "implementation": _ANVIL_IMPL_A,
                    },
                },
                "discovered_addresses": [],
            },
        )

        # --- Upgrade the dependency proxy to IMPL_B ---
        _set_storage(anvil_rpc, dep_addr, _EIP1967_IMPL_SLOT, _ANVIL_IMPL_B)

        # Mock non-classification parts of _run_dependency_phase
        monkeypatch.setattr(
            "workers.static_worker.build_unified_dependencies",
            lambda *a, **kw: {"target_address": target_addr, "dependencies": {}},
        )
        monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda *a, **kw: None)
        monkeypatch.setattr(
            "workers.static_worker.build_dependency_visualization",
            lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
        )
        # Step 1 inlined the upgrade-history resolver into _run_dependency_phase;
        # monkeypatch the underlying builder it now calls instead.
        monkeypatch.setattr("services.discovery.upgrade_history.build_upgrade_history", lambda *a, **kw: None)

        # Run the dependency phase
        from workers.static_worker import StaticWorker

        worker = StaticWorker()
        worker._run_dependency_phase(
            db_session,
            job,
            tmp_path,
            "Target",
            target_addr,
        )

        # The stored classifications should reflect the upgrade
        cls_result = get_artifact(db_session, job.id, "classifications")
        assert isinstance(cls_result, dict)
        dep_cls = cls_result["classifications"].get(dep_addr, {})

        assert dep_cls.get("type") == "proxy", f"Expected proxy type, got {dep_cls.get('type')}"
        assert dep_cls.get("implementation", "").lower() == _ANVIL_IMPL_B.lower(), (
            f"Expected implementation {_ANVIL_IMPL_B} (current on-chain), "
            f"but got {dep_cls.get('implementation')} (stale cache)"
        )
