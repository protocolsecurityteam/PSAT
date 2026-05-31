"""Regression tests for split-proxy *secondary implementation* handling (1A).

Models the real ether.fi LRTSquared shape: a UUPSProxy whose EIP-1967 impl
(``LRTSquaredCore``) has a ``fallback`` that delegatecalls an address held in a
non-public state var (``adminImpl``, set via ``setAdminImpl``), pointing at a
second logic contract (``LRTSquaredAdmin``). Before the fix that admin impl was
analysed standalone against its own empty storage and rendered as an ownerless
orphan; its 24 admin functions never resolved.

  * detection runs real Slither on a Core-shaped fixture and recovers the
    ``adminImpl`` pointer + its (packing-aware) storage slot;
  * the storage-word decoder honours the byte offset of a packed slot;
  * ``resolve_secondary_impl_addresses`` reads the pointer against the PROXY
    (not the impl) via a stubbed ``rpc_request``;
  * ``queue_secondary_impl_jobs`` records the secondary on the proxy row and
    queues a proxy-child analysis job (``proxy_address`` set).
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery.secondary_impl import (  # noqa: E402
    _address_from_storage_word,
    queue_secondary_impl_jobs,
    resolve_secondary_impl_addresses,
)
from tests.conftest import requires_postgres  # noqa: E402

# ---------------------------------------------------------------------------
# Detection (real Slither)
# ---------------------------------------------------------------------------

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

_CORE_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LRTSquaredStorage {
    address public governor;   // slot 0 — read by a modifier, NOT delegatecalled
    address adminImpl;         // slot 1 — non-public: no auto-getter (reverts)
    uint256 public rateLimit;  // slot 2
}

contract LRTSquaredCore is LRTSquaredStorage {
    modifier onlyGovernor() {
        require(msg.sender == governor, "only governor");
        _;
    }

    function setAdminImpl(address a) external onlyGovernor {
        adminImpl = a;
    }

    function deposit() external {}

    fallback() external {
        address impl = adminImpl;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""


@pytest.fixture(scope="module")
def core_contract(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("secimpl")
    f = tmp / "Core.sol"
    f.write_text(_CORE_SRC)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == "LRTSquaredCore")


def test_detect_finds_admin_impl_pointer(core_contract):
    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    pointers = detect_secondary_impl_pointers(core_contract)
    by_name = {p["name"]: p for p in pointers}
    assert "adminImpl" in by_name, "fallback delegatecall-target state var must be detected"
    assert by_name["adminImpl"]["slot"] == 1  # after governor at slot 0
    assert by_name["adminImpl"]["offset"] == 0
    # ``governor`` is read by a modifier (msg.sender check), never delegatecalled —
    # it must NOT be mistaken for a secondary-impl pointer.
    assert "governor" not in by_name


def test_detect_empty_for_plain_contract(tmp_path):
    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Plain { address public owner; function f() external {} }
"""
    f = tmp_path / "Plain.sol"
    f.write_text(src)
    c = next(c for c in Slither(str(f)).contracts if c.name == "Plain")
    assert detect_secondary_impl_pointers(c) == []


# ---------------------------------------------------------------------------
# Storage-word decode (pure)
# ---------------------------------------------------------------------------


def test_address_from_storage_word_offsets():
    admin = "0x" + "ab" * 20
    # offset 0: address occupies the low 20 bytes (standard, unpacked slot).
    assert _address_from_storage_word("0x" + "00" * 12 + admin[2:], 0) == admin
    # the zero address resolves to None (unset pointer).
    assert _address_from_storage_word("0x" + "00" * 32, 0) is None
    # packed at byte offset 8: 4 high bytes | 20-byte address | 8 low bytes.
    packed = "22" * 4 + admin[2:] + "11" * 8
    assert len(packed) == 64
    assert _address_from_storage_word("0x" + packed, 8) == admin
    # garbage / empty inputs are tolerated.
    assert _address_from_storage_word(None, 0) is None
    assert _address_from_storage_word("0x", 0) is None


# ---------------------------------------------------------------------------
# Pointer-value resolution (stubbed RPC) — reads against the PROXY
# ---------------------------------------------------------------------------


def test_resolve_secondary_impl_addresses_reads_proxy_storage(monkeypatch):
    proxy = "0x" + "11" * 20
    admin = "0x" + "ab" * 20
    seen_targets: list[str] = []

    def fake_rpc(rpc_url, method, params, retries=1, **_):
        assert method == "eth_getStorageAt"
        seen_targets.append(params[0])
        if params[1] == hex(1):  # adminImpl slot
            return "0x" + "00" * 12 + admin[2:]
        return "0x" + "00" * 32  # any other slot: unset

    monkeypatch.setattr("utils.rpc.rpc_request", fake_rpc)

    addrs = resolve_secondary_impl_addresses("http://stub", proxy, [{"name": "adminImpl", "slot": 1, "offset": 0}])
    assert addrs == [admin]
    # The pointer must be read from the PROXY's storage, not the impl's.
    assert seen_targets == [proxy]

    # An unset (zero) pointer yields no secondary.
    assert resolve_secondary_impl_addresses("http://stub", proxy, [{"name": "x", "slot": 9, "offset": 0}]) == []


# ---------------------------------------------------------------------------
# Recording + child-job spawn (real Postgres)
# ---------------------------------------------------------------------------


@requires_postgres
def test_queue_secondary_impl_jobs_records_and_spawns(db_session):
    from db.models import Contract, Job, JobStage, JobStatus

    proxy = "0x" + uuid.uuid4().hex[:40]
    core = "0x" + uuid.uuid4().hex[:40]
    admin = "0x" + uuid.uuid4().hex[:40]

    parent = Job(
        id=uuid.uuid4(),
        address=core,
        name="LRTSquared: (impl)",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"address": core, "proxy_address": proxy, "chain": "ethereum"},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(parent)
    proxy_contract = Contract(
        address=proxy,
        chain="ethereum",
        is_proxy=True,
        proxy_type="eip1967",
        implementation=core,
        contract_name="UUPSProxy",
    )
    db_session.add(proxy_contract)
    db_session.commit()

    created = queue_secondary_impl_jobs(
        db_session,
        proxy_contract=proxy_contract,
        secondary_addrs=[admin],
        parent_job=parent,
        rpc_url="http://stub",
        proxy_type="eip1967",
        root_job_id=str(parent.id),
        chain="ethereum",
        protocol_id=None,
        force=False,
        base_name="LRTSquared",
    )

    assert len(created) == 1
    child = created[0]
    assert child.address == admin
    assert child.request["proxy_address"] == proxy  # resolves against proxy storage
    assert child.request["discovery_relationship"] == "secondary_implementation"
    assert child.request["root_job_id"] == str(parent.id)

    db_session.refresh(proxy_contract)
    assert admin in (proxy_contract.secondary_implementations or [])

    # Idempotent within the cascade: a second call finds the existing job.
    again = queue_secondary_impl_jobs(
        db_session,
        proxy_contract=proxy_contract,
        secondary_addrs=[admin],
        parent_job=parent,
        rpc_url="http://stub",
        proxy_type="eip1967",
        root_job_id=str(parent.id),
        chain="ethereum",
        protocol_id=None,
        force=False,
        base_name="LRTSquared",
    )
    assert again == []
    remaining = db_session.query(Job).filter(Job.address == admin).count()
    assert remaining == 1

    # cleanup (db_session fixture doesn't sweep Job/Contract rows we orphan)
    db_session.query(Job).filter(Job.address.in_([core, admin])).delete(synchronize_session=False)
    db_session.query(Contract).filter(Contract.address == proxy).delete(synchronize_session=False)
    db_session.commit()
