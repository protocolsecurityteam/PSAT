"""Regression tests for split-proxy *secondary implementation* handling (1A).

The real ether.fi LRTSquared shape: a UUPSProxy whose EIP-1967 impl
(``LRTSquaredCore``) has a ``fallback`` that ``sload``s an unstructured constant
slot and delegatecalls it, pointing at a second logic contract
(``LRTSquaredAdmin``). Before the fix that admin impl was analysed standalone
against its own empty storage and rendered as an ownerless orphan.

  * ``test_pipeline_detects_real_lrtsquared_secondary_impl`` drives the ACTUAL
    on-chain LRTSquaredCore verified source (a repo-owned fixture pulled from
    Etherscan) through the production static pipeline and asserts the
    secondary-impl pointer is recovered at the real on-chain slot;
  * the remaining detection tests use small synthetic fixtures to cover edge
    shapes (named-address-var, indirected fallback, keccak / ``-1`` slot idioms)
    and the substring false-positive guard;
  * the resolver + queue + cache-hit tests cover reading the pointer against the
    PROXY (stubbed ``rpc_request``) and the proxy-child spawn.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from services.discovery.secondary_impl import (
    _address_from_storage_word,
    queue_secondary_impl_jobs,
    resolve_secondary_impl_addresses,
)
from tests.conftest import requires_postgres

# ---------------------------------------------------------------------------
# Detection (real Slither)
# ---------------------------------------------------------------------------

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402


def _compile(tmp_path, src: str, name: str):
    f = tmp_path / "C.sol"
    f.write_text(src)
    return next(c for c in Slither(str(f)).contracts if c.name == name)


# Real on-chain contract data: ether.fi LRTSquaredCore (0x1cb489ef…) verified
# source, fetched from Etherscan and saved as a repo-owned fixture (immune to
# upstream rot, no network at test time).
_LRT_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "lrtsquared_core.json"


def _analyze_real_contract(tmp_path, fixture: dict):
    """Scaffold the saved verified source into a Foundry project and run the
    PRODUCTION static pipeline (``collect_contract_analysis_with_artifacts``,
    the same entry point ``StaticWorker`` uses) over the real contract."""
    import json as _json

    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    proj = tmp_path / "proj"
    for path, content in fixture["sources"].items():
        fp = proj / path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
    remaps = "\n".join(f'    "{r}",' for r in fixture["remappings"])
    solc = fixture["compiler_version"].lstrip("v").split("+")[0]
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\n'
        f'solc = "{solc}"\nevm_version = "{fixture["evm_version"]}"\n'
        f"optimizer = true\noptimizer_runs = {fixture['optimizer_runs']}\n"
        f"remappings = [\n{remaps}\n]\n"
    )
    (proj / "contract_meta.json").write_text(
        _json.dumps(
            {
                "address": fixture["address"],
                "contract_name": fixture["contract_name"],
                "compiler_version": fixture["compiler_version"],
                "evm_version": fixture["evm_version"],
            }
        )
    )
    analysis, _trees, _effects = collect_contract_analysis_with_artifacts(proj)
    return analysis


@pytest.fixture(scope="module")
def real_lrtsquared(tmp_path_factory):
    import json as _json

    if not _LRT_FIXTURE.exists():
        pytest.skip("LRTSquaredCore source fixture missing")
    fixture = _json.loads(_LRT_FIXTURE.read_text())
    tmp = tmp_path_factory.mktemp("lrtreal")
    try:
        analysis = _analyze_real_contract(tmp, fixture)
    except Exception as exc:  # solc toolchain genuinely unavailable in this env
        pytest.skip(f"could not compile real LRTSquared source ({fixture['compiler_version']}): {exc}")
    return fixture, analysis


def test_pipeline_detects_real_lrtsquared_secondary_impl(real_lrtsquared):
    """The ACTUAL on-chain ether.fi LRTSquaredCore verified source, driven through
    the production static pipeline, must surface its split-proxy secondary-impl
    pointer (``adminImplPosition``) at the real on-chain slot. This is the pattern
    the first implementation missed entirely — the impl reads the admin logic
    address from an unstructured constant slot via assembly ``sload``, not a plain
    ``address`` state var. Real contract data, real pipeline, no replica."""
    fixture, analysis = real_lrtsquared
    pointers = analysis.get("secondary_impl_pointers") or []
    by_name = {p["name"]: p for p in pointers}
    name = fixture["admin_impl_pointer_name"]
    assert name in by_name, f"real LRTSquaredCore secondary-impl pointer not detected; got {pointers}"
    assert by_name[name]["slot"] == int(fixture["admin_impl_slot"], 16)
    assert by_name[name]["offset"] == 0


_INLINE_VAR_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SplitStorage {
    address public governor;   // slot 0 — read by a modifier, NOT delegatecalled
    address adminImpl;         // slot 1 — non-public: no auto-getter (reverts)
    uint256 public rateLimit;  // slot 2
}

contract SplitImpl is SplitStorage {
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
def inline_var_contract(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("secimpl")
    f = tmp / "Split.sol"
    f.write_text(_INLINE_VAR_SRC)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == "SplitImpl")


def test_detect_named_address_var_pointer(inline_var_contract):
    """Synthetic variant: a fallback that delegatecalls a plain ``address`` state
    var directly (inline assembly). The var is found at its layout slot, and a
    ``governor`` read by a modifier (never delegatecalled) is NOT mistaken for a
    pointer."""
    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    pointers = detect_secondary_impl_pointers(inline_var_contract)
    by_name = {p["name"]: p for p in pointers}
    assert "adminImpl" in by_name, "fallback delegatecall-target state var must be detected"
    assert by_name["adminImpl"]["slot"] == 1  # after governor at slot 0
    assert by_name["adminImpl"]["offset"] == 0
    assert "governor" not in by_name


def test_detect_empty_for_plain_contract(tmp_path):
    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    c = _compile(
        tmp_path,
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Plain { address public owner; function f() external {} }
""",
        "Plain",
    )
    assert detect_secondary_impl_pointers(c) == []


def test_detect_eip1967_style_minus_one_slot(tmp_path):
    """The ``bytes32(uint256(keccak256("…")) - 1)`` slot idiom resolves correctly."""
    from eth_utils.crypto import keccak

    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    c = _compile(
        tmp_path,
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Core {
    bytes32 internal constant SLOT = bytes32(uint256(keccak256("etherfi.admin.impl")) - 1);
    function setAdminImpl(address a) external { bytes32 s = SLOT; assembly { sstore(s, a) } }
    fallback() external { bytes32 s = SLOT; assembly { let r := delegatecall(gas(), sload(s), 0, 0, 0, 0) } }
}""",
        "Core",
    )
    by_name = {p["name"]: p for p in detect_secondary_impl_pointers(c)}
    assert by_name["SLOT"]["slot"] == int.from_bytes(keccak(text="etherfi.admin.impl"), "big") - 1


def test_detect_indirected_fallback(tmp_path):
    """A fallback that forwards through an internal helper
    (``fallback() -> _delegate(adminImpl)``) is still detected via the transitive
    IR walk — the standard OZ-style indirection the first implementation missed."""
    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    c = _compile(
        tmp_path,
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract S { address adminImpl; }
contract C is S {
    function setAdminImpl(address a) external { adminImpl = a; }
    function _delegate(address impl) private { assembly { let r := delegatecall(gas(), impl, 0, 0, 0, 0) } }
    fallback() external { _delegate(adminImpl); }
}""",
        "C",
    )
    assert "adminImpl" in {p["name"] for p in detect_secondary_impl_pointers(c)}


def test_detect_rejects_plain_call_on_delegatecall_named_var(tmp_path):
    """#3: a plain ``.call()`` on a variable merely NAMED ``delegatecallTarget``
    must NOT be flagged — detection keys on the IR operation, not a substring."""
    from services.static.contract_analysis_pipeline.secondary_impl import detect_secondary_impl_pointers

    c = _compile(
        tmp_path,
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
    address delegatecallTarget;
    function set(address a) external { delegatecallTarget = a; }
    fallback() external { (bool ok,) = delegatecallTarget.call(""); ok; }
}""",
        "C",
    )
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
    admin = "0x" + "ab" * 20  # the real secondary (has code)
    impl = "0x" + "cc" * 20  # the proxy's EIP-1967 primary impl
    nocode = "0x" + "dd" * 20  # resolves but has no bytecode
    storage_targets: list[str] = []

    def fake_rpc(rpc_url, method, params, retries=1, **_):
        if method == "eth_getStorageAt":
            storage_targets.append(params[0])
            if params[1] == hex(1):
                return "0x" + "00" * 12 + admin[2:]
            if params[1] == hex(2):
                return "0x" + "00" * 12 + impl[2:]  # slot 2 -> the primary impl
            if params[1] == hex(3):
                return "0x" + "00" * 12 + nocode[2:]
            return "0x" + "00" * 32  # any other slot: unset
        if method == "eth_getCode":
            return "0x6080" if params[0] == admin else "0x"  # only `admin` is a deployed contract
        return "0x"

    monkeypatch.setattr("utils.rpc.rpc_request", fake_rpc)

    addrs = resolve_secondary_impl_addresses(
        "http://stub",
        proxy,
        [
            {"name": "adminImpl", "slot": 1, "offset": 0},
            {"name": "primary", "slot": 2, "offset": 0},  # equals the primary impl -> excluded (#4)
            {"name": "nc", "slot": 3, "offset": 0},  # no bytecode -> dropped (has-code guard)
            {"name": "unset", "slot": 9, "offset": 0},  # zero -> dropped
        ],
        implementation=impl,
    )
    assert addrs == [admin]
    # Every slot is read against the PROXY, never the impl.
    assert set(storage_targets) == {proxy}


def test_resolve_handles_256bit_constant_slot(monkeypatch):
    """Unstructured (EIP-1967-style) pointers carry the full 256-bit constant as
    the slot; it must be passed to eth_getStorageAt as a hex quantity."""
    proxy = "0x" + "11" * 20
    admin = "0x" + "ab" * 20
    big_slot = int.from_bytes(b"\xbc" * 32, "big")

    def fake_rpc(rpc_url, method, params, retries=1, **_):
        if method == "eth_getStorageAt":
            assert params[1] == hex(big_slot)
            return "0x" + "00" * 12 + admin[2:]
        if method == "eth_getCode":
            return "0x6080"
        return "0x"

    monkeypatch.setattr("utils.rpc.rpc_request", fake_rpc)
    addrs = resolve_secondary_impl_addresses(
        "http://stub", proxy, [{"name": "adminImplPosition", "slot": big_slot, "offset": 0}]
    )
    assert addrs == [admin]


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


@requires_postgres
def test_static_cache_hit_still_resolves_secondary_impls(db_session, monkeypatch):
    """#1: an impl re-seen in proxy context whose static artifacts are CACHED
    (a normal, non-force incremental run) must still resolve + queue its
    split-proxy secondary impls — the cache-hit branch previously skipped this,
    leaving the admin impl an ownerless orphan. Drives the real
    ``StaticWorker.process`` through the cache branch.
    """
    from db.models import Contract, Job, JobStage, JobStatus
    from db.queue import store_artifact
    from workers.static_worker import StaticWorker

    def _a() -> str:
        return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]

    proxy, core, admin = _a(), _a(), _a()
    slot = int.from_bytes(b"\xbc" * 32, "big")  # an unstructured (256-bit) admin slot

    impl_job = Job(
        id=uuid.uuid4(),
        address=core,
        name="LRTSquaredCore: (impl)",
        status=JobStatus.processing,
        stage=JobStage.static,
        request={
            "address": core,
            "proxy_address": proxy,
            "chain": "ethereum",
            "rpc_url": "http://stub",
            "static_cached": True,  # <- the cache-hit path
            "root_job_id": str(uuid.uuid4()),
        },
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(impl_job)
    db_session.add(Contract(address=proxy, chain="ethereum", is_proxy=True, proxy_type="eip1967", implementation=core))
    db_session.add(
        Contract(address=core, chain="ethereum", is_proxy=False, contract_name="LRTSquaredCore", job_id=impl_job.id)
    )
    db_session.commit()
    # The cached contract_analysis carries the detected pointer (copy_static_cache copies it).
    store_artifact(
        db_session,
        impl_job.id,
        "contract_analysis",
        data={
            "schema_version": "0.1",
            "subject": {"name": "LRTSquaredCore"},
            "secondary_impl_pointers": [{"name": "adminImplPosition", "slot": slot, "offset": 0}],
        },
    )
    db_session.commit()

    def fake_rpc(rpc_url, method, params, retries=1, **_):
        if method == "eth_getStorageAt":
            return "0x" + "00" * 12 + admin[2:]
        if method == "eth_getCode":
            return "0x6080" if params[0] == admin else "0x"
        return "0x"

    monkeypatch.setattr("utils.rpc.rpc_request", fake_rpc)

    worker = StaticWorker()
    # Stub the heavy, unrelated phases so the test exercises the cache branch only.
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_dependency_phase", lambda *a, **kw: None)
    monkeypatch.setattr("workers.static_worker.get_source_files", lambda *a, **kw: {"C.sol": "contract C {}"})
    monkeypatch.setattr("workers.static_worker._check_proxy_cache", lambda *a, **kw: {"type": "regular"})

    worker.process(db_session, impl_job)

    child = db_session.query(Job).filter(Job.address == admin).one_or_none()
    assert child is not None, "cache-hit path must still queue the secondary-impl child job"
    assert child.request["proxy_address"] == proxy
    assert child.request["discovery_relationship"] == "secondary_implementation"
    proxy_row = db_session.query(Contract).filter(Contract.address == proxy).one()
    assert admin in (proxy_row.secondary_implementations or [])

    db_session.query(Job).filter(Job.address.in_([core, admin])).delete(synchronize_session=False)
    db_session.query(Contract).filter(Contract.address.in_([proxy, core])).delete(synchronize_session=False)
    db_session.commit()
