"""End-to-end resolution of the Part-2 cofinite/denylist opening, on 100% real data.

Drives the REAL resolver (``resolve_contract_capabilities`` → AdapterRegistry →
cross-contract inline → capability algebra → CapabilitySurface) against snapshots of the
prod etherfi contracts (real ``predicate_trees`` + ``state_var_values`` pulled from the
analysis artifacts by ``tests/fixtures/cofinite/generate.py``). Seeds Job +
predicate_trees artifact + Contract/ControllerValue the production path reads, then
asserts at the surface/status level — so a revert at any layer (negate, membership
normalization, projection) is caught.

Pins, end-to-end, the Part-2 safety contract:
  * ``BoringVault.transfer``/``transferFrom`` — gated ONLY by the inlined Teller
    ``beforeTransfer`` denylist hook → resolve **public** (a ``cofinite_blacklist`` with
    the denylist + share-lock surfaced as conditions). The headline opening.
  * ``WeETH.recoverERC20/721/ETH`` (``if(!hasRole(...)) revert``, truthy) → stay **gated**
    (never public) — the polarity boundary the negate change must not cross.
  * ``RolesAuthority.setUserRole`` + ``Accountant`` admin (Solmate ``requiresAuth``) →
    stay **gated**, never public — the canaries the provisional "open-on-ambiguity" fix
    erased (93 authorities); this opening must erase 0.
  * ``NodeOperatorManager.registerNodeOperator`` (``require(!registered[caller])``) →
    **public** (the already-cofinite P1/P2 case, projected through the same seam).

Hermetic: consumes only the committed fixture JSON; ``generate.py`` (manual, prod-read)
is the network-touching step. RPC is stubbed dead so authority resolution degrades to its
event/state-var paths — all these fixtures need.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cofinite"
_ZERO = "0x" + "0" * 40

# Addresses this test seeds — cleanup is scoped to these so parallel workers / sibling
# tests are untouched.
_BORING_VAULT = "0xca8711daf13d852ed2121e4be3894dae366039e4"
_TELLER = "0x63ede83cbb1c8d90ba52e9497e6c1226a673e884"
_WEETH = "0x2d10683e941275d502173053927ad6066e6afd6b"
_ROLES_AUTHORITY = "0x02904af5c3be78481528e0f01780439f024109a6"
_ACCOUNTANT = "0x04b8136820598a4e50bee21b8b6a23fe25df9bd8"
_NODE_OP_MANAGER = "0xfcc674fc9a0602692d2a91905e7e978ae6ee2caf"
_SEEDED = [_BORING_VAULT, _TELLER, _WEETH, _ROLES_AUTHORITY, _ACCOUNTANT, _NODE_OP_MANAGER]


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text())


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


def _wipe(sess):
    from sqlalchemy import text

    from db.models import Contract, ControllerValue, Job

    addrs = tuple(_SEEDED)
    sess.query(ControllerValue).filter(
        ControllerValue.contract_id.in_(sess.query(Contract.id).filter(Contract.address.in_(addrs)))
    ).delete(synchronize_session=False)
    sess.query(Contract).filter(Contract.address.in_(addrs)).delete(synchronize_session=False)
    sess.query(Job).filter(Job.address.in_(addrs)).delete(synchronize_session=False)
    # Protocols this test created carry a 'cofinite_e2e_' name prefix.
    sess.execute(text("delete from protocols where name like 'cofinite_e2e_%'"))
    sess.commit()


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    _wipe(s)
    try:
        yield s
    finally:
        s.rollback()
        _wipe(s)
        s.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Stub RPC dead so the Solmate adapter's bytecode confirmation / owner-getter probes
    fail and the resolver falls back to its event-only / state-var paths."""
    import utils.rpc as rpc

    def _boom(*_a, **_k):
        raise RuntimeError("network disabled in test")

    monkeypatch.setattr(rpc, "rpc_request", _boom, raising=False)
    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _boom, raising=False)


def _seed_job_with_trees(session, *, address: str, artifact: dict):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    job = Job(
        address=address,
        request={"address": address, "name": "C", "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    # The resolver reads ``artifact["trees"]`` (+ canonical_signatures); store the dump verbatim.
    store_artifact(
        session,
        job.id,
        "predicate_trees",
        data={
            "trees": artifact["trees"],
            "canonical_signatures": artifact.get("canonical_signatures"),
            "contract": artifact.get("contract", address),
        },
    )
    session.commit()
    return job


def _seed_contract(session, *, address: str, job_id, controllers: dict[str, str]):
    from db.models import Contract, ControllerValue, Protocol

    proto = Protocol(name=f"cofinite_e2e_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=proto.id, job_id=job_id)
    session.add(contract)
    session.flush()
    for cid, value in controllers.items():
        session.add(ControllerValue(contract_id=contract.id, controller_id=cid, value=value, source="test"))
    session.commit()
    return contract


def _resolve(session, *, address: str, job_id):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    out = resolve_contract_capabilities(session, address=address, chain_id=1, job_id=job_id)
    assert out is not None, f"resolver returned None for {address} — predicate_trees artifact not found"
    return out


def _status(cap: dict) -> str | None:
    from services.policy.capability_surface import capability_surface_status, project_capability_surface

    surface = project_capability_surface(cap)
    return capability_surface_status(cap, surface)


def _seed_canary(session, name: str, address: str, controllers: dict[str, str] | None = None):
    art = _fixture(name)
    job = _seed_job_with_trees(session, address=address, artifact=art)
    _seed_contract(
        session,
        address=address,
        job_id=job.id,
        controllers=controllers or {"state_variable:owner": _ZERO},
    )
    return _resolve(session, address=address, job_id=job.id)


# ---------------------------------------------------------------------------
# Headline: BoringVault.transfer opens via the inlined Teller beforeTransfer denylist
# ---------------------------------------------------------------------------


@requires_postgres
def test_boring_vault_transfer_opens_via_inlined_denylist(session):
    teller = _fixture("teller")
    vault = _fixture("boring_vault")

    # Seed the Teller (the inline callee) so beforeTransfer is the resolvable hook.
    teller_job = _seed_job_with_trees(session, address=_TELLER, artifact=teller)
    _seed_contract(
        session,
        address=_TELLER,
        job_id=teller_job.id,
        controllers={
            "external_contract:authority": teller["state_var_values"].get("authority", _ZERO),
            "external_contract:vault": _BORING_VAULT,
            "state_variable:owner": _ZERO,
        },
    )

    # Seed the BoringVault; its ``hook`` state var points at the Teller so transfer inlines
    # beforeTransfer (the denylist) into a bound frame.
    vault_job = _seed_job_with_trees(session, address=_BORING_VAULT, artifact=vault)
    _seed_contract(
        session,
        address=_BORING_VAULT,
        job_id=vault_job.id,
        controllers={
            "external_contract:hook": _TELLER,
            "external_contract:authority": vault["state_var_values"].get("authority", _ZERO),
            "state_variable:owner": _ZERO,
        },
    )

    out = _resolve(session, address=_BORING_VAULT, job_id=vault_job.id)

    for sig in ("transfer(address,uint256)", "transferFrom(address,address,uint256)"):
        cap = out[sig]
        assert cap.get("kind") == "cofinite_blacklist", (
            f"{sig} must resolve to a cofinite_blacklist via the inlined beforeTransfer denylist; "
            f"got kind={cap.get('kind')}"
        )
        assert _status(cap) == "public", f"{sig} (denylist-only gate) must project public; got {_status(cap)}"
        # The denylist must be surfaced as a side-condition, never silently dropped.
        assert cap.get("conditions"), f"{sig} cofinite must carry the denylist/share-lock as conditions"


# ---------------------------------------------------------------------------
# Canaries — the negate change must open EXACTLY 0 of these
# ---------------------------------------------------------------------------


@requires_postgres
def test_weeth_recover_stays_gated(session):
    # ``if(!roleRegistry.hasRole(WEETH_OPERATING_ADMIN_ROLE, sender)) revert`` is a TRUTHY
    # positive gate — never negated — so it stays an external check, never public.
    out = _seed_canary(
        session,
        "weeth",
        _WEETH,
        controllers={"external_contract:roleRegistry": _ZERO, "state_variable:owner": _ZERO},
    )
    for sig in (
        "recoverERC20(address,address,uint256)",
        "recoverERC721(address,address,uint256)",
        "recoverETH(address,uint256)",
    ):
        assert _status(out[sig]) != "public", f"WeETH.{sig} is a role gate — must NOT open to public"


@requires_postgres
def test_roles_authority_setuserrole_stays_gated(session):
    # Solmate ``requiresAuth`` (positive ``canCall``/owner gate); with the authority
    # uncrawled it falls to a gated external check, never public.
    out = _seed_canary(
        session,
        "roles_authority",
        _ROLES_AUTHORITY,
        controllers={"external_contract:authority": _ROLES_AUTHORITY, "state_variable:owner": _ZERO},
    )
    assert _status(out["setUserRole(address,uint8,bool)"]) != "public", (
        "RolesAuthority.setUserRole (Solmate requiresAuth) must NOT open to public"
    )


@requires_postgres
def test_accountant_admin_stays_gated(session):
    # Solmate ``requiresAuth`` admin surface — a canary the provisional fix erased.
    out = _seed_canary(
        session,
        "accountant",
        _ACCOUNTANT,
        controllers={"external_contract:authority": _ZERO, "state_variable:owner": _ZERO},
    )
    for sig in ("updateExchangeRate(uint96)", "setRateProviderData(ERC20,bool,address)"):
        if sig in out:
            assert _status(out[sig]) != "public", f"Accountant.{sig} (requiresAuth) must NOT open to public"


# ---------------------------------------------------------------------------
# NodeOperatorManager.registerNodeOperator — the already-cofinite P1/P2 case
# ---------------------------------------------------------------------------


@requires_postgres
def test_node_operator_register_resolves_public(session):
    # ``require(!registered[msg.sender])`` is an exact-finite denylist → cofinite →
    # public (permissionless self-registration, whenNotPaused). Rides the same projection.
    out = _seed_canary(session, "node_operator_manager", _NODE_OP_MANAGER)
    cap = out["registerNodeOperator(bytes,uint64)"]
    assert _status(cap) == "public", (
        f"registerNodeOperator (permissionless self-registration) must resolve public; "
        f"got kind={cap.get('kind')} status={_status(cap)}"
    )
