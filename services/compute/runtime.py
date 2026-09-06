"""Versioned non-secret runtime attestation shared through Postgres and storage."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert

from db.models import OpsKv
from db.storage import _key_prefix, get_storage_client
from utils.chains import supported_chain_ids

CONTRACT_VERSION = 1
SCHEMA_REVISION = "d9e7a31c402f"
WORKER_MODULES = (
    "workers.static_worker",
    "workers.resolution_worker",
    "workers.policy_worker",
    "workers.effects_worker",
)
CONTRACT_KEY = "local_compute_runtime"
# Explicitly exclude credentials and placement/liveness settings. Missing flags
# are compared too: the same SHA supplies the same implementation defaults.
_PLACEMENT_FLAGS = {"PSAT_COMPUTE_TARGET", "PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "PSAT_LOCAL_COMPUTE_PREPARE"}


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def runtime_fingerprint(sha: str) -> dict:
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("A full deployed Git SHA is required")
    if not os.getenv("PSAT_RPC_ROUTING_IDENTITY"):
        raise ValueError("PSAT_RPC_ROUTING_IDENTITY is required")
    toolchain = {
        name: importlib.metadata.version(name) for name in ("slither-analyzer", "crytic-compile", "solc-select")
    }
    for tool in ("forge", "anvil", "solc"):
        toolchain[tool] = subprocess.run(
            [tool, "--version"], capture_output=True, text=True, check=True, timeout=10
        ).stdout.strip()
    return {
        "version": CONTRACT_VERSION,
        "sha": sha,
        "analyzer_schema": ANALYSIS_SCHEMA_VERSION,
        "alembic_revision": SCHEMA_REVISION,
        "flags": {
            key: digest(value)
            for key, value in sorted(os.environ.items())
            if key.startswith("PSAT_")
            and key not in _PLACEMENT_FLAGS
            and not any(word in key for word in ("KEY", "TOKEN", "SECRET"))
        },
        "chains": sorted(supported_chain_ids()),
        "rpc_identity": os.environ["PSAT_RPC_ROUTING_IDENTITY"],
        "rpc_route_digest": digest(os.getenv("ERPC_BASE_URL", "")),
        "storage_namespace": digest(
            [os.getenv("ARTIFACT_STORAGE_ENDPOINT"), os.getenv("ARTIFACT_STORAGE_BUCKET"), _key_prefix()]
        ),
        "toolchain": toolchain,
    }


def assert_schema(session) -> None:
    revisions = session.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
    if revisions != [SCHEMA_REVISION]:
        raise ValueError("Compute runtime schema revision mismatch")
    columns = session.execute(
        text("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='jobs'")
    )
    if not {"compute_target", "compute_group_id", "lease_id"} <= {row[0] for row in columns}:
        raise ValueError("Compute routing/fencing columns are missing")


def _put_kv(session, key: str, value: dict) -> None:
    stmt = insert(OpsKv).values(key=key, value=value)
    session.execute(stmt.on_conflict_do_update(index_elements=["key"], set_={"value": stmt.excluded.value}))


def publish_worker_runtime(session, stage: str) -> None:
    """Cloud-worker startup only; no migrations, APIs, or credential logging."""
    if stage not in {module.removeprefix("workers.").removesuffix("_worker") for module in WORKER_MODULES}:
        raise ValueError("Only routed cloud compute workers publish this contract")
    assert_schema(session)
    fingerprint = runtime_fingerprint(os.getenv("GIT_SHA", ""))
    client = get_storage_client()
    if client is None:
        raise ValueError("Runtime publication requires object storage")
    session.execute(text("SELECT pg_advisory_xact_lock(713903208114)"))
    existing = session.get(OpsKv, CONTRACT_KEY)
    if existing is not None and existing.value.get("fingerprint") == fingerprint:
        contract = existing.value
        if hashlib.sha256(client.get(contract["sentinel_key"])).hexdigest() != contract["sentinel_sha256"]:
            raise ValueError("Storage sentinel digest mismatch")
    else:
        body = uuid.uuid4().bytes
        key = f"{_key_prefix()}local_compute_runtime/{fingerprint['sha']}/{uuid.uuid4()}"
        client.put(key, body, "application/octet-stream")
        if client.get(key) != body:
            raise ValueError("Runtime sentinel could not be read back")
        contract = {
            "fingerprint": fingerprint,
            "sentinel_key": key,
            "sentinel_sha256": hashlib.sha256(body).hexdigest(),
        }
        _put_kv(session, CONTRACT_KEY, contract)
    _put_kv(session, f"{CONTRACT_KEY}:{stage}", {"fingerprint_digest": digest(fingerprint)})
    session.commit()


def ready_contract(session) -> dict:
    assert_schema(session)
    row = session.get(OpsKv, CONTRACT_KEY)
    if row is None:
        raise ValueError("Production compute runtime contract is missing")
    contract = row.value
    fingerprint = contract.get("fingerprint", {})
    if fingerprint.get("version") != CONTRACT_VERSION or fingerprint.get("alembic_revision") != SCHEMA_REVISION:
        raise ValueError("Unsupported production compute runtime contract")
    for module in WORKER_MODULES:
        stage = module.removeprefix("workers.").removesuffix("_worker")
        record = session.get(OpsKv, f"{CONTRACT_KEY}:{stage}")
        if record is None or record.value.get("fingerprint_digest") != digest(fingerprint):
            raise ValueError("All four cloud workers must attest the same runtime")
    return contract


def preflight(session, *, repository: Path) -> None:
    from sqlalchemy.engine import make_url

    from db.compute import worker_compute_target

    if worker_compute_target() != "local":
        raise ValueError("Preflight requires the local compute target")
    url = make_url(os.environ.get("DATABASE_URL", ""))
    if url.host not in {"localhost", "127.0.0.1", "::1"} and url.query.get("sslmode") not in {
        "require",
        "verify-ca",
        "verify-full",
    }:
        raise ValueError("Remote database access requires TLS")
    if url.host in {"localhost", "127.0.0.1", "::1"} and url.database != "psat_test":
        raise ValueError("Local development databases are not compute targets")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if status.strip():
        raise ValueError("Application checkout must be clean")
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, capture_output=True, text=True, check=True
    ).stdout.strip()
    contract = ready_contract(session)
    if runtime_fingerprint(sha) != contract["fingerprint"]:
        raise ValueError("Workstation and cloud worker runtime fingerprints differ")
    client = get_storage_client()
    if client is None:
        raise ValueError("Object storage is required")
    if hashlib.sha256(client.get(contract["sentinel_key"])).hexdigest() != contract["sentinel_sha256"]:
        raise ValueError("Storage sentinel digest mismatch")
    key = f"{_key_prefix()}local_compute_runtime/probes/{uuid.uuid4()}"
    body = uuid.uuid4().bytes
    try:
        client.put(key, body, "application/octet-stream")
        if client.get(key) != body:
            raise ValueError("Storage probe readback mismatch")
    finally:
        client.delete(key)
