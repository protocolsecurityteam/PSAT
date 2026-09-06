import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import delete

from db.attempts import JobAttempt, LeaseLost, bind_job_attempt, install_attempt_subprocess_tracking
from db.models import OpsKv
from services.compute import runtime

SHA = "a" * 40


@pytest.fixture
def attested(db_session, storage_bucket, monkeypatch):
    monkeypatch.setenv("GIT_SHA", SHA)
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "1")
    monkeypatch.setenv("PSAT_RPC_ROUTING_IDENTITY", "test-erpc")
    monkeypatch.setenv("DATABASE_URL", "postgresql://psat:psat@localhost:5433/psat_test")

    def run(args, **kwargs):
        if args[:2] == ["git", "status"]:
            return SimpleNamespace(stdout="")
        if args[:2] == ["git", "rev-parse"]:
            return SimpleNamespace(stdout=SHA)
        return SimpleNamespace(stdout=f"{args[0]} disposable-version")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    for module in runtime.WORKER_MODULES:
        runtime.publish_worker_runtime(db_session, module.split(".")[-1].removesuffix("_worker"))
    monkeypatch.setenv("PSAT_COMPUTE_TARGET", "local")
    yield
    db_session.rollback()
    db_session.execute(delete(OpsKv).where(OpsKv.key.startswith(runtime.CONTRACT_KEY)))
    db_session.commit()


def test_runtime_and_real_minio_sentinel_and_probe(db_session, storage_bucket, attested):
    runtime.preflight(db_session, repository=Path.cwd())
    keys = storage_bucket._client.list_objects_v2(Bucket=storage_bucket.bucket).get("Contents", [])
    assert len(keys) == 1  # sentinel remains; unique write/read probe was deleted


@pytest.mark.parametrize(
    "mismatch", ["flags", "rpc", "sha", "sentinel", "schema", "partial_storage", "worker", "dirty"]
)
def test_preflight_fails_closed(db_session, storage_bucket, attested, monkeypatch, mismatch):
    if mismatch == "flags":
        monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    elif mismatch == "rpc":
        monkeypatch.setenv("PSAT_RPC_ROUTING_IDENTITY", "different")
    elif mismatch == "sha":
        original = runtime.subprocess.run
        monkeypatch.setattr(
            runtime.subprocess,
            "run",
            lambda args, **kwargs: (
                SimpleNamespace(stdout="b" * 40) if args[:2] == ["git", "rev-parse"] else original(args, **kwargs)
            ),
        )
    elif mismatch == "dirty":
        original = runtime.subprocess.run
        monkeypatch.setattr(
            runtime.subprocess,
            "run",
            lambda args, **kwargs: (
                SimpleNamespace(stdout=" M workers/static_worker.py")
                if args[:2] == ["git", "status"]
                else original(args, **kwargs)
            ),
        )
    elif mismatch == "sentinel":
        contract = runtime.ready_contract(db_session)
        storage_bucket.put(contract["sentinel_key"], b"wrong", "application/octet-stream")
    elif mismatch == "schema":
        monkeypatch.setattr(runtime, "SCHEMA_REVISION", "wrong")
    elif mismatch == "worker":
        db_session.execute(delete(OpsKv).where(OpsKv.key == runtime.CONTRACT_KEY + ":effects"))
        db_session.commit()
    else:
        from db.storage import reset_client_cache

        monkeypatch.delenv("ARTIFACT_STORAGE_SECRET_KEY")
        reset_client_cache()
    from db.storage import StorageUnavailable

    with pytest.raises((ValueError, StorageUnavailable)):
        runtime.preflight(db_session, repository=Path.cwd())


def test_missing_attempt_cancels_before_subprocess_starts():
    install_attempt_subprocess_tracking()
    attempt = JobAttempt(uuid.uuid4(), uuid.uuid4())
    with bind_job_attempt(attempt):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(30)"],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        attempt.cancel()
        assert process.wait(timeout=5) == -signal.SIGKILL
        with pytest.raises(LeaseLost):
            subprocess.Popen([sys.executable, "-c", "raise AssertionError('must not start')"])


def test_launcher_is_singleton_and_accepts_no_job_arguments(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    launcher = deploy / "start_local_compute.sh"
    launcher.write_bytes((repository / "deploy/start_local_compute.sh").read_bytes())
    (tmp_path / ".env.compute").write_text("# Disposable configuration; no resources.\n")
    (tmp_path / ".env.compute").chmod(0o600)
    binary = tmp_path / ".venv/bin/python"
    binary.parent.mkdir(parents=True)
    ready = tmp_path / "started"
    binary.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nimport time\nPath({str(ready)!r}).touch()\ntime.sleep(30)\n"
    )
    binary.chmod(0o700)
    env = {"PATH": os.environ["PATH"]}
    first = subprocess.Popen(["bash", str(launcher)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        second = subprocess.run(["bash", str(launcher)], env=env, capture_output=True, text=True, timeout=5)
        assert second.returncode == 1 and "already running" in second.stderr
        invalid = subprocess.run(["bash", str(launcher), "job-id"], env=env, capture_output=True, text=True, timeout=5)
        assert invalid.returncode == 2
    finally:
        first.terminate()
        first.wait(timeout=5)


def test_supervisor_starts_only_four_workers_and_stops_siblings(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    from services.compute import supervisor

    processes = []

    def spawn(args, **kwargs):
        process = MagicMock()
        process.returncode = 0
        process.poll.return_value = 0 if not processes else None
        processes.append((args, process))
        return process

    monkeypatch.setattr(supervisor, "__file__", str(tmp_path / "services/compute/supervisor.py"))
    monkeypatch.setattr(supervisor, "preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr(supervisor, "SessionLocal", MagicMock())
    monkeypatch.setattr(supervisor.socket, "socket", MagicMock())
    monkeypatch.setattr(supervisor.subprocess, "Popen", spawn)
    monkeypatch.setattr(supervisor.signal, "signal", lambda *_: None)
    monkeypatch.setattr(supervisor.sys, "argv", ["supervisor"])
    supervisor.main()
    assert [args for args, _ in processes] == [[sys.executable, "-m", m] for m in runtime.WORKER_MODULES]
    for _, process in processes:
        process.wait.assert_called_once()
    for _, process in processes[1:]:
        process.terminate.assert_called_once()


def test_supervisor_refuses_conflicting_anvil_port(monkeypatch):
    import socket
    from unittest.mock import MagicMock

    from services.compute import supervisor

    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        monkeypatch.setenv("PSAT_EFFECTS_ANVIL_PORT", str(occupied.getsockname()[1]))
        monkeypatch.setattr(supervisor.sys, "argv", ["supervisor"])
        preflight = MagicMock()
        monkeypatch.setattr(supervisor, "preflight", preflight)
        with pytest.raises(OSError):
            supervisor.main()
        preflight.assert_not_called()


def test_any_heartbeat_lease_loss_cancels_registered_attempt(monkeypatch):
    from unittest.mock import MagicMock

    from workers.static_worker import StaticWorker

    monkeypatch.setattr("workers.base.SessionLocal", MagicMock())
    monkeypatch.setattr("workers.base.heartbeat_job", MagicMock(side_effect=LeaseLost("reclaimed")))
    worker = StaticWorker()
    attempt = JobAttempt(uuid.uuid4(), uuid.uuid4())
    worker._attempts[attempt.job_id] = attempt
    job = MagicMock(id=attempt.job_id, lease_id=attempt.lease_id)
    job._heartbeat_job_id = attempt.job_id
    job._heartbeat_lease_id = attempt.lease_id
    with pytest.raises(LeaseLost):
        worker._heartbeat(MagicMock(), job)
    assert attempt.cancelled.is_set()
