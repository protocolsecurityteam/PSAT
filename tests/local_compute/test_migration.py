"""Run the actual prior binary on a populated, migrated disposable database."""

import json
import os
import subprocess
import tarfile
import uuid
from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command

BASE_SHA = "50f3bcb74f25f797e450e94b74a193ad82bb25df"
REPOSITORY = Path(__file__).resolve().parents[2]
OLD_INSERTS = """
import json
import uuid
from types import SimpleNamespace
from db.models import SessionLocal
from db.queue import create_job
from services.monitoring.reanalysis import maybe_queue_reanalysis
with SessionLocal() as session:
    root = create_job(session, {"company": "disposable-compatibility"})
    child = create_job(session, {
        "address": "0x"+uuid.uuid4().hex+"11111111", "chain": "ethereum", "parent_job_id": str(root.id)
    })
    monitored = SimpleNamespace(
        address="0x"+uuid.uuid4().hex+"22222222", chain="ethereum", protocol_id=None, contract_id=None
    )
    background = maybe_queue_reanalysis(session, monitored, "upgraded")
    repair = create_job(session, {"address": "0x"+uuid.uuid4().hex+"33333333", "chain": "ethereum", "name": "repair"})
    print(json.dumps([str(job.id) for job in (root, child, background, repair)]))
"""


def test_populated_migration_and_previous_binary(db_session, tmp_path):
    source_url = db_session.get_bind().url
    assert source_url.host in {"localhost", "127.0.0.1"}
    assert source_url.database.startswith("psat_test")
    database = "psat_test_compute_" + uuid.uuid4().hex
    admin = create_engine(source_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    test_url = source_url.set(database=database)
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{database}"'))
    old = tmp_path / "old"
    old.mkdir()
    archive = tmp_path / "base.tar"
    with archive.open("wb") as output:
        subprocess.run(["git", "archive", BASE_SHA], cwd=REPOSITORY, stdout=output, check=True)
    with tarfile.open(archive) as bundle:
        # The trusted local Git tree has no credential files or absolute paths.
        bundle.extractall(old)
    cfg = Config(str(REPOSITORY / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPOSITORY / "alembic"))
    cfg.set_main_option("sqlalchemy.url", test_url.render_as_string(hide_password=False))
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(old),
        "PYTHON_DOTENV_DISABLED": "1",
        "DATABASE_URL": test_url.render_as_string(hide_password=False),
        "ERPC_BASE_URL": "http://erpc.invalid",
    }

    def old_insert():
        result = subprocess.run(
            [str(REPOSITORY / ".venv/bin/python"), "-c", OLD_INSERTS],
            cwd=old,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return json.loads(result.stdout)

    engine = create_engine(test_url)
    try:
        command.upgrade(cfg, "b3d7e1f05a92")
        before = old_insert()
        command.upgrade(cfg, "head")
        with engine.connect() as connection:
            rows = connection.execute(text("SELECT id, compute_target, compute_group_id FROM jobs")).all()
        assert len(rows) == len(before)
        assert all(target == "cloud" and job_id == group for job_id, target, group in rows)
        # Insert with the unmodified old ORM/API helper after upgrade and again
        # as an operational rollback. Columns and defaults stay in place.
        after = old_insert()
        rollback = old_insert()
        with engine.connect() as connection:
            rows = connection.execute(text("SELECT id, compute_target, compute_group_id FROM jobs")).all()
        assert {str(row.id) for row in rows} == set(before + after + rollback)
        assert all(row.compute_target == "cloud" and row.compute_group_id for row in rows)
        assert len({row.compute_group_id for row in rows}) == len(rows)
        command.check(cfg)
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{database}" WITH (FORCE)'))
        admin.dispose()
