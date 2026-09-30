"""Two PRs adding revisions with the same ``down_revision`` branch the history silently, which only errors at deploy."""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from db.models import include_object
from tests.conftest import DATABASE_URL, requires_postgres


def _script_dir() -> ScriptDirectory:
    repo_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    return ScriptDirectory.from_config(cfg)


def test_single_head_revision():
    heads = _script_dir().get_heads()
    assert len(heads) == 1, (
        f"Alembic has multiple heads: {heads}. Two migrations share a "
        "down_revision — merge them with `alembic merge` or rebase one onto "
        "the other before this lands."
    )


@requires_postgres
def test_no_autogenerate_drift_between_models_and_migrations():
    """Also gates ``alembic/env.py``'s mapped-view filter: without it the ``ContractBalanceLatest`` VIEW reads as a
    missing table and autogenerate would emit a shadowing ``CREATE TABLE``.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine

    from db.models import Base

    engine = create_engine(DATABASE_URL)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(
                conn,
                opts={"include_object": include_object, "compare_type": False, "compare_server_default": False},
            )
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()
    assert diff == [], f"models/migrations drift: {diff}"
