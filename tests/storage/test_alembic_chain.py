"""Guards against accidental migration branching.

When two PRs add independent revisions, Alembic can produce multiple heads.
``alembic upgrade head`` then fails at deploy time. A merge revision joins
both histories while preserving revisions already applied in production.
"""

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


def test_only_intentional_branch_point():
    script = _script_dir()
    branched = {r.revision for r in script.walk_revisions() if r.is_branch_point}
    assert branched == {"b3d7e1f05a92"}, f"Unexpected Alembic branch points: {branched}"
    join = script.get_revision("c90d1fe9c8e1")
    assert join is not None
    assert isinstance(join.down_revision, tuple)
    assert set(join.down_revision) == {"a8c2d4e6f901", "c6a10d82e5b7"}


@requires_postgres
def test_no_autogenerate_drift_between_models_and_migrations():
    """The migrations and ``db.models`` describe the same schema.

    This is the gate the mapped-view filter in ``alembic/env.py`` depends on.
    ``ContractBalanceLatest`` maps a VIEW, and Alembic cannot tell a mapped view
    from a mapped table — without the ``include_object`` filter it would report
    the view as a missing TABLE here, and a later autogenerate would emit a
    ``CREATE TABLE`` that shadows it. Asserting no drift is what proves the
    filter is doing its job rather than merely being present.

    It also catches the ordinary case: a column added to a model and not to a
    migration, which shows up in production as ``UndefinedColumn``.
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
