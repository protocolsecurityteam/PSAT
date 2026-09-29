"""Per-section servability markers, revision change times, heartbeat-quiet jobs trigger.

Revision ID: bbad3ee1de37
Revises: e1c72a9d4b03
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import sqlalchemy as sa

from alembic import op

revision = "bbad3ee1de37"
down_revision = "e1c72a9d4b03"
branch_labels = None
depends_on = None

spec = spec_from_file_location("page_sections_base", Path(__file__).with_name("e1c72a9d4b03_company_sections.py"))
assert spec is not None and spec.loader is not None
sections = module_from_spec(spec)
spec.loader.exec_module(sections)

JOB_COLUMNS = sections.base.UPDATE_FIELDS["jobs"] + ", company"
# Lease renewal rewrites updated_at on in-progress jobs; only a completed
# job's updated_at orders anything a page publishes.
QUIET_JOB_COLUMNS = JOB_COLUMNS.replace(
    "updated_at", "CASE WHEN status = 'completed' THEN updated_at END AS updated_at"
)
MARKERS = (
    ("schema_version", sa.Integer()),
    ("semantic_epoch", sa.Integer()),
    ("chain_set", sa.Text()),
    ("builder_digest", sa.Text()),
)
MARKER_COLUMNS = [
    (("" if section == "overview" else section + "_") + name, type_)
    for section in ("overview", "functions", "summary")
    for name, type_ in MARKERS
]


def _jobs_update(columns):
    query = " UNION ALL ".join(
        sections._keys("jobs", f"(SELECT {columns} FROM {rows} EXCEPT SELECT {columns} FROM {other})", True)
        for rows, other in (("old_rows", "new_rows"), ("new_rows", "old_rows"))
    )
    op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_jobs_update() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM psat_page_touch(ARRAY({query})); RETURN NULL; END
    $$""")


def upgrade():
    for name, type_ in MARKER_COLUMNS:
        op.add_column("company_page_snapshots", sa.Column(name, type_))
    op.drop_column("company_page_snapshots", "version")
    # Unindexed so touches stay HOT updates; scope remains the only index.
    op.add_column(
        "company_page_revisions",
        sa.Column(
            "changed_at", sa.DateTime(timezone=True), server_default=sa.func.statement_timestamp(), nullable=False
        ),
    )
    op.execute("""CREATE OR REPLACE FUNCTION psat_page_touch(scopes text[]) RETURNS void LANGUAGE sql AS $$
        INSERT INTO company_page_revisions (key, scope, transaction_id, changed_at)
        SELECT DISTINCT key,
            CASE WHEN key LIKE 'legacy:job:%' THEN 'legacy:jobs'
            ELSE substring(key from '^(?:overview:|summary:)?protocol:[0-9]+') END, txid_current(),
            statement_timestamp()
        FROM unnest(scopes) key WHERE key IS NOT NULL ORDER BY key
        ON CONFLICT (key) DO UPDATE SET token = gen_random_uuid(), transaction_id = excluded.transaction_id,
            changed_at = excluded.changed_at
        WHERE company_page_revisions.transaction_id <> excluded.transaction_id
    $$""")
    # Scheduling hint only; never a freshness witness.
    op.execute("""CREATE FUNCTION psat_page_changed_at(dependency text) RETURNS timestamptz LANGUAGE sql STABLE AS $$
        SELECT CASE WHEN dependency LIKE '%protocol:%' OR dependency = 'legacy:jobs' THEN
            (SELECT max(changed_at) FROM company_page_revisions WHERE scope = dependency)
        ELSE (SELECT changed_at FROM company_page_revisions WHERE key = dependency) END
    $$""")
    _jobs_update(QUIET_JOB_COLUMNS)


def downgrade():
    _jobs_update(JOB_COLUMNS)
    op.execute("DROP FUNCTION psat_page_changed_at(text)")
    op.execute("""CREATE OR REPLACE FUNCTION psat_page_touch(scopes text[]) RETURNS void LANGUAGE sql AS $$
        INSERT INTO company_page_revisions (key, scope, transaction_id)
        SELECT DISTINCT key,
            CASE WHEN key LIKE 'legacy:job:%' THEN 'legacy:jobs'
            ELSE substring(key from '^(?:overview:|summary:)?protocol:[0-9]+') END, txid_current()
        FROM unnest(scopes) key WHERE key IS NOT NULL ORDER BY key
        ON CONFLICT (key) DO UPDATE SET token = gen_random_uuid(), transaction_id = excluded.transaction_id
        WHERE company_page_revisions.transaction_id <> excluded.transaction_id
    $$""")
    op.drop_column("company_page_revisions", "changed_at")
    op.add_column("company_page_snapshots", sa.Column("version", sa.String(100)))
    for name, _ in MARKER_COLUMNS:
        op.drop_column("company_page_snapshots", name)
