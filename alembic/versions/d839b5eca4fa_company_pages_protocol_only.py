"""Company pages identify companies by Protocol row only.

Revision ID: d839b5eca4fa
Revises: bbad3ee1de37
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from alembic import op

revision = "d839b5eca4fa"
down_revision = "bbad3ee1de37"
branch_labels = None
depends_on = None


def _load(name, filename):
    spec = spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sections = _load("page_sections_base", "e1c72a9d4b03_company_sections.py")
staleness = _load("page_staleness_base", "bbad3ee1de37_company_page_staleness.py")


def _functions(*, legacy):
    scope = "substring(key from '^(?:overview:|summary:)?protocol:[0-9]+')"
    if legacy:
        scope = f"CASE WHEN key LIKE 'legacy:job:%' THEN 'legacy:jobs' ELSE {scope} END"
    legacy_group = " OR dependency = 'legacy:jobs'" if legacy else ""
    op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_touch(scopes text[]) RETURNS void LANGUAGE sql AS $$
        INSERT INTO company_page_revisions (key, scope, transaction_id, changed_at)
        SELECT DISTINCT key, {scope}, txid_current(), statement_timestamp()
        FROM unnest(scopes) key WHERE key IS NOT NULL ORDER BY key
        ON CONFLICT (key) DO UPDATE SET token = gen_random_uuid(), transaction_id = excluded.transaction_id,
            changed_at = excluded.changed_at
        WHERE company_page_revisions.transaction_id <> excluded.transaction_id
    $$""")
    op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_revision(dependency text) RETURNS text LANGUAGE sql STABLE AS $$
        SELECT CASE WHEN dependency LIKE '%protocol:%'{legacy_group} THEN
            (SELECT md5(string_agg(key || '=' || token::text, ',' ORDER BY key))
             FROM company_page_revisions WHERE scope = dependency)
        ELSE (SELECT token::text FROM company_page_revisions WHERE key = dependency) END
    $$""")
    op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_changed_at(dependency text) RETURNS timestamptz
        LANGUAGE sql STABLE AS $$
        SELECT CASE WHEN dependency LIKE '%protocol:%'{legacy_group} THEN
            (SELECT max(changed_at) FROM company_page_revisions WHERE scope = dependency)
        ELSE (SELECT changed_at FROM company_page_revisions WHERE key = dependency) END
    $$""")


def upgrade():
    op.execute("DELETE FROM company_page_snapshots WHERE protocol_id IS NULL")
    op.execute("DELETE FROM company_page_revisions WHERE key LIKE 'legacy:%'")
    op.alter_column("company_page_snapshots", "protocol_id", nullable=False)
    # Only completed jobs emit keys, so lease/heartbeat updates touch nothing.
    sections._triggers("jobs", split=False)
    _functions(legacy=False)


def downgrade():
    _functions(legacy=True)
    sections._triggers("jobs", split=True)
    staleness._jobs_update(staleness.QUIET_JOB_COLUMNS)
    op.alter_column("company_page_snapshots", "protocol_id", nullable=True)
