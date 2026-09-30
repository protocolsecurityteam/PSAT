"""Split company preparation dependencies by response section.

Revision ID: e1c72a9d4b03
Revises: d1e8b72f4a63
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "e1c72a9d4b03"
down_revision = "d1e8b72f4a63"
branch_labels = None
depends_on = None

# Reuse the frozen revision's key and source-column audit. This migration
# changes section ownership, not the per-contract writer-lock granularity.
spec = spec_from_file_location("page_revision_base", Path(__file__).with_name("d1e8b72f4a63_company_page_revisions.py"))
assert spec is not None and spec.loader is not None
base = module_from_spec(spec)
spec.loader.exec_module(base)
OVERVIEW = {
    "contract_balances",
    "contract_balance_fetches",
    "upgrade_events",
    "upgrade_transactions",
    "contract_creation_witnesses",
}
SUMMARY = {"tvl_snapshots", "pending_effects_work"}
NEW_TABLES = ("pending_effects_work", "upgrade_transactions", "contract_creation_witnesses")


def _keys(table, rows, split):
    if table == "pending_effects_work":
        return f"SELECT 'summary:protocol:' || r.protocol_id || ':pending:' || r.id AS key FROM {rows} r"
    if table in {"upgrade_transactions", "contract_creation_witnesses"}:
        join = (
            "e.chain_id = r.chain_id AND lower(e.tx_hash) = r.tx_hash"
            if table == "upgrade_transactions"
            else "e.chain_id = r.chain_id AND lower(e.proxy_address) = r.address"
        )
        return f"""SELECT unnest(ARRAY['overview:contract:' || e.contract_id,
            'overview:protocol:' || c.protocol_id || ':contract:' || c.id]) AS key
            FROM {rows} r JOIN upgrade_events e ON {join} JOIN contracts c ON c.id = e.contract_id"""
    keys = base._keys(table, rows)
    if split and table == "jobs":
        # Parent links may change legacy membership without a Contract row.
        # Per-job tokens avoid a common writer lock; legacy readers fingerprint
        # this conservative scope. Modern readers never depend on it.
        keys += f" UNION ALL SELECT 'legacy:job:' || r.id AS key FROM {rows} r"
    if split and table in OVERVIEW | SUMMARY:
        prefix = "summary:" if table in SUMMARY else "overview:"
        return f"SELECT '{prefix}' || key AS key FROM ({keys}) source_keys"
    return keys


def _triggers(table, *, split):
    for event, relations in (
        ("insert", ("new_rows",)),
        ("update", ("old_rows", "new_rows")),
        ("delete", ("old_rows",)),
    ):
        if event == "update":
            columns = "*" if table == "contract_balance_fetches" and split else base.UPDATE_FIELDS.get(table, "*")
            if split and table == "jobs":
                columns += ", company"
            query = " UNION ALL ".join(
                _keys(table, f"(SELECT {columns} FROM {rows} EXCEPT SELECT {columns} FROM {other})", split)
                for rows, other in (("old_rows", "new_rows"), ("new_rows", "old_rows"))
            )
        else:
            query = " UNION ALL ".join(_keys(table, rows, split) for rows in relations)
        # Protocol rename/delete outbox logic remains in the original triggers.
        if table == "protocols":
            continue
        function = f"psat_page_{table}_{event}"
        op.execute(f"""CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM psat_page_touch(ARRAY({query})); RETURN NULL; END
        $$""")
        referencing = " ".join(
            "OLD TABLE AS old_rows" if r == "old_rows" else "NEW TABLE AS new_rows" for r in relations
        )
        op.execute(f"DROP TRIGGER IF EXISTS psat_page_{event} ON {table}")
        op.execute(f"""CREATE TRIGGER psat_page_{event} AFTER {event.upper()} ON {table}
            REFERENCING {referencing} FOR EACH STATEMENT EXECUTE FUNCTION {function}()""")
    prefix = ("summary:" if table in SUMMARY else "overview:") if split and table in OVERVIEW | SUMMARY else ""
    op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_{table}_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM psat_page_touch(ARRAY['{prefix}all']); RETURN NULL; END
    $$""")
    op.execute(f"DROP TRIGGER IF EXISTS psat_page_truncate ON {table}")
    op.execute(f"""CREATE TRIGGER psat_page_truncate AFTER TRUNCATE ON {table}
        FOR EACH STATEMENT EXECUTE FUNCTION psat_page_{table}_truncate()""")


def upgrade():
    op.add_column("company_page_snapshots", sa.Column("cache_key", sa.String(300)))
    op.execute("UPDATE company_page_snapshots SET cache_key = 'protocol:' || protocol_id")
    op.alter_column("company_page_snapshots", "cache_key", nullable=False)
    op.execute("""UPDATE company_page_snapshots s SET company_name = p.name
                  FROM protocols p WHERE p.id = s.protocol_id""")
    op.drop_constraint("company_page_snapshots_pkey", "company_page_snapshots", type_="primary")
    op.alter_column("company_page_snapshots", "protocol_id", nullable=True)
    op.alter_column("company_page_snapshots", "company_name", nullable=False)
    op.create_primary_key("company_page_snapshots_pkey", "company_page_snapshots", ["cache_key"])
    op.create_index("ix_company_page_snapshots_company_name", "company_page_snapshots", ["company_name"])
    op.create_unique_constraint("company_page_snapshots_protocol_id_key", "company_page_snapshots", ["protocol_id"])
    for name, type_ in (
        ("functions_source_revisions", pg.JSONB()),
        ("functions_source_started_at", sa.DateTime(timezone=True)),
        ("summary_gzip", sa.LargeBinary()),
        ("summary_source_revisions", pg.JSONB()),
        ("summary_source_started_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("company_page_snapshots", sa.Column(name, type_))
    op.execute("""CREATE OR REPLACE FUNCTION psat_page_touch(scopes text[]) RETURNS void LANGUAGE sql AS $$
        INSERT INTO company_page_revisions (key, scope, transaction_id)
        SELECT DISTINCT key,
            CASE WHEN key LIKE 'legacy:job:%' THEN 'legacy:jobs'
            ELSE substring(key from '^(?:overview:|summary:)?protocol:[0-9]+') END, txid_current()
        FROM unnest(scopes) key WHERE key IS NOT NULL ORDER BY key
        ON CONFLICT (key) DO UPDATE SET token = gen_random_uuid(), transaction_id = excluded.transaction_id
        WHERE company_page_revisions.transaction_id <> excluded.transaction_id
    $$""")
    op.execute("""CREATE OR REPLACE FUNCTION psat_page_revision(dependency text) RETURNS text LANGUAGE sql STABLE AS $$
        SELECT CASE WHEN dependency LIKE '%protocol:%' OR dependency = 'legacy:jobs' THEN
            (SELECT md5(string_agg(key || '=' || token::text, ',' ORDER BY key))
             FROM company_page_revisions WHERE scope = dependency)
        ELSE (SELECT token::text FROM company_page_revisions WHERE key = dependency) END
    $$""")
    for table in (*base.TABLES, *NEW_TABLES):
        _triggers(table, split=True)


def downgrade():
    for table in base.TABLES:
        _triggers(table, split=False)
    for table in base.TABLES:
        op.execute(f"DROP TRIGGER psat_page_truncate ON {table}")
        op.execute(f"DROP FUNCTION psat_page_{table}_truncate()")
        op.execute(f"""CREATE TRIGGER psat_page_truncate AFTER TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION psat_page_truncate()""")
    for table in NEW_TABLES:
        for event in ("insert", "update", "delete", "truncate"):
            op.execute(f"DROP TRIGGER psat_page_{event} ON {table}")
            op.execute(f"DROP FUNCTION psat_page_{table}_{event}()")
    op.execute("DELETE FROM company_page_snapshots WHERE protocol_id IS NULL")
    op.drop_constraint("company_page_snapshots_pkey", "company_page_snapshots", type_="primary")
    op.drop_constraint("company_page_snapshots_protocol_id_key", "company_page_snapshots", type_="unique")
    op.alter_column("company_page_snapshots", "protocol_id", nullable=False)
    op.alter_column("company_page_snapshots", "company_name", nullable=True)
    op.create_primary_key("company_page_snapshots_pkey", "company_page_snapshots", ["protocol_id"])
    op.drop_index("ix_company_page_snapshots_company_name", table_name="company_page_snapshots")
    op.drop_column("company_page_snapshots", "cache_key")
    for name in (
        "summary_source_started_at",
        "summary_source_revisions",
        "summary_gzip",
        "functions_source_started_at",
        "functions_source_revisions",
    ):
        op.drop_column("company_page_snapshots", name)
    # The broadened revision functions understand the old namespace unchanged.
