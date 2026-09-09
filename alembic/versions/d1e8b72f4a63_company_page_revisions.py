"""Replace time-driven page refresh with transactional dependency revisions.

Revision ID: d1e8b72f4a63
Revises: c8a41e6d2b90
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "d1e8b72f4a63"
down_revision = "c8a41e6d2b90"
branch_labels = None
depends_on = None

# Frozen source audit: overview/jobs/prefetch/governance/functions plus the
# reach loaders (control, conditions, conferral, population, entity aliases).
# Views are covered through their backing tables. Statement triggers coalesce
# bulk writes, and project scalar identities instead of decoding large JSONB.
CONTRACT_CHILDREN = (
    "contract_summaries",
    "controller_values",
    "control_graph_nodes",
    "control_graph_edges",
    "effective_functions",
    "principal_labels",
    "contract_balances",
    "contract_balance_fetches",
    "upgrade_events",
)
PROTOCOL_CHILDREN = ("tvl_snapshots", "function_score_signals", "token_protocol_reference")
TABLES = (
    *CONTRACT_CHILDREN,
    *PROTOCOL_CHILDREN,
    "contracts",
    "jobs",
    "protocols",
    "function_principals",
    "token_delivery_evidence",
)


def _keys(table: str, rows: str) -> str:
    if table == "contracts":
        return f"""SELECT unnest(ARRAY['contract:' || r.id, 'address:' || lower(r.address),
            'protocol:' || r.protocol_id, 'protocol:' || r.nominated_protocol_id]) AS key FROM {rows} r"""
    if table == "protocols":
        return f"SELECT 'protocol:' || r.id AS key FROM {rows} r"
    if table == "jobs":
        return f"""SELECT unnest(ARRAY['address:' || lower(r.address),
            'protocol:' || c.protocol_id, 'protocol:' || c.nominated_protocol_id]) AS key
            FROM {rows} r LEFT JOIN contracts c ON c.address = lower(r.address)
            WHERE r.status = 'completed' AND r.address IS NOT NULL"""
    if table == "token_delivery_evidence":
        return f"SELECT 'holder:' || lower(r.holder_address) AS key FROM {rows} r"
    if table in PROTOCOL_CHILDREN:
        return f"SELECT 'protocol:' || r.protocol_id AS key FROM {rows} r"
    if table == "function_principals":
        return f"""SELECT unnest(ARRAY['contract:' || f.contract_id, 'protocol:' || c.protocol_id]) AS key
            FROM {rows} r JOIN effective_functions f ON f.id = r.function_id
            LEFT JOIN contracts c ON c.id = f.contract_id"""
    return f"""SELECT unnest(ARRAY['contract:' || r.contract_id, 'protocol:' || c.protocol_id]) AS key
        FROM {rows} r LEFT JOIN contracts c ON c.id = r.contract_id"""


def upgrade() -> None:
    op.add_column("company_page_snapshots", sa.Column("source_revisions", pg.JSONB()))
    op.drop_column("company_page_snapshots", "dirty_token")
    op.drop_column("company_page_snapshots", "built_token")
    op.create_table(
        "company_page_revisions",
        sa.Column("key", sa.String(200), primary_key=True),
        sa.Column("token", pg.UUID(as_uuid=True), server_default=sa.func.gen_random_uuid(), nullable=False),
        sa.Column("transaction_id", sa.BigInteger(), nullable=False),
    )
    op.create_table(
        "company_page_purges",
        sa.Column("company_name", sa.String(255), primary_key=True),
        sa.Column("token", pg.UUID(as_uuid=True), server_default=sa.func.gen_random_uuid(), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    # Tokens change once per writer transaction. Rollback rolls back the token
    # too, and commit publishes the data and invalidation together. No producer
    # catches/drops these changes, and no periodic expensive sweep is required.
    op.execute("""CREATE FUNCTION psat_page_touch(scopes text[]) RETURNS void LANGUAGE sql AS $$
        INSERT INTO company_page_revisions (key, transaction_id)
        SELECT DISTINCT scope, txid_current() FROM unnest(scopes) scope
        WHERE scope IS NOT NULL ORDER BY scope
        ON CONFLICT (key) DO UPDATE SET token = gen_random_uuid(), transaction_id = excluded.transaction_id
        WHERE company_page_revisions.transaction_id <> excluded.transaction_id
    $$""")
    op.execute("""CREATE FUNCTION psat_page_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM psat_page_touch(ARRAY['all']); RETURN NULL; END
    $$""")
    for table in TABLES:
        for event, relations in (
            ("insert", ("new_rows",)),
            ("update", ("old_rows", "new_rows")),
            ("delete", ("old_rows",)),
        ):
            query = " UNION ALL ".join(_keys(table, rows) for rows in relations)
            purge = ""
            if table == "protocols" and event != "insert":
                # Preserve retired names even though their prepared row is
                # renamed/deleted. No management HTTP calls inside a DB txn.
                retired = "SELECT name FROM old_rows"
                if event == "update":
                    retired += " EXCEPT SELECT name FROM new_rows"
                purge = f"""INSERT INTO company_page_purges (company_name) {retired}
                    ON CONFLICT (company_name) DO UPDATE SET token = gen_random_uuid(),
                    attempts = 0, next_attempt_at = clock_timestamp();"""
            function = f"psat_page_{table}_{event}"
            op.execute(f"""CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN PERFORM psat_page_touch(ARRAY({query})); {purge} RETURN NULL; END
            $$""")
            referencing = " ".join(
                "OLD TABLE AS old_rows" if r == "old_rows" else "NEW TABLE AS new_rows" for r in relations
            )
            op.execute(f"""CREATE TRIGGER psat_page_{event} AFTER {event.upper()} ON {table}
                REFERENCING {referencing} FOR EACH STATEMENT EXECUTE FUNCTION {function}()""")
        op.execute(f"""CREATE TRIGGER psat_page_truncate AFTER TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION psat_page_truncate()""")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TRIGGER psat_page_truncate ON {table}")
        for event in ("insert", "update", "delete"):
            op.execute(f"DROP TRIGGER psat_page_{event} ON {table}")
            op.execute(f"DROP FUNCTION psat_page_{table}_{event}()")
    op.execute("DROP FUNCTION psat_page_truncate()")
    op.execute("DROP FUNCTION psat_page_touch(text[])")
    op.drop_table("company_page_purges")
    op.drop_table("company_page_revisions")
    op.drop_column("company_page_snapshots", "source_revisions")
    op.add_column("company_page_snapshots", sa.Column("dirty_token", pg.UUID(as_uuid=True)))
    op.add_column("company_page_snapshots", sa.Column("built_token", pg.UUID(as_uuid=True)))
