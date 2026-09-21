"""Durable change tracking for indexer enrollment and reconciliation.

Revision ID: c4e8f2a06b93
Revises: b3d7e1f05a92
"""

from alembic import op

revision = "c4e8f2a06b93"
down_revision = "b3d7e1f05a92"
branch_labels = None
depends_on = None

# Row triggers compare only semantic inputs. Artifact UPDATE deliberately has
# no equality guard: an object can change under an unchanged key/size.
WATCHES = {
    "jobs": "id,status,stage,address,chain_id,request",
    "artifacts": "",
    "contracts": "id,job_id,address,chain",
    "controller_values": "contract_id,controller_id,value,deployment_address",
    "effective_functions": "contract_id,capability_expr,deployment_address",
    "contract_dependencies": "contract_id,dependency_address,relationship_type,implementation",
    "job_dependencies": "depender_job_id,provider_chain,provider_address,status,required_stage",
    "monitored_contracts": "id,address,chain,is_active,tracked_topics",
    "indexed_event_cursors": "chain_id,event_address,topic0,backfill_complete,enrollment_basis",
}


def upgrade():
    op.execute("""
    CREATE TABLE indexer_work (
      kind varchar(24) NOT NULL, key varchar(100) NOT NULL,
      revision bigint NOT NULL DEFAULT 1, dirty boolean NOT NULL DEFAULT true,
      available_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
      attempts integer NOT NULL DEFAULT 0, lease_id uuid, lease_expires_at timestamptz,
      PRIMARY KEY(kind, key)
    );
    CREATE INDEX ix_indexer_work_due ON indexer_work(kind, dirty, available_at);
    CREATE INDEX ix_indexer_work_repair ON indexer_work(kind, dirty, completed_at);

    CREATE FUNCTION indexer_mark_dirty(k text, v text) RETURNS void LANGUAGE plpgsql AS $$
    BEGIN
      IF v IS NULL THEN RETURN; END IF;
      INSERT INTO indexer_work(kind,key) VALUES(k,v)
      ON CONFLICT(kind,key) DO UPDATE SET revision=indexer_work.revision+1,
        dirty=true, available_at=statement_timestamp(), attempts=0;
    END $$;

    CREATE FUNCTION indexer_source_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE o jsonb; n jsonb; r jsonb; col text; changed boolean := false;
      jobs_to_mark uuid[] := '{}'; chains_to_mark text[] := '{}';
      monitored_to_mark text[] := '{}'; owner_id uuid; target record;
    BEGIN
      IF TG_OP <> 'INSERT' THEN o := to_jsonb(OLD); END IF;
      IF TG_OP <> 'DELETE' THEN n := to_jsonb(NEW); END IF;
      IF TG_TABLE_NAME='monitored_contracts' THEN
        o := o || jsonb_build_object('tracked_topics',o->'monitoring_config'->'tracked_topics');
        n := n || jsonb_build_object('tracked_topics',n->'monitoring_config'->'tracked_topics');
      END IF;
      -- A rewind invalidates already folded events, even if DELETE removed no
      -- rows. Normal head advancement/last_run_at alone never dirties a chain.
      IF TG_TABLE_NAME='indexed_event_cursors' AND TG_OP='UPDATE'
         AND (n->>'last_indexed_block')::bigint < (o->>'last_indexed_block')::bigint THEN
        PERFORM indexer_mark_dirty('reorg',o->>'chain_id'||':'||lower(o->>'event_address'));
      END IF;
      IF TG_OP='UPDATE' AND TG_ARGV[0] <> '' THEN
        FOREACH col IN ARRAY string_to_array(TG_ARGV[0],',') LOOP
          changed := changed OR (o->col IS DISTINCT FROM n->col);
        END LOOP;
        IF NOT changed THEN RETURN NULL; END IF;
      END IF;
      -- Collect owners, then deduplicate KEYS (not the whole old/new rows).
      -- Chain before source matches cursor insertion followed by enrollment
      -- lease renewal, avoiding the opposite lock order between those writers.
      FOR r IN SELECT value FROM jsonb_array_elements(jsonb_build_array(o,n))
               WHERE value <> 'null'::jsonb LOOP
        CASE TG_TABLE_NAME
        WHEN 'jobs' THEN
          jobs_to_mark := array_append(jobs_to_mark,(r->>'id')::uuid);
          chains_to_mark := array_append(chains_to_mark,r->>'chain_id');
        WHEN 'artifacts' THEN
          IF r->>'name'='predicate_trees' THEN
            jobs_to_mark := array_append(jobs_to_mark,(r->>'job_id')::uuid);
          END IF;
        WHEN 'contracts' THEN
          jobs_to_mark := array_append(jobs_to_mark,(r->>'job_id')::uuid);
          IF r->>'job_id' IS NULL THEN
            -- Orphan adoption can affect chains with matching candidate jobs.
            chains_to_mark := chains_to_mark || ARRAY(SELECT key FROM indexer_work WHERE kind='reconcile');
          END IF;
        WHEN 'controller_values', 'effective_functions', 'contract_dependencies' THEN
          SELECT job_id INTO owner_id FROM contracts WHERE id=(r->>'contract_id')::integer;
          jobs_to_mark := array_append(jobs_to_mark,owner_id);
          IF owner_id IS NULL THEN
            chains_to_mark := chains_to_mark || ARRAY(SELECT key FROM indexer_work WHERE kind='reconcile');
          END IF;
        WHEN 'job_dependencies' THEN
          jobs_to_mark := array_append(jobs_to_mark,(r->>'depender_job_id')::uuid);
        WHEN 'monitored_contracts' THEN
          monitored_to_mark := array_append(monitored_to_mark,r->>'id');
        WHEN 'indexed_event_cursors' THEN
          chains_to_mark := array_append(chains_to_mark,r->>'chain_id');
        ELSE NULL;
        END CASE;
      END LOOP;
      FOR target IN
        SELECT * FROM (
        SELECT 'job' AS kind,id::text AS key FROM jobs
          WHERE id=ANY(jobs_to_mark) AND status='completed' AND address IS NOT NULL
        UNION SELECT 'reconcile',chain_id::text FROM jobs
          WHERE id=ANY(jobs_to_mark) AND chain_id IS NOT NULL
        UNION SELECT 'reconcile',v FROM unnest(chains_to_mark) AS v WHERE v IS NOT NULL
        UNION SELECT 'monitored',v FROM unnest(monitored_to_mark) AS v WHERE v IS NOT NULL
        ) AS work ORDER BY (kind='reconcile') DESC,kind,key
      LOOP
        PERFORM indexer_mark_dirty(target.kind,target.key);
      END LOOP;
      RETURN NULL;
    END $$;

    CREATE FUNCTION indexer_logs_inserted() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE c integer;
    BEGIN
      -- Statement transition tables contain only inserted rows: an empty or
      -- all-conflicting batch does no work. No per-log queue writes.
      FOR c IN SELECT DISTINCT chain_id FROM new_logs LOOP
        PERFORM indexer_mark_dirty('reconcile',c::text);
      END LOOP;
      RETURN NULL;
    END $$;
    CREATE FUNCTION indexer_logs_removed() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE r record;
    BEGIN
      FOR r IN SELECT DISTINCT chain_id,lower(event_address) AS address FROM old_logs LOOP
        PERFORM indexer_mark_dirty('reorg',r.chain_id::text||':'||r.address);
      END LOOP;
      RETURN NULL;
    END $$;
    CREATE FUNCTION indexer_logs_replaced() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE r record;
    BEGIN
      FOR r IN SELECT chain_id,lower(event_address) AS address FROM old_logs
               UNION SELECT chain_id,lower(event_address) AS address FROM new_logs
               ORDER BY chain_id,address LOOP
        PERFORM indexer_mark_dirty('reorg',r.chain_id::text||':'||r.address);
        PERFORM indexer_mark_dirty('reconcile',r.chain_id::text);
      END LOOP;
      RETURN NULL;
    END $$;
    CREATE TRIGGER indexer_logs_insert AFTER INSERT ON indexed_event_logs
      REFERENCING NEW TABLE AS new_logs FOR EACH STATEMENT EXECUTE FUNCTION indexer_logs_inserted();
    CREATE TRIGGER indexer_logs_delete AFTER DELETE ON indexed_event_logs
      REFERENCING OLD TABLE AS old_logs FOR EACH STATEMENT EXECUTE FUNCTION indexer_logs_removed();
    CREATE TRIGGER indexer_logs_update AFTER UPDATE ON indexed_event_logs
      REFERENCING OLD TABLE AS old_logs NEW TABLE AS new_logs
      FOR EACH STATEMENT EXECUTE FUNCTION indexer_logs_replaced();
    """)
    for table, columns in WATCHES.items():
        update_columns = columns.replace("tracked_topics", "monitoring_config")
        if table == "indexed_event_cursors":
            update_columns += ",last_indexed_block"
        update_event = f"UPDATE OF {update_columns}" if update_columns else "UPDATE"
        op.execute(
            f"CREATE TRIGGER indexer_source_insert_delete AFTER INSERT OR DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION indexer_source_changed('{columns}')"
        )
        op.execute(
            f"CREATE TRIGGER indexer_source_change AFTER {update_event} ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION indexer_source_changed('{columns}')"
        )
    # Atomic bootstrap has no newest-500 cutoff. Each source is subsequently
    # handled in bounded, leased batches, including sources created mid-drain.
    op.execute("""
    INSERT INTO indexer_work(kind,key) SELECT 'job',id::text FROM jobs
      WHERE status='completed' AND address IS NOT NULL ON CONFLICT DO NOTHING;
    INSERT INTO indexer_work(kind,key) SELECT 'monitored',id::text FROM monitored_contracts
      WHERE is_active ON CONFLICT DO NOTHING;
    INSERT INTO indexer_work(kind,key) SELECT DISTINCT 'reconcile',chain_id::text FROM jobs
      WHERE chain_id IS NOT NULL ON CONFLICT DO NOTHING;
    """)


def downgrade():
    for table in WATCHES:
        op.execute(f"DROP TRIGGER indexer_source_change ON {table}")
        op.execute(f"DROP TRIGGER indexer_source_insert_delete ON {table}")
    for suffix in ("insert", "delete", "update"):
        op.execute(f"DROP TRIGGER indexer_logs_{suffix} ON indexed_event_logs")
    for name, args in (
        ("indexer_logs_inserted", ""),
        ("indexer_logs_removed", ""),
        ("indexer_logs_replaced", ""),
        ("indexer_source_changed", ""),
        ("indexer_mark_dirty", "text,text"),
    ):
        op.execute(f"DROP FUNCTION {name}({args})")
    op.execute("DROP TABLE indexer_work")
