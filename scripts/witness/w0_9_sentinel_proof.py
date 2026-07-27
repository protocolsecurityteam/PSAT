#!/usr/bin/env python
"""W0-9 evidence, re-runnable. R2: prove the sentinels FIRE on real data.

W0-9 replaces a fabricated ``UpgradeEvent.block_number=0`` with NULL and adds
a ``source`` discriminator. Both are only worth anything if they are reached,
and ``select count(*) from upgrade_events where block_number = 0`` is 0 today
— which measures watcher uptime, not correctness. So this script drives the
**real production write paths** against **real rows and real artifacts**, and
reports what they produce:

1. ``_sync_relational_from_poll`` — the storage-poll writer — run against a
   real armed ``MonitoredContract`` (``needs_polling AND is_active`` with an
   ``implementation`` entry in its polling plan) with a real historical
   implementation address as the newly-observed value. Reports the written
   row and its position in the canonical ordering every consumer uses.
2. ``project_to_events`` — the backfill writer — run against a real
   ``upgrade_history`` artifact fetched from the bucket, reporting how many
   rows come back stamped ``source='backfill'``.
3. A discriminating control: the same ordering query with the pre-fix
   ``block_number=0`` row instead, which must still sort ahead of the genuine
   genesis deployment. If it does not, the ordering assertion has stopped
   being able to see the defect.

**Every write is rolled back.** The script asserts the ``upgrade_events`` row
count is identical before and after, and exits non-zero if it is not.

Usage:  set -a && source .env && set +a && \
        uv run python scripts/witness/w0_9_sentinel_proof.py
"""

from __future__ import annotations

import json
import os
import sys

import boto3
from botocore.config import Config
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from db.models import (  # noqa: E402
    UPGRADE_SOURCE_BACKFILL,
    UPGRADE_SOURCE_POLL,
    Contract,
    MonitoredContract,
    UpgradeEvent,
)
from services.discovery.upgrade_history import project_to_events  # noqa: E402
from services.monitoring.unified_watcher import _sync_relational_from_poll  # noqa: E402

CANONICAL_ORDER = (UpgradeEvent.block_number.asc().nullslast(), UpgradeEvent.id.asc())

ARMED_SQL = """
select mc.id
from monitored_contracts mc
where mc.needs_polling and mc.is_active and mc.contract_id is not null
  and exists (
    select 1 from jsonb_array_elements(
      case when jsonb_typeof(mc.monitoring_config->'polling_plan') = 'array'
           then mc.monitoring_config->'polling_plan' else '[]'::jsonb end) e
    where e->>'field' = 'implementation')
order by (select count(*) from upgrade_events ue where ue.contract_id = mc.contract_id) desc
"""

failures: list[str] = []


def check(label: str, ok: bool, detail: str) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {detail}")
    if not ok:
        failures.append(label)


def bucket_get(storage_key: str) -> bytes | None:
    """Fetch by the recorded key, then by the prefix-stripped candidate.

    ``artifacts.storage_key`` carries a stale ``pr-160/`` prefix while the
    bytes sit at the stripped path; a miss on the recorded key is never
    evidence the object does not exist.
    """
    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ["ARTIFACT_STORAGE_ENDPOINT"],
        aws_access_key_id=os.environ["ARTIFACT_STORAGE_ACCESS_KEY"],
        aws_secret_access_key=os.environ["ARTIFACT_STORAGE_SECRET_KEY"],
        config=Config(signature_version="s3v4"),
    )
    bucket = os.environ.get("ARTIFACT_STORAGE_BUCKET", "psat-artifacts")
    stripped = "artifacts/" + storage_key.split("artifacts/", 1)[-1] if "artifacts/" in storage_key else storage_key
    for key in (storage_key, stripped):
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except Exception:
            continue
    return None


def main() -> int:
    engine = create_engine(os.environ["DATABASE_URL"])
    with Session(engine) as session:
        before = session.execute(select(func.count()).select_from(UpgradeEvent)).scalar_one()
        print(f"upgrade_events rows before: {before}")

        # The poll writer calls ``_refresh_coverage_after_upgrade``, which
        # calls ``upsert_coverage_for_protocol``, which COMMITS. Without this
        # the "rolled back" claim below is false and this script permanently
        # writes a fabricated upgrade into the working DB — it did, twice,
        # before the neutralisation was added. Downgrading commit to flush
        # keeps every production code path intact inside one transaction.
        session.commit = session.flush  # type: ignore[method-assign]

        armed = session.execute(text(ARMED_SQL)).scalars().all()
        print(f"armed population (needs_polling AND is_active AND polls 'implementation'): {len(armed)}")

        # --- 1. the poll writer, on a real armed row --------------------
        mc = session.get(MonitoredContract, armed[0])
        assert mc is not None and mc.contract_id is not None
        contract = session.get(Contract, mc.contract_id)
        assert contract is not None
        existing = list(
            session.execute(
                select(UpgradeEvent).where(UpgradeEvent.contract_id == contract.id).order_by(*CANONICAL_ORDER)
            )
            .scalars()
            .all()
        )
        old_value = (mc.last_known_state or {}).get("implementation") or contract.implementation
        # A real historical implementation of this same proxy, so the value
        # the writer records is one the chain actually produced.
        new_value = next(
            (e.new_impl for e in reversed(existing) if e.new_impl and e.new_impl.lower() != str(old_value).lower()),
            None,
        )
        print(f"\n1. poll writer on {mc.address} (contract {contract.id}, {len(existing)} real events)")
        print(f"   old={old_value}\n   new={new_value}")

        _sync_relational_from_poll(session, mc, "implementation", new_value, old_value)
        session.flush()
        after_rows = list(
            session.execute(
                select(UpgradeEvent).where(UpgradeEvent.contract_id == contract.id).order_by(*CANONICAL_ORDER)
            )
            .scalars()
            .all()
        )
        written = [r for r in after_rows if r.id not in {e.id for e in existing}]
        check("poll writer wrote exactly one row", len(written) == 1, str(len(written)))
        row = written[0]
        check("source stamped 'poll'", row.source == UPGRADE_SOURCE_POLL, repr(row.source))
        check("block_number is NULL, not 0", row.block_number is None, repr(row.block_number))
        check("tx_hash is NULL, not ''", row.tx_hash is None, repr(row.tx_hash))
        check("timestamp present (detection time)", row.timestamp is not None, str(row.timestamp))
        check("old_impl recorded by this writer", bool(row.old_impl), repr(row.old_impl))
        check(
            "sorts LAST in the canonical ordering",
            after_rows[-1].id == row.id,
            f"position {after_rows.index(row) + 1}/{len(after_rows)}",
        )
        check(
            "genuine genesis still sorts FIRST",
            after_rows[0].id == existing[0].id and after_rows[0].block_number == existing[0].block_number,
            f"block {after_rows[0].block_number}",
        )

        # --- 2. the discriminating control ------------------------------
        # The pre-fix value, on the same real history. It must still corrupt
        # the ordering, or the check above cannot see the defect any more.
        row.block_number = 0
        session.flush()
        ctrl = list(
            session.execute(
                select(UpgradeEvent).where(UpgradeEvent.contract_id == contract.id).order_by(*CANONICAL_ORDER)
            )
            .scalars()
            .all()
        )
        print("\n2. control: the same row with the pre-fix block_number=0")
        check(
            "block_number=0 still sorts ahead of genesis (defect visible)",
            ctrl[0].id == row.id,
            f"position {ctrl.index(row) + 1}/{len(ctrl)}, genesis now {ctrl[1].block_number}",
        )
        session.rollback()

        # --- 3. the backfill writer, on a real artifact -----------------
        print("\n3. backfill writer on a real bucket artifact")
        rows = session.execute(
            text(
                "select job_id, storage_key from artifacts where name = 'upgrade_history' "
                "order by created_at desc limit 40"
            )
        ).all()
        proved = False
        for job_id, storage_key in rows:
            raw = bucket_get(storage_key)
            if not raw:
                continue
            data = json.loads(raw)
            proxies = data.get("proxies") or {}
            if not proxies:
                continue
            subject = (
                session.execute(
                    select(Contract).where(func.lower(Contract.address) == str(data.get("target_address", "")).lower())
                )
                .scalars()
                .first()
            )
            if subject is None:
                continue
            stats = project_to_events(
                session,
                subject_contract_id=subject.id,
                subject_chain=subject.chain,
                artifact_data=data,
            )
            session.flush()
            if not stats["events_written"]:
                session.rollback()
                continue
            n_backfill = session.execute(
                select(func.count()).select_from(UpgradeEvent).where(UpgradeEvent.source == UPGRADE_SOURCE_BACKFILL)
            ).scalar_one()
            print(f"   artifact job {job_id} → {stats['events_written']} events written")
            check(
                "source stamped 'backfill' on real artifact rows",
                n_backfill >= stats["events_written"],
                f"{n_backfill} rows carry source='backfill'",
            )
            session.rollback()
            proved = True
            break
        if not proved:
            check("a real upgrade_history artifact was projected", False, "no artifact yielded events")

        del session.commit  # restore the real method before the final rollback
        session.rollback()
        after = session.execute(select(func.count()).select_from(UpgradeEvent)).scalar_one()
        check("every write rolled back", after == before, f"{before} → {after}")

    print("\nRESULT:", "PASS" if not failures else f"FAIL ({', '.join(failures)})")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
