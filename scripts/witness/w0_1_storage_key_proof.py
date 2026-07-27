#!/usr/bin/env python
"""W0-1 evidence, re-runnable. Read-only against the working DB + bucket.

Answers three questions a reviewer would otherwise have to take on trust:

1. **Does the prefix fallback fire on real rows?** For every recorded key in
   the five affected columns, is the object at the key the row records, or only
   at the prefix-stripped candidate? This is the whole fix, measured.

2. **Does the discriminating control stay flagged?** ``audit_reports`` keys use
   the ``audits/`` namespace, which ``storage_key_candidates`` must refuse to
   strip. A row whose object is genuinely gone must still raise
   ``StorageKeyMissing`` — the fallback must not explain a real absence away.

3. **Is ``StorageKeyAbsent`` realised on real rows?** It is the third state and
   the class this item introduced, so its realisation is reported as a number
   rather than asserted. On the working DB today that number is 0, which is a
   lower bound on prevalence (one protocol, largely one pipeline run) and *not*
   evidence the class is dead: it is reachable by construction, from
   ``store_artifact`` with no payload under an unconfigured backend.

Usage:  set -a && source .env && set +a && uv run python scripts/witness/w0_1_storage_key_proof.py
"""

from __future__ import annotations

import os
import sys

import boto3
import psycopg2
from botocore.config import Config

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from db.storage import StorageClient, StorageKeyMissing, storage_key_candidates  # noqa: E402

AFFECTED = [
    ("artifacts.storage_key", "select storage_key from artifacts where storage_key is not null"),
    ("source_files.storage_key", "select storage_key from source_files where storage_key is not null"),
    (
        "cm.analysis_blob_key",
        "select analysis_blob_key from contract_materializations where analysis_blob_key is not null",
    ),
    (
        "cm.tracking_plan_blob_key",
        "select tracking_plan_blob_key from contract_materializations where tracking_plan_blob_key is not null",
    ),
    (
        "cm.predicate_trees_blob_key",
        "select predicate_trees_blob_key from contract_materializations where predicate_trees_blob_key is not null",
    ),
]
CONTROL = [
    (
        "audit_reports.text_storage_key",
        "select id, text_storage_key from audit_reports where text_storage_key is not null",
    ),
    (
        "audit_reports.scope_storage_key",
        "select id, scope_storage_key from audit_reports where scope_storage_key is not null",
    ),
]
# The keyless shape: no key AND no inline body -> StorageKeyAbsent on the
# single-row path, ``not_determined`` in the collection reads.
KEYLESS = [
    (
        "artifacts",
        "select count(*) from artifacts where storage_key is null "
        "and (data is null or jsonb_typeof(data)='null') and text_data is null",
    ),
    ("source_files", "select count(*) from source_files where storage_key is null and content is null"),
]


def main() -> int:
    bucket = os.environ["ARTIFACT_STORAGE_BUCKET"]
    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ["ARTIFACT_STORAGE_ENDPOINT"],
        aws_access_key_id=os.environ["ARTIFACT_STORAGE_ACCESS_KEY"],
        aws_secret_access_key=os.environ["ARTIFACT_STORAGE_SECRET_KEY"],
        region_name="auto",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    client = StorageClient(
        os.environ["ARTIFACT_STORAGE_ENDPOINT"],
        bucket,
        os.environ["ARTIFACT_STORAGE_ACCESS_KEY"],
        os.environ["ARTIFACT_STORAGE_SECRET_KEY"],
    )

    present: set[str] = set()
    token = None
    while True:
        kw = {"Bucket": bucket, "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kw)
        present.update(o["Key"] for o in resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            break
        token = resp["NextContinuationToken"]

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cur = conn.cursor()

    print(f"bucket {bucket}: {len(present)} objects\n")
    print("1. prefix fallback on the five affected columns")
    print(f"   {'column':<32}{'rows':>7}{'at recorded':>13}{'at stripped':>13}{'absent':>8}")
    tot_rows = tot_recorded = tot_stripped = 0
    for label, sql in AFFECTED:
        cur.execute(sql)
        keys = [r[0] for r in cur.fetchall()]
        recorded = stripped = absent = 0
        for k in keys:
            cands = storage_key_candidates(k)
            if cands[0] in present:
                recorded += 1
            elif any(c in present for c in cands[1:]):
                stripped += 1
            else:
                absent += 1
        print(f"   {label:<32}{len(keys):>7}{recorded:>13}{stripped:>13}{absent:>8}")
        tot_rows += len(keys)
        tot_recorded += recorded
        tot_stripped += stripped
    print(f"   {'TOTAL':<32}{tot_rows:>7}{tot_recorded:>13}{tot_stripped:>13}")
    after = tot_recorded + tot_stripped
    print(f"   -> pre-fix readable {tot_recorded}/{tot_rows}; post-fix readable {after}/{tot_rows}\n")

    print("2. control: audits/ keys are never stripped, and a real absence stays flagged")
    ok = True
    for label, sql in CONTROL:
        cur.execute(sql)
        rows = cur.fetchall()
        multi = [k for _, k in rows if len(storage_key_candidates(k)) != 1]
        missing = []
        for rid, k in rows:
            if k in present:
                continue
            try:
                client.get(k)
                print(f"   !! {label} id={rid} key={k} read despite not being listed")
                ok = False
            except StorageKeyMissing as exc:
                missing.append(f"id={rid} {exc}")
        print(f"   {label:<32} rows={len(rows):<4} keys_with_a_fallback={len(multi)}")
        for m in missing:
            print(f"       still flagged proven-absent: {m}")
        if multi:
            print(f"   !! {label}: {len(multi)} key(s) offered a fallback candidate")
            ok = False
    print()

    print("3. StorageKeyAbsent realisation (the third state) -- reported, not asserted")

    def scalar(sql: str) -> int:
        cur.execute(sql)
        row = cur.fetchone()
        return int(row[0]) if row else 0

    for label, sql in KEYLESS:
        n = scalar(sql)
        total = scalar(f"select count(*) from {label}")
        print(f"   {label:<32} keyless-and-bodyless rows: {n}/{total}")
    print("   Reachable by construction and test-covered; a 0 here is a lower bound on")
    print("   prevalence (one protocol, largely one pipeline run), not a dead class.")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
