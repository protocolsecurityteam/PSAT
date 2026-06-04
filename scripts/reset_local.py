#!/usr/bin/env python3
"""Local reset — wipe run data from Postgres + MinIO, KEEP the caches.

DRY-RUN by default; pass --yes to apply. Runs from any cwd:
    uv run python scripts/reset_local.py          # preview
    uv run python scripts/reset_local.py --yes    # apply

Gives a clean local slate for testing WITHOUT re-paying for cached work:
  KEPT  - DB:      alembic_version (migrations) + IMMUTABLE external-data caches
                   (etherscan_cache = verified source/ABI; bytecode_cache = on-chain code)
  KEPT  - storage: tavily-cache/, exa-cache/  (Exa/Tavily research = external API data)
  WIPED - everything else, incl. LOGIC-DERIVED caches that must recompute when you
          change analysis code: mapping_enumeration_cache, contract_materializations
          (+ jobs, contracts, artifacts, source_files, audits, ...)

Reads config straight from .env and refuses to touch anything non-local.
"""

from __future__ import annotations

import pathlib
import re
import sys

# ---- edit these to taste --------------------------------------------------
# Keep only caches of IMMUTABLE external data (safe across code changes). Caches of
# computed analysis (mapping_enumeration_cache, contract_materializations) are NOT
# kept — they must recompute when you iterate on the analysis logic.
KEEP_TABLES = {"alembic_version", "etherscan_cache", "bytecode_cache"}
KEEP_PREFIXES = ("tavily-cache/", "exa-cache/", "audits/")
# To also keep downloaded audits (re-crawling them costs GitHub API + LLM), add "audits/".
# ---------------------------------------------------------------------------

# This script lives in scripts/; anchor .env to the repo root so it resolves from
# any cwd (the deleted bash wrapper used to guarantee cwd via `cd`).
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_env(path: pathlib.Path | None = None) -> dict[str, str]:
    p = path if path is not None else REPO_ROOT / ".env"
    env: dict[str, str] = {}
    for line in p.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            env[m.group(1)] = m.group(2).strip().strip('"')
    return env


def is_local(s: str) -> bool:
    return bool(re.search(r"(@|//)(localhost|127\.0\.0\.1)[:/]", s or ""))


def main() -> int:
    execute = ("--yes" in sys.argv) or ("-y" in sys.argv)
    env = load_env()
    db_url = env.get("DATABASE_URL", "")
    ep = env.get("ARTIFACT_STORAGE_ENDPOINT", "")
    print(f"=== local reset [{'EXECUTE' if execute else 'DRY-RUN — pass --yes to apply'}] ===")

    # Safety: never truncate/delete against a non-local target.
    if db_url and not is_local(db_url):
        print(f"ABORT: DATABASE_URL is not local ({db_url}) — refusing.")
        return 1
    if ep and not is_local(ep):
        print(f"ABORT: ARTIFACT_STORAGE_ENDPOINT is not local ({ep}) — refusing.")
        return 1

    # ---------- Postgres ----------
    if db_url:
        import psycopg2

        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
        tables = [r[0] for r in cur.fetchall()]
        truncate = [t for t in tables if t not in KEEP_TABLES]
        kept = [t for t in tables if t in KEEP_TABLES]
        # Guard: would CASCADE wipe a kept table? (FK from a kept table into wiped data)
        cur.execute("SELECT conrelid::regclass::text, confrelid::regclass::text FROM pg_constraint WHERE contype='f'")
        risk = sorted({a for a, b in cur.fetchall() if a in KEEP_TABLES and b in set(truncate)})
        print(f"\nPostgres ({db_url.rsplit('/', 1)[-1]}):")
        print(f"  keep    : {', '.join(kept)}")
        print(f"  truncate: {len(truncate)} tables")
        if risk:
            print(f"  !! ABORT: kept table(s) {risk} FK-reference wiped data; CASCADE would wipe them too.")
            conn.close()
            return 1
        if execute and truncate:
            cur.execute("TRUNCATE TABLE " + ", ".join(f'"{t}"' for t in truncate) + " RESTART IDENTITY CASCADE")
            conn.commit()
            print("  -> truncated (schema + caches kept).")
        conn.close()

    # ---------- MinIO ----------
    bk = env.get("ARTIFACT_STORAGE_BUCKET")
    ak, sk = env.get("ARTIFACT_STORAGE_ACCESS_KEY"), env.get("ARTIFACT_STORAGE_SECRET_KEY")
    if all([ep, bk, ak, sk]):
        import boto3
        from botocore.config import Config

        c = boto3.client(
            "s3",
            endpoint_url=ep,
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name="auto",
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )
        delete: list[dict[str, str]] = []
        keep_n = 0
        for page in c.get_paginator("list_objects_v2").paginate(Bucket=bk):
            for o in page.get("Contents", []):
                if o["Key"].startswith(KEEP_PREFIXES):
                    keep_n += 1
                else:
                    delete.append({"Key": o["Key"]})
        print(f"\nMinIO ({bk}):")
        print(f"  keep ({', '.join(KEEP_PREFIXES)}): {keep_n} objects")
        print(f"  delete: {len(delete)} objects")
        if execute and delete:
            for i in range(0, len(delete), 1000):
                c.delete_objects(Bucket=bk, Delete={"Objects": delete[i : i + 1000]})
            print("  -> deleted (caches kept).")
    else:
        print("\nMinIO: ARTIFACT_STORAGE_* not fully set — skipped.")

    if not execute:
        print("\n(dry-run — nothing changed; re-run with --yes to apply.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
