"""Explicit operator controls. Pause/drain before deploy; resume after checks."""

import argparse
import json

from sqlalchemy import text

from db.models import SessionLocal
from services.process_singleton import KEYS, NAMESPACE


def readiness(session) -> dict:
    """Check controller decisions and actual indexer ownership, without RPC."""
    controller = (
        session.execute(
            text(
                "SELECT status, detail, beat_at > clock_timestamp() - interval '45 seconds' AS fresh "
                "FROM worker_heartbeats WHERE process='worker_lifecycle'"
            )
        )
        .mappings()
        .one_or_none()
    )
    owner = session.execute(
        text(
            "SELECT a.application_name FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid "
            "WHERE l.locktype='advisory' AND l.classid=:namespace AND l.objid=:key "
            "AND l.objsubid=2 AND l.granted AND l.database=(SELECT oid FROM pg_database "
            "WHERE datname=current_database())"
        ),
        {"namespace": NAMESPACE, "key": KEYS["indexer"]},
    ).scalar_one_or_none()
    return {
        "controller": dict(controller) if controller else None,
        "indexer_owner": owner,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "pause", "drain", "resume", "ready"))
    args = parser.parse_args()
    with SessionLocal() as session:
        session.execute(text("SET LOCAL statement_timeout='5s'"))
        if args.action == "drain":
            session.execute(text("UPDATE worker_lifecycle SET paused=true, phase='draining' WHERE id=1"))
        elif args.action in {"pause", "resume"}:
            session.execute(
                text("UPDATE worker_lifecycle SET paused=:paused WHERE id=1"), {"paused": args.action == "pause"}
            )
        row = (
            session.execute(
                text(
                    "SELECT *, heartbeat_at > clock_timestamp() - interval '30 seconds' AS boot_fresh "
                    "FROM worker_lifecycle WHERE id=1"
                )
            )
            .mappings()
            .one()
        )
        checks = readiness(session) if args.action == "ready" else {}
        session.commit()
        print(json.dumps({**dict(row), **checks, "control_version": 1}, default=str))


if __name__ == "__main__":
    main()
