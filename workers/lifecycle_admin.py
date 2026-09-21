"""Explicit operator controls. Pause/drain before deploy; resume after checks."""

import argparse
import json

from sqlalchemy import text

from db.models import SessionLocal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "pause", "drain", "resume"))
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
        session.commit()
        print(json.dumps({**dict(row), "control_version": 1}, default=str))


if __name__ == "__main__":
    main()
