"""Read-only census of what the witness taxonomy makes of the enrolled fleet.

Answers three questions over ``monitored_contracts.monitoring_config``, which
is the only fleet-wide evidence available offline:

  1. **Tier distribution** — how every persisted tracked-topic spec classifies
     under :func:`classify_witness_tier`, with readability taken from the
     contract's own persisted polling plan (the same projection enrollment
     used). This is the "what publishes today" number.

  2. **Member-path population** — specs whose controller names a struct member.
     F8 makes those controllers readable, so they move activity → hint — but
     only when the plan is REBUILT: the effect is derivation-side, and a
     persisted config carries neither a member poll entry nor a member witness.
     ``member_poll_entries`` is that check; a non-zero count would mean some
     config had already been re-derived.

  3. **Unreadable controllers by shape** — every spec whose controller has no
     poll entry PROVEN to read it (``source == "analyzer:<controller_id>"``),
     grouped by controller. This is the input to the F8 storage-slot-emitter
     question: which of them are mappings (no slot read can help), which are
     member paths (the getter projection covers them), and which are
     getter-less scalars (the only population a storage-slot emitter would
     serve).

**Read-only.** No statement here is a claim about a contract's SOURCE: whether
a given getter-less scalar is an IR-proven reentrancy latch, or whether a given
struct is word-projectable, is decided by re-analysing that contract, which this
script does not do and cannot fake. It reports what the enrolled configs say.

Usage::

    uv run python -m scripts.monitoring_tier_census            # DATABASE_URL
    uv run python -m scripts.monitoring_tier_census --json
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from typing import Any

from sqlalchemy import create_engine, text

from services.monitoring.event_topics import classify_witness_tier


def _controller_var(controller_id: str) -> str:
    return controller_id.split(":", 1)[1] if ":" in controller_id else controller_id


def census(database_url: str) -> dict[str, Any]:
    engine = create_engine(database_url)
    with engine.connect() as connection:
        rows = connection.execute(text("SELECT address, chain, monitoring_config FROM monitored_contracts")).all()

    tiers: Counter[str] = Counter()
    unreadable: Counter[str] = Counter()
    member_specs = 0
    member_contracts: set[str] = set()
    member_poll_entries = 0
    with_topics = 0

    for address, _chain, config in rows:
        config = config or {}
        plan = [entry for entry in (config.get("polling_plan") or []) if isinstance(entry, dict)]
        sources = {entry.get("source") for entry in plan}
        member_poll_entries += sum(
            1 for entry in plan if entry.get("member_word_index") is not None or "." in str(entry.get("field") or "")
        )
        specs = config.get("tracked_topics") or []
        if specs:
            with_topics += 1
        for spec in specs:
            controller_id = spec.get("controller_id") or ""
            readable = f"analyzer:{controller_id}" in sources
            tiers[
                classify_witness_tier(
                    event_type=spec.get("event_type"),
                    controller_id=controller_id,
                    inputs=spec.get("inputs"),
                    effect_tags=spec.get("effect_tags"),
                    member_witness=spec.get("member_witness"),
                    writer_openness=spec.get("writer_openness"),
                    poll_decodable=readable,
                )
            ] += 1
            if not readable:
                unreadable[controller_id] += 1
            if "." in _controller_var(controller_id):
                member_specs += 1
                member_contracts.add(address)

    return {
        "monitored_contracts": len(rows),
        "contracts_with_tracked_topics": with_topics,
        "tiers": dict(sorted(tiers.items())),
        "member_path_specs": member_specs,
        "member_path_contracts": len(member_contracts),
        "member_poll_entries": member_poll_entries,
        "unreadable_by_controller": dict(unreadable.most_common()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"))
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    if not args.database_url:
        parser.error("no --database-url and no DATABASE_URL in the environment")

    result = census(args.database_url)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"monitored contracts        {result['monitored_contracts']}")
    print(f"  with tracked_topics      {result['contracts_with_tracked_topics']}")
    print(f"tiers over persisted specs {result['tiers']}")
    print(
        f"member-path specs          {result['member_path_specs']} across {result['member_path_contracts']} contracts"
    )
    print(f"member poll entries        {result['member_poll_entries']}  (non-zero ⇒ a config was re-derived post-F8)")
    print("unreadable controllers (no poll entry proven to read them):")
    for controller_id, count in result["unreadable_by_controller"].items():
        print(f"  {count:>4}  {controller_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
