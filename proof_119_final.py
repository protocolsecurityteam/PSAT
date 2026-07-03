"""Issue #119 FINAL proof — real psat_test Postgres, REAL edited code.

Run from the WORKTREE (faithful fix applied to event_logs_pg.py +
event_logs_hypersync.py + capability_resolver head-pin). No monkeypatch, no
hardcoded answers. Proves:

 1. Fold gate: block=None  -> partial/cursor_behind_block -> adapter lower_bound.
 2. Head-pin preserves exactness: a cursor that COVERS the pinned finalized head
    (head-12 <= cursor) stays enumerable/exact; one that does NOT (head-12 >
    cursor) demotes. Mirrors what capability_resolver now passes as ctx.block.
 3. fold_event_values gated the same way.
 4. Empty-set side effect: an empty exact set is NOT a root-authority blocker
    (function stays PUBLIC); an empty lower_bound set IS a blocker (PUBLIC sibling
    stripped -> GATED). Fail-closed, accepted.
 5. HyperSync sibling: read-confirmed identical gate now demotes to_block=None.
"""

import os
import sys

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from db.models import IndexedEventCursor, IndexedEventLog
from services.policy.capability_surface import _is_root_authority_blocker
from services.resolution.capabilities import negate
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo, _cursor_covers_block

TEST_DB = os.environ["TEST_DATABASE_URL"]
CHAIN_ID = 999_119
EVENT_ADDRESS = "0x0000000000000000000000000000000011900119"
TOPIC0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
A = "0x000000000000000000000000000000000000aaaa"
B = "0x000000000000000000000000000000000000bbbb"
C = "0x000000000000000000000000000000000000cccc"


def _pad(addr):
    return "0x" + addr[2:].rjust(64, "0")


def _grant(acct, blk, li):
    return IndexedEventLog(
        chain_id=CHAIN_ID,
        event_address=EVENT_ADDRESS.lower(),
        topic0=TOPIC0,
        tx_hash=(blk * 1000 + li).to_bytes(32, "big"),
        log_index=li,
        block_number=blk,
        block_hash=blk.to_bytes(32, "big"),
        transaction_index=0,
        topics=[TOPIC0, _pad(acct)],
        data_words=[],
    )


def cleanup(s):
    s.execute(delete(IndexedEventLog).where(IndexedEventLog.chain_id == CHAIN_ID))
    s.execute(delete(IndexedEventCursor).where(IndexedEventCursor.chain_id == CHAIN_ID))
    s.commit()


def q(conf):
    return "exact" if conf == "enumerable" else "lower_bound"


def main():
    engine = create_engine(TEST_DB)
    session = sessionmaker(bind=engine)()
    try:
        cleanup(session)
        CURSOR = 1000  # backfill_complete head as of last indexer pass
        session.add(
            IndexedEventCursor(
                chain_id=CHAIN_ID,
                event_address=EVENT_ADDRESS.lower(),
                topic0=TOPIC0,
                last_indexed_block=CURSOR,
                backfill_complete=True,
            )
        )
        session.add(_grant(A, 900, 0))
        session.add(_grant(B, 950, 0))
        session.commit()
        repo = PostgresEventLogRepo(session)
        ks = [{"source": "msg_sender"}]
        t2k = {1: 0}
        hint = {"topic0": TOPIC0, "direction": "add", "topics_to_keys": t2k, "data_to_keys": {}}
        cshort = "0x" + C[2:]

        def writes(block):
            return repo.fold_event_writes(
                chain_id=CHAIN_ID,
                event_address=EVENT_ADDRESS,
                topic0=TOPIC0,
                topics_to_keys=t2k,
                data_to_keys={},
                key_sources=ks,
                direction="add",
                block=block,
            )

        def hist(block):
            return repo.fold_event_history(
                chain_id=CHAIN_ID, event_address=EVENT_ADDRESS, event_hints=[hint], key_sources=ks, block=block
            )

        # --- 1. block=None (unpinned head: no RPC available) ---
        w_none = writes(None)
        h_none = hist(None)
        # --- 2. head-pin: pinned finalized head the cursor COVERS (head-12=990<=1000) ---
        w_cov = writes(990)
        h_cov = hist(990)
        # --- 2b. head-pin: pinned finalized head the cursor does NOT cover (1050>1000) ---
        w_lag = writes(1050)

        print("=== fold_event_writes ===")
        for tag, r in [
            ("block=None (unpinned)", w_none),
            ("block=990 (cursor COVERS)", w_cov),
            ("block=1050 (cursor LAGS)", w_lag),
        ]:
            print(
                f"  {tag:28s} conf={r.confidence!r:12} reason={r.partial_reason!r:22} "
                f"-> quality={q(r.confidence)!r:13} members={sorted(m[-4:] for m in r.members)} C={cshort in r.members}"
            )
        print("=== fold_event_history ===")
        for tag, r in [("block=None (unpinned)", h_none), ("block=990 (cursor COVERS)", h_cov)]:
            print(
                f"  {tag:28s} conf={r.confidence!r:12} reason={r.partial_reason!r:22} -> quality={q(r.confidence)!r:13}"
            )

        # --- 3. fold_event_values ---
        vh = [{"topic0": TOPIC0, "topics_to_keys": t2k, "data_to_keys": {}, "value_position": 1}]
        v_none = repo.fold_event_values(
            chain_id=CHAIN_ID,
            event_address=EVENT_ADDRESS,
            value_hints=vh,
            key_sources=ks,
            fold_key_position=None,
            block=None,
        )
        v_cov = repo.fold_event_values(
            chain_id=CHAIN_ID,
            event_address=EVENT_ADDRESS,
            value_hints=vh,
            key_sources=ks,
            fold_key_position=None,
            block=990,
        )
        print("=== fold_event_values ===")
        vnq = "exact" if v_none.complete else "lower_bound"
        vcq = "exact" if v_cov.complete else "lower_bound"
        print(f"  block=None   complete={v_none.complete} reason={v_none.partial_reason!r} -> quality={vnq}")
        print(f"  block=990    complete={v_cov.complete} reason={v_cov.partial_reason!r} -> quality={vcq}")

        # --- 4. empty-set -> blocker flip ---
        empty_exact = {"kind": "finite_set", "members": [], "membership_quality": "exact", "subject": "root"}
        empty_lb = {"kind": "finite_set", "members": [], "membership_quality": "lower_bound", "subject": "root"}
        blk_exact = _is_root_authority_blocker(empty_exact)
        blk_lb = _is_root_authority_blocker(empty_lb)
        print("=== empty-set -> _is_root_authority_blocker (capability_surface) ===")
        print(f"  empty EXACT       blocker={blk_exact}  (False => PUBLIC sibling kept)")
        print(f"  empty LOWER_BOUND blocker={blk_lb}  (True  => PUBLIC sibling stripped, fn reads GATED; fail-closed)")

        # --- 5. ROUND-2 headline: head pin must NOT strip an indexed denylist member ---
        # Re-seed: cursor=1028 (>= pin), DENIED blocked @1010 (indexed, in (pin=976, cursor]).
        # The fold row scan must reach the cursor, not stop at the lower finality pin —
        # else DENIED falls out of the EXACT blacklist after negate() and reads PUBLIC.
        cleanup(session)
        DENIED = "0x000000000000000000000000000000000000dead"
        session.add(
            IndexedEventCursor(
                chain_id=CHAIN_ID,
                event_address=EVENT_ADDRESS.lower(),
                topic0=TOPIC0,
                last_indexed_block=1028,
                backfill_complete=True,
            )
        )
        session.add(_grant(DENIED, 1010, 0))
        session.commit()
        from services.resolution.capabilities import CapabilityExpr

        blocked = writes(976)  # pin = head(1040) - margin(64)
        as_exact = CapabilityExpr.finite_set(
            list(blocked.members),
            quality="exact" if blocked.confidence == "enumerable" else "lower_bound",
        )
        allowed = negate(as_exact)
        dshort = "0x" + DENIED[2:]
        print("=== denylist under head pin (negate -> cofinite blacklist) ===")
        print(
            f"  fold(block=pin=976) conf={blocked.confidence!r} members={[m[-4:] for m in blocked.members]} "
            f"-> blacklist={[m[-4:] for m in (allowed.blacklist or [])]} quality={allowed.blacklist_quality!r}"
        )
        denylist_gated = (
            blocked.confidence == "enumerable"
            and dshort in blocked.members
            and allowed.kind == "cofinite_blacklist"
            and dshort in (allowed.blacklist or [])
            and allowed.blacklist_quality == "exact"
        )

        ok = (
            denylist_gated
            and w_none.confidence == "partial"
            and w_none.partial_reason == "cursor_behind_block"
            and q(w_none.confidence) == "lower_bound"
            and h_none.confidence == "partial"
            and h_none.partial_reason == "cursor_behind_block"
            and w_cov.confidence == "enumerable"
            and q(w_cov.confidence) == "exact"  # head-pin preserves exact
            and h_cov.confidence == "enumerable"
            and w_lag.confidence == "partial"
            and w_lag.partial_reason == "cursor_behind_block"
            and v_none.complete is False
            and v_none.partial_reason == "cursor_behind_block"
            and v_cov.complete is True
            and blk_exact is False
            and blk_lb is True
            and cshort not in w_none.members  # C invisible either way (lag is a real data gap)
            and _cursor_covers_block(1000, 990)
            and not _cursor_covers_block(1000, 1050)
            and not _cursor_covers_block(1000, None)
        )
        print("\nPROOF:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        cleanup(session)
        session.close()
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
