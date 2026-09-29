"""Fence every internal commit of a multi-transaction operation."""

from contextlib import contextmanager

from sqlalchemy import event


@contextmanager
def fenced_commits(session, check):
    """Check/renew ownership in the SAME transaction as each business commit.

    The callback must lock the queue row until commit and raise on lost ownership.
    Unlike a timer heartbeat, this also rejects a paused process resuming after a
    takeover. Remove the listener before acknowledgement deletes the queue row.
    """

    def before_commit(current):
        with current.no_autoflush:
            check(current)

    event.listen(session, "before_commit", before_commit)
    try:
        yield
    finally:
        event.remove(session, "before_commit", before_commit)
