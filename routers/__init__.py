"""FastAPI routers. ``spa`` must be included LAST: its catch-all swallows anything after it.

No eager submodule imports here: ``services.aggregations`` imports ``routers.deps``, so eager imports create a cycle.
"""
