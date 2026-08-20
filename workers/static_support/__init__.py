"""Module-level helper library lifted out of ``workers.static_worker``.

``static_worker`` re-binds these at module level, so test patches on
``workers.static_worker.<name>`` keep intercepting the worker's calls.
"""
