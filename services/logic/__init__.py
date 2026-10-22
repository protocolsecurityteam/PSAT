"""Authorization as logic: a function's success condition as one formula over a few kinds of value, then who
satisfies it.

``terms`` holds the values (caller, arguments, storage, hashes, calls, time) and connectives, ``lower`` turns Slither IR
into the formula, and ``decide`` asks which identities satisfy it against chain state. Nothing in here names a pattern
(allowlist, role, Merkle proof); those are what the pieces combine into.
"""
