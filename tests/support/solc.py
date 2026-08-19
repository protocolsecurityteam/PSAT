"""solc-select lookup shared by the real-Slither integration tests, which each
previously carried a private copy.
"""

from __future__ import annotations

from typing import cast


def solc_path_for(floor: tuple[int, int, int]) -> str | None:
    """Highest installed solc in the same major.minor line as ``floor`` whose
    patch is >= floor (i.e. a ``^floor`` match). None if nothing satisfies it."""
    try:
        from solc_select import solc_select as ss
    except Exception:
        return None
    best: tuple[int, int, int] | None = None
    for version in ss.installed_versions():
        try:
            parsed = cast("tuple[int, int, int]", tuple(int(x) for x in version.split(".")))
        except ValueError:
            continue
        if parsed[:2] == floor[:2] and parsed >= floor and (best is None or parsed > best):
            best = parsed
    if best is None:
        return None
    return str(ss.artifact_path(".".join(str(x) for x in best)))
