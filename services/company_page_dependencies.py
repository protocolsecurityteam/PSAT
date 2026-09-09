"""Collect bounded dependency scopes only during prepared snapshot builds.

Protocol scopes include member/candidate changes and member child rows. Contract
scopes cover borrowed implementations. Address scopes include implementations
that do not exist yet; holder scopes cover the independently stored delivery
evidence. Address scopes intentionally over-invalidate same-address chain twins,
matching the resolver's conservative address join without duplicating its rules.
"""

from collections.abc import Iterable

from sqlalchemy.orm import Session


def track(session: Session, kind: str, keys: Iterable[object]) -> None:
    dependencies = session.info.get("company_page_dependencies")
    if dependencies is not None:
        dependencies.update(f"{kind}:{str(key).lower()}" for key in keys if key is not None)
