"""Consumer-coverage allowlist for the claims plane.

The consumer-coverage invariant is: claim ids a downstream consumer branches on
must be a subset of the registry, which must be a subset of the ids the fixture
corpus produces. Only the first half is enforced today (``test_claims_registry``);
the second half tightens as matchers land.

``CONSUMER_REFERENCED_CLAIM_IDS`` is the tolerant allowlist a later stage grows:
it is empty at skeleton time because the effective-permissions payload now
*exposes* per-function ``claims`` but no consumer yet *reads* a claim_id (lanes,
severity, and principal tags still key off legacy ``effect_labels``). As each
consumer cuts over it adds the ids it reads here, and CI asserts the set stays
within the registry so a consumer can never reference a claim the producer
cannot mint.
"""

from __future__ import annotations

CONSUMER_REFERENCED_CLAIM_IDS: frozenset[str] = frozenset()
