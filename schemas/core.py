"""Shared core vocabulary for pipeline artifacts.

The stage-to-stage wire is a named JSON artifact; this module is the small
set of shapes every stage document is built from, defined ONCE so no stage
re-invents them:

- ``ResolvedControllerType`` / ``coerce_resolved_controller_type``: the
  principal-type vocabulary. ``schemas.control_tracking`` re-exports these
  so existing import sites keep working.
- ``ArtifactEnvelope``: the header every flat-identity stage document carries.
- ``Principal``: the resolved-authority identity — one address, its type,
  what is known about it. Specialized (not redeclared) by
  ``schemas.effective_permissions.ResolvedPrincipal``,
  ``schemas.principal_labels.PrincipalProfile``, and
  ``services.resolution.recursive.RolePrincipal``.

Imported via ``typing_extensions`` (not ``typing``) on Python < 3.12:
pydantic's ``TypeAdapter`` — which gives the artifact loaders in
``db.queue.typed`` runtime teeth — rejects ``typing.TypedDict`` there.
"""

from __future__ import annotations

from typing import Literal, cast, get_args

from typing_extensions import TypedDict

ResolvedControllerType = Literal[
    "zero",
    "eoa",
    "safe",
    "timelock",
    "proxy_admin",
    "contract",
    "unknown",
    # Signature- and Merkle-gated functions: no finite on-chain
    # principal set (whoever holds the signer key / matching proof).
    "off_chain_witness",
    # L2 principal that is an aliased L1 owner or an OP-stack bridge predeploy.
    # A label, not a cross-chain control edge.
    "cross_chain_authority",
]

# Derived from the Literal so a membership set can never drift from the type.
RESOLVED_CONTROLLER_TYPES: frozenset[str] = frozenset(get_args(ResolvedControllerType))


def coerce_resolved_controller_type(value: object) -> ResolvedControllerType:
    """Boundary validator for ``resolved_type`` values of unproven provenance
    (persisted artifacts, pre-seeded caches, JSONB rows).

    Only a proven vocabulary member passes through; ``None``, the stringified
    ``"None"`` a legacy store could carry, and any out-of-vocabulary token all
    surface as ``"unknown"`` — the vocabulary's not-determined arm — because a
    token nothing downstream knows licenses no concrete branch.
    """
    if value is None:
        return "unknown"
    text = str(value)
    if text in RESOLVED_CONTROLLER_TYPES:
        return cast(ResolvedControllerType, text)
    return "unknown"


class ArtifactEnvelope(TypedDict):
    """Header shared by the stage documents minted with a flat identity
    (``control_tracking``, ``effective_permissions``, ``principal_labels``).

    Documents whose identity is nested (``ContractAnalysis.subject``) or
    named differently (``resolved_control_graph.root_contract_address``,
    ``upgrade_history.target_address``) carry the same information under
    their own layout and do NOT extend this class.
    """

    schema_version: str
    contract_address: str
    contract_name: str


class Principal(TypedDict):
    """One resolved authority: address, what kind of principal it is, and
    what is known about it.

    ``resolved_type`` is the core vocabulary; undetermined types surface as
    ``"unknown"``, never a fabricated concrete token (see
    ``coerce_resolved_controller_type``). ``details`` stays open: each
    resolver records the shape its consumers replay (owners, signers,
    delay, ...). A display name is enrichment added downstream
    (``PrincipalProfile``), not part of the identity.
    """

    address: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
