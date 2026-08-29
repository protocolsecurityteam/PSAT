"""Typed readers for the stage-to-stage artifact wire.

``store_artifact`` / ``get_artifact`` transport arbitrary JSON; the type of
an artifact dies at serialization and readers used to resurrect it with
``cast`` — a promise pyright believes and Python never checks. The loaders
here make the read boundary honest: each named artifact is validated against
its ``schemas`` TypedDict (via pydantic ``TypeAdapter``) the moment it comes
back out of storage, so schema drift fails LOUDLY at the boundary with the
offending field named, instead of surfacing as a missing key three stages
downstream.

Design points:

- **Fail closed.** A stored document that violates its schema raises
  :class:`ArtifactSchemaError`. ``None`` means "no artifact row" — never
  "artifact present but unusable".
- **No data loss.** Validation returns the ORIGINAL dict object after it
  passes the type check (pydantic's own output would drop unknown keys a
  future producer added, silently truncating the artifact).
- **Legacy documents.** Older jobs may hold artifacts minted before a field
  existed. Loaders for documents with a documented legacy population take
  ``lenient=True`` and re-attempt with the legacy-tolerant shape before
  failing; the strict path is the default.
"""

from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter, ValidationError

from schemas.contract_analysis import ContractAnalysis
from schemas.control_tracking import ControlSnapshot, ControlTrackingPlan
from schemas.effective_permissions import EffectivePermissions
from schemas.principal_labels import PrincipalLabels
from schemas.resolved_control_graph import ResolvedControlGraph

__all__ = [
    "ArtifactSchemaError",
    "load_contract_analysis",
    "load_control_snapshot",
    "load_control_tracking_plan",
    "load_effective_permissions",
    "load_principal_labels",
    "load_resolved_control_graph",
]


class ArtifactSchemaError(RuntimeError):
    """An artifact row exists but its body violates the declared schema."""

    def __init__(self, artifact_name: str, problems: list[str]) -> None:
        self.artifact_name = artifact_name
        self.problems = problems
        super().__init__(f"artifact {artifact_name!r} failed schema validation: {'; '.join(problems)}")


def _problem_list(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}" for err in exc.errors()]


def _load_typed(
    read: Any,
    session: Any,
    job_id: Any,
    name: str,
    adapter: TypeAdapter[Any],
) -> Any:
    raw = read(session, job_id, name)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ArtifactSchemaError(name, [f"expected a JSON object, got {type(raw).__name__}"])
    try:
        adapter.validate_python(raw)
    except ValidationError as exc:
        raise ArtifactSchemaError(name, _problem_list(exc)) from None
    return raw


_CONTRACT_ANALYSIS_ADAPTER = TypeAdapter(ContractAnalysis)
_CONTROL_SNAPSHOT_ADAPTER = TypeAdapter(ControlSnapshot)
_CONTROL_TRACKING_PLAN_ADAPTER = TypeAdapter(ControlTrackingPlan)
_EFFECTIVE_PERMISSIONS_ADAPTER = TypeAdapter(EffectivePermissions)
_PRINCIPAL_LABELS_ADAPTER = TypeAdapter(PrincipalLabels)
_RESOLVED_CONTROL_GRAPH_ADAPTER = TypeAdapter(ResolvedControlGraph)


def load_contract_analysis(read: Any, session: Any, job_id: Any) -> ContractAnalysis | None:
    """The static stage's dossier. ``None`` when the artifact is absent."""
    return _load_typed(read, session, job_id, "contract_analysis", _CONTRACT_ANALYSIS_ADAPTER)


def load_control_snapshot(read: Any, session: Any, job_id: Any) -> ControlSnapshot | None:
    """The resolution stage's live controller state."""
    return _load_typed(read, session, job_id, "control_snapshot", _CONTROL_SNAPSHOT_ADAPTER)


def load_control_tracking_plan(read: Any, session: Any, job_id: Any) -> ControlTrackingPlan | None:
    """The static stage's watch plan, consumed by resolution."""
    return _load_typed(read, session, job_id, "control_tracking_plan", _CONTROL_TRACKING_PLAN_ADAPTER)


def load_effective_permissions(read: Any, session: Any, job_id: Any) -> EffectivePermissions | None:
    """The policy stage's permission ledger."""
    return _load_typed(read, session, job_id, "effective_permissions", _EFFECTIVE_PERMISSIONS_ADAPTER)


def load_principal_labels(read: Any, session: Any, job_id: Any) -> PrincipalLabels | None:
    """The policy stage's principal labeling output."""
    return _load_typed(read, session, job_id, "principal_labels", _PRINCIPAL_LABELS_ADAPTER)


def load_resolved_control_graph(read: Any, session: Any, job_id: Any) -> ResolvedControlGraph | None:
    """The resolution stage's recursive control graph."""
    return _load_typed(read, session, job_id, "resolved_control_graph", _RESOLVED_CONTROL_GRAPH_ADAPTER)
