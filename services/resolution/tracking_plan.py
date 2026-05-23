"""Compile runtime control-tracking plans from structured contract analysis."""

from __future__ import annotations

from schemas.contract_analysis import ContractAnalysis
from schemas.control_tracking import ControlTrackingPlan, EventWatch, PollingFallback, TrackedController


def _is_address_like_read_spec(read_spec: object) -> bool:
    if not isinstance(read_spec, dict):
        return True
    type_kind = str(read_spec.get("type_kind") or "").strip().lower()
    if type_kind:
        return type_kind in {"address", "contract"}
    type_name = str(read_spec.get("type") or "").strip().lower()
    if not type_name:
        return True
    return _is_external_contract_read_spec(read_spec)


def _is_external_contract_read_spec(read_spec: object) -> bool:
    if not isinstance(read_spec, dict):
        return True
    type_kind = str(read_spec.get("type_kind") or "").strip().lower()
    if type_kind:
        return type_kind in {"address", "contract"}
    type_name = str(read_spec.get("type") or "").strip().lower()
    if not type_name:
        return True
    if type_name in {"address", "address payable"}:
        return True
    if "mapping" in type_name or "[" in type_name:
        return False
    if type_name.startswith(("bool", "uint", "int", "string", "bytes")):
        return False
    return True


def _is_runtime_resolvable_controller(target: object) -> bool:
    """A controller earns inclusion in the tracking plan if it's either
    pollable (address-like state we can read via eth_call) OR
    event-watchable (any state var whose writers emit logs we can
    subscribe to).

    The poller filters by type_kind itself (it only handles a fixed
    set of slot shapes), so non-address vars surfaced here flow purely
    through the event pathway. This lets us track Governor proposal
    mappings, role-bitmap slots, threshold ints, etc. by listening to
    their emitted events without needing per-shape polling support.
    """
    if not isinstance(target, dict):
        return False
    kind = target.get("kind")
    if kind == "role_identifier":
        return True
    if kind == "state_variable":
        if _is_address_like_read_spec(target.get("read_spec")):
            return True
        # Non-address state vars (mappings, uints, bools, structs) earn
        # inclusion via event coverage. Any writer that emits a log is a
        # signal worth subscribing to — semantics get classified later
        # from the emitter's effect_tags.
        return bool(target.get("associated_events"))
    if kind == "external_contract":
        return _is_external_contract_read_spec(target.get("read_spec"))
    return False


def build_control_tracking_plan(analysis: ContractAnalysis) -> ControlTrackingPlan:
    """Build an event-first, polling-backed watch plan from contract analysis output."""
    contract_address = analysis["subject"]["address"]
    contract_name = analysis["subject"]["name"]

    tracked_controllers: list[TrackedController] = []
    for target in analysis.get("controller_tracking", []):
        if not _is_runtime_resolvable_controller(target):
            continue
        associated_events = list(target.get("associated_events", []))
        writer_functions = [item["function"] for item in target.get("writer_functions", [])]

        event_watch: EventWatch | None = None
        if associated_events:
            event_watch = {
                "transport": "wss_logs",
                "contract_address": contract_address,
                "events": associated_events,
                "writer_functions": writer_functions,
            }

        cadence = "state_only"
        if target["tracking_mode"] == "event_plus_state":
            cadence = "realtime_confirm"
        elif target["tracking_mode"] == "manual_review":
            cadence = "periodic_reconciliation"

        polling_fallback: PollingFallback = {
            "contract_address": contract_address,
            "polling_sources": list(target.get("polling_sources", [])),
            "cadence": cadence,
            "notes": list(target.get("notes", [])),
        }

        tracked_controllers.append(
            {
                "controller_id": target["controller_id"],
                "label": target["label"],
                "source": target["source"],
                "kind": target["kind"],
                "read_spec": target.get("read_spec"),
                "tracking_mode": target["tracking_mode"],
                "event_watch": event_watch,
                "polling_fallback": polling_fallback,
                "notes": list(target.get("notes", [])),
            }
        )

    return {
        "schema_version": "0.1",
        "contract_address": contract_address,
        "contract_name": contract_name,
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": sorted(tracked_controllers, key=lambda item: item["label"]),
    }
