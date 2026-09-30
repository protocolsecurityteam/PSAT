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


def is_primitive_scalar_read_spec(read_spec: object) -> bool:
    """Whether the slot holds a primitive scalar (uint/int/bool/bytes/string/enum).

    Such slots are kept out of the address snapshot, where a uint like ``_minDelay`` would mint a phantom EOA. Address,
    mapping, array and struct slots return False.
    """
    if not isinstance(read_spec, dict):
        return False
    type_kind = str(read_spec.get("type_kind") or "").strip().lower()
    if type_kind:
        return type_kind == "primitive"
    # Older specs may omit type_kind.
    type_name = str(read_spec.get("type") or "").strip().lower()
    return type_name.startswith(("uint", "int", "bool", "bytes", "string", "enum"))


def _is_runtime_resolvable_controller(target: object) -> bool:
    """A controller is tracked if pollable (address-like state via eth_call) or event-watchable (writers emit logs).

    Non-address vars flow only through the event pathway.
    """
    if not isinstance(target, dict):
        return False
    kind = target.get("kind")
    if kind == "role_identifier":
        return True
    if kind == "state_variable":
        if _is_address_like_read_spec(target.get("read_spec")):
            return True
        # Non-address vars earn inclusion via event coverage; semantics come later from effect_tags.
        return bool(target.get("associated_events"))
    if kind == "external_contract":
        return _is_external_contract_read_spec(target.get("read_spec"))
    return False


def build_control_tracking_plan(analysis: ContractAnalysis) -> ControlTrackingPlan:
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

        tracked: TrackedController = {
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
        # Absent stays absent for pre-provenance artifacts.
        provenance = target.get("authority_provenance")
        if provenance:
            tracked["authority_provenance"] = provenance
        tracked_controllers.append(tracked)

    return {
        "schema_version": "0.1",
        "contract_address": contract_address,
        "contract_name": contract_name,
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": sorted(tracked_controllers, key=lambda item: item["label"]),
    }
