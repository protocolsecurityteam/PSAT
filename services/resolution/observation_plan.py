"""Compile runtime control-tracking plans from structured contract analysis."""

from __future__ import annotations

from collections.abc import Mapping

from schemas.observations import ControllerInstruction, EventWatch, ObservationPlan, PollingFallback
from schemas.static_facts import Controller, StaticFacts


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
    """True when the slot holds a primitive scalar (uint/int/bool/bytes/string/
    enum) — a number that is never an address.

    Used to keep such slots out of the *resolved-address value snapshot*
    (``observe_controllers``), where coercing a scalar to a 20-byte address
    mints phantom EOA principals (a uint ``_minDelay == 864000`` becomes
    ``0x…0d2f00``, has no code, classifies "eoa"). Address/contract slots are
    real principals; mapping/array/struct slots are enumerated elsewhere (a
    bare getter reverts on them) — all of those return False so they pass
    through untouched.
    """
    if not isinstance(read_spec, dict):
        return False
    type_kind = str(read_spec.get("type_kind") or "").strip().lower()
    if type_kind:
        return type_kind == "primitive"
    # Older specs may omit type_kind; fall back to the Solidity type string.
    type_name = str(read_spec.get("type") or "").strip().lower()
    return type_name.startswith(("uint", "int", "bool", "bytes", "string", "enum"))


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


def build_observation_plan(analysis: StaticFacts) -> ObservationPlan:
    """Build an event-first, polling-backed watch plan from contract analysis output."""
    return compile_observation_plan(
        analysis["subject"]["address"],
        analysis["subject"]["name"],
        {target["controller_id"]: target for target in analysis["controller_tracking"]},
    )


def compile_observation_plan(
    contract_address: str, contract_name: str, controllers: Mapping[str, Controller]
) -> ObservationPlan:
    """Compile the same controller instructions for root and recursive analysis."""
    tracked_controllers: list[ControllerInstruction] = []
    for controller_id, target in controllers.items():
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

        tracked: ControllerInstruction = {
            "controller_id": controller_id,
            "label": target["label"],
            "source": target["source"],
            "kind": target["kind"],
            "read_spec": target.get("read_spec"),
            "tracking_mode": target["tracking_mode"],
            "event_watch": event_watch,
            "polling_fallback": polling_fallback,
            "notes": list(target.get("notes", [])),
        }
        # Absent stays absent: a plan built from a pre-provenance analysis
        # artifact must not claim either value.
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
