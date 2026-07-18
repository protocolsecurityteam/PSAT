// Single-source-of-truth selection reducer for the Surface page.
//
// State is KEYS ONLY (addresses + a guard key + sub-mode flags); every entity
// object is derived per render through the entity index, so a snapshot can
// never go stale (the class of bug the old selectedMachine/selectedPrincipal
// useState pair produced). All selection transitions and their invariants live
// in the reducer, not at the seven former call sites.

import { useCallback, useEffect, useMemo, useReducer, useRef } from "react";

import { machineFunctions } from "./lane.js";
import { entityKey } from "./entityKey.js";
import { resolveEntity } from "./layout/entities.js";

const INITIAL = { selection: null, guardKey: null, radar: null, focus: null };

// Camera one-shot: a monotonic counter (NOT Date.now) so identical repeat
// focuses still register as a new request for the canvas effect.
function bumpFocus(state, address) {
  return { address: address ? address.toLowerCase() : null, key: (state.focus?.key || 0) + 1 };
}

// A clear (deselect / reset) drops the focus *address* but must PRESERVE the
// monotonic counter — otherwise the key rolls back to 0 and re-selecting the
// same entity produces the identical key the canvas already consumed, so the
// camera never re-centers (FocusOnNode dedupes on the key).
function clearedFocus(state) {
  return state.focus ? { address: null, key: state.focus.key } : null;
}

function reducer(state, action) {
  switch (action.type) {
    case "select": {
      // select(null) === full clear (pane-click / deselect path).
      if (action.address == null) return { ...INITIAL, focus: clearedFocus(state) };
      const address = action.address.toLowerCase();
      // Entity change always clears the guard + radar sub-mode. Applied
      // unconditionally (matches the old handleSelectMachine/Principal, which
      // cleared on every select, even a re-select of the same entity).
      return {
        selection: { address, hint: action.hint ?? null },
        guardKey: null,
        radar: null,
        focus: bumpFocus(state, address),
      };
    }
    case "guard": {
      // Opening a guard exits radar mode (matches today's handleSelectGuard).
      return { ...state, guardKey: action.key ?? null, radar: null };
    }
    case "radar": {
      // Contract selection + radar flyout sub-mode; guardKey == the example fn.
      const address = action.address ? action.address.toLowerCase() : null;
      return {
        selection: address ? { address, hint: null } : null,
        guardKey: action.functionKey ?? null,
        radar: { functionKey: action.functionKey ?? null },
        focus: address ? bumpFocus(state, address) : state.focus,
      };
    }
    case "focusPreview": {
      // Browsing / contract-pager: bump the camera one-shot ONLY. Never
      // touches selection, guard, or radar.
      return { ...state, focus: bumpFocus(state, action.address) };
    }
    case "reset":
      return { ...INITIAL, focus: clearedFocus(state) };
    default:
      return state;
  }
}

// Derive the fnView for a guard key. Guard keys are globally unique
// (`${contract.address}:${selector||function}`, buildMachines.js), so the
// owning contract is the key's prefix — look it up in the index and scan its
// functions. Addresses never contain ':' and neither do selectors/signatures,
// so splitting on the first ':' is unambiguous.
function guardFromKey(index, guardKey, chain = "ethereum") {
  if (!guardKey || !index) return null;
  const sep = guardKey.indexOf(":");
  if (sep < 0) return null;
  const contractAddress = guardKey.slice(0, sep).toLowerCase();
  const machine = index.get(entityKey(chain, contractAddress))?.machine;
  if (!machine) return null;
  return machineFunctions(machine).find((fn) => fn.key === guardKey) || null;
}

// entityIndex: Map<addrLc, {address, machine|null, principal|null}> (built by
//   buildEntityIndex). machines: the machine list resolveEntity uses to
//   synthesize controls for off-index navigate targets. companyName: switching
//   it clears ALL selection state.
export function useSurfaceSelection({ entityIndex, machines = [], companyName, chain = "ethereum" } = {}) {
  const [state, dispatch] = useReducer(reducer, INITIAL);

  // Clear everything on a real company change. Skip the first mount so a
  // URL-restore select() (fired from a later, machines-gated effect) survives.
  const firstCompany = useRef(true);
  useEffect(() => {
    if (firstCompany.current) {
      firstCompany.current = false;
      return;
    }
    dispatch({ type: "reset" });
  }, [companyName]);

  const select = useCallback((address, opts = {}) => {
    if (address == null) {
      dispatch({ type: "select", address: null });
      return;
    }
    dispatch({ type: "select", address: address.toLowerCase(), hint: opts.hint });
  }, []);

  const guard = useCallback((key) => dispatch({ type: "guard", key }), []);
  const radar = useCallback(
    (address, functionKey) => dispatch({ type: "radar", address, functionKey }),
    [],
  );
  const focusPreview = useCallback((address) => dispatch({ type: "focusPreview", address }), []);

  const selectedEntity = useMemo(
    () =>
      state.selection
        ? resolveEntity(entityIndex, state.selection.address, {
            machines,
            hint: state.selection.hint,
            chain,
          })
        : null,
    [entityIndex, machines, state.selection, chain],
  );

  // At most one facet is ever non-null: the machine card is strictly richer, so
  // it wins whenever the entity has one; a principal card renders only for a
  // principal-only entity. No stored view can contradict the entity's facets.
  const selectedMachine = selectedEntity?.machine ?? null;
  const selectedPrincipal = selectedEntity?.machine ? null : selectedEntity?.principal ?? null;
  const selectedGuard = useMemo(
    () => guardFromKey(entityIndex, state.guardKey, chain),
    [entityIndex, state.guardKey, chain],
  );

  return {
    // raw keyed state
    selection: state.selection,
    guardKey: state.guardKey,
    radarSelection: state.radar,
    focus: state.focus, // { address, key } — the canvas camera one-shot
    // derived-per-render entities (staleness impossible)
    selectedEntity,
    selectedMachine,
    selectedPrincipal,
    selectedGuard,
    focusedAddress: state.focus?.address ?? null,
    // actions (stable identities)
    select,
    guard,
    radar,
    focusPreview,
  };
}
