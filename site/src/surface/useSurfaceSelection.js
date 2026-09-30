// The Surface selection reducer. State holds keys only; entities are derived
// per render through the entity index, so nothing goes stale.

import { useCallback, useEffect, useMemo, useReducer, useRef } from "react";

import { machineFunctions } from "./lane.js";
import { entityKey } from "./entityKey.js";
import { resolveEntity } from "./layout/entities.js";

const INITIAL = { selection: null, guardKey: null, radar: null, focus: null, reach: null };

// Score-page click-throughs can reach a contract transitively; the direct host
// isn't derivable from the target, so it's stored.
function reachFrom(action) {
  const hosts = (Array.isArray(action.reachedFrom) ? action.reachedFrom : action.reachedFrom ? [action.reachedFrom] : [])
    .map((a) => String(a || "").toLowerCase())
    .filter(Boolean);
  return hosts.length ? { hosts } : null;
}

// A counter, not Date.now, so repeated focuses still register.
function bumpFocus(state, address) {
  return { address: address ? address.toLowerCase() : null, key: (state.focus?.key || 0) + 1 };
}

// Keep the counter: rolling back to 0 repeats a key FocusOnNode already
// consumed, and the camera never re-centers.
function clearedFocus(state) {
  return state.focus ? { address: null, key: state.focus.key } : null;
}

function reducer(state, action) {
  switch (action.type) {
    case "select": {
      if (action.address == null) return { ...INITIAL, focus: clearedFocus(state) };
      const address = action.address.toLowerCase();
      // Always clears guard and radar, even on re-selecting the same entity.
      return {
        selection: { address, hint: action.hint ?? null },
        guardKey: null,
        radar: null,
        reach: reachFrom(action),
        focus: bumpFocus(state, address),
      };
    }
    case "guard": {
      return { ...state, guardKey: action.key ?? null, radar: null };
    }
    case "radar": {
      // guardKey is the example function; callerAddress is dropped when no
      // function resolved (a chip without a row would claim an unshown pair).
      const address = action.address ? action.address.toLowerCase() : null;
      const functionKey = action.functionKey ?? null;
      return {
        selection: address ? { address, hint: null } : null,
        guardKey: functionKey,
        reach: address ? reachFrom(action) : null,
        radar: {
          functionKey,
          callerAddress: functionKey && action.callerAddress ? action.callerAddress.toLowerCase() : null,
        },
        focus: address ? bumpFocus(state, address) : state.focus,
      };
    }
    case "focusPreview": {
      // Camera only; never touches selection.
      return { ...state, focus: bumpFocus(state, action.address) };
    }
    case "reset":
      return { ...INITIAL, focus: clearedFocus(state) };
    default:
      return state;
  }
}

// Guard keys are `${address}:${selector||function}`; neither part contains ':',
// so split on the first.
function guardFromKey(index, guardKey, chain = "ethereum") {
  if (!guardKey || !index) return null;
  const sep = guardKey.indexOf(":");
  if (sep < 0) return null;
  const contractAddress = guardKey.slice(0, sep).toLowerCase();
  const machine = index.get(entityKey(chain, contractAddress))?.machine;
  if (!machine) return null;
  return machineFunctions(machine).find((fn) => fn.key === guardKey) || null;
}

export function useSurfaceSelection({ entityIndex, machines = [], companyName, chain = "ethereum" } = {}) {
  const [state, dispatch] = useReducer(reducer, INITIAL);

  // Skip the first mount so a URL-restore select() survives.
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
    dispatch({ type: "select", address: address.toLowerCase(), hint: opts.hint, reachedFrom: opts.reachedFrom });
  }, []);

  const guard = useCallback((key) => dispatch({ type: "guard", key }), []);
  const radar = useCallback(
    (address, functionKey, callerAddress = null, reachedFrom = null) =>
      dispatch({ type: "radar", address, functionKey, callerAddress, reachedFrom }),
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

  // The machine card wins whenever the entity has one.
  const selectedMachine = selectedEntity?.machine ?? null;
  const selectedPrincipal = selectedEntity?.machine ? null : selectedEntity?.principal ?? null;
  const selectedGuard = useMemo(
    () => guardFromKey(entityIndex, state.guardKey, chain),
    [entityIndex, state.guardKey, chain],
  );

  return {
    selection: state.selection,
    guardKey: state.guardKey,
    radarSelection: state.radar,
    reachHosts: state.reach?.hosts || null,
    focus: state.focus,
    selectedEntity,
    selectedMachine,
    selectedPrincipal,
    selectedGuard,
    focusedAddress: state.focus?.address ?? null,
    select,
    guard,
    radar,
    focusPreview,
  };
}
