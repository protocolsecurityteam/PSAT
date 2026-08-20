import { useCallback, useMemo, useState } from "react";

import { coalesceChain } from "../entityKey.js";
import { deriveAvailableChains, defaultChainFor, pickActiveChain } from "../chainScope.js";

// Active-chain scope for the whole page (multichain inv. 13). The Surface
// renders exactly one chain at a time; `chosenChain` is the user's explicit
// pick (via the switcher), seeded once from the shareable ?chain= URL param.
// null = follow the default chain. Read synchronously at mount so the first
// render is already scoped correctly (no effect race with the selection
// restore, which is gated on the resulting machines).
export function useChainScope({ companyData, embedded }) {
  const [chosenChain, setChosenChain] = useState(() => {
    if (embedded || typeof window === "undefined") return null;
    const ch = new URLSearchParams(window.location.search).get("chain");
    return ch ? coalesceChain(ch) : null;
  });

  // Chains this protocol actually has contracts on — derived from the loaded
  // payload (only contracts carry a chain; NULL coalesces to ethereum), never a
  // static list. The switcher offers exactly these; a single-chain protocol
  // yields one entry and no switcher. See chainScope.js. Declared before
  // functionData so the inline-functions map can be chain-scoped too.
  const availableChains = useMemo(
    () => deriveAvailableChains(companyData?.contracts),
    [companyData]
  );
  // The chain the page falls back to with no explicit pick — kept out of the
  // URL so single-chain and default-chain views have clean links.
  const defaultChain = useMemo(() => defaultChainFor(availableChains), [availableChains]);
  // An unknown/typo'd/off-protocol ?chain= degrades to the default (never a
  // blank canvas) — pickActiveChain enforces that.
  const activeChain = useMemo(
    () => pickActiveChain(availableChains, chosenChain),
    [availableChains, chosenChain]
  );
  const isMultichain = availableChains.length > 1;

  // The chain half of a chain switch: scope state + the shareable ?chain=
  // param write (?chain omitted for the default chain so those links stay
  // clean; the old chain's selection params cleared alongside). The component
  // composes this with its selection/overlay clears in handleSelectChain —
  // `select` does not exist yet at this hook's call site.
  const rescopeChain = useCallback((name) => {
    setChosenChain(name);
    if (embedded || typeof window === "undefined") return;
    const url = new URL(window.location.href);
    if (name && name !== defaultChain) url.searchParams.set("chain", name);
    else url.searchParams.delete("chain");
    url.searchParams.delete("sel");
    url.searchParams.delete("score");
    url.searchParams.delete("fn");
    window.history.replaceState({}, "", url.toString());
  }, [embedded, defaultChain]);

  return { availableChains, activeChain, isMultichain, rescopeChain };
}
