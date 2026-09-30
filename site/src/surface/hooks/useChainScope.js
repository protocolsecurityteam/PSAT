import { useCallback, useMemo, useState } from "react";

import { coalesceChain } from "../entityKey.js";
import { deriveAvailableChains, defaultChainFor, pickActiveChain } from "../chainScope.js";

// The page renders one chain. `chosenChain` is seeded once from
// ?chain=, read synchronously so the first render is already scoped.
export function useChainScope({ companyData, embedded }) {
  const [chosenChain, setChosenChain] = useState(() => {
    if (embedded || typeof window === "undefined") return null;
    const ch = new URLSearchParams(window.location.search).get("chain");
    return ch ? coalesceChain(ch) : null;
  });

  // Derived from the payload, never a static list. Single-chain protocols get
  // one entry and no switcher.
  const availableChains = useMemo(
    () => deriveAvailableChains(companyData?.contracts),
    [companyData]
  );
  // Kept out of the URL so default links stay clean.
  const defaultChain = useMemo(() => defaultChainFor(availableChains), [availableChains]);
  const activeChain = useMemo(
    () => pickActiveChain(availableChains, chosenChain),
    [availableChains, chosenChain]
  );
  const isMultichain = availableChains.length > 1;

  // The chain half of a switch; the component adds selection clears, since
  // `select` doesn't exist at this hook's call site.
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
