// Invert per-function authority into an authority-address → governed-contracts
// index — the "authority OUT" view that mirrors the Control tab's "authority
// IN". Pure — no React.
//
// For every contract's functions, each direct caller (direct_owner,
// authority_roles principals, controllers principals — via collectDirectCallers)
// becomes an authority that governs that function on that contract. Keyed by
// lowercased authority address so a non-principal authority (e.g. an analyzed
// timelock that has no entry in the principals list) still resolves its
// governed set — the reason the inversion is client-side rather than read off
// principal.controls_detail.

import { functionName, isRoleConstant } from "../format.js";
import { entityKey } from "../entityKey.js";
import { collectDirectCallers } from "./controlGraph.js";

export function buildGovernsIndex(machines = [], functionData = {}) {
  // authority addr (lc) → (governed contract addr (lc) → {contractAddress,
  // contractName, functions: Set<name>})
  //
  // Iterate the machines (already scoped to the active chain) and read each
  // one's functions by its (chain, address) key, rather than walking the raw
  // functionData map — that map is composite-keyed across every chain, so a
  // bare walk would fold another chain's same-address authority in (inv. 13).
  const byAuthority = new Map();
  for (const machine of machines) {
    const contractLc = String(machine?.address || "").toLowerCase();
    if (!contractLc) continue;
    const contractName = machine.name || null;
    const fns = functionData[entityKey(machine.chain, machine.address)];
    for (const fn of fns || []) {
      const signature = fn.function || fn.abi_signature || "";
      const name = functionName(signature);
      if (!name || name === "?" || isRoleConstant(name)) continue;
      for (const caller of collectDirectCallers(fn)) {
        const authorityLc = caller.address; // collectDirectCallers lowercases
        // Governs = authority over OTHER contracts; a contract owning its own
        // functions is the Control tab's job.
        if (authorityLc === contractLc) continue;
        let governed = byAuthority.get(authorityLc);
        if (!governed) {
          governed = new Map();
          byAuthority.set(authorityLc, governed);
        }
        let entry = governed.get(contractLc);
        if (!entry) {
          entry = { contractAddress: contractLc, contractName, functions: new Set() };
          governed.set(contractLc, entry);
        }
        entry.functions.add(name);
      }
    }
  }

  const index = new Map();
  for (const [authorityLc, governed] of byAuthority) {
    const rows = [...governed.values()]
      .map((entry) => ({
        contractAddress: entry.contractAddress,
        contractName: entry.contractName,
        functions: [...entry.functions].sort(),
      }))
      .sort((a, b) =>
        String(a.contractName || a.contractAddress).localeCompare(
          String(b.contractName || b.contractAddress),
        ),
      );
    index.set(authorityLc, rows);
  }
  return index;
}
