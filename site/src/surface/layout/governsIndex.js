// Authority address → governed contracts (Governs tab). Client-side so
// machine-only authorities (an analyzed timelock with no principal entry) still
// resolve.

import { functionName, isRoleConstant } from "../format.js";
import { entityKey } from "../entityKey.js";
import { collectDirectCallers } from "./controlGraph.js";

export function buildGovernsIndex(machines = [], functionData = {}) {
  // Iterate the chain-scoped machines rather than the cross-chain functionData
  // map, which would fold in another chain's authority.
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
        const authorityLc = caller.address;
        // Owning its own functions is the Control tab's job.
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
