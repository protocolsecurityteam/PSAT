// Contract → "machine" view: functions grouped into control / ops / inflow /
// outflow lanes.

import { functionName, isRoleConstant } from "../format.js";
import { entityKey } from "../entityKey.js";
import {
  compactActionSummary,
  laneForFunction,
  lanePriority,
  toneForFunction,
} from "../lane.js";
import {
  buildControlNodeIndex,
  buildIndirectCallerContext,
  collectDirectCallers,
  collectIndirectCallers,
} from "./controlGraph.js";
import { guardSummary } from "./guardSummary.js";

export function buildMachines(companyData, functionData, { functionsLoading = false, activeChain = null } = {}) {
  // Flags passthrough timelocks (their own node is typed "timelock").
  const nodeInfo = buildControlNodeIndex(companyData);
  const indirectCtx = buildIndirectCallerContext(companyData, activeChain);
  return companyData.contracts
    .map((contract) => {
      const rawFunctions = (functionData[entityKey(contract.chain, contract.address)] || [])
        .filter((fn) => !isRoleConstant(functionName(fn.function)));
      const lanes = { top: [], left: [], right: [], ops: [] };

      for (const fn of rawFunctions) {
        const lane = laneForFunction(fn);
        const direct = collectDirectCallers(fn);
        const indirect = collectIndirectCallers(direct, indirectCtx);
        lanes[lane].push({
          key: `${contract.address}:${fn.selector || fn.function}`,
          contractName: contract.name,
          contractAddress: contract.address,
          name: functionName(fn.function),
          signature: fn.function || fn.abi_signature || "?",
          lane,
          tone: toneForFunction(fn, lane),
          action: compactActionSummary(fn),
          effectLabels: fn.effect_labels || [],
          claims: fn.claims || [],
          guard: guardSummary(fn, companyData),
          // `principals` is who can call now; `indirectPrincipals` are
          // agency-reach standing above contract-typed callers (never used to
          // claim call rights).
          principals: direct,
          indirectPrincipals: indirect,
          authorityPublic: Boolean(fn.authority_public),
        });
      }

      for (const lane of Object.keys(lanes)) {
        lanes[lane].sort((left, right) => {
          const score = lanePriority({ effect_labels: left.effectLabels, claims: left.claims })
            - lanePriority({ effect_labels: right.effectLabels, claims: right.claims });
          if (score !== 0) return score;
          return left.name.localeCompare(right.name);
        });
      }

      const totalFunctions = lanes.top.length + lanes.ops.length + lanes.left.length + lanes.right.length;
      const tlNode = nodeInfo.get((contract.address || "").toLowerCase());
      const isTimelock = tlNode?.type === "timelock";
      return {
        ...contract,
        totalFunctions,
        lanes,
        // Typed timelock but Safe-owned; flagged for the card and Timelocks
        // filter.
        isTimelock,
        timelockDelay: isTimelock ? tlNode?.details?.delay ?? null : null,
      };
    })
    .filter((machine) =>
      machine.totalFunctions > 0
      || machine.is_proxy
      // Every analyzed contract has totalFunctions=0 until /functions lands;
      // don't hide them meanwhile.
      || (functionsLoading && machine.contract_id != null)
    )
    .sort((left, right) => {
      if (right.totalFunctions !== left.totalFunctions) return right.totalFunctions - left.totalFunctions;
      return String(left.name || "").localeCompare(String(right.name || ""));
    });
}
