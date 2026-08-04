// Group functions per contract into the four lanes (control / ops / inflow /
// outflow), sort within each lane, and project the contract → "machine" view
// the canvas + sidebar consume. Pure — no React.

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
  // Node-type index over every contract's control_graph; used to flag
  // passthrough timelock contracts (their own node is typed "timelock").
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
          // `principals` is the direct-callers list — exactly who can fire
          // msg.sender on this function right now. `indirectPrincipals` are
          // the principals whose witnessed-agency reach can stand on a
          // contract-typed direct caller — secondary context in the inspector
          // (never used to claim call rights).
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
        // Passthrough timelock contracts: typed "timelock" in the control
        // graph but owned by a Safe (still credited via primary_for). Flagged
        // so the card + Timelocks filter can identify them.
        isTimelock,
        timelockDelay: isTimelock ? tlNode?.details?.delay ?? null : null,
      };
    })
    .filter((machine) =>
      machine.totalFunctions > 0
      || machine.is_proxy
      // While /functions is in flight, every analyzed contract has
      // totalFunctions=0 — don't hide them from the canvas in that
      // window or only proxies render.
      || (functionsLoading && machine.contract_id != null)
    )
    .sort((left, right) => {
      if (right.totalFunctions !== left.totalFunctions) return right.totalFunctions - left.totalFunctions;
      return String(left.name || "").localeCompare(String(right.name || ""));
    });
}
