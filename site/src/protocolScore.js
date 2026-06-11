import { bytecodeVerifiedAudits, isBytecodeVerifiedAudit } from "./auditCoverage.js";
import { isInertOneShot, isLiveOneShot } from "./oneShot.js";

// Generic protocol-posture score built from the control surface, upgrade
// state, and audit coverage. This intentionally avoids Slither high/medium
// counts: the grade is about who can do what, how much coordination/delay
// protects that power, and whether the running code is audit-matched.

const CONFIG_HINTS = [
  "set",
  "update",
  "config",
  "fee",
  "oracle",
  "admin",
  "authority",
  "role",
  "owner",
  "guardian",
  "operator",
];

const AXIS_DESCRIPTIONS = {
  authority: "Who can execute sensitive protocol actions and how protected that authority is.",
  audits: "How much deployed code is audit-matched with source and bytecode evidence.",
  upgrades: "How much of the protocol can change after deployment and how protected those changes are.",
  pause: "Whether emergency stops exist and whether resuming the system is sufficiently controlled.",
  safes: "How much sensitive power is protected by Safes or timelocks, including Safe threshold strength.",
  data: "How complete the analysis inputs are for source, functions, proxies, and resolved principals.",
};

const HIGH_RISK_ACTION_KINDS = new Set(["upgrade", "execution", "admin", "asset_out", "unpause", "timelock"]);

function clamp01(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function lower(value) {
  return String(value || "").toLowerCase();
}

function functionName(signature) {
  return lower(String(signature || "").split("(")[0]);
}

function weightedAverage(items, fallback = 0.5) {
  let total = 0;
  let weight = 0;
  for (const item of items) {
    const w = Number(item.weight);
    const v = Number(item.value);
    if (!Number.isFinite(w) || w <= 0 || !Number.isFinite(v)) continue;
    total += clamp01(v) * w;
    weight += w;
  }
  return weight > 0 ? clamp01(total / weight) : fallback;
}

function contractImportance(contract) {
  const usd = Number(contract?.total_usd || 0);
  const balanceWeight = usd > 0 ? Math.min(2, Math.log10(usd + 1) / 6) : 0;
  const role = lower(contract?.role);
  const roleWeight = ["value_handler", "token", "governance", "bridge"].includes(role) ? 0.45 : 0;
  const proxyWeight = contract?.is_proxy ? 0.2 : 0;
  return 1 + balanceWeight + roleWeight + proxyWeight;
}

function safeScore(details = {}) {
  const owners = asArray(details.owners);
  const n = owners.length || Number(details.owner_count || 0);
  const m = Number(details.threshold || 0);
  if (!Number.isFinite(m) || m <= 0 || !Number.isFinite(n) || n <= 0) return 0.55;

  const ratio = clamp01(m / n);
  const thresholdStrength = clamp01(m / 4);
  const ownerStrength = clamp01(n / 7);
  const score = 0.15 + ratio * 0.35 + thresholdStrength * 0.35 + ownerStrength * 0.15;
  return m <= 1 ? Math.min(score, 0.35) : clamp01(score);
}

function delayScore(seconds) {
  const delay = Number(seconds || 0);
  if (!Number.isFinite(delay) || delay <= 0) return 0.4;
  if (delay >= 7 * 86400) return 0.95;
  if (delay >= 3 * 86400) return 0.88;
  if (delay >= 86400) return 0.75;
  if (delay >= 6 * 3600) return 0.6;
  return 0.45;
}

function principalType(principal) {
  return lower(principal?.resolved_type || principal?.resolvedType || principal?.type || "unknown");
}

function pausePrincipalScore(principal) {
  const type = principalType(principal);
  if (type === "eoa") return 0.9;
  if (type === "safe") return Math.max(0.75, safeScore(principal.details));
  if (type === "timelock") return 0.45;
  if (type === "contract" || type === "proxy_admin") return 0.55;
  if (type === "zero") return 0.1;
  return 0.35;
}

function principalProtectionScore(principal, actionKind) {
  const type = principalType(principal);
  if (type === "safe") return safeScore(principal.details);
  if (type === "timelock") return delayScore(principal.details?.delay);
  if (type === "eoa") {
    if (actionKind === "pause") return 0.9;
    if (actionKind === "unpause") return 0.35;
    return 0.15;
  }
  if (type === "contract") return 0.5;
  if (type === "proxy_admin") return 0.45;
  if (type === "zero") return 0.1;
  return 0.3;
}

function isExactEmptyCapability(cap) {
  if (!cap || typeof cap !== "object") return false;
  if (cap.kind === "finite_set") {
    return cap.membership_quality === "exact" && Array.isArray(cap.members) && cap.members.length === 0;
  }
  const children = asArray(cap.children);
  if (cap.kind === "AND") return children.some(isExactEmptyCapability);
  if (cap.kind === "OR") return children.length > 0 && children.every(isExactEmptyCapability);
  return false;
}

function isResolvedEmptyFunction(fn) {
  return fn?.status === "resolved_empty" || isExactEmptyCapability(fn?.capability_expr);
}

function isResolvedEmptyAction(action) {
  return isResolvedEmptyFunction(action.fn);
}

function collectPrincipals(fn) {
  const out = [];
  if (fn?.direct_owner) out.push(fn.direct_owner);
  for (const grant of asArray(fn?.authority_roles)) {
    out.push(...asArray(grant.principals));
  }
  for (const controller of asArray(fn?.controllers)) {
    out.push(...asArray(controller.principals));
  }
  const seen = new Set();
  return out.filter((principal) => {
    const key = lower(principal?.address) || `${principalType(principal)}:${JSON.stringify(principal?.details || {})}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function classifyAction(fn) {
  const effects = new Set(asArray(fn?.effect_labels).map(lower));
  const name = functionName(fn?.function || fn?.abi_signature);
  const isUnpause = name.includes("unpause") || name.includes("resume") || name.includes("restart");
  const isPause = !isUnpause && name.includes("pause");
  const isUpgrade = effects.has("implementation_update") || name.includes("upgrade") || name.includes("implementation");

  if (isUpgrade) return { kind: "upgrade", severity: 1 };
  if (effects.has("arbitrary_external_call") || effects.has("delegatecall_execution")) return { kind: "execution", severity: 0.95 };
  if (effects.has("ownership_transfer") || effects.has("role_management") || effects.has("authority_update")) return { kind: "admin", severity: 0.88 };
  if (effects.has("hook_update")) return { kind: "config", severity: 0.78 };
  if (isUnpause) return { kind: "unpause", severity: 0.68 };
  if (effects.has("asset_send") || effects.has("burn")) return { kind: "asset_out", severity: 0.78 };
  if (isPause) return { kind: "pause", severity: 0.25 };
  if (effects.has("asset_pull") || effects.has("mint")) return { kind: "asset_in", severity: 0.5 };
  if (effects.has("timelock_operation")) return { kind: "timelock", severity: 0.62 };
  if (CONFIG_HINTS.some((hint) => name.includes(hint))) return { kind: "config", severity: 0.45 };
  return { kind: "other", severity: 0 };
}

function collectActions(contracts) {
  const actions = [];
  for (const contract of contracts) {
    const importance = contractImportance(contract);
    for (const fn of asArray(contract.functions)) {
      const action = classifyAction(fn);
      if (action.severity <= 0) continue;
      actions.push({
        contract,
        fn,
        kind: action.kind,
        severity: action.severity,
        weight: action.severity * importance,
        principals: collectPrincipals(fn),
      });
    }
  }
  return actions;
}

function actionProtectionScore(action) {
  if (action.principals.length === 0) {
    // A consumed one-shot initializer is inert — the open path can never be
    // taken again — so it is as protected as a no-active-principal action,
    // never scored as an exploitable open. A LIVE one-shot is the opposite:
    // anyone can call it right now, the worst principal-less state.
    if (isInertOneShot(action.fn)) return 0.95;
    if (isLiveOneShot(action.fn)) return 0;
    if (isResolvedEmptyAction(action)) return 0.95;
    return action.fn?.authority_public ? 0.1 : 0.35;
  }
  return Math.min(...action.principals.map((principal) => principalProtectionScore(principal, action.kind)));
}

function auditBriefScore(audit) {
  if (!audit) return 0;
  if (!isBytecodeVerifiedAudit(audit)) return 0;

  const proofKind = lower(audit.proof_kind);
  if (proofKind === "pre_fix_unpatched") return 0.25;
  return 1;
}

function coverageMaps(auditCoverage) {
  const byAddress = new Map();
  for (const row of asArray(auditCoverage?.coverage)) {
    const address = lower(row.address);
    if (address) byAddress.set(address, row);
  }
  return byAddress;
}

function contractAuditScore(contract, coverageByAddress) {
  const row = coverageByAddress.get(lower(contract?.address)) || coverageByAddress.get(lower(contract?.implementation));
  if (!row) return 0;
  const auditScores = bytecodeVerifiedAudits(row.audits).map(auditBriefScore);
  if (auditScores.length) return Math.max(...auditScores);
  return 0;
}

function authorityScore(actions) {
  return weightedAverage(
    actions.map((action) => ({
      value: actionProtectionScore(action),
      weight: action.weight,
    })),
    1,
  );
}

function safeguardScore(actions) {
  const rows = [];
  for (const action of actions) {
    const safeguards = action.principals.filter((principal) => ["safe", "timelock"].includes(principalType(principal)));
    if (safeguards.length === 0) {
      if (isResolvedEmptyAction(action)) {
        rows.push({ value: 0.95, weight: action.weight });
        continue;
      }
      if (action.severity > 0.4) rows.push({ value: 0.2, weight: action.weight });
      continue;
    }
    rows.push({
      value: Math.max(...safeguards.map((principal) => principalProtectionScore(principal, action.kind))),
      weight: action.weight,
    });
  }
  return weightedAverage(rows, actions.length ? 0.2 : 0.8);
}

function upgradeScore(contracts, actions, coverageByAddress) {
  const byContract = new Map();
  for (const action of actions) {
    if (action.kind !== "upgrade") continue;
    const key = lower(action.contract?.address);
    if (!key) continue;
    if (!byContract.has(key)) byContract.set(key, []);
    byContract.get(key).push(action);
  }

  return weightedAverage(
    contracts.map((contract) => {
      const upgradeActions = byContract.get(lower(contract.address)) || [];
      const upgradeable = Boolean(contract.is_proxy || contract.capabilities?.includes("upgrade") || upgradeActions.length);
      if (!upgradeable) return { value: 1, weight: contractImportance(contract) };

      const auth = weightedAverage(
        upgradeActions.map((action) => ({ value: actionProtectionScore(action), weight: action.weight })),
        0.3,
      );
      const audit = contractAuditScore(contract, coverageByAddress);
      const observability = (contract.implementation ? 0.5 : 0) + (contract.upgrade_count != null ? 0.5 : 0);
      return {
        value: Math.min(0.95, 0.15 + auth * 0.4 + audit * 0.3 + observability * 0.15),
        weight: contractImportance(contract),
      };
    }),
    1,
  );
}

function pauseScore(contracts, actions) {
  const byContract = new Map();
  for (const action of actions) {
    const key = lower(action.contract?.address);
    if (!key) continue;
    if (!byContract.has(key)) byContract.set(key, []);
    byContract.get(key).push(action);
  }

  return weightedAverage(
    contracts.map((contract) => {
      const contractActions = byContract.get(lower(contract.address)) || [];
      const pauseActions = contractActions.filter((action) => action.kind === "pause");
      const unpauseActions = contractActions.filter((action) => action.kind === "unpause");
      const important = contract.is_proxy || contract.total_usd > 0 || ["value_handler", "token", "governance", "bridge"].includes(lower(contract.role));

      if (pauseActions.length === 0 && unpauseActions.length === 0) {
        return { value: important ? 0.45 : 0.65, weight: contractImportance(contract) };
      }

      const pauseAccess = pauseActions.length
        ? Math.max(...pauseActions.map((action) => (
          action.principals.length ? Math.max(...action.principals.map(pausePrincipalScore)) : 0.3
        )))
        : 0.2;
      const unpauseControl = unpauseActions.length
        ? Math.min(...unpauseActions.map(actionProtectionScore))
        : 0.55;

      return {
        value: pauseAccess * 0.45 + unpauseControl * 0.55,
        weight: contractImportance(contract),
      };
    }),
    0.5,
  );
}

function auditScore(contracts, coverageByAddress) {
  return weightedAverage(
    contracts.map((contract) => ({
      value: contractAuditScore(contract, coverageByAddress),
      weight: contractImportance(contract),
    })),
    0,
  );
}

function dataConfidenceScore(contracts, actions) {
  const contractRows = contracts.map((contract) => {
    const checks = [
      contract.source_verified === true ? 1 : 0,
      asArray(contract.functions).length > 0 ? 1 : 0,
    ];
    if (contract.is_proxy) {
      checks.push(contract.implementation ? 1 : 0);
      checks.push(contract.upgrade_count != null ? 1 : 0);
    }
    return { value: checks.reduce((a, b) => a + b, 0) / checks.length, weight: contractImportance(contract) };
  });

  const principalRows = [];
  for (const action of actions) {
    for (const principal of action.principals) {
      const type = principalType(principal);
      let value = type && type !== "unknown" ? 0.75 : 0.15;
      if (type === "safe") {
        value = principal.details?.threshold && asArray(principal.details?.owners).length ? 1 : 0.55;
      } else if (type === "timelock") {
        value = principal.details?.delay ? 1 : 0.55;
      }
      principalRows.push({ value, weight: action.weight });
    }
  }

  return weightedAverage([...contractRows, ...principalRows], 0.5);
}

function normalizeInputs(companyOrContracts, hierarchyOrCoverage, maybeCoverage) {
  if (Array.isArray(companyOrContracts)) {
    return {
      contracts: companyOrContracts,
      hierarchy: asArray(hierarchyOrCoverage),
      auditCoverage: maybeCoverage,
      principals: [],
    };
  }
  const company = companyOrContracts || {};
  return {
    contracts: asArray(company.contracts),
    hierarchy: asArray(company.ownership_hierarchy || company.hierarchy),
    auditCoverage: hierarchyOrCoverage,
    principals: asArray(company.principals),
  };
}

function plural(count, singular, pluralWord = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralWord}`;
}

function verb(count, singular, pluralWord) {
  return count === 1 ? singular : pluralWord;
}

function shortAddress(address) {
  const text = String(address || "");
  return text.length > 12 ? `${text.slice(0, 6)}..${text.slice(-4)}` : text;
}

function contractName(contract) {
  return contract?.name || contract?.label || shortAddress(contract?.address || contract?.implementation) || "Unknown contract";
}

function functionLabel(fn) {
  return fn?.function || fn?.abi_signature || "unknown function";
}

function principalLabel(principal) {
  const type = principalType(principal);
  const address = shortAddress(principal?.address);
  if (type === "safe") {
    const threshold = principal?.details?.threshold;
    const owners = asArray(principal?.details?.owners).length || principal?.details?.owner_count;
    const quorum = threshold && owners ? ` ${threshold}/${owners}` : "";
    return `Safe${quorum}${address ? ` ${address}` : ""}`;
  }
  if (type === "timelock") {
    const delay = principal?.details?.delay;
    const days = Number.isFinite(Number(delay)) && Number(delay) > 0
      ? ` ${Math.round(Number(delay) / 86400)}d`
      : "";
    return `Timelock${days}${address ? ` ${address}` : ""}`;
  }
  return `${type.toUpperCase()}${address ? ` ${address}` : ""}`;
}

function actionExample(action, reason) {
  const principals = action.principals.map(principalLabel).join(", ");
  const address = action.contract?.address || action.contract?.implementation || "";
  const signature = action.fn?.function || action.fn?.abi_signature || "";
  const emptyMeta = isResolvedEmptyAction(action)
    ? "no active principal"
    : action.fn?.authority_public
      ? "permissionless"
      : "controller unresolved";
  return {
    title: `${contractName(action.contract)} · ${functionLabel(action.fn)}`,
    detail: reason,
    meta: [
      action.kind,
      principals ? `by ${principals}` : emptyMeta,
      shortAddress(address),
    ].filter(Boolean).join(" · "),
    contractAddress: address,
    functionSignature: signature,
    selector: action.fn?.selector || null,
  };
}

function contractExample(contract, reason, meta) {
  const address = contract?.address || contract?.implementation || "";
  return {
    title: contractName(contract),
    detail: reason,
    meta: [meta, shortAddress(address)].filter(Boolean).join(" · "),
    contractAddress: address,
    functionSignature: null,
    selector: null,
  };
}

function uniqueExamples(examples) {
  const seen = new Set();
  const out = [];
  for (const example of examples) {
    const key = `${example.title}|${example.detail}|${example.meta}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(example);
  }
  return out;
}

function principalKey(principal) {
  return lower(principal?.address) || `${principalType(principal)}:${JSON.stringify(principal?.details || {})}`;
}

function uniquePrincipals(actions, predicate) {
  const seen = new Set();
  const out = [];
  for (const action of actions) {
    for (const principal of action.principals) {
      if (predicate && !predicate(principal)) continue;
      const key = principalKey(principal);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(principal);
    }
  }
  return out;
}

function isHighRiskAction(action) {
  return HIGH_RISK_ACTION_KINDS.has(action.kind) || action.severity >= 0.75;
}

function isImportantContract(contract) {
  return Boolean(
    contract?.is_proxy
      || contract?.total_usd > 0
      || ["value_handler", "token", "governance", "bridge"].includes(lower(contract?.role)),
  );
}

function buildAuthorityTooltip(actions) {
  const sensitive = actions.filter(isHighRiskAction);
  const protectedActions = sensitive.filter((action) => actionProtectionScore(action) >= 0.65);
  const noActivePrincipal = sensitive.filter(isResolvedEmptyAction);
  const weakActions = sensitive.filter((action) => actionProtectionScore(action) < 0.65);
  const eoaControlled = sensitive.filter((action) => (
    action.kind !== "pause"
      && action.principals.some((principal) => principalType(principal) === "eoa")
  ));
  const unresolved = sensitive.filter((action) => (
    action.principals.length === 0 && !isResolvedEmptyAction(action) && !action.fn?.authority_public
  ));

  let positive = "No sensitive function-level authority was detected.";
  if (noActivePrincipal.length) {
    positive = `${plural(noActivePrincipal.length, "sensitive action")} currently ${verb(noActivePrincipal.length, "has", "have")} no active principal.`;
  } else if (sensitive.length) {
    positive = `${protectedActions.length}/${sensitive.length} sensitive actions have strong resolved protection.`;
  }

  let negative = "Remaining risk comes from lower-confidence contract or proxy-admin control paths.";
  if (eoaControlled.length) {
    negative = `${plural(eoaControlled.length, "sensitive action")} ${verb(eoaControlled.length, "still traces", "still trace")} to EOAs.`;
  } else if (unresolved.length) {
    negative = `${plural(unresolved.length, "sensitive action")} ${verb(unresolved.length, "has", "have")} unresolved controllers.`;
  } else if (noActivePrincipal.length === sensitive.length && sensitive.length > 0) {
    negative = "No sensitive authority is currently assigned to an active principal.";
  }

  const negativeExamples = weakActions.map((action) => {
    const eoas = action.principals.filter((principal) => principalType(principal) === "eoa");
    if (eoas.length && action.kind !== "pause") {
      return actionExample(action, "Sensitive authority is controlled by an EOA.");
    }
    if (action.principals.length === 0) {
      if (isLiveOneShot(action.fn)) {
        return actionExample(action, "This sensitive action is a live one-shot initializer — anyone can call it once until it is consumed.");
      }
      if (action.fn?.authority_public) {
        return actionExample(action, "This sensitive action is permissionless — callable by anyone.");
      }
      return actionExample(action, "No resolved controller was found for this sensitive action.");
    }
    return actionExample(action, "Controller protection is weaker than the target threshold.");
  });

  return {
    description: AXIS_DESCRIPTIONS.authority,
    positive,
    negative,
    negativeExamples: uniqueExamples(negativeExamples),
  };
}

function buildAuditsTooltip(contracts, coverageByAddress) {
  if (!contracts.length) {
    return {
      description: AXIS_DESCRIPTIONS.audits,
      positive: "No contracts are loaded.",
      negative: "Audit coverage cannot be evaluated without contract data.",
      negativeExamples: [],
    };
  }
  const auditRows = contracts.map((contract) => ({
    contract,
    score: contractAuditScore(contract, coverageByAddress),
  }));
  const strong = auditRows.filter((row) => row.score >= 0.75).length;
  const covered = auditRows.filter((row) => row.score > 0).length;
  const uncovered = auditRows.filter((row) => row.score <= 0).length;
  const weak = auditRows.filter((row) => row.score > 0 && row.score < 0.75).length;

  const positive = strong
    ? `${strong}/${contracts.length} contracts have bytecode-verified audit matches.`
    : covered
      ? `${covered}/${contracts.length} contracts have bytecode matches with unresolved audit findings.`
      : "No bytecode-verified audit matches are present yet.";
  const negative = uncovered
    ? `${uncovered}/${contracts.length} contracts have no bytecode-verified audit coverage.`
    : weak
      ? `${plural(weak, "contract")} have bytecode proof but unresolved fix evidence.`
      : "No bytecode-verified audit gap is visible in the current coverage data.";

  const negativeExamples = auditRows
    .filter((row) => row.score < 0.75)
    .map((row) => {
      if (row.score <= 0) {
        return contractExample(row.contract, "No proven bytecode/source match was found.", "audit score 0%");
      }
      return contractExample(
        row.contract,
        "Bytecode matched an audit commit, but deployed code appears pre-fix or otherwise unresolved.",
        `audit score ${Math.round(row.score * 100)}%`,
      );
    });

  return {
    description: AXIS_DESCRIPTIONS.audits,
    positive,
    negative,
    negativeExamples: uniqueExamples(negativeExamples),
  };
}

function buildUpgradesTooltip(contracts, actions) {
  if (!contracts.length) {
    return {
      description: AXIS_DESCRIPTIONS.upgrades,
      positive: "No contracts are loaded.",
      negative: "Upgrade posture cannot be evaluated without contract data.",
      negativeExamples: [],
    };
  }
  const upgradeActionByContract = new Set(
    actions
      .filter((action) => action.kind === "upgrade")
      .map((action) => lower(action.contract?.address))
      .filter(Boolean),
  );
  const upgradeable = contracts.filter((contract) => (
    contract.is_proxy
      || contract.capabilities?.includes("upgrade")
      || upgradeActionByContract.has(lower(contract.address))
  ));
  const nonUpgradeable = contracts.length - upgradeable.length;
  const upgradeActions = actions.filter((action) => action.kind === "upgrade");
  const protectedUpgradeActions = upgradeActions.filter((action) => actionProtectionScore(action) >= 0.65);

  const positive = nonUpgradeable
    ? `${nonUpgradeable}/${contracts.length} contracts appear non-upgradeable.`
    : `${protectedUpgradeActions.length}/${upgradeActions.length || 1} upgrade paths have stronger resolved controllers.`;
  const negative = upgradeable.length
    ? `${upgradeable.length}/${contracts.length} contracts remain upgradeable, so this axis is capped below perfect.`
    : "No upgradeability weakness is visible from the current data.";

  const weakUpgradeActions = upgradeActions.filter((action) => actionProtectionScore(action) < 0.65);
  const negativeExamples = [
    ...upgradeable.map((contract) => contractExample(
      contract,
      "This contract appears upgradeable, so implementation changes remain possible.",
      "upgradeable",
    )),
    ...weakUpgradeActions.map((action) => actionExample(
      action,
      "Upgrade authority is not protected strongly enough.",
    )),
  ];

  return {
    description: AXIS_DESCRIPTIONS.upgrades,
    positive,
    negative,
    negativeExamples: uniqueExamples(negativeExamples),
  };
}

function buildPauseTooltip(contracts, actions) {
  if (!contracts.length) {
    return {
      description: AXIS_DESCRIPTIONS.pause,
      positive: "No contracts are loaded.",
      negative: "Pause posture cannot be evaluated without contract data.",
      negativeExamples: [],
    };
  }
  const pauseActions = actions.filter((action) => action.kind === "pause");
  const unpauseActions = actions.filter((action) => action.kind === "unpause");
  const eoaPause = pauseActions.filter((action) => (
    action.principals.some((principal) => principalType(principal) === "eoa")
  )).length;
  const eoaUnpause = unpauseActions.filter((action) => (
    action.principals.some((principal) => principalType(principal) === "eoa")
  )).length;
  const contractsWithPause = new Set(pauseActions.map((action) => lower(action.contract?.address)));
  const importantWithoutPauseContracts = contracts.filter((contract) => (
    isImportantContract(contract) && !contractsWithPause.has(lower(contract.address))
  ));
  const importantWithoutPause = importantWithoutPauseContracts.length;

  const positive = eoaPause
    ? `${plural(eoaPause, "pause path")} can be triggered quickly by EOAs, which is useful for emergency stops.`
    : pauseActions.length
      ? `${plural(pauseActions.length, "pause path")} are present for emergency response.`
      : "The model treats pause-only authority as lower risk than unpause or upgrade power.";
  const negative = eoaUnpause
    ? `${plural(eoaUnpause, "unpause path")} ${verb(eoaUnpause, "is", "are")} EOA-controlled; resuming should be more coordinated.`
    : importantWithoutPause
      ? `${importantWithoutPause}/${contracts.length} important contracts do not expose detected pause controls.`
      : "No major unpause weakness is visible in the current control data.";

  const eoaUnpauseActions = unpauseActions.filter((action) => (
    action.principals.some((principal) => principalType(principal) === "eoa")
  ));
  const negativeExamples = [
    ...eoaUnpauseActions.map((action) => actionExample(
      action,
      "Unpause/resume authority is EOA-controlled.",
    )),
    ...importantWithoutPauseContracts.map((contract) => contractExample(
      contract,
      "Important contract has no detected pause function.",
      "pause missing",
    )),
  ];

  return {
    description: AXIS_DESCRIPTIONS.pause,
    positive,
    negative,
    negativeExamples: uniqueExamples(negativeExamples),
  };
}

function buildSafesTooltip(actions) {
  const sensitive = actions.filter(isHighRiskAction);
  const safes = uniquePrincipals(actions, (principal) => principalType(principal) === "safe");
  const timelocks = uniquePrincipals(actions, (principal) => principalType(principal) === "timelock");
  const strongSafes = safes.filter((safe) => safeScore(safe.details) >= 0.75);
  const unsafeguarded = sensitive.filter((action) => (
    !isResolvedEmptyAction(action)
      && !action.principals.some((principal) => ["safe", "timelock"].includes(principalType(principal)))
  ));
  const weakSafeActions = sensitive.filter((action) => (
    action.principals.some((principal) => (
      principalType(principal) === "safe" && safeScore(principal.details) < 0.75
    ))
  ));

  const positive = strongSafes.length
    ? `${plural(strongSafes.length, "strong Safe")} ${verb(strongSafes.length, "protects", "protect")} sensitive authority.`
    : timelocks.length
      ? `${plural(timelocks.length, "timelock")} ${verb(timelocks.length, "protects", "protect")} sensitive authority.`
      : "No strong Safe or timelock protection was detected.";
  const negative = unsafeguarded.length
    ? `${plural(unsafeguarded.length, "sensitive action")} ${verb(unsafeguarded.length, "lacks", "lack")} Safe or timelock protection.`
    : "No major Safe/timelock gap is visible for sensitive actions.";

  const negativeExamples = [
    ...unsafeguarded.map((action) => actionExample(
      action,
      "Sensitive action lacks Safe or timelock protection.",
    )),
    ...weakSafeActions.map((action) => actionExample(
      action,
      "Sensitive action uses a Safe, but the threshold/owner ratio is weak.",
    )),
  ];

  return {
    description: AXIS_DESCRIPTIONS.safes,
    positive,
    negative,
    negativeExamples: uniqueExamples(negativeExamples),
  };
}

function buildDataTooltip(contracts, actions) {
  if (!contracts.length) {
    return {
      description: AXIS_DESCRIPTIONS.data,
      positive: "No contracts are loaded.",
      negative: "Data confidence cannot be evaluated without contract data.",
      negativeExamples: [],
    };
  }
  const verified = contracts.filter((contract) => contract.source_verified === true).length;
  const withFunctions = contracts.filter((contract) => asArray(contract.functions).length > 0).length;
  const proxies = contracts.filter((contract) => contract.is_proxy);
  const incompleteProxies = proxies.filter((contract) => (
    !contract.implementation || contract.upgrade_count == null
  )).length;
  const unresolvedPrincipals = uniquePrincipals(actions, (principal) => principalType(principal) === "unknown").length;

  const positive = `${verified}/${contracts.length} contracts have verified source; ${withFunctions}/${contracts.length} have discovered callable functions.`;
  const negative = incompleteProxies
    ? `${incompleteProxies}/${proxies.length} proxies lack implementation or upgrade observability.`
    : unresolvedPrincipals
      ? `${plural(unresolvedPrincipals, "authority principal")} are unresolved.`
      : "Proxy and principal metadata is mostly present.";

  const negativeExamples = [
    ...contracts
      .filter((contract) => contract.source_verified !== true)
      .map((contract) => contractExample(contract, "Source is not marked verified.", "source unverified")),
    ...contracts
      .filter((contract) => asArray(contract.functions).length === 0)
      .map((contract) => contractExample(contract, "No callable functions were discovered.", "functions missing")),
    ...proxies
      .filter((contract) => !contract.implementation || contract.upgrade_count == null)
      .map((contract) => contractExample(contract, "Proxy lacks implementation or upgrade-count observability.", "proxy metadata incomplete")),
    ...uniquePrincipals(actions, (principal) => principalType(principal) === "unknown")
      .map((principal) => ({
        title: principalLabel(principal),
        detail: "Authority principal could not be resolved to EOA, Safe, timelock, or contract.",
        meta: shortAddress(principal?.address),
      })),
  ];

  return {
    description: AXIS_DESCRIPTIONS.data,
    positive,
    negative,
    negativeExamples: uniqueExamples(negativeExamples),
  };
}

function buildAxisTooltip(axis, context) {
  const { contracts, actions, coverageByAddress } = context;
  if (axis.key === "authority") return buildAuthorityTooltip(actions);
  if (axis.key === "audits") return buildAuditsTooltip(contracts, coverageByAddress);
  if (axis.key === "upgrades") return buildUpgradesTooltip(contracts, actions);
  if (axis.key === "pause") return buildPauseTooltip(contracts, actions);
  if (axis.key === "safes") return buildSafesTooltip(actions);
  if (axis.key === "data") return buildDataTooltip(contracts, actions);
  return {
    description: "How this part of the protocol posture contributes to the composite score.",
    positive: "This category has enough data to be scored.",
    negative: "Some residual risk may remain outside the current analysis data.",
    negativeExamples: [],
  };
}

export function computeProtocolScore(companyOrContracts, hierarchyOrCoverage, maybeCoverage) {
  const { contracts, auditCoverage } = normalizeInputs(companyOrContracts, hierarchyOrCoverage, maybeCoverage);
  const actions = collectActions(contracts);
  const coverageByAddress = coverageMaps(auditCoverage);
  const context = { contracts, actions, coverageByAddress };

  const axes = [
    { key: "authority", label: "Authority", value: authorityScore(actions), weight: 0.25 },
    { key: "audits", label: "Audit", value: auditScore(contracts, coverageByAddress), weight: 0.22 },
    { key: "upgrades", label: "Upgrades", value: upgradeScore(contracts, actions, coverageByAddress), weight: 0.18 },
    { key: "pause", label: "Pause", value: pauseScore(contracts, actions), weight: 0.14 },
    { key: "safes", label: "Safes", value: safeguardScore(actions), weight: 0.13 },
    { key: "data", label: "Data", value: dataConfidenceScore(contracts, actions), weight: 0.08 },
  ].map((axis) => ({
    ...axis,
    value: clamp01(axis.value),
    display: `${Math.round(clamp01(axis.value) * 100)}%`,
    tooltip: buildAxisTooltip({ ...axis, value: clamp01(axis.value) }, context),
  }));

  const totalWeight = axes.reduce((sum, axis) => sum + axis.weight, 0);
  const composite = Math.round((axes.reduce((sum, axis) => sum + axis.value * axis.weight, 0) / totalWeight) * 100);
  const grade = composite >= 85 ? "a" : composite >= 70 ? "b" : composite >= 55 ? "c" : composite >= 40 ? "d" : "f";
  return { axes, composite, grade };
}
