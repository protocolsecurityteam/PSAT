/**
 * RiskSurface — function-centric view of the protocol.
 * Groups all functions across all contracts by impact severity,
 * shows the full auth chain for each.
 */

import { useEffect, useMemo, useState } from "react";

function shortAddr(addr) {
  if (!addr || addr.length < 12) return addr || "";
  return addr.slice(0, 6) + ".." + addr.slice(-4);
}

const ROLE_COLORS = {
  PROPOSER: "#00D4AA", EXECUTOR: "#6366F1", CANCELLER: "#FF6B35",
  ADMIN: "#6366F1", ORACLE: "#00D4AA", PAUSER: "#F59E0B", UPGRADER: "#EC4899",
};

function roleColor(role) {
  if (!role) return "#777";
  const upper = role.toUpperCase();
  for (const [key, color] of Object.entries(ROLE_COLORS)) {
    if (upper.includes(key)) return color;
  }
  return "#777";
}

function Pill({ label, color }) {
  return (
    <span style={{
      padding: "2px 7px", borderRadius: 6, background: color + "18",
      color, fontSize: 9, fontWeight: 600, fontFamily: "JetBrains Mono, monospace", whiteSpace: "nowrap",
    }}>{label}</span>
  );
}

// ── Impact categories with severity ordering ─────────────────────────────────

const IMPACT_CATEGORIES = [
  {
    key: "impl_update",
    label: "Implementation Upgrades",
    description: "Can replace all contract logic via delegatecall. Highest impact — changes everything.",
    severity: "critical",
    color: "#EC4899",
    match: (effects, name) => effects.includes("implementation_update") || effects.includes("delegatecall_execution") || name.includes("upgrade"),
  },
  {
    key: "ownership",
    label: "Ownership Transfers",
    description: "Can change who controls the contract. Irreversible if renounced.",
    severity: "critical",
    color: "#FF6B35",
    match: (effects, name) => effects.includes("ownership_transfer") || name.includes("transferOwnership") || name.includes("renounceOwnership"),
  },
  {
    key: "role_mgmt",
    label: "Role & Access Management",
    description: "Can grant or revoke roles, changing who can call gated functions.",
    severity: "high",
    color: "#6366F1",
    match: (effects, name) => effects.includes("role_management") || name.includes("Role") || name.includes("Admin") || name.includes("admin"),
  },
  {
    key: "pause",
    label: "Pause / Emergency",
    description: "Can halt protocol operations. Affects deposits, staking, withdrawals.",
    severity: "high",
    color: "#F59E0B",
    match: (effects, name) => effects.includes("pause_toggle") || name.toLowerCase().includes("pause"),
  },
  {
    key: "asset",
    label: "Asset Movement",
    description: "Can send assets out of the contract.",
    severity: "high",
    color: "#FF6B35",
    match: (effects, name) => effects.includes("asset_send") || name.includes("transfer") || name.includes("withdraw") || name.includes("send"),
  },
  {
    key: "external",
    label: "External Contract Calls",
    description: "Calls into other contracts (EigenLayer, Lido, etc). Can trigger state changes elsewhere.",
    severity: "medium",
    color: "#00D4AA",
    match: (effects, name) => effects.includes("external_contract_call") || effects.includes("timelock_operation"),
  },
  {
    key: "config",
    label: "Configuration Changes",
    description: "Writes config variables — thresholds, addresses, parameters.",
    severity: "low",
    color: "#777",
    match: () => true, // catch-all
  },
];

const SEVERITY_COLORS = {
  critical: "#EC4899",
  high: "#FF6B35",
  medium: "#F59E0B",
  low: "#777",
};

// ── Build auth chain description ─────────────────────────────────────────────

function buildAuthChain(fn) {
  const steps = [];
  const owner = fn.direct_owner;
  const controllers = fn.controllers || [];

  if (owner) {
    const ownerType = owner.resolved_type || "unknown";
    const delay = owner.details?.delay;
    if (ownerType === "timelock" && delay) {
      steps.push({ label: "Safe 0x1a2b..", color: "#00D4AA", type: "safe" });
      steps.push({ label: `${Math.round(delay / 86400)}d delay`, color: "#FF6B35", type: "delay" });
    }
    steps.push({ label: `${ownerType} ${shortAddr(owner.address)}`, color: "#FF6B35", type: "owner" });
  }

  for (const ctrl of controllers) {
    if (ctrl.label === "roleRegistry") {
      // Determine which role
      const fnName = fn.function || "";
      let role = "ADMIN";
      if (fnName.toLowerCase().includes("pause")) role = "PAUSER";
      else if (fnName.toLowerCase().includes("upgrade")) role = "UPGRADER";
      else if (fnName.toLowerCase().includes("execute") || fnName.toLowerCase().includes("oracle") || fnName.toLowerCase().includes("validator")) role = "ORACLE_EXEC";

      if (steps.length === 0) {
        // Role-only gating (no owner)
        steps.push({ label: `${role} holder`, color: roleColor(role), type: "role" });
      }
      steps.push({ label: `roleRegistry`, color: "#6366F1", type: "registry" });
    } else if (ctrl.label && !ctrl.label.includes("owner")) {
      steps.push({ label: ctrl.label, color: "#00D4AA", type: "contract" });
    }
  }

  if (steps.length === 0) {
    steps.push({ label: "unknown", color: "#777", type: "unknown" });
  }

  return steps;
}

// ── Function row component ───────────────────────────────────────────────────

function FunctionRow({ fn, contractName, category }) {
  const [expanded, setExpanded] = useState(false);
  const authChain = useMemo(() => buildAuthChain(fn), [fn]);
  const name = fn.function?.replace(/\(.*/, "()") || fn.function || "?";
  const fullSig = fn.function || fn.abi_signature || "?";
  const action = fn.action_summary || "";

  return (
    <div className="rs-fn-row" onClick={() => setExpanded(!expanded)}>
      <div className="rs-fn-main">
        <span className="rs-fn-dot" style={{ background: category.color }} />
        <span className="rs-fn-name">{name}</span>
        <span className="rs-fn-contract">{contractName}</span>
        <div className="rs-fn-chain">
          {authChain.map((step, i) => (
            <span key={i} className="rs-chain-step">
              {i > 0 && <span className="rs-chain-arrow">→</span>}
              <Pill label={step.label} color={step.color} />
            </span>
          ))}
        </div>
      </div>
      {expanded && (
        <div className="rs-fn-detail">
          <div className="rs-fn-sig">{fullSig}</div>
          {action && <div className="rs-fn-action">{action}</div>}
          {fn.effect_labels?.length > 0 && (
            <div className="rs-fn-effects">
              {fn.effect_labels.map((e, i) => (
                <Pill key={i} label={e} color={e.includes("impl") ? "#EC4899" : e.includes("owner") ? "#FF6B35" : e.includes("pause") ? "#F59E0B" : "#777"} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────────────────

export default function RiskSurface({ companyName }) {
  const [companyData, setCompanyData] = useState(null);
  const [functionData, setFunctionData] = useState({});
  const [error, setError] = useState(null);
  const [selectedAddr, setSelectedAddr] = useState(null);

  useEffect(() => {
    if (!companyName) return;
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch(`/api/company/${encodeURIComponent(companyName)}`);
        if (!res.ok) throw new Error("Failed to load");
        const data = await res.json();
        if (cancelled) return;
        setCompanyData(data);

        const fnData = {};
        for (const contract of data.contracts) {
          if (!contract.analysis_job_id) continue;
          try {
            const lookupId = contract.implementation_analysis_job_id || contract.analysis_job_id;
            const fnRes = await fetch(`/api/analyses/${lookupId}/artifact/effective_permissions`);
            if (fnRes.ok) {
              const perms = await fnRes.json();
              fnData[contract.address] = perms.functions || [];
            }
          } catch {}
        }
        if (cancelled) return;
        setFunctionData(fnData);
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [companyName]);

  // Build categorized function list
  const categories = useMemo(() => {
    if (!companyData) return [];
    const contractMap = {};
    for (const c of companyData.contracts) {
      contractMap[c.address] = c.name;
    }

    const result = IMPACT_CATEGORIES.map((cat) => ({ ...cat, functions: [] }));

    for (const [addr, fns] of Object.entries(functionData)) {
      const contractName = contractMap[addr] || shortAddr(addr);
      for (const fn of fns) {
        const effects = fn.effect_labels || [];
        const name = fn.function || "";

        // Find first matching category
        let placed = false;
        for (const cat of result) {
          if (cat.key !== "config" && cat.match(effects, name)) {
            cat.functions.push({ fn, contractName, addr });
            placed = true;
            break;
          }
        }
        if (!placed) {
          result[result.length - 1].functions.push({ fn, contractName, addr });
        }
      }
    }

    return result.filter((cat) => cat.functions.length > 0);
  }, [companyData, functionData]);

  // "What can this address do?" lookup
  const principals = useMemo(() => {
    if (!companyData) return [];
    const addrSet = new Map();

    for (const fns of Object.values(functionData)) {
      for (const fn of fns) {
        if (fn.direct_owner?.address) {
          const a = fn.direct_owner.address.toLowerCase();
          if (!addrSet.has(a)) addrSet.set(a, { address: a, type: fn.direct_owner.resolved_type || "unknown", functions: [] });
          addrSet.get(a).functions.push(fn);
        }
        for (const ctrl of fn.controllers || []) {
          for (const p of ctrl.principals || []) {
            if (p.address) {
              const a = p.address.toLowerCase();
              if (!addrSet.has(a)) addrSet.set(a, { address: a, type: p.resolved_type || "unknown", functions: [] });
              addrSet.get(a).functions.push(fn);
            }
          }
        }
      }
    }

    return [...addrSet.values()].sort((a, b) => b.functions.length - a.functions.length);
  }, [companyData, functionData]);

  // Stats
  const totalFns = Object.values(functionData).reduce((s, fns) => s + fns.length, 0);
  const criticalFns = categories.filter((c) => c.severity === "critical").reduce((s, c) => s + c.functions.length, 0);
  const highFns = categories.filter((c) => c.severity === "high").reduce((s, c) => s + c.functions.length, 0);

  if (error) return <p className="empty">Failed to load: {error}</p>;
  if (!companyData) return <p className="empty">Loading risk surface...</p>;

  return (
    <div className="rs-container">
      {/* Header */}
      <div className="rs-header">
        <div>
          <h2 className="rs-title">{companyName}</h2>
          <div className="rs-subtitle">Risk Surface — {totalFns} gated functions across {companyData.contracts.length} contracts</div>
        </div>
        <div className="rs-stats">
          <div className="rs-stat">
            <span className="rs-stat-value" style={{ color: "#EC4899" }}>{criticalFns}</span>
            <span className="rs-stat-label">critical</span>
          </div>
          <div className="rs-stat">
            <span className="rs-stat-value" style={{ color: "#FF6B35" }}>{highFns}</span>
            <span className="rs-stat-label">high</span>
          </div>
          <div className="rs-stat">
            <span className="rs-stat-value" style={{ color: "#FFFFFF" }}>{totalFns}</span>
            <span className="rs-stat-label">total</span>
          </div>
        </div>
      </div>

      <div className="rs-layout">
        {/* Left: Principal sidebar */}
        <div className="rs-principals">
          <div className="rs-principals-hdr">What can this address do?</div>
          {principals.slice(0, 12).map((p) => (
            <button
              key={p.address}
              className={`rs-principal-row ${selectedAddr === p.address ? "active" : ""}`}
              onClick={() => setSelectedAddr(selectedAddr === p.address ? null : p.address)}
            >
              <Pill label={p.type} color={p.type === "timelock" ? "#FF6B35" : p.type === "contract" ? "#6366F1" : "#00D4AA"} />
              <span className="rs-principal-addr">{shortAddr(p.address)}</span>
              <span className="rs-principal-count">{p.functions.length} fns</span>
            </button>
          ))}
        </div>

        {/* Right: Function categories */}
        <div className="rs-categories">
          {categories.map((cat) => {
            // If an address is selected, filter to only functions reachable by that address
            let fns = cat.functions;
            if (selectedAddr) {
              fns = fns.filter(({ fn }) => {
                if (fn.direct_owner?.address?.toLowerCase() === selectedAddr) return true;
                for (const ctrl of fn.controllers || []) {
                  for (const p of ctrl.principals || []) {
                    if (p.address?.toLowerCase() === selectedAddr) return true;
                  }
                }
                return false;
              });
            }
            if (fns.length === 0) return null;

            return (
              <div key={cat.key} className="rs-category">
                <div className="rs-category-header" style={{ borderLeftColor: cat.color }}>
                  <div className="rs-category-title">
                    <span style={{ color: cat.color }}>{cat.label}</span>
                    <Pill label={cat.severity} color={SEVERITY_COLORS[cat.severity]} />
                    <Pill label={`${fns.length} functions`} color="#777" />
                  </div>
                  <div className="rs-category-desc">{cat.description}</div>
                </div>
                <div className="rs-category-fns">
                  {fns.map(({ fn, contractName }, i) => (
                    <FunctionRow key={i} fn={fn} contractName={contractName} category={cat} />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
