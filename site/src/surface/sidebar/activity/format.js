import { shortenAddress } from "../../../shared/format.js";
import { tagsForEvent, witnessedSlot } from "./eventClass.js";

// Relative/scalar formatters and per-write-target renderers; classification
// lives in eventClass.js.

export function relativeTime(iso, now = Date.now()) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.round(d / 30);
  return `${mo}mo ago`;
}

function shortHash(h) {
  if (!h || typeof h !== "string") return "—";
  if (h.length <= 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-4)}`;
}

function fmtSeconds(sec) {
  if (sec == null) return null;
  const n = Number(sec);
  if (!Number.isFinite(n)) return null;
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${Math.round(n / 60)}m`;
  if (n < 86400) return `${Math.round(n / 3600)}h`;
  return `${Math.round(n / 86400)}d`;
}

function arrowSub(from, to) {
  return from && to ? `${shortenAddress(from)} → ${shortenAddress(to)}` : null;
}

// Truncating a uint would state a different value.
function shortenIfHex(value) {
  const s = String(value);
  return /^0x[0-9a-f]{40}$/i.test(s) ? shortenAddress(s) : s;
}

// Token decimals are unknown, so no unit: big integers go scientific, with a
// relative delta.
const DECIMAL_INT = /^-?\d+$/;
const COMPACT_OVER_DIGITS = 12;

function isLongInt(s) {
  return DECIMAL_INT.test(s) && s.replace("-", "").length > COMPACT_OVER_DIGITS;
}

function fmtScalar(value) {
  const s = String(value);
  if (!isLongInt(s)) return shortenIfHex(s);
  const neg = s.startsWith("-");
  const digits = neg ? s.slice(1) : s;
  return `${neg ? "-" : ""}${digits[0]}.${digits.slice(1, 5)}e${digits.length - 1}`;
}

function pctDelta(before, after) {
  const b = String(before);
  const a = String(after);
  if (!DECIMAL_INT.test(b) || !DECIMAL_INT.test(a)) return null;
  const bi = BigInt(b);
  const ai = BigInt(a);
  if (bi === 0n) return null;
  const base = bi < 0n ? -bi : bi;
  const milliPct = ((ai - bi) * 100000n) / base;
  const sign = ai >= bi ? "+" : "-";
  if (milliPct === 0n) return ai === bi ? null : `${sign}<0.001%`;
  const abs = milliPct < 0n ? -milliPct : milliPct;
  return `${sign}${abs / 1000n}.${(abs % 1000n).toString().padStart(3, "0")}%`;
}

function diffSub(before, after) {
  if (before == null || after == null) return null;
  const b = String(before);
  const a = String(after);
  const compacted = isLongInt(b) || isLongInt(a);
  const delta = compacted ? pctDelta(b, a) : null;
  return `${fmtScalar(b)} → ${fmtScalar(a)}${delta ? ` (${delta})` : ""}`;
}

// Renderers are ``(data, event_type) → { title, sub }``; event_type lets paired
// events swap verbs. Underscore targets are activity events with no slot.

// Mirrors ``safe_exec.status`` (services/monitoring/enrichment.py); unknown
// statuses render verbatim.
const SAFE_EXEC_STATUS_SUB = {
  not_top_level_call: "not a direct execTransaction on this Safe — inner call not witnessed",
  over_budget: "not decoded this pass (transaction budget)",
  args_undecodable: "execTransaction arguments did not decode",
  ambiguous_attribution:
    "this Safe executed more than once in this transaction — which call these arguments describe is not witnessed",
};

const SAFE_EXEC_BATCH_REASON = {
  malformed_payload: "payload did not decode",
  nested_payload_undecodable: "a nested payload did not decode",
  nested_depth_exceeded: "nested deeper than the decoder expands",
};

// The type list goes in the tooltip. Selectors stay raw rather than get an
// invented name.
function fnDisplay(signature) {
  const s = String(signature || "");
  const paren = s.indexOf("(");
  return paren > 0 ? `${s.slice(0, paren)}()` : s || null;
}

// Display-only; never changes what's claimed or its salience.
function addrDisplay(addr, opts) {
  if (!addr) return null;
  const name = opts?.nameFor ? opts.nameFor(addr) : null;
  return name || shortenAddress(addr);
}

// `onGraph` is null (not false) when no resolver was supplied. Off-graph
// targets render the full address.
function callTarget(addr, opts, prep = "on") {
  if (!addr) return null;
  const label = opts?.nameFor ? opts.nameFor(addr) : null;
  return { address: addr, label, prep, onGraph: opts?.nameFor ? Boolean(label) : null };
}

// Plain text because the feed row is itself a <button>.
export function targetText(target) {
  if (!target?.address) return null;
  const prep = target.prep || "on";
  if (target.label) return `${prep} ${target.label}`;
  const short = shortenAddress(target.address);
  return target.onGraph === false ? `${prep} ${short} (not on graph)` : `${prep} ${short}`;
}

const RENDER_BY_WRITE_TARGET = {
  owner: (d) => {
    const renounced = d.new_owner && /^0x0+$/i.test(d.new_owner);
    return {
      title: renounced ? "Ownership renounced" : "Ownership transferred",
      sub: arrowSub(d.old_owner, d.new_owner),
    };
  },
  pendingOwner: (d) => ({
    title: "Ownership transfer initiated",
    sub: arrowSub(d.old_owner, d.new_owner),
  }),
  authority: (d) => ({
    title: "Authority updated",
    sub: arrowSub(d.old_authority, d.new_authority),
  }),
  implementation: (d) => ({
    title: "Implementation upgraded",
    sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
  }),
  pendingImplementation: (d) => ({
    title: "Pending implementation queued",
    sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
  }),
  beacon: (d) => ({
    title: "Beacon upgraded",
    sub: d.beacon ? `beacon ${shortenAddress(d.beacon)}` : null,
  }),
  facets: () => ({ title: "Diamond cut (facets changed)", sub: null }),
  admin: (d) => ({
    title: "Proxy admin changed",
    sub: d.new_admin ? `new admin ${shortenAddress(d.new_admin)}` : null,
  }),
  paused: (d, type) => ({
    title: type === "paused" ? "Contract paused" : "Contract unpaused",
    sub: d.account
      ? `${type === "paused" ? "paused" : "unpaused"} by ${shortenAddress(d.account)}`
      : null,
  }),
  _roles: (d, type) => {
    const granted = type === "role_granted";
    return {
      title: granted ? "Role granted" : "Role revoked",
      sub: d.account
        ? `${granted ? "to" : "from"} ${shortenAddress(d.account)}${d.sender ? ` by ${shortenAddress(d.sender)}` : ""}`
        : null,
    };
  },
  owners: (d, type) => ({
    title: type === "signer_added" ? "Safe signer added" : "Safe signer removed",
    sub: d.owner ? shortenAddress(d.owner) : null,
  }),
  threshold: (d) => ({
    title: "Safe threshold changed",
    sub: d.threshold != null ? `new threshold ${d.threshold}` : null,
  }),
  min_delay: (d) => {
    const oldD = fmtSeconds(d.old_delay);
    const newD = fmtSeconds(d.new_delay);
    return {
      title: "Timelock delay changed",
      sub: oldD && newD ? `${oldD} → ${newD}` : null,
    };
  },
  _safe_op: (d, type, opts) => {
    const executed = type === "safe_tx_executed";
    // Never fetched: the Safe-internal hash is all that was witnessed.
    const unenriched = {
      title: executed ? "Safe transaction executed" : "Safe transaction reverted",
      sub: d.safe_tx_hash
        ? `safeTxHash ${shortHash(d.safe_tx_hash)}${d.payment ? ` · payment ${d.payment} wei` : ""}`
        : null,
    };
    const se = d.safe_exec;
    if (!se || typeof se !== "object") return unenriched;

    // A stated decode gap renders as one, not as the bare hash.
    if (se.status !== "decoded") {
      return { ...unenriched, sub: SAFE_EXEC_STATUS_SUB[se.status] || `not decoded (${se.status})` };
    }

    if (se.batch_status === "undecodable") {
      const why = SAFE_EXEC_BATCH_REASON[se.batch_status_reason];
      const parts = ["delegatecall"];
      if (why) parts.push(why);
      return {
        title: `${executed ? "MultiSend batch" : "Reverted MultiSend batch"} — did not decode`,
        target: callTarget(se.to, opts),
        sub: parts.join(" · "),
      };
    }

    const batch = Array.isArray(se.batch) ? se.batch : null;
    const head = batch && batch.length ? batch[0] : null;
    const call = head || se;
    // The row shows the name; the full signature is in the tooltip. Selectors
    // stay raw.
    const signature = head ? head.signature : se.target_function?.signature;
    const name = fnDisplay(signature) || call.selector || null;
    const title = executed
      ? name
        ? `Executed ${name}`
        : "Safe transaction executed"
      : `Reverted: ${name || "Safe transaction"}`;

    const parts = [];
    // Only delegatecall is worth ink; unknown operations say so.
    if (call.operation === 1 || call.operation_label === "delegatecall") {
      parts.push(
        se.multisend_recognized === false && !batch
          ? "delegatecall — not a pinned MultiSend"
          : "delegatecall",
      );
    }
    if (se.value && se.value !== "0") parts.push(`value ${se.value} wei`);
    if (batch && batch.length > 1) parts.push(`+${batch.length - 1} more in batch`);
    return {
      title,
      titleDetail: signature || null,
      target: callTarget(call.to, opts),
      sub: parts.length ? parts.join(" · ") : null,
    };
  },
  _safe_module_op: (d, type, opts) => ({
    title: type === "safe_module_executed" ? "Safe module executed" : "Safe module reverted",
    target: callTarget(d.module, opts, "via module"),
    sub: null,
  }),
  _timelock_op: (d, type, opts) => {
    const scheduled = type === "timelock_scheduled";
    const signature = d.target_function?.signature || null;
    const name = fnDisplay(signature) || (d.selector ? `sel ${d.selector}` : null);
    const delay = fmtSeconds(d.delay);
    const subParts = [];
    if (scheduled && delay) subParts.push(`delay ${delay}`);
    return {
      title: `Timelock ${scheduled ? "scheduled" : "executed"}${name ? ` ${name}` : " operation"}`,
      titleDetail: signature,
      target: callTarget(d.target, opts),
      sub: subParts.length ? subParts.join(" · ") : null,
    };
  },
};

// ``changed_master_copy`` writes ``implementation`` like a proxy upgrade but
// reads "Safe singleton swapped".
const TITLE_OVERRIDES = {
  changed_master_copy: "Safe singleton (mastercopy) swapped",
};

// Event row → { title, sub }; unknown types fall back to a generic shape.
// `opts.nameFor` is display-only.
export function decodeEvent(evt, opts = undefined) {
  const d = evt?.data || {};
  const type = evt?.event_type || "unknown";

  // No decoder or tags. Older rows use the shorter keys.
  if (type === "state_changed_poll") {
    const field = d.field || "state";
    const rawBefore = d.old != null ? d.old : d.old_value;
    const rawAfter = d.new != null ? d.new : d.new_value;
    return {
      title: `${field} changed (polled)`,
      sub: diffSub(rawBefore, rawAfter),
    };
  }

  // Handled before the tag table: the proven payload is the claim, and the
  // emitter's write set must not re-title it.
  const witnessed = witnessedSlot(type);
  if (witnessed?.stem === "value") {
    return {
      title: `${witnessed.slot} changed (verified)`,
      sub: diffSub(d.old, d.new),
    };
  }
  if (witnessed?.stem === "member") {
    const key = d.key != null ? shortenIfHex(d.key) : null;
    // Without a direction, name no verb.
    const verb = { add: "added", remove: "removed", set: "set" }[d.direction] || "changed";
    const parts = [];
    if (key) parts.push(key);
    if (d.value != null) parts.push(`= ${shortenIfHex(d.value)}`);
    return {
      title: `${witnessed.slot} entry ${verb}`,
      sub: parts.length ? parts.join(" ") : null,
    };
  }

  // First matching write target wins; tags emit writes in priority order.
  const tags = tagsForEvent(evt);
  const writes = tags.writes || [];
  for (const wt of writes) {
    const renderer = RENDER_BY_WRITE_TARGET[wt];
    if (renderer) {
      const result = renderer(d, type, opts);
      if (TITLE_OVERRIDES[type]) {
        result.title = TITLE_OVERRIDES[type];
      }
      return result;
    }
  }

  const entries = Object.entries(d)
    .filter(([k]) => !["contract_address", "contract_type", "chain", "effect_tags"].includes(k))
    .slice(0, 3);
  const sub = entries.length
    ? entries
        .map(
          ([k, v]) =>
            `${k}: ${typeof v === "string" && v.startsWith("0x") ? shortenAddress(v) : v}`,
        )
        .join(" · ")
    : null;

  // Keep the stem verbatim: only `controller_changed:` claims an authority
  // binding moved (event_topics._resolve_event_type).
  const terminal = /^(controller|state)_changed:(.+)$/.exec(type);
  if (terminal) {
    const slot = terminal[2].split(":").pop();
    return {
      title: terminal[1] === "controller" ? `Controller changed: ${slot}` : `State changed: ${slot}`,
      sub,
    };
  }

  return { title: type.replace(/_/g, " "), sub };
}

// Returns [{ k, v, tone }], tone "ok" | "warn" | "muted" | null.
export function stateRows(contract) {
  const s = contract?.last_known_state || {};
  const cfg = contract?.monitoring_config || {};
  const rows = [];

  if (contract?.contract_type === "safe") {
    if (s.threshold != null) {
      rows.push({ k: "Threshold", v: String(s.threshold), tone: null });
    }
  }
  if ("owner" in s) {
    const renounced = /^0x0+$/i.test(s.owner || "");
    rows.push({
      k: "Owner",
      v: renounced ? "renounced" : shortenAddress(s.owner),
      tone: renounced ? "ok" : null,
    });
  }
  if ("paused" in s) {
    rows.push({
      k: "Paused",
      v: s.paused ? "yes" : "no",
      tone: s.paused ? "warn" : "ok",
    });
  }
  if ("implementation" in s) {
    rows.push({ k: "Impl", v: shortenAddress(s.implementation), tone: null });
  }
  if ("admin" in s) {
    rows.push({ k: "Admin", v: shortenAddress(s.admin), tone: null });
  }
  if ("min_delay" in s) {
    const f = fmtSeconds(s.min_delay) || `${s.min_delay}s`;
    rows.push({ k: "Min delay", v: f, tone: null });
  }

  // Shown even with no state yet, so the row doesn't look broken.
  const watching = [];
  if (cfg.watch_upgrades) watching.push("upgrades");
  if (cfg.watch_ownership) watching.push("owner");
  if (cfg.watch_pause) watching.push("pause");
  if (cfg.watch_roles) watching.push("roles");
  if (cfg.watch_safe_signers || cfg.watch_signers) watching.push("safe");
  if (cfg.watch_timelock) watching.push("timelock");
  // `watch_state` is a phantom flag; the polling plan is the witness.
  if (cfg.watch_state || (Array.isArray(cfg.polling_plan) && cfg.polling_plan.length > 0)) watching.push("state");
  if (watching.length === 0) watching.push("nothing");
  rows.push({ k: "Watching", v: watching.join(" · "), tone: "muted" });

  return rows;
}

// Youngest updated_at across contracts (bumped every scan) → { tone, label }.
export function scannerHealth(contracts, now = Date.now()) {
  if (!contracts || contracts.length === 0) {
    return { tone: "muted", label: "no contracts" };
  }
  const stamps = contracts
    .map((c) => c.updated_at)
    .filter(Boolean)
    .map((s) => new Date(s).getTime())
    .filter(Number.isFinite);
  if (stamps.length === 0) return { tone: "muted", label: "no scan yet" };
  const youngest = Math.max(...stamps);
  const ageS = Math.round((now - youngest) / 1000);
  // Hourly cadence: 2× is lagging, 5× stalled.
  let tone = "ok";
  if (ageS > 3600 * 2) tone = "warn";
  if (ageS > 3600 * 5) tone = "err";
  return { tone, label: `scanned ${relativeTime(new Date(youngest).toISOString(), now)}` };
}
