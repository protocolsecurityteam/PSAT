// Pure URL parsing/building used by App + page-level components.
// Pure JS — no React imports.

export const TABS = ["summary", "permissions", "principals", "graph", "dependencies", "upgrades", "raw"];

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

export function formatJson(value) {
  return JSON.stringify(value, null, 2);
}

export function normalizeTab(tab) {
  return TABS.includes(tab) ? tab : "summary";
}

export function isAddress(value) {
  return ADDRESS_RE.test(String(value || "").trim());
}

export function parseLocationPath(pathname) {
  const segments = String(pathname || "/")
    .split("/")
    .filter(Boolean)
    .map((segment) => decodeURIComponent(segment));

  if (!segments.length) {
    return { mode: "default", value: null, tab: "summary" };
  }

  if (segments[0] === "monitor") {
    return { mode: "monitor", value: null, tab: "summary" };
  }

  if (segments[0] === "company" && segments[1]) {
    const validCompanyTabs = ["overview", "surface", "graph", "risk", "monitoring", "audits"];
    const companyTab = validCompanyTabs.includes(segments[2]) ? segments[2] : "overview";
    return { mode: "company", value: segments[1], tab: "summary", companyTab };
  }

  if (segments[0] === "runs" && segments[1]) {
    return {
      mode: "run",
      value: segments[1],
      tab: normalizeTab(segments[2]),
    };
  }

  if (segments[0] === "address" && segments[1] && isAddress(segments[1])) {
    const maybeChainId = Number.parseInt(segments[2], 10);
    if (Number.isInteger(maybeChainId) && maybeChainId > 0) {
      return {
        mode: "address",
        value: segments[1],
        chainId: maybeChainId,
        tab: normalizeTab(segments[3]),
      };
    }
    return {
      mode: "address",
      value: segments[1],
      chainId: null,
      tab: normalizeTab(segments[2]),
    };
  }

  if (isAddress(segments[0])) {
    const maybeChainId = Number.parseInt(segments[1], 10);
    if (Number.isInteger(maybeChainId) && maybeChainId > 0) {
      return {
        mode: "address",
        value: segments[0],
        chainId: maybeChainId,
        tab: normalizeTab(segments[2]),
      };
    }
    return {
      mode: "address",
      value: segments[0],
      chainId: null,
      tab: normalizeTab(segments[1]),
    };
  }

  return { mode: "default", value: null, tab: "summary" };
}

export function buildLocationPath(runId, address, tab, chainId = null) {
  const nextTab = normalizeTab(tab);
  const parsedChainId = Number.parseInt(chainId, 10);
  if (isAddress(address)) {
    if (Number.isInteger(parsedChainId) && parsedChainId > 0) {
      return `/address/${String(address).trim()}/${parsedChainId}/${nextTab}`;
    }
    if (runId) {
      return `/runs/${encodeURIComponent(runId)}/${nextTab}`;
    }
    return `/address/${String(address).trim()}/${nextTab}`;
  }
  if (runId) {
    return `/runs/${encodeURIComponent(runId)}/${nextTab}`;
  }
  return "/";
}
