
const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

export function isAddress(value) {
  return ADDRESS_RE.test(String(value || "").trim());
}

export function parseLocationPath(pathname) {
  const segments = String(pathname || "/")
    .split("/")
    .filter(Boolean)
    .map((segment) => decodeURIComponent(segment));

  if (!segments.length) {
    return { mode: "default", value: null };
  }

  if (segments[0] === "monitor") {
    return { mode: "monitor", value: null };
  }

  if (segments[0] === "account") {
    return { mode: "account", value: null };
  }

  if (segments[0] === "set-password") {
    return { mode: "set-password", value: null };
  }

  if (segments[0] === "company" && segments[1]) {
    const validCompanyTabs = ["overview", "surface"];
    const companyTab = validCompanyTabs.includes(segments[2]) ? segments[2] : "overview";
    return { mode: "company", value: segments[1], companyTab };
  }

  return { mode: "default", value: null };
}
