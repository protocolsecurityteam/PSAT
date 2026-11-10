import { ROLE_META } from "../surface/meta.js";

// Overview entry `role` + `role_evidence`. A role reached only through
// not-determined inputs is not a fact. An unlisted token renders raw.
export function roleLabel(entry) {
  const evidence = entry?.role_evidence;
  if (evidence === "not_determined") return "Role not determined";
  const role = entry?.role;
  const meta = role == null ? ROLE_META.utility : ROLE_META[role];
  const word = meta ? meta.singular : String(role);
  return evidence == null || evidence === "witnessed" ? word : `${word} · ${evidence}`;
}
