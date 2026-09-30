// Never implies a settled key where the chain didn't terminate. Null for
// terminal principals. Shape: {kind: "terminated"|"ambiguous"|"unresolved",
// ...}.
export function terminalControllerNote(principal) {
  const details = (principal && principal.details) || {};
  const resolvedType =
    (principal && (principal.resolvedType || principal.resolved_type)) ||
    "unknown";
  if (details.terminal === true) return null;

  const tp = details.terminal_principal;
  if (tp && typeof tp === "object") {
    if (tp.terminal === true && tp.address) {
      return {
        kind: "terminated",
        address: tp.address,
        resolvedType: String(tp.resolved_type || "unknown"),
      };
    }
    // Parallel control planes: show each plane's own walk so the weakest is
    // visible; never collapse to one key.
    if (
      tp.status === "multi_plane" &&
      Array.isArray(tp.planes) &&
      tp.planes.length
    ) {
      const planes = tp.planes.map((p) => {
        const rec = (p && p.terminal_record) || {};
        const outcome =
          rec.terminal === true && rec.address
            ? {
                resolved: true,
                address: rec.address,
                resolvedType: String(rec.resolved_type || "unknown"),
              }
            : { resolved: false, status: String(rec.status || "unknown") };
        return { controller: (p && p.controller) || null, outcome };
      });
      return { kind: "multi_plane", planes };
    }
    // No per-plane walk to show (nested fork, or planes missing).
    if (tp.status === "multi_plane" || tp.status === "ambiguous_controllers") {
      const planes = Array.isArray(tp.controllers) ? tp.controllers : [];
      return { kind: "ambiguous", planes };
    }
    // cycle | depth_exceeded | unknown_unfetched | controllers_not_determined
    // (silent getters, not proof of no controller) | legacy no_controller rows:
    // all unresolved, status carried through.
    return { kind: "unresolved", status: tp.status || "unknown" };
  }

  if (resolvedType === "contract" || details.terminal === false) {
    return { kind: "unresolved", status: "unknown_unfetched" };
  }
  return null;
}

// Tier 1 signer overlap: attribution context, not proof of shared organization.
// Returns {selfOwnerCount, strongest} or null.
export function signerOverlapNote(principal) {
  const so = principal && principal.details && principal.details.signer_overlap;
  if (!so || !Array.isArray(so.overlaps) || !so.overlaps.length) return null;
  const withShared = so.overlaps.filter(
    (o) => o && typeof o.shared_count === "number" && o.shared_count > 0,
  );
  if (!withShared.length)
    return { selfOwnerCount: so.self_owner_count, strongest: null };
  const strongest = withShared.reduce((best, o) =>
    o.jaccard > best.jaccard ? o : best,
  );
  return {
    selfOwnerCount: so.self_owner_count,
    strongest: {
      address: strongest.address,
      sharedCount: strongest.shared_count,
      otherOwnerCount: strongest.other_owner_count,
      subset: Boolean(strongest.subset),
      superset: Boolean(strongest.superset),
      equal: Boolean(strongest.equal),
      jaccard: strongest.jaccard,
    },
  };
}

// Same deployer is witnessed but only a heuristic for attribution (factories
// defeat it). Inspector-only, and the copy must hedge when `heuristic`. Returns
// {deployer, otherCount, heuristic} or null.
export function sharedDeployerNote(principal) {
  const sd =
    principal && principal.details && principal.details.shared_deployer;
  if (!sd || typeof sd.deployer !== "string") return null;
  const addresses = Array.isArray(sd.addresses) ? sd.addresses : [];
  const self = String((principal && principal.address) || "").toLowerCase();
  // `addresses` includes this principal.
  const others = addresses.filter((a) => String(a).toLowerCase() !== self);
  const otherCount = others.length || Math.max(0, addresses.length - 1);
  if (otherCount <= 0) return null;
  return {
    deployer: sd.deployer,
    otherCount,
    heuristic: sd.heuristic !== false,
  };
}
