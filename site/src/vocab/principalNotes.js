// A resolved-principal's terminal-controller note. Reads
// the non-terminal marking + terminal walk so the inspector NEVER implies a
// settled key where the control chain didn't terminate. Returns null for a
// principal that is itself terminal (a settled Safe/EOA/timelock), or when there
// is nothing to say. Shape: {kind: "terminated"|"ambiguous"|"unresolved", ...}.
export function terminalControllerNote(principal) {
  const details = (principal && principal.details) || {};
  const resolvedType =
    (principal && (principal.resolvedType || principal.resolved_type)) ||
    "unknown";
  // A settled key (terminal === true) needs no way-point note.
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
    // Multiple parallel control planes (Solmate/Solady Auth owner + authority).
    // `multi_plane` at the top level carries `tp.planes` — each plane walked to
    // its OWN terminal — so the verbose inspector can show every plane's controller
    // and outcome (a reviewer needs to see the weakest plane). The header still says
    // "no single settled key"; we never collapse to one key.
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
    // `ambiguous_controllers` (a nested plane that itself forked) has no per-plane
    // walk to show — render the flat controller count as "no single settled key".
    // A `multi_plane` status without a usable `planes` array degrades here too.
    if (tp.status === "multi_plane" || tp.status === "ambiguous_controllers") {
      const planes = Array.isArray(tp.controllers) ? tp.controllers : [];
      return { kind: "ambiguous", planes };
    }
    // cycle | depth_exceeded | unknown_unfetched | controllers_not_determined
    // (canonical getters silent — NOT proof of no controller; the record
    // carries probes_silent/undetermined_at as the basis) | legacy
    // no_controller rows persisted before the proven-absence claim was
    // retired → all honestly unresolved, with the true status carried through.
    return { kind: "unresolved", status: tp.status || "unknown" };
  }

  // resolved_type=contract way-point with no terminal walk: still non-terminal.
  if (resolvedType === "contract" || details.terminal === false) {
    return { kind: "unresolved", status: "unknown_unfetched" };
  }
  return null;
}

// Signer-overlap attribution CONTEXT for a Safe principal.
// Tier 1 (on-chain owner reads). NB the honesty boundary baked into the copy this
// feeds: shared signers is attribution context, NOT proof of shared org identity.
// Returns {selfOwnerCount, strongest: {address, sharedCount, otherOwnerCount,
// subset, superset, equal, jaccard}} or null.
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

// Shared-deployer attribution HINT for a principal.
// A Tier-1 on-chain read (`provenance:"deployer_read"`) but a HEURISTIC for
// attribution — factories, shared deployer EOAs and vanity-deployer services all
// defeat "same deployer ⇒ same org". The fact is honest; the conclusion is not.
// INSPECTOR-ONLY (never a chip qualifier), and the copy this feeds MUST carry the
// hedge whenever `heuristic` is true — never phrased as org identity or control.
// Returns {deployer, otherCount, heuristic} or null (absent fact → nothing).
export function sharedDeployerNote(principal) {
  const sd =
    principal && principal.details && principal.details.shared_deployer;
  if (!sd || typeof sd.deployer !== "string") return null;
  const addresses = Array.isArray(sd.addresses) ? sd.addresses : [];
  const self = String((principal && principal.address) || "").toLowerCase();
  // `addresses` is the full deployer group INCLUDING this principal; count the
  // OTHERS. Fall back to the raw length only if self isn't in the list.
  const others = addresses.filter((a) => String(a).toLowerCase() !== self);
  const otherCount = others.length || Math.max(0, addresses.length - 1);
  if (otherCount <= 0) return null;
  return {
    deployer: sd.deployer,
    otherCount,
    heuristic: sd.heuristic !== false,
  };
}
