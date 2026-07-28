// Audit-coverage matching helpers for the Upgrades tab.
//
// Extracted from App.jsx so they can be unit-tested and kept pure.
// These functions decide which audit coverage row (from the
// audit_timeline API) attaches to which implementation era in the
// upgrade_history artifact.
//
// Backend note: the `contracts` table only has a row for the CURRENT
// implementation of each proxy, so every coverage row's
// `impl_address` points at the current impl — even for audits that
// cover past impls. The frontend has richer context via the static-
// pipeline upgrade_history artifact, so for name-based matches
// (`direct` / `impl_era`) it does its own temporal placement with
// a grace zone, and only source-equivalence proofs
// (`match_type === "reviewed_commit"`) stay strictly bound to the
// impl_address the backend matched.

// Days of slack on either side of an impl's active window. An audit
// finalized within two weeks of an impl going live (or being replaced)
// is almost certainly reviewing *that* impl — engagement ends and the
// PDF ships just before the upgrade, or review continues just after it.
// Mirrors the backend's GRACE_DAYS in services/audits/coverage.py.
const GRACE_MS = 14 * 24 * 3600 * 1000;

export function parseAuditTs(date) {
  if (!date) return null;
  const t = Date.parse(date);
  return Number.isNaN(t) ? null : t;
}

export function matchesEra(cov, impl) {
  const addrMatch = !!(
    cov?.impl_address &&
    impl?.address &&
    cov.impl_address.toLowerCase() === impl.address.toLowerCase()
  );

  // Source-equivalence is a cryptographic proof the audit reviewed
  // one specific impl's source — don't let temporal logic spread it
  // across other eras.
  if (cov?.match_type === "reviewed_commit") {
    return addrMatch;
  }

  // Block-range constraint from the backend (populated when impl_era
  // match has a window). Hard constraint: overlap required.
  //
  // An ABSENT era bound is not a bound value. Folding `block_introduced` to
  // -Infinity and `block_replaced` to Infinity let a fully block-bounded audit
  // overlap an era whose window was never determined — a poll-detected impl
  // publishes `block_introduced: null` (L-26), and the fold answers the hard
  // constraint "yes" from the absence of the data it is meant to test.
  //
  // KEY PRESENCE is the successor discriminator, taken from the producer:
  // `_build_implementation_timeline` writes `block_replaced` from the next upgrade
  // event unconditionally, so the key is absent only on the current impl (whose
  // era really does run to now) and present-but-null exactly when a successor
  // exists whose block was never determined.
  //
  // When a bound the constraint needs is not determined, this branch DECLINES —
  // it falls through to the temporal match below, which has its own evidence and
  // its own hedges, instead of returning an answer it cannot support.
  const covFrom = cov?.covered_from_block;
  const covTo = cov?.covered_to_block;
  if (covFrom != null || covTo != null) {
    const eraFrom = impl?.block_introduced;
    const eraToKnown = typeof impl?.block_replaced === "number";
    const eraHasSuccessor = impl != null && Object.prototype.hasOwnProperty.call(impl, "block_replaced");
    const eraTo = eraToKnown ? impl.block_replaced : eraHasSuccessor ? null : Infinity;
    if (typeof eraFrom === "number" && eraTo !== null) {
      const cFrom = covFrom ?? -Infinity;
      const cTo = covTo ?? Infinity;
      return cFrom < eraTo && cTo > eraFrom;
    }
  }

  // Temporal match: audit date vs impl-era timestamps, with 14-day grace
  // on both sides. We do NOT short-circuit on addrMatch here — for
  // `direct` matches the backend pins impl_address to the CURRENT impl
  // regardless of when the audit was published, so short-circuiting
  // would drag e.g. a 2024-10-08 Certora audit onto the 2026 impl.
  const auditTs = parseAuditTs(cov?.date);
  if (auditTs == null) {
    // No audit date → only signal we have is addrMatch.
    return addrMatch;
  }
  // Same rule as the block branch above, on the sibling field — and it is not
  // optional here: with the block branch now declining on an undetermined window,
  // an era whose TIMESTAMPS were also never determined would fall through to this
  // test and be answered "yes" by the ±Infinity fold, which would make the decline
  // above cosmetic. An era with no known start cannot be shown to contain an audit
  // date, so the only signal left is addrMatch.
  const eraFromTs =
    impl?.timestamp_introduced != null ? impl.timestamp_introduced * 1000 : null;
  const eraHasSuccessorTs = impl != null && Object.prototype.hasOwnProperty.call(impl, "timestamp_replaced");
  const eraToTs =
    impl?.timestamp_replaced != null
      ? impl.timestamp_replaced * 1000
      : eraHasSuccessorTs
        ? null
        : Infinity;
  if (eraFromTs === null || eraToTs === null) {
    return addrMatch;
  }
  return auditTs >= eraFromTs - GRACE_MS && auditTs < eraToTs + GRACE_MS;
}
