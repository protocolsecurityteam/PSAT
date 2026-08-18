// Which direction the figure bounds the principal in, and never a floor by
// default. Only a PROVEN direction earns a badge: an undetermined one renders
// nothing — the possible-deductions table is where unresolved questions live —
// and a document that does not carry the field wears no badge either. Neither
// label is a claim that the value is protected.
//
// Shared because every surface that prints a value band owes the reader the
// same direction beside it: a band shown bare on one row and badged on another
// reads as two different claims about the same field.
const BOUND_BADGE = { floor: "floor", ceiling: "ceiling" };
const BOUND_TITLE = {
  floor: "at least this much — the priced entities and answered instances are a floor over what this reaches",
  ceiling: "at most this much — composed from the destination's own witness, which bounds one call from above",
};

export default function BoundBadge({ direction }) {
  const label = BOUND_BADGE[direction];
  if (!label) return null;
  return (
    <span className="sc-fl" title={BOUND_TITLE[direction]}>
      {label}
    </span>
  );
}
