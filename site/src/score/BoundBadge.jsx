// Only a proven direction earns a badge; undetermined or absent renders nothing
// (unresolved questions live in the possible-deductions table). Neither label
// claims the value is protected.
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
