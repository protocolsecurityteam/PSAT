// Which direction the figure bounds the principal in, and never a floor by
// default. `ceiling` and `bound not determined` are both refusals to read the
// number as an at-least — the second one refuses to read it as an at-most too,
// and says only that the producer proved no direction for it. A document that
// does not carry the field wears no badge, and none of the labels is a claim
// that the value is protected.
//
// Shared because every surface that prints a value band owes the reader the
// same direction beside it: a band shown bare on one row and badged on another
// reads as two different claims about the same field.
export const BOUND_BADGE = { floor: "floor", ceiling: "ceiling", not_determined: "bound not determined" };
export const BOUND_TITLE = {
  floor: "at least this much — the priced entities and answered instances are a floor over what this reaches",
  ceiling: "at most this much — composed from the destination's own witness, which bounds one call from above",
  not_determined:
    "the producer proved no direction for this total — neither an at-least nor an at-most: see value_at_stake_basis",
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
