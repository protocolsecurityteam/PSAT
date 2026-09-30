import { clickable } from "../shared/clickable.js";

// The one clickable-entity pathway on the score page, so every entity click has
// one keyboard contract.

// Function-only targets are deliberate: the document never names the host
// contract, so the surface graph resolves it.
function actionable(onSelect, target) {
  return Boolean(onSelect) && Boolean(target?.address || target?.functionSignature);
}

// Props for an element that IS the control; a wrapper would change what a flex
// parent lays out.
export function entityProps({ onSelect, target, title, ariaLabel }) {
  if (!actionable(onSelect, target)) return null;
  return { ...clickable(() => onSelect(target)), title, "aria-label": ariaLabel };
}

// Without a handler the children stay plain text.
//
// A span with the button role, not a <button>: a button is an atomic
// inline-block the text-overflow ellipsis can't reach into.
export default function EntityButton({ onSelect, target, title, ariaLabel, children }) {
  const props = entityProps({ onSelect, target, title, ariaLabel });
  if (!props) return children;
  return (
    <span className="sc-lnk" {...props}>
      {children}
    </span>
  );
}
