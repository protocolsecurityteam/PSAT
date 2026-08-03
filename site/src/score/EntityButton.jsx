// The one clickable-entity pathway on the score page. Contract names,
// controller addresses, protection principals and example function names all
// go through it, so there is one definition of what a score-page entity click
// is and one keyboard contract.

// A target is actionable when it names an entity (an address) or a function.
// A function-only target is deliberate: the score document never publishes the
// contract a capability's example function lives on, so the surface graph has
// to resolve the host — the page must not pick one.
function actionable(onSelect, target) {
  return Boolean(onSelect) && Boolean(target?.address || target?.functionSignature);
}

// Interactive props for an element that IS the control, rather than one wrapped
// in a control. Used where an extra wrapper would change what a flex parent
// lays out (the protection rows' kind chip) — the props go onto the element the
// page already renders, so the geometry is untouched.
export function entityProps({ onSelect, target, title, ariaLabel }) {
  if (!actionable(onSelect, target)) return null;
  const activate = () => onSelect(target);
  return {
    role: "button",
    tabIndex: 0,
    title,
    "aria-label": ariaLabel,
    onClick: activate,
    onKeyDown: (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      activate();
    },
  };
}

// Without a handler (the band rendered outside a page that hosts a surface)
// the children stay plain text — an element that looks clickable and does
// nothing is worse than one that doesn't.
//
// A span carrying the button role, not a <button>: these sit inside lines that
// truncate with text-overflow, and a real button is an atomic inline-block that
// the ellipsis cannot reach into, so the trailing entity would clip with no "…"
// to say it had. Keyboard activation is wired to match the role.
export default function EntityButton({ onSelect, target, title, ariaLabel, children }) {
  const props = entityProps({ onSelect, target, title, ariaLabel });
  if (!props) return children;
  return (
    <span className="sc-lnk" {...props}>
      {children}
    </span>
  );
}
