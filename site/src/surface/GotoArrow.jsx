// The one "go to" commit affordance shared by every in-card entity reference:
// lane caller buttons (FunctionPort), Governs rows (GovernsTab), and Guard
// Inspector principal cards (InspectorCard). In all three the row/button BODY
// previews the target on the canvas (a light camera peek, no selection change);
// this arrow is the single control that COMMITS — it selects the target and
// swaps the sidebar to its card. stopPropagation keeps an arrow click from also
// firing the body's peek.
export function GotoArrow({ onCommit, label = "Go to" }) {
  return (
    <button
      type="button"
      className="ps-goto-arrow"
      title={label}
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation();
        onCommit();
      }}
    >
      →
    </button>
  );
}
