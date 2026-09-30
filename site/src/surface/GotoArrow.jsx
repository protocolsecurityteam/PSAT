// The shared "go to" commit on in-card entity references. The row body only
// previews; this arrow selects and swaps the sidebar card. stopPropagation
// keeps it from also firing the preview.
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
