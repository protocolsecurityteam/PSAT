// The control that reveals the rest of a table. Both score-page tables cut
// their list at a fixed head and hide the remainder behind this one button, so
// the affordance — the chevron, the wording, the alignment under the first
// column — is defined once. What the collapsed label SAYS about the hidden rows
// is the caller's, because the two tables count different things.
export default function TailToggle({ open, onToggle, children }) {
  return (
    <button type="button" className="sc-tail-btn" onClick={onToggle}>
      {open ? (
        <>
          <span className="sc-tail-chev">▲</span> hide the tail
        </>
      ) : (
        <>
          {children}
          <span className="sc-tail-chev">▼</span>
        </>
      )}
    </button>
  );
}
