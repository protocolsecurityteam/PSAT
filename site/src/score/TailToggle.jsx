// The control that reveals the rest of a table. Every score-page table cuts
// its list at a fixed head and hides the remainder behind this one button, so
// the affordance — the chevron, the wording — is defined once. What the
// collapsed label SAYS about the hidden rows is the caller's, and so is the
// left inset: the default aligns under the deduction rows' content column,
// and a table with no points gutter passes `flush`.
export default function TailToggle({ open, onToggle, flush = false, children }) {
  return (
    <button type="button" className={`sc-tail-btn${flush ? " sc-tail-flush" : ""}`} onClick={onToggle}>
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
