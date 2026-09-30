// Reveals the rest of a table; the collapsed label is the caller's. Pass
// `flush` for tables without a points gutter.
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
