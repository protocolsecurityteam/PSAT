// Detail tab's empty state — when nothing is selected. The composite-score
// block and radar that used to fill it were projections of a retired scorer;
// the protocol grade now lives on the company page's score band, where every
// figure comes from the scorer's own published document.
export function DetailEmptyState({ companyName, companyData }) {
  if (!companyData) {
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">Loading protocol overview…</div>
      </section>
    );
  }
  return (
    <section className="ps-detail-empty">
      <div className="ps-detail-empty-hdr">{companyName}</div>
      <div className="ps-detail-empty-hint">
        Click a contract or principal on the canvas for its detail.
      </div>
    </section>
  );
}
