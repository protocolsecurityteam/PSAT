import { useMemo, useState } from "react";

import ProtocolLogo from "../ProtocolLogo.jsx";

export default function RunsPage({ analyses, onSelectCompany }) {
  const [search, setSearch] = useState("");

  const companies = useMemo(() => {
    const map = new Map();
    for (const a of analyses) {
      const co = a.company;
      if (!co) continue;
      if (!map.has(co)) map.set(co, { company: co, contracts: 0 });
      map.get(co).contracts++;
    }
    return [...map.values()].sort((a, b) => b.contracts - a.contracts);
  }, [analyses]);

  const filtered = useMemo(() => {
    if (!search.trim()) return companies;
    const q = search.toLowerCase();
    return companies.filter((c) => c.company.toLowerCase().includes(q));
  }, [companies, search]);

  return (
    <div>
      <section id="protocols" className="home-protocol-section">
        <div className="home-protocol-header">
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>Analyzed Protocols</p>
            <h2>All protocols</h2>
          </div>
          <div className="home-protocol-search">
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search protocols..." />
          </div>
        </div>

        {filtered.length > 0 ? (
          <div className="home-protocol-list">
            {filtered.map((c) => (
              <button key={c.company} className="home-protocol-row" onClick={() => onSelectCompany(c.company)}>
                <ProtocolLogo name={c.company} />
                <span className="home-protocol-row-name">{c.company}</span>
                <span className="home-protocol-row-count">{c.contracts} contracts</span>
                <span className="home-protocol-row-arrow" aria-hidden="true">→</span>
              </button>
            ))}
          </div>
        ) : (
          <p className="empty">{search ? "No protocols match your search." : "No analyses yet. Submit a protocol to get started."}</p>
        )}
      </section>
    </div>
  );
}
