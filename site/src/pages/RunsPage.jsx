import { useMemo, useRef, useState } from "react";

import ProtocolLogo from "../ProtocolLogo.jsx";

export default function RunsPage({ analyses, onSelect, onDiscoverMore, onSelectCompany }) {
  const [search, setSearch] = useState("");
  const protocolSectionRef = useRef(null);

  const { companies, standalone } = useMemo(() => {
    const map = new Map();
    const solo = [];
    for (const a of analyses) {
      const co = a.company;
      if (!co) { solo.push(a); continue; }
      if (!map.has(co)) map.set(co, { company: co, contracts: 0 });
      map.get(co).contracts++;
    }
    return { companies: [...map.values()].sort((a, b) => b.contracts - a.contracts), standalone: solo };
  }, [analyses]);

  const filtered = useMemo(() => {
    if (!search.trim()) return companies;
    const q = search.toLowerCase();
    return companies.filter((c) => c.company.toLowerCase().includes(q));
  }, [companies, search]);

  const contractCount = analyses.length;

  function scrollToProtocols() {
    protocolSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <div>
      <section ref={protocolSectionRef} id="protocols" className="home-protocol-section">
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

        {standalone.length > 0 && (
          <section className="panel" style={{ marginTop: 32 }}>
            <h3 style={{ marginBottom: 12 }}>Standalone analyses</h3>
            <div className="runs-table">
              <div className="runs-table-header">
                <span style={{ flex: 2 }}>Contract</span>
                <span style={{ flex: 3 }}>Address</span>
              </div>
              {standalone.map((a) => (
                <button key={a.job_id || a.run_name} className="runs-table-row" onClick={() => onSelect(a.job_id)}>
                  <span className="runs-cell-name" style={{ flex: 2 }}>{a.contract_name || a.run_name || "Unknown"}</span>
                  <span className="mono runs-cell-addr" style={{ flex: 3 }}>{a.address || ""}</span>
                </button>
              ))}
            </div>
          </section>
        )}
      </section>
    </div>
  );
}
