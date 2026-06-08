import React from "react";

export default function SplashHero({ form, setForm, onSubmit, loading }) {
  return (
    <section className="splash-hero" aria-labelledby="splash-hero-title">
      <div className="splash-hero-inner">
        <div className="splash-hero-copy">
          <p className="splash-hero-eyebrow">Protocol Security Assessment Tool</p>
          <h1 id="splash-hero-title" className="splash-hero-title">
            Smart contract audits,<br />
            on an assembly line.
          </h1>
          <p className="splash-hero-sub">
            Drop an address or protocol name. Every contract rides the belt
            through audit, upgrade analysis, owner resolution, and a dependency
            graph check. Bad ones hit the trap door. Good ones get stamped.
          </p>

          <form className="splash-hero-form" onSubmit={onSubmit}>
            <label className="splash-hero-field splash-hero-field-main">
              <span>Address or protocol</span>
              <input
                value={form.target}
                onChange={(e) => setForm((c) => ({ ...c, target: e.target.value }))}
                placeholder="0x... or etherfi"
                required
              />
            </label>
            <label className="splash-hero-field">
              <span>Chain ID</span>
              <input
                type="number"
                min="1"
                value={form.chainId}
                onChange={(e) => setForm((c) => ({ ...c, chainId: e.target.value }))}
                placeholder="Auto"
              />
            </label>
            <label className="splash-hero-field splash-hero-field-narrow">
              <span>Limit</span>
              <input
                type="number"
                min="1"
                max="200"
                value={form.analyzeLimit}
                onChange={(e) => setForm((c) => ({ ...c, analyzeLimit: e.target.value }))}
              />
            </label>
            <button type="submit" className="splash-hero-submit" disabled={loading || !form.target}>
              {loading ? "Starting..." : "Run Audit →"}
            </button>
          </form>
        </div>
      </div>
    </section>
  );
}
