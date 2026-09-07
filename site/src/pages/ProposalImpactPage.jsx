import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client.js";

function shortId(value) {
  const text = String(value || "");
  return text.length > 22 ? `${text.slice(0, 10)}…${text.slice(-8)}` : text;
}

function displayValue(value, unit) {
  if (value == null) return "Not observed";
  if (Array.isArray(value)) return `${value.length} addresses`;
  return unit ? `${value} ${unit}` : String(value);
}

function Scope({ scope }) {
  if (!scope) return <span className="proposal-scope reported">Reported</span>;
  if (scope.kind === "scenario") return <span className="proposal-scope scenario">Scenario · step {scope.step}</span>;
  if (scope.kind === "point") return <span className="proposal-scope observed">Observed · block {scope.at?.block_number}</span>;
  return <span className="proposal-scope reported">{scope.kind || "Reported"}</span>;
}

function KeyValue({ value }) {
  if (!value || typeof value !== "object") return <span>{String(value ?? "Not recorded")}</span>;
  return (
    <dl className="proposal-kv">
      {Object.entries(value).filter(([, item]) => item != null).map(([key, item]) => (
        <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{typeof item === "object" ? JSON.stringify(item) : String(item)}</dd></div>
      ))}
    </dl>
  );
}

function ProofDetails({ proof }) {
  return (
    <details className="proposal-proof">
      <summary>Inspect proof</summary>
      <div className="proposal-proof-record">
        <h4>Claim</h4>
        <code>{proof?.claim?.id}</code>
        <Scope scope={proof?.claim?.scope} />
        <KeyValue value={proof?.claim?.proposition} />
        <h4>Evidence</h4>
        {proof?.evidence?.length ? proof.evidence.map((item) => (
          <div className="proposal-proof-item" key={item.id}>
            <code>{item.id}</code><span>{item.kind}</span>
            <span>{item.block_number ? `Block ${item.block_number}` : "No exact block"}</span>
            <KeyValue value={item.source} />
          </div>
        )) : <p>No evidence linked.</p>}
        <h4>Prerequisites</h4>
        {proof?.prerequisites?.length ? proof.prerequisites.map((item) => (
          <div className="proposal-proof-item" key={item.id}>
            <code>{item.id}</code><span>{item.kind}</span><Scope scope={item.scope} />
            <KeyValue value={item.proposition} />
          </div>
        )) : <p>None.</p>}
      </div>
    </details>
  );
}

function ScenarioTrace({ rows }) {
  const actions = rows[0]?.actions || [];
  const assumptions = rows[0]?.assumptions || [];
  const downstream = rows.flatMap((row) => row.downstream || []);
  return (
    <details className="proposal-trace">
      <summary>Review ordered actions and downstream chain</summary>
      <div className="proposal-trace-grid">
        <section><h3>Ordered actions</h3>{actions.length ? <ol>{actions.map((action, index) => <li key={index}><strong>Step {index + 1}</strong><KeyValue value={action} /></li>)}</ol> : <p>No actions recorded.</p>}</section>
        <section><h3>Assumptions</h3>{assumptions.length ? <ul>{assumptions.map((item, index) => <li key={index}><KeyValue value={item} /></li>)}</ul> : <p>No assumptions; execution evidence uses the pinned baseline.</p>}</section>
        <section><h3>Downstream claims</h3>{downstream.length ? <ol>{downstream.map((item) => <li key={item.id}><strong>{item.kind.replaceAll("_", " ")}</strong><KeyValue value={item.proposition} /></li>)}</ol> : <p>No downstream claim has been derived beyond the direct changes shown above.</p>}</section>
      </div>
    </details>
  );
}

function ScenarioChanges({ changes }) {
  const contexts = useMemo(() => [...new Set(changes.map((row) => row.context_id))], [changes]);
  const [selected, setSelected] = useState(contexts[0] || "");

  useEffect(() => {
    if (!contexts.includes(selected)) setSelected(contexts[0] || "");
  }, [contexts, selected]);

  const rows = changes.filter((row) => row.context_id === selected);
  if (!changes.length) {
    return (
      <div className="proposal-empty">
        <h2>No scenario has been evaluated</h2>
        <p>Collect a proposal and run its ordered actions against a pinned baseline to see configuration and downstream changes here.</p>
      </div>
    );
  }
  return (
    <section className="proposal-section" aria-labelledby="scenario-heading">
      <div className="proposal-section-heading">
        <div>
          <h2 id="scenario-heading">Scenario changes</h2>
          <p>Hypothetical results stay isolated from observed current state.</p>
        </div>
        {contexts.length > 1 && (
          <label className="proposal-context-select">
            <span>Scenario</span>
            <select value={selected} onChange={(event) => setSelected(event.target.value)}>
              {contexts.map((context, index) => <option key={context} value={context}>Scenario {index + 1}</option>)}
            </select>
          </label>
        )}
      </div>
      <div className="proposal-table-wrap">
        <table className="proposal-table">
            <thead><tr><th>Target</th><th>Setting</th><th>Pinned baseline</th><th>Proposed</th><th>Scope</th><th>Derivation</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.claim_id}>
                <td data-label="Target"><strong>{shortId(row.subject)}</strong><small>{row.run_name}</small></td>
                <td data-label="Setting">{String(row.parameter || "Unknown").replaceAll("_", " ")}</td>
                <td data-label="Pinned baseline" className="proposal-before">{displayValue(row.before, row.unit)}</td>
                <td data-label="Proposed" className="proposal-after">{displayValue(row.after, row.unit)}</td>
                <td data-label="Scope"><Scope scope={{ kind: "scenario", step: row.step }} /></td>
                <td data-label="Derivation"><ProofDetails proof={row.proof} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="proposal-context-strip">
        <span>Baseline</span><code>{shortId(rows[0]?.baseline?.block_hash)} · block {rows[0]?.baseline?.block_number}</code>
        <span>Ordered actions</span><strong>{rows[0]?.actions?.length || 0}</strong>
        <span>Assumptions</span><strong>{rows[0]?.assumptions?.length || 0}</strong>
      </div>
      <ScenarioTrace rows={rows} />
    </section>
  );
}

function ObservedClaims({ proposals }) {
  return (
    <section className="proposal-section" aria-labelledby="observed-heading">
      <div className="proposal-section-heading">
        <div>
          <h2 id="observed-heading">Observed proposal record</h2>
          <p>Lifecycle, timing, operation, and configuration-binding claims collected from chain state.</p>
        </div>
      </div>
      {proposals.length ? (
        <div className="proposal-table-wrap">
          <table className="proposal-table">
            <thead><tr><th>Subject</th><th>Fact</th><th>Value</th><th>Scope</th><th>Derivation</th></tr></thead>
            <tbody>
              {proposals.map((row) => (
                <tr key={row.claim_id}>
                  <td data-label="Subject"><strong>{shortId(row.subject)}</strong><small>{row.run_name}</small></td>
                  <td data-label="Fact">{row.kind.replaceAll("_", " ")}</td>
                  <td data-label="Value"><KeyValue value={row.proposition} /></td>
                  <td data-label="Scope"><Scope scope={row.scope} /></td>
                  <td data-label="Derivation"><ProofDetails proof={row.proof} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="proposal-empty compact">
          <h3>No proposal claims collected</h3>
          <p>Run governance collection with proposal or operation IDs to populate this record.</p>
        </div>
      )}
    </section>
  );
}

export default function ProposalImpactPage({ companyName }) {
  const [state, setState] = useState({ status: "loading", data: null, error: null });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading", data: null, error: null });
    api(`/api/company/${encodeURIComponent(companyName)}/proposal-impact`, { silent: true })
      .then((data) => { if (!cancelled) setState({ status: "ready", data, error: null }); })
      .catch((error) => { if (!cancelled) setState({ status: "error", data: null, error }); });
    return () => { cancelled = true; };
  }, [companyName, attempt]);

  return (
    <main className="proposal-page">
      <header className="proposal-header">
        <div>
          <h1>Proposal impact</h1>
          <p>Compare observed governance facts with isolated, ordered scenarios and trace every change to its proof.</p>
          {state.data?.data_origin === "synthetic_fixture" && <span className="proposal-fixture-label">Synthetic fixture data</span>}
        </div>
        <div className="proposal-legend" aria-label="Scope legend">
          <span><i className="observed" />Observed state</span>
          <span><i className="scenario" />Hypothetical scenario</span>
        </div>
      </header>

      {state.status === "loading" && <div className="proposal-loading" aria-live="polite"><p>Loading proposal impact…</p><span /><span /><span /></div>}
      {state.status === "error" && (
        <div className="proposal-error" role="alert">
          <h2>Proposal impact could not be loaded</h2>
          <p>The assessment API did not complete. Reload the page; no empty-state conclusion has been inferred.</p>
          <button type="button" onClick={() => setAttempt((value) => value + 1)}>Retry loading</button>
        </div>
      )}
      {state.status === "ready" && (
        <>
          <ScenarioChanges changes={state.data.changes || []} />
          <ObservedClaims proposals={state.data.proposals || []} />
          {!!state.data.limitations?.length && (
            <section className="proposal-limitations" aria-labelledby="limitations-heading">
              <h2 id="limitations-heading">Coverage limitations</h2>
              <ul>{state.data.limitations.map((item, index) => <li key={`${item.job_id}-${item.code}-${index}`}><strong>{item.code.replaceAll("_", " ")}</strong><span>{item.message}</span></li>)}</ul>
            </section>
          )}
        </>
      )}
    </main>
  );
}
