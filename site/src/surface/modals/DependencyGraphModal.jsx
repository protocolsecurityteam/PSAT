import { useEffect, useState } from "react";

import DependencyGraphTab from "../../DependencyGraphTab.jsx";
import { api } from "../../api/client.js";
import { blockExplorerAddressUrl } from "../../blockExplorer.js";
import { shortAddr } from "../format.js";
import { buildFallbackDependencyGraph } from "../layout/dependencyFallback.js";

export function DependencyGraphModal({ machine, onClose }) {
  const [graphData, setGraphData] = useState(null);
  const [graphNote, setGraphNote] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === "Escape") onClose?.();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    if (!machine) return undefined;
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      setGraphData(null);
      setGraphNote(null);
      const ids = [machine.analysis_job_id, machine.implementation_analysis_job_id, machine.address]
        .filter(Boolean)
        .filter((id, index, arr) => arr.indexOf(id) === index);
      let sawArtifact = false;
      let lastError = null;

      for (const id of ids) {
        const encoded = encodeURIComponent(id);
        try {
          const detail = await api(`/api/analyses/${encoded}`);
          if (cancelled) return;
          if (detail?.dependency_graph_viz?.nodes?.length) {
            setGraphData(detail.dependency_graph_viz);
            setGraphNote(null);
            setLoading(false);
            return;
          }
          if ((detail?.available_artifacts || []).includes("dependency_graph_viz")) {
            sawArtifact = true;
          }
        } catch (err) {
          lastError = err;
        }

        if (!sawArtifact) continue;

        try {
          const artifact = await api(`/api/analyses/${encoded}/artifact/dependency_graph_viz.json`);
          if (cancelled) return;
          if (artifact?.nodes?.length) {
            setGraphData(artifact);
            setGraphNote(null);
            setLoading(false);
            return;
          }
        } catch (err) {
          lastError = err;
        }
      }

      if (cancelled) return;
      const fallback = buildFallbackDependencyGraph(machine);
      if (fallback?.nodes?.length) {
        setGraphData(fallback);
        setGraphNote("Fallback graph generated from selected contract metadata because no stored dependency artifact loaded.");
        setLoading(false);
        return;
      }

      if (!cancelled) {
        setError(
          sawArtifact
            ? `Dependency graph artifact is listed, but it could not be loaded${lastError?.message ? `: ${lastError.message}` : "."}`
            : "No dependency graph artifact is available for this contract.",
        );
        setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [machine]);

  if (!machine) return null;

  return (
    <div className="ps-modal-backdrop" onMouseDown={onClose}>
      <div
        className="ps-dependency-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Dependency graph"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="ps-dependency-modal-header">
          <div>
            <div className="ps-dependency-modal-eyebrow">Dependency Graph</div>
            <h2>{machine.name || shortAddr(machine.address)}</h2>
            {blockExplorerAddressUrl(machine.address, machine.chain_id) ? (
              <a
                className="ps-dependency-modal-sub ps-scanner-link"
                href={blockExplorerAddressUrl(machine.address, machine.chain_id)}
                target="_blank"
                rel="noreferrer"
              >
                {machine.address}
              </a>
            ) : (
              <div className="ps-dependency-modal-sub">{machine.address}</div>
            )}
          </div>
          <button type="button" className="ps-modal-close" onClick={onClose} aria-label="Close dependency graph">
            x
          </button>
        </header>
        <div className="ps-dependency-modal-body">
          {loading && <div className="ps-modal-empty">Loading dependency graph...</div>}
          {!loading && error && <div className="ps-modal-empty ps-modal-empty-error">{error}</div>}
          {!loading && graphData && (
            <>
              {graphNote && <div className="ps-dependency-note">{graphNote}</div>}
              <DependencyGraphTab data={graphData} runName={null} chainId={machine.chain_id} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
