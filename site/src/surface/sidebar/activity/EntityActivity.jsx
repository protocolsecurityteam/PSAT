import { useEffect, useMemo, useState } from "react";

import { api } from "../../../api/client.js";
import { AlertControls } from "./AlertControls.jsx";
import { StatusStrip } from "./StatusStrip.jsx";
import { Timeline } from "./Timeline.jsx";
import { buildTimeline } from "./buildTimeline.js";

const POLL_MS = 30_000;

// Entity mode: the selected contract's status strip + alert controls (admin) +
// the unified timeline. Owns the per-contract event fetch and the per-proxy
// upgrade-history fetch (memoized in the shared cache); the merge itself is
// pure (buildTimeline).
export function EntityActivity({
  machine,
  contract,
  subscriptions,
  isAdmin,
  saving,
  onAttachWebhook,
  cache,
  onCache,
  now,
}) {
  const [events, setEvents] = useState([]);
  const [history, setHistory] = useState(null);
  // Three states for the upgrade history, not two: loaded, proven-absent, and
  // "the server could not determine it". Only the third gets a marker.
  //
  // Held as the job_id the 503 was about, never as a bare boolean: this
  // component is reused across selections (ActivityPanel renders it with no
  // key), so a boolean outlives the selection that earned it and hedges the
  // *next* entity — a history that read fine, or an entity with no history at
  // all. Tying the marker to the identity it describes makes that unrenderable.
  const [unknownForJob, setUnknownForJob] = useState(null);

  const address = machine?.address;
  const chain = machine?.chain || contract?.chain || "ethereum";
  const isProxy = Boolean(machine?.is_proxy);

  // Per-contract events (all kinds), captured from enrollment forward.
  useEffect(() => {
    if (!address) { setEvents([]); return undefined; }
    let cancelled = false;
    const load = async () => {
      try {
        const q = `address=${encodeURIComponent(address)}&chain=${encodeURIComponent(chain)}&limit=100`;
        const evs = await api(`/api/monitored-events?${q}`);
        if (!cancelled) setEvents(Array.isArray(evs) ? evs : []);
      } catch {
        if (!cancelled) setEvents([]);
      }
    };
    load();
    const t = setInterval(load, POLL_MS);
    return () => { cancelled = true; clearInterval(t); };
  }, [address, chain]);

  // Deep upgrade history for a proxy (back-filled to deployment). Cached by
  // job_id across selections. Only upgrade_history is needed — the timeline
  // renders impl addresses, not resolved names, so dependencies is skipped.
  useEffect(() => {
    // Cleared before either early return: a cached history is proven-present
    // and a non-proxy has no history to hedge, so both paths must drop a
    // previous selection's marker rather than inherit it.
    setUnknownForJob(null);
    if (!isProxy || !machine?.job_id) { setHistory(null); return undefined; }
    const cached = cache && cache[machine.job_id];
    if (cached?.history) { setHistory(cached.history); return undefined; }
    let cancelled = false;
    const jid = encodeURIComponent(machine.job_id);
    api(`/api/analyses/${jid}/artifact/upgrade_history`)
      .then((body) => {
        if (cancelled) return;
        const h = body && typeof body === "object" ? body : null;
        setHistory(h);
        if (onCache) onCache(machine.job_id, h, {});
      })
      .catch((e) => {
        if (cancelled) return;
        setHistory(null);
        // 503 is the API's "we could not find out" (storage unreachable). The
        // timeline below draws a proxy with no history as a proxy that has
        // never been upgraded, so this state has to be said out loud rather
        // than rendered as the same empty rail. A 404 is a real negative and
        // stays silent. Never cached — the answer can change without us.
        setUnknownForJob(e?.status === 503 ? machine.job_id : null);
      });
    return () => { cancelled = true; };
    // cache/onCache omitted deliberately: read once per selection so this
    // fetch's own cache write doesn't retrigger the effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [machine?.job_id, isProxy]);

  // Only ever true for the selection the 503 was actually about.
  const historyUnknown = isProxy && Boolean(machine?.job_id) && unknownForJob === machine.job_id;

  const proxy = useMemo(() => {
    if (!history?.proxies) return null;
    const target = (address || "").toLowerCase();
    return history.proxies[target] || Object.values(history.proxies)[0] || null;
  }, [history, address]);

  const enrollmentBlock = contract?.enrollment_block ?? null;
  const timeline = useMemo(
    () => buildTimeline({ events, proxy, enrollmentBlock, isProxy }),
    [events, proxy, enrollmentBlock, isProxy],
  );

  // "Monitoring started" label: created_at is when the MonitoredContract row was
  // written at enroll time — a truthful stand-in for the block→timestamp we
  // don't have client-side. Fall back to the earliest captured event.
  // TODO(activity): exact enrollment timestamp from enrollment_block.
  const boundaryDate = contract?.created_at
    || (events.length ? events[events.length - 1]?.detected_at : null);

  const newestEventAt = events[0]?.detected_at || null;

  return (
    <section className="ps-activity-entity">
      <StatusStrip machine={machine} contract={contract} lastEventAt={newestEventAt} now={now} />

      {contract ? (
        <AlertControls
          contract={contract}
          subscriptions={subscriptions}
          isAdmin={isAdmin}
          saving={saving}
          onAttachWebhook={(url, label, groupKeys) => onAttachWebhook(contract, url, label, groupKeys)}
        />
      ) : null}

      <div className="ps-activity-sect-title" style={{ marginTop: 2 }}>Timeline</div>
      {historyUnknown ? (
        <div className="ps-activity-unknown" role="status">
          Upgrade history could not be read — this proxy's pre-enrollment
          upgrades are unknown, not absent.
        </div>
      ) : null}
      <Timeline
        above={timeline.above}
        below={timeline.below}
        boundaryBlock={timeline.boundaryBlock}
        boundaryDate={boundaryDate}
        isProxy={isProxy}
        chain={chain}
        now={now}
      />
    </section>
  );
}
