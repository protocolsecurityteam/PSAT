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
  // The settled outcome of the upgrade-history read, as `{ jobId, state }` with
  // state in present | absent | not_determined. There is no "pending" member
  // here on purpose: pending is the ABSENCE of a settled outcome for the
  // current job, and is derived below rather than stored, so no code path can
  // forget to re-enter it.
  //
  // Carried with the job_id it was earned by, never as a bare flag: this
  // component is reused across selections (ActivityPanel renders it with no
  // key), so between a new selection arriving and its effect running, the
  // previous entity's outcome is still in state. Comparing identity turns that
  // window into "pending", which is what it is, instead of into the last
  // entity's answer about a different contract.
  const [historyOutcome, setHistoryOutcome] = useState(null);

  const address = machine?.address;
  const chain = machine?.chain || contract?.chain || "ethereum";
  const isProxy = Boolean(machine?.is_proxy);

  // Per-contract events (all kinds), captured from enrollment forward.
  useEffect(() => {
    // Dropped before the fetch, not after it resolves: this component is reused
    // across selections, so between the new address arriving and its events
    // landing the strip and timeline would otherwise render the *previous*
    // contract's events under the new one — a positive claim about the wrong
    // subject, which is worse than the empty rail it replaces.
    setEvents([]);
    if (!address) { return undefined; }
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
    // Both pieces of state are earned by one selection and must not survive it.
    // The marker would hedge an entity whose history read fine; the history
    // would attribute one proxy's proven upgrade timeline to another — and the
    // fall-through in the `proxy` memo below (`Object.values(...)[0]`) makes
    // that happen even when the new address is not a key in the stale payload.
    // Cleared here rather than per-branch so no path can be added that skips it;
    // React batches these with whatever the branches set, so no extra render.
    setHistoryOutcome(null);
    setHistory(null);
    if (!isProxy || !machine?.job_id) { return undefined; }
    const cached = cache && cache[machine.job_id];
    if (cached?.history) {
      setHistory(cached.history);
      setHistoryOutcome({ jobId: machine.job_id, state: "present" });
      return undefined;
    }
    let cancelled = false;
    const jid = encodeURIComponent(machine.job_id);
    api(`/api/analyses/${jid}/artifact/upgrade_history`)
      .then((body) => {
        if (cancelled) return;
        const h = body && typeof body === "object" && !Array.isArray(body) ? body : null;
        setHistory(h);
        // A 200 whose body is not a plain object (a scalar, or an array —
        // `typeof [] === "object"`) collapses to the same `null` a failed read
        // produces, and the timeline cannot tell them apart from the payload
        // alone. It is not an answer about the history, so it is not written
        // as one.
        setHistoryOutcome({ jobId: machine.job_id, state: h ? "present" : "not_determined" });
        if (onCache) onCache(machine.job_id, h, {});
      })
      .catch((e) => {
        if (cancelled) return;
        setHistory(null);
        // The timeline below draws a proxy with no history as a proxy that has
        // never been upgraded, so anything short of an answer has to be said
        // out loud rather than rendered as the same empty rail. Only a 404 is a
        // proven negative — "this job has no upgrade_history" — and stays
        // silent. Everything else keeps the question open: a 503 (storage
        // unreachable), a 500, a 502/504 from the edge while the web machine is
        // autostopping, and a network failure, which `api` rethrows with no
        // `status` at all. The hedge is the default so that a non-answer nobody
        // enumerated cannot be drawn as an absence. Never cached — the answer
        // can change without us.
        setHistoryOutcome({
          jobId: machine.job_id,
          state: e?.status === 404 ? "absent" : "not_determined",
        });
      });
    return () => { cancelled = true; };
    // cache/onCache omitted deliberately: read once per selection so this
    // fetch's own cache write doesn't retrigger the effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [machine?.job_id, isProxy]);

  // Four states, and only ever the one this selection earned.
  const historyState = useMemo(() => {
    // No back-fill channel exists for a non-proxy, so the below-the-line set is
    // empty by construction. Nothing is in flight and nothing failed: that is an
    // answer, not a gap.
    if (!isProxy) return "absent";
    // A proxy with no analysis job to ask about. No read is pending, because
    // none was ever issued — so nobody knows, which is not the same as nothing
    // being there.
    if (!machine?.job_id) return "not_determined";
    // Outcome belongs to a previous selection (or none yet): this one is still
    // in flight. `api()` has no timeout, so this window is open until the read
    // settles — indefinitely if it never does.
    if (historyOutcome?.jobId !== machine.job_id) return "pending";
    return historyOutcome.state;
  }, [isProxy, machine?.job_id, historyOutcome]);

  // Only ever true for the selection whose read did not answer.
  const historyUnknown = historyState === "not_determined";

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
          Upgrade history was not read — this proxy's pre-enrollment upgrades
          are unknown, not absent.
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
        // The marker above and the timeline's empty states describe the same
        // period, so they have to be driven by the same fact — otherwise the
        // panel hedges in one line and asserts absence in the next.
        historyState={historyState}
      />
    </section>
  );
}
