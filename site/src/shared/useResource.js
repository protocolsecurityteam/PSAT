import { useEffect, useState } from "react";

const IDLE = { data: null, error: null, loading: false };

// Runs `load` when `deps` change (and every `poll` ms), dropping responses from
// a superseded run. A failed poll keeps the last good data. With `reset: false`
// the previous data stays visible while a new dependency set loads.
export function useResource(load, deps, { enabled = true, poll = 0, reset = true } = {}) {
  const [state, setState] = useState(() => (enabled ? { ...IDLE, loading: true } : IDLE));

  useEffect(() => {
    if (!enabled) return undefined;
    let cancelled = false;
    setState((prev) => ({ data: reset ? null : prev.data, error: null, loading: true }));
    const run = () =>
      Promise.resolve()
        .then(load)
        .then(
          (data) => { if (!cancelled) setState({ data, error: null, loading: false }); },
          (error) => { if (!cancelled) setState((prev) => ({ data: prev.data, error, loading: false })); },
        );
    run();
    const timer = poll ? setInterval(run, poll) : null;
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [enabled, poll, reset, ...deps]); // eslint-disable-line react-hooks/exhaustive-deps

  return state;
}
