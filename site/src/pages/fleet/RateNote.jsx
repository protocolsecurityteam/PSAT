import React from "react";

// Rate annotation next to a metric. ``good`` paints it green (healthy
// direction) vs amber (concerning).
export function RateNote({ text, good }) {
  if (!text) return null;
  return (
    <span className="dmn-rate" style={{ color: good ? "#34d399" : "#fbbf24" }}>
      {text}
    </span>
  );
}
