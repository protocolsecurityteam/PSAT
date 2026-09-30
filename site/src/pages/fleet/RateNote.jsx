import React from "react";

export function RateNote({ text, good }) {
  if (!text) return null;
  return (
    <span className="dmn-rate" style={{ color: good ? "#34d399" : "#fbbf24" }}>
      {text}
    </span>
  );
}
