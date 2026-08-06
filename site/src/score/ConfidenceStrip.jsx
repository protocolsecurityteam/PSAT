export default function ConfidenceStrip({ channels }) {
  return (
    <div className="sc-conf-strip">
      {channels.map((channel) => (
        <div className="sc-channel" key={channel.id}>
          <div className="sc-row1">
            <span className="sc-nm">{channel.name}</span>
            {channel.isMin && <span className="sc-hd">min</span>}
            <span className="sc-pv">
              {channel.pct === null ? <span className="sc-nd">not determined</span> : `${channel.pct.toFixed(1)}%`}
            </span>
          </div>
          <div className="sc-meter">
            {channel.pct !== null && <div className="sc-meter-fill" style={{ width: `${channel.pct}%` }} />}
          </div>
          <div className="sc-desc">{channel.desc}</div>
        </div>
      ))}
      <div className="sc-conf-note">
        Confidence is the <b>lowest</b> of these — it measures how much of the protocol the grade is
        built on, not how correct it is.
      </div>
    </div>
  );
}
