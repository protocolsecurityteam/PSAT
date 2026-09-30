import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="page" style={{ paddingTop: 80 }}>
          <div className="card" style={{ maxWidth: 600, margin: "0 auto" }}>
            <h3>Something went wrong</h3>
            <p className="muted">{String(this.state.error)}</p>
            <button className="btn" onClick={() => { this.setState({ error: null }); window.location.reload(); }}>Reload</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
