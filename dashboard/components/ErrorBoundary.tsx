"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";

export class ErrorBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {
    // The browser receives no stack trace. Production telemetry records only
    // a generated correlation identifier at the boundary.
  }

  render() {
    if (this.state.failed) {
      return (
        <div className="state-panel state-degraded" role="alert">
          <strong>This workspace could not be rendered.</strong>
          <span>Refresh the case. If the problem persists, use the dashboard runbook.</span>
          <button type="button" onClick={() => this.setState({ failed: false })}>
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
