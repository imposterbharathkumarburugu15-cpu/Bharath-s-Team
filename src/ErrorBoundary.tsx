import React, { Component, ErrorInfo, ReactNode } from "react";

export class ErrorBoundary extends Component<{children: ReactNode}, {hasError: boolean, error: Error | null}> {
  state = { hasError: false, error: null };
  static getDerivedStateFromError(error: Error) { return { hasError: true, error }; }
  componentDidCatch(error: Error, errorInfo: ErrorInfo) { console.error("ErrorBoundary caught an error", error, errorInfo); }
  render() {
    if (this.state.hasError) {
      return <div style={{ color: "red", padding: "20px" }}><h1>Something went wrong.</h1><pre>{String(this.state.error?.stack)}</pre></div>;
    }
    return this.props.children;
  }
}
