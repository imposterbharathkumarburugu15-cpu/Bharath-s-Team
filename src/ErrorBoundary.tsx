import React, { Component, ErrorInfo, ReactNode } from "react";

export class ErrorBoundary extends Component<{children: ReactNode}, {hasError: boolean, error: Error | null}> {
  state = { hasError: false, error: null };
  
  static getDerivedStateFromError(error: Error) { 
    // If it's the known internal Firebase Auth race condition, we don't need to disrupt the user
    if (error?.message?.includes('Pending promise was never set')) {
      console.warn('ErrorBoundary intercepted Firebase pending promise assertion error.');
      return { hasError: false, error: null };
    }
    return { hasError: true, error }; 
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) { 
    console.error("ErrorBoundary caught an error:", error, errorInfo); 
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#03060a] text-white flex items-center justify-center p-6 font-mono">
          <div className="max-w-xl w-full bg-[#0a0f1d] border border-red-500/40 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 font-bold">
                !
              </div>
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight">System Exception Intercepted</h1>
                <p className="text-xs text-gray-400">The application encountered an unexpected runtime state.</p>
              </div>
            </div>

            <div className="bg-black/60 border border-white/10 rounded-xl p-4 text-xs text-red-400 overflow-x-auto max-h-48 font-mono">
              {this.state.error?.message || 'Unknown runtime error'}
            </div>

            <div className="pt-2 flex items-center justify-end gap-3">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-black transition-all cursor-pointer shadow-lg active:scale-95"
              >
                Reset & Continue
              </button>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white transition-all cursor-pointer"
              >
                Reload App
              </button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
