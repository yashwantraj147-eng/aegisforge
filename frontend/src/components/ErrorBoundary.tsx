import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error inside component:', error, errorInfo);
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 bg-red-950/30 border border-red-800/80 rounded-2xl text-red-200 space-y-4 my-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-red-950 border border-red-700 text-red-400">
              <AlertOctagon className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">
                {this.props.fallbackTitle || 'Component Rendering Exception'}
              </h3>
              <p className="text-xs text-red-300">
                An isolated interface fault occurred. Surrounding dashboard operations remain stable.
              </p>
            </div>
          </div>

          {this.state.error && (
            <div className="p-3 bg-slate-950 rounded-lg border border-red-900/60 font-mono text-xs text-red-400 overflow-x-auto">
              {this.state.error.message}
            </div>
          )}

          <div className="flex justify-end">
            <button
              onClick={this.handleReset}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-900/60 hover:bg-red-800 border border-red-700 text-xs font-semibold text-white transition cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Component View
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
