import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export default class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Aegis UI caught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[60vh] p-8 text-center">
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-full text-red-400 mb-4">
            <AlertOctagon size={48} />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">Dashboard Display Error</h2>
          <p className="text-gray-400 max-w-md mb-6 text-sm">
            {this.state.error?.message || 'An unexpected rendering error occurred in this view.'}
          </p>
          <button
            onClick={() => {
              this.setState({ hasError: false });
              window.location.reload();
            }}
            className="flex items-center gap-2 px-4 py-2 bg-aegis-accent hover:bg-aegis-accent/80 text-white rounded-md transition-colors text-sm font-medium"
          >
            <RefreshCw size={16} /> Reload View
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
