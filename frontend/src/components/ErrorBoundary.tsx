import React from 'react'

interface ErrorBoundaryProps {
  children: React.ReactNode
  fallbackTitle?: string
  fallbackHint?: string
}

interface ErrorBoundaryState {
  error: Error | null
}

/** Generic error boundary that catches render crashes and shows a retry UI. */
export default class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error(this.props.fallbackTitle || 'Component crashed:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="border border-red-500/30 bg-red-500/10 rounded p-3 text-sm text-red-400">
          <div className="font-medium mb-1">
            {this.props.fallbackTitle || 'Error'}: {this.state.error.message}
          </div>
          {this.props.fallbackHint && (
            <div className="text-xs text-slate-400">{this.props.fallbackHint}</div>
          )}
          <button
            type="button"
            className="btn-secondary text-xs mt-2"
            onClick={() => this.setState({ error: null })}
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
