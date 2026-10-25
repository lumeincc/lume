// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import React, { Component, type ErrorInfo, type ReactNode } from 'react';

import { t } from '@/lib/i18n';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    if (process.env.NODE_ENV !== 'production') {
      console.error('ErrorBoundary caught:', error, errorInfo);
    }
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen flex items-center justify-center p-6" role="alert">
          <div className="auth-card lume-panel p-8 max-w-md w-full text-center">
            <div className="w-16 h-16 mx-auto rounded-full border border-[var(--border)] bg-[var(--surface-strong)] flex items-center justify-center text-[var(--accent)] mb-4">
              <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 9v4" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 17h.01" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M10.3 3.4a2 2 0 013.4 0l8.2 14.2A2 2 0 0120.2 21H3.8a2 2 0 01-1.7-3.4l8.2-14.2z" />
              </svg>
            </div>
            <h2 className="text-base font-semibold text-[var(--text-primary)] mb-2">
              {t('error.title')}
            </h2>
            <p className="text-xs text-[var(--text-muted)] mb-6">
              {t('error.body')}
            </p>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
              className="apple-button px-6"
            >
              {t('error.reload')}
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
