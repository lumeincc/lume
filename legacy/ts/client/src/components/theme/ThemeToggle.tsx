// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import { t } from "@/lib/i18n";
import React from 'react';
import { applyTheme, getCurrentTheme } from '@/lib/theme';

export default function ThemeToggle({
  className = '',
  size = 'md',
}: {
  className?: string;
  size?: 'sm' | 'md';
}) {
  const sizes = size === 'sm' ? 'w-9 h-9' : 'w-10 h-10';

  const toggle = () => {
    const current = getCurrentTheme();
    applyTheme(current === 'dark' ? 'light' : 'dark');
  };

  return (
    <button
      type="button"
      onClick={toggle}
      className={`${sizes} inline-flex items-center justify-center rounded-full border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-alt)] transition-colors ${className}`}
      aria-label={t("theme.toggle")}
      title={t("theme.toggle")}
    >
      <span className="theme-icon theme-icon--sun" aria-hidden="true">
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.8"
            d="M12 18a6 6 0 100-12 6 6 0 000 12z"
          />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 2v2" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 20v2" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M4.93 4.93l1.41 1.41" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M17.66 17.66l1.41 1.41" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M2 12h2" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M20 12h2" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M4.93 19.07l1.41-1.41" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M17.66 6.34l1.41-1.41" />
        </svg>
      </span>
      <span className="theme-icon theme-icon--moon" aria-hidden="true">
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.8"
            d="M21 12.8A8.6 8.6 0 1111.2 3a7 7 0 009.8 9.8z"
          />
        </svg>
      </span>
    </button>
  );
}
