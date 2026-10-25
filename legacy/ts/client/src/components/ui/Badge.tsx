// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { t } from "@/lib/i18n";
import React from 'react';

interface BadgeProps {
  variant?: 'success' | 'warning' | 'error' | 'info' | 'neutral';
  size?: 'sm' | 'md';
  icon?: React.ReactNode;
  children: React.ReactNode;
}

export function Badge({ variant = 'neutral', size = 'md', icon, children }: BadgeProps) {
  const variants = {
    success: 'bg-[var(--accent)] text-[var(--accent-contrast)] border-[var(--accent)]',
    warning: 'bg-transparent text-[var(--text-primary)] border-[var(--border)] border-dashed',
    error: 'bg-transparent text-[var(--text-primary)] border-[var(--border)] border-dashed',
    info: 'bg-[var(--surface-alt)] text-[var(--text-primary)] border-[var(--border)]',
    neutral: 'bg-[var(--surface-alt)] text-[var(--text-secondary)] border-[var(--border)]',
  };

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
  };

  return (
    <span
      className={`
        inline-flex items-center
        font-medium rounded-full border
        ${variants[variant]}
        ${sizes[size]}
      `}
    >
      {icon && <span className="mr-1">{icon}</span>}
      {children}
    </span>
  );
}

export function SecureBadge() {
  return (
    <Badge
      variant="success"
      size="sm"
      icon={
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path
            fillRule="evenodd"
            d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z"
            clipRule="evenodd"
          />
        </svg>
      }
    >
      {t("status.secure")}
    </Badge>
  );
}

export function VerifiedBadge() {
  return (
    <Badge
      variant="success"
      size="sm"
      icon={
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path
            fillRule="evenodd"
            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
            clipRule="evenodd"
          />
        </svg>
      }
    >
      {t("status.verified")}
    </Badge>
  );
}

export function KeyUpdatedBadge() {
  return (
    <Badge
      variant="info"
      size="sm"
      icon={
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path
            fillRule="evenodd"
            d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z"
            clipRule="evenodd"
          />
        </svg>
      }
    >
      {t("status.keyUpdated")}
    </Badge>
  );
}

export function OfflineBadge() {
  return (
    <Badge variant="neutral" size="sm">
      {t("status.offline")}
    </Badge>
  );
}

export function OnlineBadge() {
  return (
    <Badge variant="success" size="sm">
      {t("status.online")}
    </Badge>
  );
}

export default Badge;
