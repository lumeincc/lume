// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import { useUIStore } from '@/stores';
import { t, type TranslationKey } from '@/lib/i18n';

type WsStatus = ReturnType<typeof useUIStore.getState>['wsStatus'];

/**
 * Only genuine failures get a banner. Transient states — connected, connecting,
 * disconnected — have no entry, so the absence of a message is what suppresses
 * the banner rather than a separate condition listing them.
 */
const WS_STATUS_MESSAGES: Partial<Record<WsStatus, TranslationKey>> = {
  rate_limited: 'status.rateLimited',
  kicked: 'status.kicked',
  auth_error: 'status.authError',
};

export default function StatusBanner() {
  const cryptoBanner = useUIStore((state) => state.cryptoBanner);
  const wsStatus = useUIStore((state) => state.wsStatus);

  // Prefer surfacing crypto/keys issues over transport noise.
  if (cryptoBanner) {
    const tone =
      cryptoBanner.level === 'error'
        ? 'text-[var(--accent)]'
        : cryptoBanner.level === 'warning'
        ? 'text-[var(--text-primary)]'
        : 'text-[var(--text-secondary)]';

    return (
      <div role="status" aria-live="polite" className={`w-full px-3 py-2 text-xs sm:text-sm text-center font-medium transition-colors duration-300 bg-[var(--surface)] border-b border-[var(--border)] animate-slide-down ${tone}`}>
        {cryptoBanner.message}
      </div>
    );
  }

  const messageKey = WS_STATUS_MESSAGES[wsStatus];
  if (!messageKey) return null;

  const bg = 'bg-[var(--surface)]';
  const tone = 'text-[var(--accent)]';

  return (
    <div role="status" aria-live="polite" className={`w-full px-3 py-2 text-xs sm:text-sm text-center font-medium transition-colors duration-300 ${bg} ${tone} border-b border-[var(--border)] animate-slide-down`}>
      {t(messageKey)}
    </div>
  );
}
