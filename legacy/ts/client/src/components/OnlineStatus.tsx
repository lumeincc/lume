// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import { useEffect } from 'react';
import { useUIStore } from '@/stores';

/**
 * Tracks navigator.onLine and the online/offline events, and mirrors them into
 * the UI store.
 *
 * It deliberately does NOT ask for notification permission. It used to, from
 * this effect on mount, and Firefox and Safari refuse a permission request that
 * does not come from a user gesture — so on those browsers the prompt never
 * appeared and notifications silently never worked. Chrome allowed it, which is
 * why it went unnoticed.
 *
 * The request belongs to the notifications toggle in settings, which is a real
 * click and already does it correctly.
 */
export default function OnlineStatus() {
  useEffect(() => {
    const setOnline = useUIStore.getState().setOnline;

    setOnline(navigator.onLine);

    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return null;
}
