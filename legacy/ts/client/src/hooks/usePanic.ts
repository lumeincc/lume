// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Shared hook: panic wipe logic.
 * Eliminates copy-paste between chats/page.tsx and chat/[id]/page.tsx.
 */

import { useState, useCallback } from "react";
import {
  useAuthStore,
  useUIStore,
  useContactsStore,
  useChatsStore,
  useSessionsStore,
  useTypingStore,
  useBlockedStore,
} from "@/stores";
import { wsClient } from "@/lib/websocket";
import { panicWipe } from "@/crypto/storage";

export function usePanic() {
  const isPanicMode = useUIStore((s) => s.isPanicMode);
  const setPanicMode = useUIStore((s) => s.setPanicMode);

  const [showPanicConfirm, setShowPanicConfirm] = useState(false);

  const executePanic = useCallback(async () => {
    setPanicMode(true);
    wsClient.disconnect();

    // Zero key material and empty the in-memory stores BEFORE clearing storage,
    // so any pending/in-flight debounced persist cannot re-encrypt and re-write
    // old data. panicWipe() also disables persistence for the rest of the
    // session (storage-level guard), covering already-scheduled timers. SEC-20260621-016.
    useAuthStore.getState().clearAuth();
    useContactsStore.getState().setContacts([]);
    useChatsStore.getState().setChats([]);
    useSessionsStore.getState().setSessions({});
    useTypingStore.getState().clearAll();
    useBlockedStore.getState().setBlockedIds([]);

    await panicWipe();

    useUIStore.getState().setPanicMode(false);
    useUIStore.getState().setShowHiddenChats(false);
    useUIStore.getState().clearCryptoBanner();

    // Use location.replace to clear bfcache (back-forward cache)
    // so pressing "Back" won't reveal any sensitive UI state
    window.location.replace("/");
  }, [setPanicMode]);

  return {
    isPanicMode,
    showPanicConfirm,
    setShowPanicConfirm,
    executePanic,
  };
}
