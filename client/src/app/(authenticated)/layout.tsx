// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import type { ReactNode } from "react";
import { useMessengerSync } from "@/hooks/useMessengerSync";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { useIdleLock } from "@/hooks/useIdleLock";
import { ShortcutsModal } from "@/components/modals";
import IdleLockWarning from "@/components/IdleLockWarning";
import { useAuthStore } from "@/stores";

/**
 * Shared layout for all authenticated routes (chats, chat/[id], settings).
 *
 * Running useMessengerSync here means the WebSocket connection, local-data
 * hydration, message/read handlers, and persistence subscriptions live ONCE per
 * session. Navigating between authenticated pages keeps this layout mounted, so
 * we no longer repeat getSession / IndexedDB reloads / handler churn on every
 * route change (the previous behaviour when the hook was mounted per page).
 *
 * There is deliberately no template.tsx wrapper: a template re-mounts and
 * re-animates this entire subtree on every navigation, which read as the whole
 * screen reloading. Entrance motion belongs on the content blocks themselves.
 *
 * The idle lock lives here for the same reason as the sync hook: it must span
 * the whole authenticated session. Mounted per page it would reset its deadline
 * on every navigation, so a user clicking between chats would never idle out —
 * the timer would measure time-since-last-route rather than time-since-last-use.
 */
export default function AuthenticatedLayout({
  children,
}: {
  children: ReactNode;
}) {
  useMessengerSync();
  const { isHelpOpen, closeHelp } = useKeyboardShortcuts();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const { secondsLeft, stayUnlocked } = useIdleLock(isAuthenticated);

  return (
    <div className="h-full min-h-0">
      {/*
        The locale key that used to live here moved to LocaleShell in the root
        layout: the unauthenticated screens need the same remount, and two
        mechanisms for one job is how they drift apart.
      */}
      {children}
      <ShortcutsModal isOpen={isHelpOpen} onClose={closeHelp} />
      {/*
        Outside the locale-keyed subtree: a language change remounts that, and
        the warning should not vanish because the countdown's own container was
        replaced underneath it.
      */}
      <IdleLockWarning secondsLeft={secondsLeft} onStayUnlocked={stayUnlocked} />
    </div>
  );
}
