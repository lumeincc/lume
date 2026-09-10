// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import type { ReactNode } from "react";
import { useUIStore } from "@/stores";

/**
 * Re-renders everything below it when the language changes.
 *
 * Components read their strings through a module-level `t()`, which is not
 * reactive: changing the locale changes what `t()` returns but tells React
 * nothing, so nothing re-renders. Keying on the locale remounts the subtree,
 * which is blunt but correct, and it happens at most twice in a session — once
 * when `LocaleBoot` applies the detected language, and again only if the reader
 * changes it in settings.
 *
 * This sits at the root rather than inside the authenticated layout, where an
 * equivalent key used to live, because the unauthenticated screens need it too:
 * setup, unlock and recovery are the first things a reader sees and they were
 * left in the default language until a navigation happened to remount them.
 *
 * The old placement existed to keep `useMessengerSync` from reconnecting its
 * WebSocket on a language change. That cost is now real but small: the first
 * switch fires within milliseconds of mount, long before a socket exists — one
 * cannot be opened until the vault is unlocked — and a deliberate change from
 * settings visibly reloads the interface anyway.
 */
export default function LocaleShell({ children }: { children: ReactNode }) {
  const locale = useUIStore((s) => s.locale);
  return (
    <div key={locale} className="flex-1 min-h-0">
      {children}
    </div>
  );
}
