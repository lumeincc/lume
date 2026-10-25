// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Global keyboard shortcuts for authenticated routes.
 *
 * Mounted once in the authenticated layout, alongside useMessengerSync, so a
 * single listener serves every page instead of one per route.
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useUIStore } from "@/stores";
import {
  matchShortcut,
  isEditableTarget,
  type ShortcutCommandId,
} from "@/lib/shortcuts";

export function useKeyboardShortcuts() {
  const router = useRouter();
  const isPanicMode = useUIStore((s) => s.isPanicMode);
  const contactsPanelCollapsed = useUIStore((s) => s.contactsPanelCollapsed);
  const setContactsPanelCollapsed = useUIStore((s) => s.setContactsPanelCollapsed);

  const [isHelpOpen, setHelpOpen] = useState(false);

  const closeHelp = useCallback(() => setHelpOpen(false), []);

  const run = useCallback(
    (command: ShortcutCommandId) => {
      const handlers: Record<ShortcutCommandId, () => void> = {
        showHelp: () => setHelpOpen((open) => !open),
        openSettings: () => router.push("/settings"),
        toggleContactsPanel: () => setContactsPanelCollapsed(!contactsPanelCollapsed),
      };

      handlers[command]();
    },
    [router, contactsPanelCollapsed, setContactsPanelCollapsed],
  );

  useEffect(() => {
    // During a panic wipe the UI is being torn down; navigating or opening a
    // dialog mid-wipe would fight that teardown.
    if (isPanicMode) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented) return;
      if (isEditableTarget(event.target)) return;

      const command = matchShortcut(event);
      if (!command) return;

      event.preventDefault();
      run(command);
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isPanicMode, run]);

  return { isHelpOpen, closeHelp };
}
