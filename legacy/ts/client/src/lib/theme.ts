// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Unified theme management.
 *
 * Single source of truth for applying / reading the current theme.
 * Used by ThemeToggle, Settings page, and the layout inline script
 * (the inline script uses localStorage directly for flash prevention).
 */

import { loadSettings, saveSettings } from '@/crypto/storage';

export type ThemePreference = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'lume-theme';

/**
 * Resolve "system" to an actual light/dark value.
 */
export function resolveTheme(pref: ThemePreference): ResolvedTheme {
  if (pref === 'system') {
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return 'light';
  }
  return pref;
}

/**
 * Apply theme to the DOM + localStorage.
 * When `skipPersist` is true, skip saving to Settings (caller handles persistence).
 */
export function applyTheme(pref: ThemePreference, skipPersist = false): void {
  const resolved = resolveTheme(pref);

  // DOM
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;

  // localStorage (read by layout inline script on next load to prevent flash)
  try {
    localStorage.setItem(STORAGE_KEY, resolved);
  } catch {
    // ignore — private browsing or quota
  }

  // Persist preference ("system" | "light" | "dark") to encrypted Settings
  if (!skipPersist) {
    void (async () => {
      try {
        const current = await loadSettings();
        if (current.theme !== pref) {
          await saveSettings({ ...current, theme: pref });
        }
      } catch {
        // ignore — user may not be authenticated yet
      }
    })();
  }
}

/**
 * Read the currently active resolved theme from the DOM.
 */
export function getCurrentTheme(): ResolvedTheme {
  if (typeof document === 'undefined') return 'light';
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}
