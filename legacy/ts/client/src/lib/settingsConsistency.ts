// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import type { Settings } from "@/crypto/storage";
import { hasHiddenChatPin, loadSettings, saveSettings } from "@/crypto/storage";
import { useChatsStore, useUIStore } from "@/stores";
import type { Chat } from "@/stores";

export interface SettingsConsistencyInput {
  settings: Settings;
  chats: Chat[];
  showHiddenChats: boolean;
}

export interface SettingsConsistencyResult {
  chats: Chat[];
  showHiddenChats: boolean;
  changed: boolean;
  issues: string[];
}

export function reconcileSettingsConsistency(
  input: SettingsConsistencyInput,
): SettingsConsistencyResult {
  const { settings } = input;
  let chats = input.chats;
  let showHiddenChats = input.showHiddenChats;
  let changed = false;
  const issues: string[] = [];

  if (!settings.hiddenChatsEnabled) {
    if (showHiddenChats) {
      showHiddenChats = false;
      changed = true;
      issues.push(
        "Hidden mode was open while hidden chats setting is disabled.",
      );
    }

    const hasHidden = chats.some((chat) => chat.isHidden);
    if (hasHidden) {
      chats = chats.map((chat) =>
        chat.isHidden ? { ...chat, isHidden: false } : chat,
      );
      changed = true;
      issues.push(
        "Found hidden chats while hidden chats setting is disabled; unhidden automatically.",
      );
    }
  }

  if (settings.hiddenChatsEnabled && !settings.hiddenChatPinHash) {
    issues.push("Hidden chats enabled but hidden PIN hash is missing.");
  }

  return {
    chats,
    showHiddenChats,
    changed,
    issues,
  };
}

// ==================== Post-restore reconciliation ====================

const VALID_THEMES = new Set<string>(["light", "dark", "system"]);
const VALID_SELF_DESTRUCT = new Set<number | null>([null, 5, 30, 60, 300, 3600]);

export interface RestoreConsistencyResult {
  issues: string[];
  settingsPatched: boolean;
}

/**
 * Run after a successful importEncryptedBackup / account restore.
 *
 * 1. If hidden chats are disabled → unhide all chats in memory + close hidden mode.
 * 2. Validate settings fields; patch any corrupt values back to safe defaults and
 *    persist the corrected settings.
 * 3. Log dev-mode warnings for every inconsistency found.
 */
export async function reconcileRestoreConsistency(): Promise<RestoreConsistencyResult> {
  const issues: string[] = [];
  let settingsPatched = false;

  let settings: Settings;
  try {
    settings = await loadSettings();
  } catch {
    issues.push("reconcileRestoreConsistency: could not load settings — skipping.");
    warnIssues(issues);
    return { issues, settingsPatched };
  }

  let nextSettings = { ...settings };

  // --- 1. Hidden chats state ---
  if (!settings.hiddenChatsEnabled) {
    const uiState = useUIStore.getState();
    if (uiState.showHiddenChats) {
      uiState.setShowHiddenChats(false);
      issues.push("Hidden mode was active while hiddenChatsEnabled=false after restore; reset to false.");
    }

    const chats = useChatsStore.getState().chats;
    const hasHidden = chats.some((c) => c.isHidden);
    if (hasHidden) {
      const fixed = chats.map((c) => (c.isHidden ? { ...c, isHidden: false } : c));
      useChatsStore.getState().setChats(fixed);
      issues.push("Found hidden chats while hiddenChatsEnabled=false after restore; unhidden in memory.");
    }
  }

  // --- 2. Settings integrity ---

  // theme
  if (!VALID_THEMES.has(settings.theme)) {
    issues.push(`Invalid theme "${String(settings.theme)}" after restore; reset to "system".`);
    nextSettings = { ...nextSettings, theme: "system" };
    settingsPatched = true;
  }

  // selfDestructDefault
  if (!VALID_SELF_DESTRUCT.has(settings.selfDestructDefault)) {
    issues.push(
      `Invalid selfDestructDefault "${String(settings.selfDestructDefault)}" after restore; reset to null.`,
    );
    nextSettings = { ...nextSettings, selfDestructDefault: null };
    settingsPatched = true;
  }

  // PIN-state consistency: if hiddenChatsEnabled=true but no pin hash, that's inconsistent.
  // Use hasHiddenChatPin() to check storage directly — loadSettings() without masterKey
  // won't expose the decrypted hash, so we can't rely on settings.hiddenChatPinHash here.
  const pinExists = await hasHiddenChatPin();
  if (settings.hiddenChatsEnabled && !pinExists) {
    issues.push(
      "hiddenChatsEnabled=true but hiddenChatPinHash is missing after restore; disabling hidden chats.",
    );
    nextSettings = { ...nextSettings, hiddenChatsEnabled: false };
    settingsPatched = true;
  }

  // Persist corrections if needed
  if (settingsPatched) {
    try {
      await saveSettings(nextSettings);
    } catch {
      issues.push("reconcileRestoreConsistency: failed to persist patched settings.");
    }
  }

  warnIssues(issues);
  return { issues, settingsPatched };
}

function warnIssues(issues: string[]): void {
  if (process.env.NODE_ENV !== "production" && issues.length > 0) {
    console.warn("[restore-consistency]", issues.join(" | "));
  }
}
