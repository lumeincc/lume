// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Settings page — thin orchestrator that composes section components.
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { t } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import { Button, Modal, SettingsSkeleton } from "@/components/ui";
import LeftRail from "@/components/messenger/LeftRail";
import { useHydrated } from "@/hooks/useMessengerSync";
import { usePanic } from "@/hooks/usePanic";
import { useAuthStore } from "@/stores";
import { loadSettings, saveSettings, type Settings } from "@/crypto/storage";
import { applyTheme } from "@/lib/theme";
import { isSoundEnabled } from "@/lib/sounds";
import { vaultGetMasterKey, vaultHasMasterKey } from "@/crypto/keyVault";

import ProfileSection from "./components/ProfileSection";
import AppearanceSection from "./components/AppearanceSection";
import NotificationsSection from "./components/NotificationsSection";
import PrivacySection from "./components/PrivacySection";
import SecuritySection from "./components/SecuritySection";
import DangerZoneSection from "./components/DangerZoneSection";
import { BUILD_LABEL } from "@/lib/buildInfo";

export default function SettingsPage() {
  const router = useRouter();
  const hydrated = useHydrated();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const { isPanicMode, showPanicConfirm, setShowPanicConfirm, executePanic } =
    usePanic();

  const [settings, setSettingsState] = useState<Settings | null>(null);
  const [saveFlash, setSaveFlash] = useState(false);
  const [soundOn, setSoundOn] = useState(true);
  const [backupWarning, setBackupWarning] = useState(false);

  useEffect(() => {
    if (hydrated && !isAuthenticated) {
      router.replace("/");
    }
  }, [hydrated, isAuthenticated, router]);

  useEffect(() => {
    if (hydrated && isAuthenticated) {
      const mk = vaultHasMasterKey() ? vaultGetMasterKey() : undefined;
      loadSettings(mk).then(setSettingsState);
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSoundOn(isSoundEnabled());
    }
  }, [hydrated, isAuthenticated]);

  const triggerSaveFlash = useCallback(() => {
    setSaveFlash(true);
    setTimeout(() => setSaveFlash(false), 1200);
  }, []);

  const updateSetting = useCallback(
    async <K extends keyof Settings>(key: K, value: Settings[K]) => {
      if (!settings) return;
      const next = { ...settings, [key]: value };
      setSettingsState(next);
      if (key === "theme") {
        applyTheme(value as Settings["theme"], true);
      }
      const mk = vaultHasMasterKey() ? vaultGetMasterKey() : undefined;
      await saveSettings(next, mk);
      triggerSaveFlash();
    },
    [settings, triggerSaveFlash],
  );

  if (!hydrated || !settings) {
    return (
      <div className="h-[100dvh] w-full overflow-hidden">
        <div className="md:hidden h-full min-h-0">
          <SettingsSkeleton />
        </div>
        <div className="hidden md:block h-full min-h-0">
          <div className="h-full w-full grid min-h-0 grid-cols-1 lg:grid-cols-[76px_1fr]">
            <div className="hidden lg:block min-h-0 border-r border-[var(--border)]" />
            <div className="min-h-0" aria-busy="true">
              <SettingsSkeleton />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) return null;

  if (isPanicMode) {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-[var(--text-secondary)] text-sm">
          No messages
        </p>
      </div>
    );
  }

  const settingsContent = (
    <div className="h-full overflow-hidden flex flex-col">
      <div className="px-4 sm:px-6 pt-4 sm:pt-6 pb-4 sm:pb-5 border-b border-[var(--border)]/70">
        <div className="max-w-2xl mx-auto w-full flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <button
              type="button"
              onClick={() => router.push("/chats")}
              className="lume-icon-btn md:hidden flex-shrink-0"
              aria-label={t("settings.backToChats")}
              title={t("settings.back")}
            >
              <svg
                className="w-5 h-5"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M15 19l-7-7 7-7"
                />
              </svg>
            </button>
            <h1 className="text-xl font-semibold tracking-[-0.01em] text-[var(--text-primary)]">
              {t("settings.title")}
            </h1>
          </div>
          {saveFlash ? (
            <span className="text-caption text-[var(--text-muted)] animate-pulse flex-shrink-0">
              {t("common.saved")}
            </span>
          ) : null}
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-4 sm:px-6 py-5 sm:py-6">
        <div className="max-w-2xl mx-auto space-y-8 animate-settle">
          <ProfileSection />

          <AppearanceSection settings={settings} onUpdate={updateSetting} />

          <NotificationsSection
            settings={settings}
            soundOn={soundOn}
            onSoundChange={setSoundOn}
            onUpdate={updateSetting}
          />

          <PrivacySection
            settings={settings}
            onSettingsChange={setSettingsState}
            onUpdate={updateSetting}
            onSaveFlash={triggerSaveFlash}
          />

          {backupWarning ? (
            <div className="p-3 rounded-[var(--radius-md)] border border-[var(--text-muted)]/30 bg-[var(--surface-alt)]">
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                <span className="font-semibold">{t("settings.pinChanged")}</span>{" "}
                {t("settings.backupStale")}
              </p>
              <button
                type="button"
                onClick={() => setBackupWarning(false)}
                className="mt-2 text-caption text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
              >
                {t("common.dismiss")}
              </button>
            </div>
          ) : null}

          <SecuritySection onBackupWarning={setBackupWarning} />

          <DangerZoneSection />

          {/*
            Build identity, at the bottom where a version belongs.
            Selectable on purpose: the point of showing a commit is that someone
            can copy it into a bug report, and text you cannot select is a
            version string that only looks helpful.
          */}
          <p className="pt-2 pb-6 text-center text-xs text-[var(--text-muted)] select-text tabular-nums">
            {BUILD_LABEL}
          </p>
        </div>
      </div>

      <Modal
        isOpen={showPanicConfirm}
        onClose={() => setShowPanicConfirm(false)}
        title={t("settings.wipe.title")}
      >
        <div className="space-y-4">
          <p className="text-body text-[var(--text-secondary)] text-center">
            {t("settings.wipe.warning")}
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => setShowPanicConfirm(false)}
              className="apple-button-secondary flex-1"
            >
              {t("common.cancel")}
            </button>
            <Button onClick={executePanic} className="flex-1">
              {t("settings.wipe.confirm")}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );

  return (
    <div className="h-[100dvh] w-full overflow-hidden">
      {/* Mobile: settings panel full-screen */}
      <div className="md:hidden h-full min-h-0">
        {settingsContent}
      </div>

      {/* Desktop: rail + full-width settings */}
      <div className="hidden md:block h-full min-h-0">
        <div className="h-full w-full grid min-h-0 grid-cols-1 lg:grid-cols-[76px_1fr]">
          <div className="hidden lg:block min-h-0 border-r border-[var(--border)]">
            <LeftRail onPanic={() => setShowPanicConfirm(true)} />
          </div>
          <div className="min-h-0">{settingsContent}</div>
        </div>
      </div>
    </div>
  );
}
