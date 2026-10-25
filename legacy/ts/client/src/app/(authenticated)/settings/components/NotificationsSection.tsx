// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Settings — Notifications section (desktop notifications + sound).
 */

"use client";

import { useState, useCallback } from "react";
import type { Settings } from "@/crypto/storage";
import {
  requestNotificationPermission,
  getNotificationPermission,
} from "@/lib/notifications";
import { subscribeToPush, unsubscribeFromPush } from "@/lib/pushSubscription";
import { setSoundEnabled } from "@/lib/sounds";
import { useAuthStore } from "@/stores";
import { SectionHeading, ToggleRow } from "./shared";
import { t } from "@/lib/i18n";

interface NotificationsSectionProps {
  settings: Settings;
  soundOn: boolean;
  onSoundChange: (v: boolean) => void;
  onUpdate: <K extends keyof Settings>(key: K, value: Settings[K]) => void;
}

export default function NotificationsSection({
  settings,
  soundOn,
  onSoundChange,
  onUpdate,
}: NotificationsSectionProps) {
  const [browserPermission, setBrowserPermission] = useState(
    getNotificationPermission,
  );
  const userId = useAuthStore((s) => s.userId);

  const handleToggle = useCallback(
    async (enabled: boolean) => {
      void onUpdate("notifications", enabled);
      if (enabled) {
        const granted = await requestNotificationPermission().catch(
          () => false,
        );
        setBrowserPermission(granted ? "granted" : getNotificationPermission());
        if (granted && userId) {
          void subscribeToPush(userId);
        }
      } else if (userId) {
        void unsubscribeFromPush(userId);
      }
    },
    [onUpdate, userId],
  );

  const permissionHint =
    settings.notifications && browserPermission === "denied"
      ? t("settings.notifications.blocked")
      : undefined;

  return (
    <section>
      <SectionHeading>{t("settings.notifications.title")}</SectionHeading>
      <ToggleRow
        label={t("settings.notifications.desktop")}
        description={permissionHint ?? t("settings.notifications.desktopHint")}
        checked={settings.notifications}
        onChange={(v) => void handleToggle(v)}
      />
      <ToggleRow
        label={t("settings.notifications.sound")}
        description={t("settings.notifications.soundHint")}
        checked={soundOn}
        onChange={(v) => {
          onSoundChange(v);
          setSoundEnabled(v);
        }}
      />
    </section>
  );
}
