// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Settings — Appearance section (theme selector).
 */

"use client";

import type { Settings } from "@/crypto/storage";
import { SectionHeading } from "./shared";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { t, LOCALES, LOCALE_NAMES, type Locale } from "@/lib/i18n";
import { useUIStore } from "@/stores";

interface AppearanceSectionProps {
  settings: Settings;
  onUpdate: <K extends keyof Settings>(key: K, value: Settings[K]) => void;
}

export default function AppearanceSection({
  settings,
  onUpdate,
}: AppearanceSectionProps) {
  const locale = useUIStore((s) => s.locale);
  const setLocale = useUIStore((s) => s.setLocale);

  return (
    <section>
      <SectionHeading>{t("settings.appearance.title")}</SectionHeading>
      <p className="text-body text-[var(--text-secondary)] mb-3">
        {t("settings.appearance.theme")}
      </p>
      <SegmentedControl<"light" | "dark" | "system">
        options={[
          { label: t("settings.appearance.light"), value: "light" },
          { label: t("settings.appearance.dark"), value: "dark" },
          { label: t("settings.appearance.system"), value: "system" },
        ]}
        value={settings.theme}
        onChange={(v) => onUpdate("theme", v)}
      />

      <p className="text-body text-[var(--text-secondary)] mt-6 mb-3">
        {t("settings.appearance.language")}
      </p>
      <SegmentedControl<Locale>
        options={LOCALES.map((code) => ({ label: LOCALE_NAMES[code], value: code }))}
        value={locale}
        onChange={setLocale}
      />
    </section>
  );
}
