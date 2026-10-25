// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useEffect } from "react";
import { useUIStore } from "@/stores";

/**
 * Keeps `<html lang>` matching the active locale.
 *
 * The root layout is a server component and renders `lang="en"`. Setting the
 * attribute any earlier than an effect does not survive — hydration reconciles
 * it back to what the server sent. Without this, a browser-detected Russian
 * interface is still announced as English to a screen reader, and the wrong
 * hyphenation and quotation rules apply.
 *
 * Renders nothing.
 */
export default function LocaleLang() {
  const locale = useUIStore((s) => s.locale);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  return null;
}
