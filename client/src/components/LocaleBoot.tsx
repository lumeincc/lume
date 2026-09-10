// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useEffect } from "react";
import { detectLocale, DEFAULT_LOCALE } from "@/lib/i18n";
import { useUIStore } from "@/stores";

/**
 * Applies the reader's actual language once, after the first render.
 *
 * The server cannot know it. The choice lives in `localStorage` — deliberately,
 * so that an anonymous account hands the server one attribute fewer — and the
 * fallback is `navigator.language`, which is equally unavailable during
 * server rendering.
 *
 * So the locale used to be resolved at module scope, which meant the client
 * bundle resolved Russian while the server had already rendered English. Every
 * `t()` disagreed across the boundary, React found a text mismatch, and threw
 * away the entire server-rendered tree to rebuild it — the React #418 that sat
 * in the console on every load.
 *
 * Both sides now start at the default and this shifts to the real locale on
 * mount. The reader still sees the default for one frame, exactly as before —
 * the difference is that the frame is now a deliberate re-render of a tree
 * React kept, rather than the wreckage of one it discarded.
 *
 * Removing that frame entirely would mean telling the server the language, and
 * the only safe way to do that here is a cookie. `t()` is a module-scoped
 * singleton: setting it per request in a shared server process would let one
 * reader's language leak into another's response. That is a real refactor, not
 * a quick fix, and not worth trading a correctness hazard for one frame.
 */
export default function LocaleBoot() {
  useEffect(() => {
    const detected = detectLocale();
    if (detected === DEFAULT_LOCALE) return;
    // Reading through getState avoids subscribing this component to the very
    // value it sets, which would re-run the effect for no reason.
    if (useUIStore.getState().locale === detected) return;
    useUIStore.getState().setLocale(detected);
  }, []);

  return null;
}
