// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useEffect } from "react";

export default function ServiceWorkerRegistration() {
  useEffect(() => {
    if (typeof window === "undefined" || !("serviceWorker" in navigator)) return;
    // Dev + Turbopack/HMR: SW cache causes stale JS and hydration reload loops.
    if (process.env.NODE_ENV !== "production") return;

    navigator.serviceWorker
      .register("/sw.js")
      .then((reg) => {
        reg.addEventListener("updatefound", () => {
          const newWorker = reg.installing;
          if (!newWorker) return;
          newWorker.addEventListener("statechange", () => {
            if (
              newWorker.state === "activated" &&
              navigator.serviceWorker.controller
            ) {
              // New version available — reload on next navigation
              if (process.env.NODE_ENV !== 'production') console.log("[SW] New version activated.");
            }
          });
        });
      })
      .catch((err) => {
        if (process.env.NODE_ENV !== 'production') console.warn("[SW] Registration failed:", err);
      });
  }, []);

  return null;
}
