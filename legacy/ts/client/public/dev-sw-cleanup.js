// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

(() => {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;

  const cleanup = async () => {
    try {
      const hadController = Boolean(navigator.serviceWorker.controller);
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.map((reg) => reg.unregister()));

      if ("caches" in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map((key) => caches.delete(key)));
      }

      // One reload so the browser drops scripts served by the old worker.
      if (hadController && !sessionStorage.getItem("lume:sw-cleared")) {
        sessionStorage.setItem("lume:sw-cleared", "1");
        window.location.reload();
      }
    } catch {
      // ignore
    }
  };

  void cleanup();
})();
