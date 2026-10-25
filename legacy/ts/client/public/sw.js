// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// LUME Service Worker
// Cache-first for static assets, network-first for API, offline fallback.

const CACHE_VERSION = "lume-v4";
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const OFFLINE_URL = "/offline.html";

// Assets to pre-cache on install
const PRECACHE_URLS = [
  OFFLINE_URL,
  "/lume-icon.png",
];

// --- Lifecycle ---

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== STATIC_CACHE)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

// --- Fetch strategies ---

function isStaticAsset(url) {
  // Never cache Next.js build output — stale chunks cause hydration mismatches.
  if (url.pathname.startsWith("/_next/")) return false;

  return /\.(js|css|png|jpg|jpeg|svg|gif|webp|ico|woff2?|ttf|eot)(\?.*)?$/i.test(
    url.pathname
  );
}

function isApiRequest(url) {
  return (
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/socket.io")
  );
}

function isNavigationRequest(request) {
  return request.mode === "navigate";
}

// Cache-first: try cache, fall back to network and update cache.
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return new Response("", { status: 503, statusText: "Service Unavailable" });
  }
}

// Network-first: always go to network, never cache.
async function networkOnly(request) {
  try {
    return await fetch(request);
  } catch {
    return new Response(JSON.stringify({ error: "offline" }), {
      status: 503,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// Navigation: network-first with offline fallback page.
async function navigationHandler(request) {
  try {
    return await fetch(request);
  } catch {
    const cached = await caches.match(OFFLINE_URL);
    return cached || new Response("Offline", { status: 503 });
  }
}

// --- Push Notifications ---

self.addEventListener("push", (event) => {
  if (!event.data) return;

  let payload;
  try {
    payload = event.data.json();
  } catch {
    payload = { title: "LUME", body: "New message" };
  }

  const options = {
    body: payload.body || "New message",
    icon: "/lume-icon.png",
    badge: "/lume-icon.png",
    tag: payload.tag || "lume-notification",
    data: { url: "/" },
  };

  event.waitUntil(
    self.registration.showNotification(payload.title || "LUME", options)
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data?.url || "/";

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && "focus" in client) {
            return client.focus();
          }
        }
        return self.clients.openWindow(url);
      })
  );
});

// --- Router ---

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Skip non-http(s) requests (e.g. chrome-extension://)
  if (!url.protocol.startsWith("http")) return;

  if (isApiRequest(url)) {
    event.respondWith(networkOnly(event.request));
  } else if (isNavigationRequest(event.request)) {
    event.respondWith(navigationHandler(event.request));
  } else if (isStaticAsset(url)) {
    event.respondWith(cacheFirst(event.request));
  } else {
    // Default: network with cache fallback
    event.respondWith(
      fetch(event.request).catch(() => caches.match(event.request))
    );
  }
});
