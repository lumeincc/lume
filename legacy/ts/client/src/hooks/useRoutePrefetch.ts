// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useCallback, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";

/**
 * Warms the router cache for routes that are one click away.
 *
 * Every screen in the messenger is a dynamic App Router route, so a
 * `router.push` cannot render anything until the server has returned that
 * route's RSC payload. Measured on a production build over loopback — no
 * network at all — a rail click took **77 ms** from press to the DOM changing,
 * of which 34–65 ms was that one round trip. Over a real connection to Vercel
 * the same click is a few hundred milliseconds, which is the delay Bogdan
 * reported as "нажал и жду прям много мс".
 *
 * `<Link>` prefetches whatever is in the viewport automatically. These screens
 * navigate from `<button onClick={router.push(...)}>` instead — for good
 * reasons, they are rail items and list rows rather than anchors — and that
 * path gets no prefetching at all. So the payload is fetched at the worst
 * possible moment: after the user has already committed to going there.
 *
 * Two entry points, because the two kinds of destination differ:
 *
 * `usePrefetchRoutes` takes the handful of fixed destinations reachable from
 * every screen (`/chats`, `/settings`) and warms them once the browser is idle,
 * so it never competes with the work of the screen the user is looking at.
 *
 * `useHoverPrefetch` returns a handler for lists where prefetching everything
 * would be wasteful — a hundred conversations is a hundred requests nobody
 * asked for. Pointer-enter arrives tens to hundreds of milliseconds before the
 * click, which is most of the round trip, and it fires once per target.
 */

/** Fixed destinations reachable from anywhere; warmed when the browser is idle. */
export function usePrefetchRoutes(routes: readonly string[]): void {
  const router = useRouter();

  useEffect(() => {
    // `requestIdleCallback` is not in Safari; the timeout fallback keeps the
    // behaviour rather than the API.
    const schedule =
      typeof window !== "undefined" && "requestIdleCallback" in window
        ? window.requestIdleCallback.bind(window)
        : (cb: () => void) => window.setTimeout(cb, 300);

    const handle = schedule(() => {
      for (const route of routes) router.prefetch(route);
    });

    return () => {
      if (typeof window !== "undefined" && "cancelIdleCallback" in window) {
        window.cancelIdleCallback(handle as number);
      } else {
        clearTimeout(handle as number);
      }
    };
    // `routes` is a literal at every call site, so this runs once per mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);
}

/**
 * Prefetch on pointer-enter, once per destination.
 *
 * The seen-set matters: without it, moving the pointer across a list re-issues
 * a request for every row it crosses, which trades one slow click for a burst
 * of pointless traffic.
 */
export function useHoverPrefetch(): (href: string) => void {
  const router = useRouter();
  const seen = useRef<Set<string>>(new Set());

  return useCallback(
    (href: string) => {
      if (seen.current.has(href)) return;
      seen.current.add(href);
      router.prefetch(href);
    },
    [router],
  );
}
