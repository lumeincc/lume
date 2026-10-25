// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * A full document load, as opposed to a client-side route change.
 *
 * The router keeps the JavaScript context alive: module state, in-memory stores,
 * pending timers and anything else already decrypted all survive a
 * `router.push`. That is the point of it, and it is exactly wrong when the
 * intent is to leave a sensitive state behind — locking the vault, or a wipe.
 * A document load discards the context wholesale, which is a guarantee no
 * amount of careful teardown gives you.
 *
 * It lives in its own module for two reasons. It names the intent, so a reader
 * meeting it in a lock path sees a decision rather than an oddly heavy
 * navigation. And it is a seam: `window.location.assign` is non-configurable in
 * jsdom, so code calling it directly cannot be tested at all — the navigation
 * either silently does nothing or the test has to fight the environment.
 */
export function hardNavigate(path: string): void {
  window.location.assign(path);
}
