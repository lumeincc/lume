// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Per-contact lock around Double Ratchet session mutations.
 *
 * Every ratchet operation reads the stored session, advances it, and writes it
 * back, with network calls in between. Two of those overlapping on one contact
 * both start from the same state, and the later write silently discards the
 * other's advance:
 *
 *   - two sends produce two messages carrying the same message number, so the
 *     recipient can only ever open one of them and the other is lost with no
 *     error raised anywhere;
 *   - a send overlapping an inbound message throws away the DH ratchet step the
 *     receive just committed, which desynchronises the session for good.
 *
 * The second case needs no mistake by the user — only a message arriving while
 * one is being sent, which is ordinary conversation.
 *
 * This lives in its own module because correctness depends on **one** lock being
 * shared by every path that touches a session. It used to be private to
 * useMessengerSync, which left the send path in the chat screen unprotected.
 *
 * **Web Locks, not just a promise chain.** Tabs of this origin share one
 * IndexedDB, so the race is reachable across them: two tabs read the same
 * session, both advance it, and each in-process lock is satisfied while the
 * store is clobbered anyway. `navigator.locks` serialises across contexts and is
 * what `crypto/spkRotation.ts` already uses for the same hazard — two mechanisms
 * for one problem, with the weaker one guarding the ratchet, was the gap
 * (SEC-20260805-003). The chain below remains as the fallback for same-tab
 * overlap where the API is missing.
 */

const senderLocks = new Map<string, Promise<unknown>>();

/** Serialises within this JS context. Fallback when Web Locks is unavailable. */
function withInProcessLock<T>(senderId: string, fn: () => Promise<T>): Promise<T> {
  const prev = senderLocks.get(senderId) ?? Promise.resolve();
  // `fn` on both branches: a rejected predecessor must not skip this task.
  const next = prev.then(fn, fn);
  senderLocks.set(senderId, next);
  next
    .catch(() => {
      // Ownership of the error belongs to the caller awaiting `next`; this
      // handler exists only so the cleanup below never triggers an unhandled
      // rejection warning.
    })
    .finally(() => {
      if (senderLocks.get(senderId) === next) {
        senderLocks.delete(senderId);
      }
    });
  return next;
}

export function withSenderLock<T>(
  senderId: string,
  fn: () => Promise<T>,
): Promise<T> {
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  if (locks && typeof locks.request === "function") {
    // Keyed per contact: conversations are independent, and one global lock
    // would serialise every conversation behind the slowest network call.
    return locks.request(`lume-ratchet-${senderId}`, fn) as Promise<T>;
  }
  return withInProcessLock(senderId, fn);
}
