// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Serialise and collapse repeated writes of the same record.
 *
 * The vault stores each collection as one sealed blob, so saving the message list
 * re-encrypts and rewrites every message every time. Receiving twenty messages in
 * a burst — which is exactly what happens when the app reconnects and drains what
 * the relay held — therefore meant twenty full encrypt-and-write cycles of an
 * ever-growing list, all of them racing each other with the last one to land
 * deciding what survived.
 *
 * This fixes both halves:
 *
 *   - **Serialised**, so writes cannot interleave and an older snapshot can never
 *     overwrite a newer one.
 *   - **Collapsed**, so while a write is in flight every further update replaces
 *     the pending one instead of queueing behind it. Only the newest state is
 *     ever written, which is the only state that matters.
 *
 * Deliberately not a debounce: the first write starts immediately, so a single
 * message is persisted at once and nothing is left in a window where killing the
 * app would lose it. Collapsing only happens under load, where it is free.
 */

export interface WriteBehind<T> {
  /** Record the newest state and make sure it reaches storage. */
  queue(value: T): void
  /** Resolve once everything queued has landed. Call before zeroing the key. */
  flush(): Promise<void>
}

export function createWriteBehind<T>(
  write: (value: T) => Promise<void>,
  onError?: (error: unknown) => void
): WriteBehind<T> {
  // A box rather than the value itself, so `undefined` is a legal state to write.
  let pending: { value: T } | null = null
  let inFlight: Promise<void> | null = null

  function drain(): void {
    if (inFlight || !pending) return
    const { value } = pending
    pending = null

    // Routed through a resolved promise so a synchronous throw inside `write`
    // lands in the catch below instead of escaping into whoever called `queue`.
    inFlight = Promise.resolve()
      .then(() => write(value))
      .catch(error => {
        // A failed write must not take the app down or stop later writes: the
        // state is still correct in memory and the next update will try again.
        onError?.(error)
      })
      .then(() => {
        inFlight = null
        drain()
      })
  }

  return {
    queue(value: T) {
      pending = { value }
      drain()
    },
    async flush() {
      // Loop rather than await once: a write that was in flight when flush was
      // called may be followed by the state queued behind it.
      while (inFlight || pending) {
        if (inFlight) await inFlight
        else drain()
      }
    },
  }
}
