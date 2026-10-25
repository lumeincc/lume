// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Serialise async work per key.
 *
 * The Double Ratchet is a state machine: every operation reads the session,
 * advances it, and writes it back. Nothing in the engine enforced that those
 * three steps happen without another operation interleaving, and on a phone they
 * routinely do — the socket delivers a frame while the pending-message drain is
 * still running, or the user taps send twice.
 *
 * Two overlapping operations on one contact both read the same chain state:
 *
 *   - two sends produce two messages carrying the SAME message number, so the
 *     recipient can only ever decrypt one of them and the other is lost for good;
 *   - two receives each advance from the same base and the later write wins, so
 *     a DH ratchet step or a set of skipped keys is discarded and the session
 *     breaks permanently for both sides.
 *
 * Serialising by contact id removes the interleaving entirely. Different contacts
 * still run in parallel, because their sessions are independent.
 */

type Task<T> = () => Promise<T>

export class SerialQueue {
  private tails = new Map<string, Promise<unknown>>()

  /**
   * Run `task` after everything already queued for `key` has settled.
   *
   * A rejected task must not poison the queue: the chain continues from a
   * resolved promise, while the caller still sees the original rejection.
   */
  run<T>(key: string, task: Task<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve()
    const result = previous.then(task, task)

    // Track a settled-only version so one failure cannot reject every later task.
    const tail = result.then(
      () => undefined,
      () => undefined
    )
    this.tails.set(key, tail)

    // Drop the entry once this is the last task for the key, so a long-lived app
    // does not accumulate one promise per contact it ever spoke to.
    void tail.then(() => {
      if (this.tails.get(key) === tail) this.tails.delete(key)
    })

    return result
  }

  /** Wait for all queued work to settle. Used before locking or backgrounding. */
  async drain(): Promise<void> {
    while (this.tails.size > 0) {
      await Promise.all([...this.tails.values()])
    }
  }

  get pendingKeys(): number {
    return this.tails.size
  }
}

/**
 * The engine-wide ratchet queue.
 *
 * Deliberately module-scoped rather than passed around: correctness here depends
 * on every call site sharing one queue, and an injected instance is exactly the
 * kind of thing a future call site would forget to wire up.
 */
export const ratchetQueue = new SerialQueue()
