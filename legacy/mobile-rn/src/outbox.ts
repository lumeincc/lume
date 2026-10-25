// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The outbound queue.
 *
 * Before this existed, sending was a single attempt: if the phone was between
 * cells, `send()` returned an error string, the chat screen showed it, and the
 * message was gone. On a desktop that is merely annoying; on a phone, where the
 * connection drops constantly, it is the difference between a messenger that
 * works and one that does not.
 *
 * So a message now becomes durable state the moment the user sends it. It is
 * written to the encrypted vault as `pending`, shown in the conversation right
 * away, and delivered by this queue — across backoff, across a reconnect, and
 * across an app restart.
 *
 * Two rules shape the retry policy:
 *
 *   1. **Only transport failures are retried.** A refused signature or an identity
 *      that does not match the pinned contact is a security stop; repeating it
 *      would bury a warning the user needs to see. Those fail immediately.
 *   2. **Giving up is visible.** After the attempt budget is spent the message is
 *      marked `failed`, not silently dropped, and the user can retry it by hand.
 *
 * Delivery is strictly one at a time and FIFO, so messages arrive in the order
 * they were written — parallel sends would reorder a conversation for no gain.
 */

import type { SendResult } from './messaging'

export type OutboxStatus = 'pending' | 'sent' | 'failed'

export interface OutboxEntry {
  /** Client-generated and stable across retries: UI key and dedup token. */
  id: string
  contactId: string
  text: string
  createdAt: number
  attempts: number
}

export interface OutboxOutcome {
  status: OutboxStatus
  error?: string
  /** The relay's id, once it has accepted the message. */
  serverId?: string
}

export interface OutboxDeps {
  deliver(entry: OutboxEntry): Promise<SendResult>
  onOutcome(entry: OutboxEntry, outcome: OutboxOutcome): void | Promise<void>
  /** Injected so tests drive time instead of waiting for it. */
  schedule?(fn: () => void, ms: number): ReturnType<typeof setTimeout>
  cancel?(handle: ReturnType<typeof setTimeout>): void
}

const BASE_RETRY_DELAY_MS = 1_000
const MAX_RETRY_DELAY_MS = 60_000
/**
 * Roughly ten minutes of backoff before a message is called failed. Long enough
 * to ride out a tunnel or a lift, short enough that the user is not left
 * believing a message is on its way an hour later.
 */
export const MAX_SEND_ATTEMPTS = 10

export class Outbox {
  private queue: OutboxEntry[] = []
  private running = false
  private timer: ReturnType<typeof setTimeout> | null = null
  private stopped = false

  private readonly schedule: NonNullable<OutboxDeps['schedule']>
  private readonly cancel: NonNullable<OutboxDeps['cancel']>

  constructor(private deps: OutboxDeps) {
    this.schedule = deps.schedule ?? ((fn, ms) => setTimeout(fn, ms))
    this.cancel = deps.cancel ?? (handle => clearTimeout(handle))
  }

  /** Queue a freshly composed message. */
  enqueue(entry: OutboxEntry): void {
    this.queue.push(entry)
    void this.pump()
  }

  /**
   * Re-queue messages that were still pending when the app last closed, oldest
   * first. Called after unlock, which is the only point where the vault has been
   * read and delivery can actually be attempted.
   */
  restore(entries: OutboxEntry[]): void {
    const known = new Set(this.queue.map(e => e.id))
    const restored = entries.filter(e => !known.has(e.id)).sort((a, b) => a.createdAt - b.createdAt)
    if (restored.length === 0) return
    this.queue = [...restored, ...this.queue]
    void this.pump()
  }

  /**
   * Try again now, ignoring any backoff already scheduled.
   *
   * Called when the socket reconnects or the app returns to the foreground:
   * either is direct evidence that the network is back, which beats waiting out
   * a timer that was sized for a blind guess.
   */
  kick(): void {
    this.clearTimer()
    void this.pump()
  }

  /** Put a message the user gave up on back in the queue with a fresh budget. */
  retry(entry: OutboxEntry): void {
    this.enqueue({ ...entry, attempts: 0 })
  }

  /**
   * Stop delivering, permanently for this instance.
   *
   * Called on lock, where the master key is about to be zeroed and a delivery in
   * flight would try to seal a message with it. Terminal by design: the next
   * unlock builds a fresh queue from the vault, so a stale instance can never
   * come back to life against another account's keys.
   */
  stop(): void {
    this.stopped = true
    this.clearTimer()
    this.queue = []
  }

  get size(): number {
    return this.queue.length
  }

  private clearTimer(): void {
    if (this.timer !== null) this.cancel(this.timer)
    this.timer = null
  }

  private async pump(): Promise<void> {
    if (this.running || this.stopped) return
    // A scheduled retry owns the queue until it fires. Without this, composing a
    // new message while offline would immediately re-attempt the stuck head, so
    // ten messages typed in a tunnel would burn the whole budget in seconds and
    // all of them would come back "failed" — the exact opposite of the point.
    // `kick()` clears the timer first, so genuine evidence of connectivity still
    // skips the wait.
    //
    // Compared against null rather than tested for truthiness: a timer handle is
    // a plain number outside Node and 0 is a legal one, which would have made the
    // guard silently do nothing.
    if (this.timer !== null) return
    this.running = true
    try {
      while (this.queue.length > 0 && !this.stopped) {
        const entry = this.queue[0]
        if (!entry) break

        const attempt = { ...entry, attempts: entry.attempts + 1 }
        let result: SendResult
        try {
          result = await this.deps.deliver(attempt)
        } catch (e) {
          // An unexpected throw is treated as a transport failure rather than
          // being allowed to kill the pump and strand every queued message.
          result = { ok: false, error: describe(e), retryable: true }
        }
        if (this.stopped) return

        if (result.ok) {
          this.queue.shift()
          await this.deps.onOutcome(attempt, { status: 'sent', serverId: result.messageId })
          continue
        }

        const budgetLeft = attempt.attempts < MAX_SEND_ATTEMPTS
        if (!result.retryable || !budgetLeft) {
          this.queue.shift()
          await this.deps.onOutcome(attempt, { status: 'failed', error: result.error })
          continue
        }

        // Keep the entry at the head — order is part of the contract — and let
        // the caller see that it is still trying.
        this.queue[0] = attempt
        await this.deps.onOutcome(attempt, { status: 'pending', error: result.error })
        this.scheduleRetry(attempt.attempts)
        return
      }
    } finally {
      this.running = false
    }
  }

  private scheduleRetry(attempts: number): void {
    const delay = Math.min(MAX_RETRY_DELAY_MS, BASE_RETRY_DELAY_MS * 2 ** (attempts - 1))
    this.clearTimer()
    this.timer = this.schedule(() => {
      this.timer = null
      void this.pump()
    }, delay)
  }
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
