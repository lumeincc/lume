// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The outbox is what makes a message survive a phone's connection. These tests
 * pin the two decisions that matter: a transport failure is retried, and a
 * security refusal is not.
 */

import { describe, it, expect, vi } from 'vitest'
import { Outbox, MAX_SEND_ATTEMPTS, type OutboxEntry, type OutboxOutcome } from '@/outbox'
import type { SendResult } from '@/messaging'

function entry(id: string, text = 'hi', contactId = 'peer'): OutboxEntry {
  return { id, contactId, text, createdAt: Date.now(), attempts: 0 }
}

/**
 * Timers are driven by hand: the real backoff reaches a minute, and a test that
 * waits for it is a test nobody runs.
 */
function harness(deliver: (e: OutboxEntry) => Promise<SendResult>) {
  const outcomes: Array<{ id: string; outcome: OutboxOutcome }> = []
  const timers: Array<() => void> = []
  const delays: number[] = []

  const outbox = new Outbox({
    deliver,
    onOutcome: (e, outcome) => {
      outcomes.push({ id: e.id, outcome })
    },
    schedule: (fn, ms) => {
      delays.push(ms)
      timers.push(fn)
      return 0 as unknown as ReturnType<typeof setTimeout>
    },
    cancel: () => {},
  })

  /** Fire every pending timer and let the resulting work settle. */
  async function tick() {
    const due = timers.splice(0)
    for (const fn of due) fn()
    await flush()
  }

  return { outbox, outcomes, delays, tick }
}

/** Let queued microtasks run; the outbox never awaits real time itself. */
async function flush() {
  for (let i = 0; i < 20; i++) await Promise.resolve()
}

describe('outbox', () => {
  it('reports a delivered message as sent, with the relay id', async () => {
    const { outbox, outcomes } = harness(async () => ({ ok: true, messageId: 'server-1' }))
    outbox.enqueue(entry('a'))
    await flush()

    expect(outcomes).toEqual([{ id: 'a', outcome: { status: 'sent', serverId: 'server-1' } }])
    expect(outbox.size).toBe(0)
  })

  it('retries a transport failure and succeeds on a later attempt', async () => {
    let attempts = 0
    const { outbox, outcomes, tick } = harness(async () => {
      attempts++
      if (attempts < 3) return { ok: false, error: 'Нет соединения', retryable: true }
      return { ok: true, messageId: 'server-1' }
    })

    outbox.enqueue(entry('a'))
    await flush()
    expect(outbox.size).toBe(1) // still queued, not lost

    await tick()
    await tick()

    expect(attempts).toBe(3)
    expect(outcomes.at(-1)).toEqual({ id: 'a', outcome: { status: 'sent', serverId: 'server-1' } })
    expect(outbox.size).toBe(0)
  })

  it('does not retry a refusal — a pinning failure must stay visible', async () => {
    const deliver = vi.fn(async () => ({
      ok: false as const,
      error: 'Recipient identity does not match the trusted contact (possible MITM)',
      retryable: false,
    }))
    const { outbox, outcomes } = harness(deliver)

    outbox.enqueue(entry('a'))
    await flush()

    expect(deliver).toHaveBeenCalledOnce()
    expect(outcomes.at(-1)?.outcome.status).toBe('failed')
    expect(outcomes.at(-1)?.outcome.error).toMatch(/MITM/)
  })

  it('gives up visibly once the attempt budget is spent', async () => {
    const { outbox, outcomes, tick } = harness(async () => ({
      ok: false,
      error: 'Нет соединения',
      retryable: true,
    }))

    outbox.enqueue(entry('a'))
    await flush()
    for (let i = 0; i < MAX_SEND_ATTEMPTS; i++) await tick()

    const last = outcomes.at(-1)
    expect(last?.outcome.status).toBe('failed')
    // Failing silently would leave the user believing the message was sent.
    expect(last?.outcome.error).toBeTruthy()
    expect(outbox.size).toBe(0)
  })

  it('backs off further with each attempt', async () => {
    const { outbox, delays, tick } = harness(async () => ({
      ok: false,
      error: 'Нет соединения',
      retryable: true,
    }))

    outbox.enqueue(entry('a'))
    await flush()
    await tick()
    await tick()

    expect(delays.length).toBeGreaterThanOrEqual(3)
    expect(delays[1]!).toBeGreaterThan(delays[0]!)
    expect(delays[2]!).toBeGreaterThan(delays[1]!)
  })

  it('delivers in the order the user wrote them', async () => {
    const order: string[] = []
    const { outbox } = harness(async e => {
      order.push(e.id)
      await new Promise(resolve => setTimeout(resolve, 5))
      return { ok: true, messageId: e.id }
    })

    outbox.enqueue(entry('a'))
    outbox.enqueue(entry('b'))
    outbox.enqueue(entry('c'))
    await vi.waitFor(() => expect(outbox.size).toBe(0))

    expect(order).toEqual(['a', 'b', 'c'])
  })

  it('does not spend the budget when a new message is queued during backoff', async () => {
    let attempts = 0
    const { outbox } = harness(async () => {
      attempts++
      return { ok: false, error: 'Нет соединения', retryable: true }
    })

    outbox.enqueue(entry('a'))
    await flush()
    expect(attempts).toBe(1)

    // Typing more messages while offline must not burn through the retries: the
    // scheduled backoff owns the queue until it fires.
    outbox.enqueue(entry('b'))
    outbox.enqueue(entry('c'))
    await flush()

    expect(attempts).toBe(1)
  })

  it('kick skips the remaining backoff', async () => {
    let attempts = 0
    const { outbox } = harness(async () => {
      attempts++
      return { ok: false, error: 'Нет соединения', retryable: true }
    })

    outbox.enqueue(entry('a'))
    await flush()
    expect(attempts).toBe(1)

    // A socket that just connected is better evidence than any timer.
    outbox.kick()
    await flush()
    expect(attempts).toBe(2)
  })

  it('restores messages left pending by a previous run, oldest first', async () => {
    const order: string[] = []
    const { outbox } = harness(async e => {
      order.push(e.id)
      return { ok: true, messageId: e.id }
    })

    outbox.restore([
      { id: 'newer', contactId: 'peer', text: 'b', createdAt: 200, attempts: 0 },
      { id: 'older', contactId: 'peer', text: 'a', createdAt: 100, attempts: 0 },
    ])
    await flush()

    expect(order).toEqual(['older', 'newer'])
  })

  it('treats an unexpected throw as a transport failure instead of stranding the queue', async () => {
    let calls = 0
    const { outbox, outcomes, tick } = harness(async () => {
      calls++
      if (calls === 1) throw new Error('boom')
      return { ok: true, messageId: 'server-1' }
    })

    outbox.enqueue(entry('a'))
    await flush()
    await tick()

    expect(outcomes.at(-1)?.outcome.status).toBe('sent')
  })

  it('stops delivering once the session is locked', async () => {
    const deliver = vi.fn(async () => ({ ok: true as const, messageId: 'm' }))
    const { outbox } = harness(deliver)

    outbox.stop()
    outbox.enqueue(entry('a'))
    await flush()

    // Delivering here would seal a message with a master key that is being zeroed.
    expect(deliver).not.toHaveBeenCalled()
  })
})
