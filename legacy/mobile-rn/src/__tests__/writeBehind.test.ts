// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect, vi } from 'vitest'
import { createWriteBehind } from '@/lib/writeBehind'

/** Resolve on demand, so a write can be held open while more updates arrive. */
function deferred<T = void>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('write-behind', () => {
  it('writes the first value immediately, with no artificial delay', async () => {
    const written: number[] = []
    const writer = createWriteBehind<number>(async v => {
      written.push(v)
    })

    writer.queue(1)
    await writer.flush()
    expect(written).toEqual([1])
  })

  it('collapses a burst into one follow-up write of the newest state', async () => {
    const written: number[] = []
    const first = deferred()
    let calls = 0

    const writer = createWriteBehind<number>(async v => {
      calls++
      written.push(v)
      if (calls === 1) await first.promise
    })

    writer.queue(1)
    // Everything below arrives while the first write is still in flight. Each one
    // used to mean another full encrypt-and-write of the entire message list.
    writer.queue(2)
    writer.queue(3)
    writer.queue(4)

    first.resolve()
    await writer.flush()

    expect(written).toEqual([1, 4])
  })

  it('never lets an older snapshot overwrite a newer one', async () => {
    const written: number[] = []
    const gates = [deferred(), deferred()]
    let calls = 0

    const writer = createWriteBehind<number>(async v => {
      const gate = gates[calls++]
      written.push(v)
      if (gate) await gate.promise
    })

    writer.queue(1)
    writer.queue(2)
    // Resolving out of order is exactly what unserialised writes allowed.
    gates[1]?.resolve()
    gates[0]?.resolve()
    await writer.flush()

    expect(written).toEqual([1, 2])
  })

  it('flush waits for work queued behind the write already in flight', async () => {
    let done = false
    const gate = deferred()
    let calls = 0

    const writer = createWriteBehind<number>(async () => {
      if (calls++ === 0) await gate.promise
      done = true
    })

    writer.queue(1)
    writer.queue(2)
    const flushed = writer.flush()
    gate.resolve()
    await flushed

    // The master key is zeroed right after flush resolves, so a write still
    // pending at that point would be lost — or seal with zeroes.
    expect(done).toBe(true)
    expect(calls).toBe(2)
  })

  it('survives a failing write and keeps accepting later ones', async () => {
    const written: number[] = []
    const errors: unknown[] = []
    let calls = 0

    const writer = createWriteBehind<number>(
      async v => {
        if (calls++ === 0) throw new Error('storage full')
        written.push(v)
      },
      e => errors.push(e)
    )

    writer.queue(1)
    await writer.flush()
    writer.queue(2)
    await writer.flush()

    expect(errors).toHaveLength(1)
    expect(written).toEqual([2])
  })

  it('reports a synchronous throw instead of letting it escape into the caller', async () => {
    const errors: unknown[] = []
    const writer = createWriteBehind<number>(
      () => {
        throw new Error('sync boom')
      },
      e => errors.push(e)
    )

    expect(() => writer.queue(1)).not.toThrow()
    await writer.flush()
    expect(errors).toHaveLength(1)
  })
})

describe('serial queue', () => {
  it('runs tasks for one key strictly one at a time', async () => {
    const { SerialQueue } = await import('@/lib/serialQueue')
    const queue = new SerialQueue()
    let active = 0
    let maxActive = 0

    async function task() {
      active++
      maxActive = Math.max(maxActive, active)
      await new Promise(resolve => setTimeout(resolve, 5))
      active--
    }

    await Promise.all([queue.run('a', task), queue.run('a', task), queue.run('a', task)])
    expect(maxActive).toBe(1)
  })

  it('runs different keys in parallel', async () => {
    const { SerialQueue } = await import('@/lib/serialQueue')
    const queue = new SerialQueue()
    let active = 0
    let maxActive = 0

    async function task() {
      active++
      maxActive = Math.max(maxActive, active)
      await new Promise(resolve => setTimeout(resolve, 5))
      active--
    }

    await Promise.all([queue.run('a', task), queue.run('b', task)])
    expect(maxActive).toBe(2)
  })

  it('a rejected task does not poison the queue', async () => {
    const { SerialQueue } = await import('@/lib/serialQueue')
    const queue = new SerialQueue()

    const failed = queue.run('a', async () => {
      throw new Error('boom')
    })
    await expect(failed).rejects.toThrow('boom')

    // The caller sees the rejection, but a later message on the same contact
    // must still be sent.
    await expect(queue.run('a', async () => 'ok')).resolves.toBe('ok')
  })

  it('forgets keys once their work is done', async () => {
    const { SerialQueue } = await import('@/lib/serialQueue')
    const queue = new SerialQueue()

    await queue.run('a', async () => undefined)
    await queue.drain()
    expect(queue.pendingKeys).toBe(0)
  })
})
