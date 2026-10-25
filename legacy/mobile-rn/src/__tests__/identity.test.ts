// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect } from 'vitest'
import { deriveMasterKey, MASTER_KEY_BYTES } from '@/identity'
import { nodePlatform } from '@/platform/node'

describe('platform seam — master key derivation', () => {
  const salt = new Uint8Array(16).fill(7)
  const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

  it('derives a 32-byte key from a PIN via the adapter', async () => {
    const key = await deriveMasterKey(nodePlatform, '123456', salt)
    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(MASTER_KEY_BYTES)
  })

  it('is deterministic for the same PIN + salt', async () => {
    const a = await deriveMasterKey(nodePlatform, '123456', salt)
    const b = await deriveMasterKey(nodePlatform, '123456', salt)
    expect(hex(a)).toBe(hex(b))
  })

  it('differs for a different PIN and a different salt', async () => {
    const base = await deriveMasterKey(nodePlatform, '123456', salt)
    const otherPin = await deriveMasterKey(nodePlatform, '654321', salt)
    const otherSalt = await deriveMasterKey(nodePlatform, '123456', new Uint8Array(16).fill(9))
    expect(hex(base)).not.toBe(hex(otherPin))
    expect(hex(base)).not.toBe(hex(otherSalt))
  })

  it('provides OS-backed randomness of the requested length', () => {
    const r = nodePlatform.randomBytes(32)
    expect(r.length).toBe(32)
    expect(r.some(byte => byte !== 0)).toBe(true)
  })
})
