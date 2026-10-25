// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The mobile adapter derives the at-rest master key with pure-JS PBKDF2
 * (@noble/hashes) instead of the WebCrypto PBKDF2 the web client uses. Same
 * construction, different implementation — so it has to be proven byte-identical,
 * otherwise a phone and a browser would disagree about the same PIN.
 *
 * The device-runtime checks (missing Buffer/TextEncoder on Hermes) live in
 * scripts/device-sim.ts — `npm run sim` — because stripping globals inside the
 * test runner breaks the runner itself.
 */

import { describe, it, expect } from 'vitest'
import { webcrypto } from 'node:crypto'
import { reactNativePlatform } from '@/platform/reactNative'

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

async function webCryptoPbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number
): Promise<Uint8Array> {
  const keyMaterial = await webcrypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
  const bits = await webcrypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    dkLen * 8
  )
  return new Uint8Array(bits)
}

describe('PBKDF2 parity — mobile (pure JS) vs web client (WebCrypto)', () => {
  const salt = new Uint8Array(16).fill(7)
  // Lower than the production 600k purely to keep the suite quick; the
  // implementations either agree at every iteration count or at none.
  const iterations = 50_000

  it('derives an identical 32-byte key', async () => {
    const pin = new TextEncoder().encode('123456')
    const mobile = await reactNativePlatform.pbkdf2(pin, salt, iterations, 32)
    const web = await webCryptoPbkdf2(pin, salt, iterations, 32)
    expect(mobile.length).toBe(32)
    expect(hex(mobile)).toBe(hex(web))
  }, 30_000)

  it('agrees on a non-ASCII PIN and a different salt', async () => {
    const pin = new TextEncoder().encode('пароль-🔐')
    const otherSalt = new Uint8Array(16).fill(200)
    const mobile = await reactNativePlatform.pbkdf2(pin, otherSalt, iterations, 32)
    const web = await webCryptoPbkdf2(pin, otherSalt, iterations, 32)
    expect(hex(mobile)).toBe(hex(web))
  }, 30_000)

  it('returns OS randomness of the requested length', () => {
    const r = reactNativePlatform.randomBytes(32)
    expect(r.length).toBe(32)
    expect(r.some(b => b !== 0)).toBe(true)
  })
})
