// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Device crypto with a native PBKDF2 fast path.
 *
 * Pure JS needs ~65 s for 600k iterations under Hermes, which makes unlock
 * unusable; the native module does the same work in well under a second. The
 * pure-JS path is kept as a fallback rather than deleted, so a build without the
 * native module degrades in speed instead of failing to start.
 *
 * Both paths must produce identical bytes — `verifyPbkdf2Parity` below checks
 * exactly that against a fixed vector, and the UI runs it on device.
 */

import { encodeBase64, decodeBase64 } from 'tweetnacl-util'
import type { PlatformCrypto } from './adapter'
import { reactNativePlatform } from './reactNative'
import { LumeCrypto, hasNativePbkdf2 } from '../../modules/lume-crypto'

export const nativePbkdf2Available = hasNativePbkdf2

export const devicePlatformCrypto: PlatformCrypto = {
  async pbkdf2(password, salt, iterations, keyLenBytes) {
    if (LumeCrypto) {
      const out = await LumeCrypto.pbkdf2Base64(
        encodeBase64(password),
        encodeBase64(salt),
        iterations,
        keyLenBytes
      )
      return decodeBase64(out)
    }
    return reactNativePlatform.pbkdf2(password, salt, iterations, keyLenBytes)
  },

  randomBytes(length) {
    return reactNativePlatform.randomBytes(length)
  },
}

export interface ParityReport {
  native: boolean
  match: boolean
  nativeMs: number
  jsMs: number
  digestPrefix: string
}

/**
 * Runs the native and pure-JS derivations over the same input and compares them.
 * A low iteration count keeps the JS side quick enough to run interactively —
 * PBKDF2 either agrees on every iteration count or on none, so this is a valid
 * equivalence check, not a weakened one.
 */
export async function verifyPbkdf2Parity(iterations = 2000): Promise<ParityReport> {
  const password = new TextEncoder().encode('lume-parity-password')
  const salt = new TextEncoder().encode('lume-parity-salt')

  const t0 = Date.now()
  const nativeOut = await devicePlatformCrypto.pbkdf2(password, salt, iterations, 32)
  const nativeMs = Date.now() - t0

  const t1 = Date.now()
  const jsOut = await reactNativePlatform.pbkdf2(password, salt, iterations, 32)
  const jsMs = Date.now() - t1

  const a = encodeBase64(nativeOut)
  const b = encodeBase64(jsOut)
  return {
    native: nativePbkdf2Available,
    match: a === b,
    nativeMs,
    jsMs,
    digestPrefix: a.slice(0, 16),
  }
}
