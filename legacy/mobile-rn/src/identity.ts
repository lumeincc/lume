// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import type { PlatformCrypto } from './platform/adapter'

/** PBKDF2 iterations for the at-rest master key — matches the web client. */
export const MASTER_KEY_ITERATIONS = 600_000
export const MASTER_KEY_BYTES = 32

/**
 * Derive the at-rest master key from the user's PIN — the same construction the
 * web client uses (PBKDF2-SHA256, 600k), but through the platform adapter so the
 * heavy derivation runs on native crypto on a phone instead of in JS.
 *
 * The master key protects the identity/session key material in storage; on the
 * web it is derived via SubtleCrypto and held only in a module-scoped cache,
 * never in application state. The mobile port keeps that invariant.
 */
export async function deriveMasterKey(
  platform: PlatformCrypto,
  pin: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const pinBytes = new TextEncoder().encode(pin)
  try {
    return await platform.pbkdf2(pinBytes, salt, MASTER_KEY_ITERATIONS, MASTER_KEY_BYTES)
  } finally {
    pinBytes.fill(0)
  }
}
