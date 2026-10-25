// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Startup validation for WS_JWT_SECRET (SEC-20260621-014).
 *
 * A length check alone is not enough: the documented example placeholder is
 * longer than 32 bytes and would pass if copied verbatim into production. We also
 * reject known placeholders and obviously low-entropy values so a real random
 * secret is required before the server will start.
 */

const KNOWN_PLACEHOLDERS = ['CHANGE_ME_TO_A_LONG_RANDOM_SECRET_AT_LEAST_32_BYTES']

const PLACEHOLDER_SUBSTRINGS = [
  'change_me',
  'changeme',
  'placeholder',
  'your-secret',
  'your_secret',
  'replace-me',
  'replaceme',
]

export type SecretValidation = { ok: true } | { ok: false; reason: string }

export function validateWsJwtSecret(secret: string | undefined | null): SecretValidation {
  if (!secret) {
    return { ok: false, reason: 'WS_JWT_SECRET is missing' }
  }
  if (Buffer.byteLength(secret) < 32) {
    return { ok: false, reason: 'WS_JWT_SECRET is too short (must be >= 32 bytes)' }
  }

  const trimmed = secret.trim()
  const lowered = trimmed.toLowerCase()
  if (
    KNOWN_PLACEHOLDERS.includes(trimmed) ||
    PLACEHOLDER_SUBSTRINGS.some(p => lowered.includes(p))
  ) {
    return {
      ok: false,
      reason: 'WS_JWT_SECRET is a known placeholder — generate a real random secret',
    }
  }

  // Reject obviously low-entropy values (e.g. "xxxxxxxx..." or "abababab...").
  const distinctChars = new Set(trimmed).size
  if (distinctChars < 8) {
    return {
      ok: false,
      reason: 'WS_JWT_SECRET has too little entropy (too few distinct characters)',
    }
  }

  return { ok: true }
}
